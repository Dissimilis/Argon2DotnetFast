using Argon2DotnetFast.Internal;

namespace Argon2DotnetFast;

/// <summary>Hashes complete passwords using a reusable arena. Use one instance per concurrent caller.</summary>
/// <remarks>
/// Passwords are never retained. With more than one execution thread, the constructor starts persistent
/// worker threads that fill lanes alongside the caller; p=1 starts none. The thread count never changes the tag.
/// A call that overlaps another call on the same instance throws <see cref="InvalidOperationException"/>.
/// </remarks>
public sealed class Argon2Hasher : IDisposable
{
    private readonly Arena arena;
    private readonly Argon2Core core;
    private readonly Lanes? lanes;
    private int busy;
    private volatile bool disposed;

    /// <summary>The immutable parameters used by this instance.</summary>
    public Argon2Parameters Parameters { get; }

    /// <summary>Actual execution thread count, including the caller.</summary>
    /// <remarks>At most min(threads, Parallelism, ProcessorCount); lower when a worker thread failed to start.</remarks>
    public int ThreadCount => lanes?.Count ?? 1;

    /// <summary>Validates parameters, allocates, aligns, and clears a reusable arena, and starts worker threads.</summary>
    /// <param name="parameters">Algorithm parameters, including tag length.</param>
    /// <param name="threads">Execution cap including the caller; zero means min(Parallelism, ProcessorCount).</param>
    public Argon2Hasher(in Argon2Parameters parameters, int threads = 0) : this(parameters, threads, touch: true)
    {
    }

    // The one-shot methods pass touch: false. Their arena is used once, so faulting its pages in up
    // front on the caller only moves the faults off the lane threads.
    internal Argon2Hasher(in Argon2Parameters parameters, int threads, bool touch)
    {
        parameters.Validate();
        Validation.Threads(threads);
        Parameters = parameters;
        int cap = Math.Min(parameters.Parallelism, Environment.ProcessorCount);
        int count = Math.Max(1, threads == 0 ? cap : Math.Min(threads, cap));
        arena = new Arena(parameters.MemoryBytes, Argon2Core.ScratchWords, count, touch);
        try
        {
            core = new Argon2Core(parameters, arena);
            if (count > 1) lanes = Lanes.Start(count - 1);
        }
        catch { arena.Dispose(); throw; }
        if (lanes is null) GC.SuppressFinalize(this);
    }

    /// <summary>Stops the idle worker threads of a hasher that was never disposed.</summary>
    ~Argon2Hasher() => lanes?.Abandon();

    /// <summary>Returns a new raw tag array while reusing the arena.</summary>
    public byte[] Hash(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, Argon2AdditionalInputs inputs = default)
    {
        ThrowIfDisposed();
        Validation.Inputs(Parameters, salt);
        byte[] output = new byte[Parameters.OutputLength];
        try { HashInto(password, salt, output, inputs); return output; }
        catch { Sensitive.Clear(output); throw; }
    }

    /// <summary>Returns a new raw tag array for a strict UTF-8 character password.</summary>
    public byte[] Hash(ReadOnlySpan<char> password, ReadOnlySpan<byte> salt, Argon2AdditionalInputs inputs = default)
    {
        ThrowIfDisposed();
        Validation.Inputs(Parameters, salt);
        byte[] output = new byte[Parameters.OutputLength];
        try { HashInto(password, salt, output, inputs); return output; }
        catch { Sensitive.Clear(output); throw; }
    }

    /// <summary>Writes a raw tag into a destination of exactly the configured length.</summary>
    /// <exception cref="ArgumentException">The destination length differs from OutputLength, or it overlaps an input.</exception>
    public void HashInto(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, Span<byte> destination,
        Argon2AdditionalInputs inputs = default)
    {
        Enter();
        try { HashCore(password, salt, destination, inputs, ThreadCount); }
        finally { Exit(); }
    }

    /// <summary>Encodes a character password as strict UTF-8 and writes a raw tag of exactly the configured length.</summary>
    /// <exception cref="ArgumentException">The destination length differs from OutputLength, or it overlaps an input.</exception>
    public void HashInto(ReadOnlySpan<char> password, ReadOnlySpan<byte> salt, Span<byte> destination,
        Argon2AdditionalInputs inputs = default)
    {
        Enter();
        try
        {
            CheckHash(salt, destination);
            Validation.NoOverlap(password, salt, destination, inputs);
            using NativeBuffer bytes = Sensitive.Encode(password);
            HashCore(bytes.Span, salt, destination, inputs, ThreadCount);
        }
        finally { Exit(); }
    }

    /// <summary>Generates a random salt and returns a PHC string using this instance's parameters.</summary>
    public string HashToString(ReadOnlySpan<byte> password, Argon2AdditionalInputs inputs = default, int saltLength = 16)
    {
        ThrowIfDisposed();
        byte[] salt = Sensitive.Salt(saltLength);
        byte[] tag = Hash(password, salt, inputs);
        try { return Phc.Encode(Parameters, salt, tag); }
        finally { Sensitive.Clear(tag); }
    }

    /// <summary>Generates a random salt and returns a PHC string for a strict UTF-8 character password.</summary>
    public string HashToString(ReadOnlySpan<char> password, Argon2AdditionalInputs inputs = default, int saltLength = 16)
    {
        ThrowIfDisposed();
        byte[] salt = Sensitive.Salt(saltLength);
        byte[] tag = Hash(password, salt, inputs);
        try { return Phc.Encode(Parameters, salt, tag); }
        finally { Sensitive.Clear(tag); }
    }

    /// <summary>Verifies PHC text under limits, reusing the arena when the stored parameters equal <see cref="Parameters"/>.</summary>
    /// <remarks>
    /// Other stored parameters are verified one-shot with a temporary arena, so peak memory is this arena plus that one.
    /// False means an input mismatch. Malformed text, exceeded limits, and resource failures throw.
    /// </remarks>
    public bool Verify(ReadOnlySpan<char> encoded, ReadOnlySpan<byte> password,
        in Argon2VerificationLimits limits, Argon2AdditionalInputs inputs = default)
    {
        Enter();
        try
        {
            ThrowIfDisposed();
            Phc.Prepare(encoded, limits, out Argon2Parameters stored, out byte[] salt, out byte[] expected);
            if (stored != Parameters)
                return Argon2.Verify(stored, password, salt, expected, inputs, limits.MaxThreads);
            return VerifyCore(password, salt, expected, inputs, limits.MaxThreads);
        }
        finally { Exit(); }
    }

    /// <summary>Verifies PHC text for a strict UTF-8 character password. See the byte overload.</summary>
    public bool Verify(ReadOnlySpan<char> encoded, ReadOnlySpan<char> password,
        in Argon2VerificationLimits limits, Argon2AdditionalInputs inputs = default)
    {
        Enter();
        try
        {
            ThrowIfDisposed();
            Phc.Prepare(encoded, limits, out Argon2Parameters stored, out byte[] salt, out byte[] expected);
            if (stored != Parameters)
                return Argon2.Verify(stored, password, salt, expected, inputs, limits.MaxThreads);
            using NativeBuffer bytes = Sensitive.Encode(password);
            return VerifyCore(bytes.Span, salt, expected, inputs, limits.MaxThreads);
        }
        finally { Exit(); }
    }

    internal bool VerifyTag(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> expected,
        Argon2AdditionalInputs inputs)
    {
        Enter();
        try { return VerifyCore(password, salt, expected, inputs, ThreadCount); }
        finally { Exit(); }
    }

    private bool VerifyCore(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> expected,
        Argon2AdditionalInputs inputs, int threads)
    {
        Validation.ExactLength(expected.Length, Parameters.OutputLength, nameof(expected));
        using var actual = new NativeBuffer(Parameters.OutputLength);
        HashCore(password, salt, actual.Span, inputs, threads);
        return Sensitive.Equals(actual.Span, expected);
    }

    private void HashCore(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, Span<byte> destination,
        Argon2AdditionalInputs inputs, int threads)
    {
        CheckHash(salt, destination);
        Validation.NoOverlap(password, salt, destination, inputs);
        bool acquired = false;
        try
        {
            arena.DangerousAddRef(ref acquired);
            arena.MarkDirty();
            try { core.Hash(password, salt, destination, inputs.Secret, inputs.AssociatedData, lanes, threads); }
            finally { arena.Clear(); }
        }
        finally { if (acquired) arena.DangerousRelease(); }
    }

    private void CheckHash(ReadOnlySpan<byte> salt, Span<byte> destination)
    {
        ThrowIfDisposed();
        Validation.Inputs(Parameters, salt);
        Validation.ExactLength(destination.Length, Parameters.OutputLength, nameof(destination));
    }

    private void Enter()
    {
        if (Interlocked.CompareExchange(ref busy, 1, 0) != 0)
            throw new InvalidOperationException("Argon2Hasher is already in use by another call. Use one instance per concurrent caller.");
    }

    private void Exit()
    {
        // A full fence, so the read of disposed below cannot move ahead of releasing the guard.
        Interlocked.Exchange(ref busy, 0);
        if (disposed) StopLanes();
    }

    // Stops the workers unless a call holds the guard; that call's Exit stops them instead.
    private void StopLanes()
    {
        if (lanes is null || Interlocked.CompareExchange(ref busy, 1, 0) != 0) return;
        try { lanes.Dispose(); }
        finally { Interlocked.Exchange(ref busy, 0); }
    }

    private void ThrowIfDisposed()
    {
        if (arena.IsClosed) throw new ObjectDisposedException(nameof(Argon2Hasher));
    }

    /// <summary>Wipes and releases the arena and stops the worker threads. Repeated disposal is harmless.</summary>
    public void Dispose()
    {
        disposed = true;
        arena.Dispose();
        StopLanes();
        GC.SuppressFinalize(this);
    }
}
