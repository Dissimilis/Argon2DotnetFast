namespace Argon2DotnetFast;

/// <summary>The Argon2 memory addressing algorithm.</summary>
public enum Argon2Type
{
    /// <summary>Data-dependent addressing.</summary>
    D = 0,
    /// <summary>Data-independent addressing.</summary>
    I = 1,
    /// <summary>Hybrid addressing, intended for password hashing.</summary>
    Id = 2
}

/// <summary>The version included in the Argon2 hash input.</summary>
public enum Argon2Version
{
    /// <summary>Argon2 version 1.0 (decimal 16).</summary>
    V10 = 0x10,
    /// <summary>Argon2 version 1.3 (decimal 19).</summary>
    V13 = 0x13
}

/// <summary>Immutable values that determine an Argon2 tag. Thread count is separate.</summary>
/// <param name="Type">Memory addressing algorithm.</param>
/// <param name="MemoryKiB">Total memory cost in kibibytes, before rounding to complete slices.</param>
/// <param name="Iterations">Number of passes over the memory.</param>
/// <param name="Parallelism">Number of algorithm lanes, independent of execution threads.</param>
/// <param name="OutputLength">Tag length in bytes, at least four.</param>
/// <param name="Version">Algorithm version.</param>
public readonly record struct Argon2Parameters(
    Argon2Type Type,
    int MemoryKiB,
    int Iterations,
    int Parallelism,
    int OutputLength = 32,
    Argon2Version Version = Argon2Version.V13)
{
    /// <summary>Argon2id, 19 MiB, two passes, one lane, 32-byte tag.</summary>
    public static Argon2Parameters OwaspMinimum { get; } = new(Argon2Type.Id, 19 * 1024, 2, 1);

    /// <summary>Argon2id, 64 MiB, three passes, four lanes, 32-byte tag.</summary>
    public static Argon2Parameters Rfc9106Low { get; } = new(Argon2Type.Id, 64 * 1024, 3, 4);

    /// <summary>Argon2id, 2 GiB, one pass, four lanes, 32-byte tag.</summary>
    public static Argon2Parameters Rfc9106High { get; } = new(Argon2Type.Id, 2 * 1024 * 1024, 1, 4);

    /// <summary>Number of 1024-byte blocks after rounding down to complete slices.</summary>
    public int BlockCount
    {
        get
        {
            Validate();
            int quantum = 4 * Parallelism;
            return MemoryKiB / quantum * quantum;
        }
    }

    /// <summary>Arena bytes, excluding object overhead and allocator padding. Does not allocate.</summary>
    public long MemoryBytes => (long)BlockCount * 1024;

    /// <summary>Describes the requested parameters without validation or allocation of an arena.</summary>
    public override string ToString() => FormattableString.Invariant(
        $"Argon2Parameters {{ Type = {Type}, MemoryKiB = {MemoryKiB}, Iterations = {Iterations}, Parallelism = {Parallelism}, OutputLength = {OutputLength}, Version = {Version} }}");

    /// <summary>Validates the algorithm parameters without allocating memory.</summary>
    /// <exception cref="ArgumentOutOfRangeException">A field is outside its supported range.</exception>
    public void Validate()
    {
        if (Type is not (Argon2Type.D or Argon2Type.I or Argon2Type.Id))
            throw new ArgumentOutOfRangeException(nameof(Type));
        if (Version is not (Argon2Version.V10 or Argon2Version.V13))
            throw new ArgumentOutOfRangeException(nameof(Version));
        if (Parallelism is < 1 or > 0xFFFFFF)
            throw new ArgumentOutOfRangeException(nameof(Parallelism));
        if (MemoryKiB < 8L * Parallelism)
            throw new ArgumentOutOfRangeException(nameof(MemoryKiB), "Memory must be at least eight KiB per lane.");
        if (Iterations < 1) throw new ArgumentOutOfRangeException(nameof(Iterations));
        if (OutputLength < 4) throw new ArgumentOutOfRangeException(nameof(OutputLength));
    }
}
