namespace Argon2DotnetFast;

/// <summary>Per-call resource ceilings for verification of stored PHC strings.</summary>
/// <param name="MaxMemoryKiB">Maximum accepted original memory cost in KiB.</param>
/// <param name="MaxIterations">Maximum accepted pass count.</param>
/// <param name="MaxParallelism">Maximum accepted algorithm lane count.</param>
/// <param name="MaxOutputLength">Maximum decoded tag length in bytes.</param>
/// <param name="MaxEncodedLength">Maximum PHC text length, checked before decoding.</param>
/// <param name="MaxThreads">Maximum execution threads including the caller; at least one.</param>
public readonly record struct Argon2VerificationLimits(
    int MaxMemoryKiB,
    int MaxIterations,
    int MaxParallelism,
    int MaxOutputLength,
    int MaxEncodedLength,
    int MaxThreads = 1)
{
    /// <summary>Uses a parameter set's costs and tag length as ceilings, with an explicit text limit.</summary>
    public Argon2VerificationLimits(in Argon2Parameters parameters, int maxEncodedLength, int maxThreads = 1)
        : this(parameters.MemoryKiB, parameters.Iterations, parameters.Parallelism,
            parameters.OutputLength, maxEncodedLength, maxThreads)
    {
        parameters.Validate();
        Validate();
    }

    /// <summary>Validates the independent limits without allocating memory.</summary>
    public void Validate()
    {
        if (MaxMemoryKiB < 1) throw new ArgumentOutOfRangeException(nameof(MaxMemoryKiB));
        if (MaxIterations < 1) throw new ArgumentOutOfRangeException(nameof(MaxIterations));
        if (MaxParallelism < 1) throw new ArgumentOutOfRangeException(nameof(MaxParallelism));
        if (MaxOutputLength < 4) throw new ArgumentOutOfRangeException(nameof(MaxOutputLength));
        if (MaxEncodedLength < 1) throw new ArgumentOutOfRangeException(nameof(MaxEncodedLength));
        if (MaxThreads < 1) throw new ArgumentOutOfRangeException(nameof(MaxThreads));
    }

    internal void CheckLength(int length)
    {
        Validate();
        if (length > MaxEncodedLength)
            throw new ArgumentOutOfRangeException("encoded", "PHC text exceeds the verification limit.");
    }

    internal void Check(in Argon2Parameters parameters)
    {
        if (parameters.MemoryKiB > MaxMemoryKiB || parameters.Iterations > MaxIterations ||
            parameters.Parallelism > MaxParallelism || parameters.OutputLength > MaxOutputLength)
            throw new ArgumentOutOfRangeException("encoded", "Hash exceeds the verification limits.");
    }
}
