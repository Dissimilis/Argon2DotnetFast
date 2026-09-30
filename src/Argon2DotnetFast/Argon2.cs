using Argon2DotnetFast.Internal;

namespace Argon2DotnetFast;

/// <summary>One-shot Argon2 hashing, PHC serialization, and bounded password verification.</summary>
public static partial class Argon2
{

    /// <summary>Returns a new raw tag of OutputLength bytes.</summary>
    public static byte[] Hash(in Argon2Parameters parameters, ReadOnlySpan<byte> password,
        ReadOnlySpan<byte> salt, Argon2AdditionalInputs inputs = default, int threads = 0)
    {
        Validation.Inputs(parameters, salt, threads);
        byte[] output = new byte[parameters.OutputLength];
        try
        {
            HashInto(parameters, password, salt, output, inputs, threads);
            return output;
        }
        catch { Sensitive.Clear(output); throw; }
    }

    /// <summary>Writes a raw tag into a destination of exactly OutputLength bytes.</summary>
    /// <exception cref="ArgumentException">The destination length differs from OutputLength, or it overlaps an input.</exception>
    public static void HashInto(in Argon2Parameters parameters, ReadOnlySpan<byte> password,
        ReadOnlySpan<byte> salt, Span<byte> destination, Argon2AdditionalInputs inputs = default, int threads = 0)
    {
        Validation.Inputs(parameters, salt, threads);
        Validation.ExactLength(destination.Length, parameters.OutputLength, nameof(destination));
        Validation.NoOverlap(password, salt, destination, inputs);
        using var hasher = new Argon2Hasher(parameters, threads, touch: false);
        hasher.HashInto(password, salt, destination, inputs);
    }

    /// <summary>Verifies a raw tag in constant time using explicit algorithm parameters.</summary>
    /// <exception cref="ArgumentException">Expected tag length does not match OutputLength.</exception>
    public static bool Verify(in Argon2Parameters parameters, ReadOnlySpan<byte> password,
        ReadOnlySpan<byte> salt, ReadOnlySpan<byte> expectedHash, Argon2AdditionalInputs inputs = default,
        int threads = 0)
    {
        Validation.Inputs(parameters, salt, threads);
        Validation.ExactLength(expectedHash.Length, parameters.OutputLength, nameof(expectedHash));
        using var hasher = new Argon2Hasher(parameters, threads, touch: false);
        return hasher.VerifyTag(password, salt, expectedHash, inputs);
    }

    /// <summary>Returns a new raw tag of OutputLength bytes after strict UTF-8 encoding.</summary>
    public static byte[] Hash(in Argon2Parameters parameters, ReadOnlySpan<char> password,
        ReadOnlySpan<byte> salt, Argon2AdditionalInputs inputs = default, int threads = 0)
    {
        Validation.Inputs(parameters, salt, threads);
        using NativeBuffer bytes = Sensitive.Encode(password);
        return Hash(parameters, bytes.Span, salt, inputs, threads);
    }

    /// <summary>Writes a raw tag into a destination of exactly OutputLength bytes after strict UTF-8 encoding.</summary>
    /// <exception cref="ArgumentException">The destination length differs from OutputLength, or it overlaps an input.</exception>
    public static void HashInto(in Argon2Parameters parameters, ReadOnlySpan<char> password,
        ReadOnlySpan<byte> salt, Span<byte> destination, Argon2AdditionalInputs inputs = default, int threads = 0)
    {
        Validation.Inputs(parameters, salt, threads);
        Validation.ExactLength(destination.Length, parameters.OutputLength, nameof(destination));
        Validation.NoOverlap(password, salt, destination, inputs);
        using NativeBuffer bytes = Sensitive.Encode(password);
        HashInto(parameters, bytes.Span, salt, destination, inputs, threads);
    }

    /// <summary>Verifies a raw tag in constant time after strict UTF-8 encoding.</summary>
    /// <exception cref="ArgumentException">Expected tag length does not match OutputLength.</exception>
    public static bool Verify(in Argon2Parameters parameters, ReadOnlySpan<char> password,
        ReadOnlySpan<byte> salt, ReadOnlySpan<byte> expectedHash, Argon2AdditionalInputs inputs = default,
        int threads = 0)
    {
        Validation.Inputs(parameters, salt, threads);
        Validation.ExactLength(expectedHash.Length, parameters.OutputLength, nameof(expectedHash));
        using NativeBuffer bytes = Sensitive.Encode(password);
        return Verify(parameters, bytes.Span, salt, expectedHash, inputs, threads);
    }
}
