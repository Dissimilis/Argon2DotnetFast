using System.Runtime.InteropServices;

namespace Argon2DotnetFast.Internal;

internal static class Validation
{
    internal static void Inputs(in Argon2Parameters parameters, ReadOnlySpan<byte> salt, int threads = 0)
    {
        parameters.Validate();
        if (salt.Length < 8) throw new ArgumentOutOfRangeException(nameof(salt), "Salt must contain at least eight bytes.");
        Threads(threads);
    }

    internal static void Threads(int threads)
    {
        if (threads < 0) throw new ArgumentOutOfRangeException(nameof(threads));
    }

    internal static void ExactLength(int actual, int expected, string name)
    {
        if (actual != expected) throw new ArgumentException("Length must match OutputLength.", name);
    }

    internal static void NoOverlap(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, Span<byte> output,
        Argon2AdditionalInputs inputs)
    {
        if (output.Overlaps(password) || output.Overlaps(salt) ||
            output.Overlaps(inputs.Secret) || output.Overlaps(inputs.AssociatedData))
            throw new ArgumentException("Output must not overlap any input.", nameof(output));
    }

    internal static void NoOverlap(ReadOnlySpan<char> password, ReadOnlySpan<byte> salt, Span<byte> output,
        Argon2AdditionalInputs inputs) =>
        NoOverlap(MemoryMarshal.AsBytes(password), salt, output, inputs);
}
