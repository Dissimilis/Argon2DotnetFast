using Argon2DotnetFast.Internal;

namespace Argon2DotnetFast;

public static partial class Argon2
{
    /// <summary>Verifies a stored PHC string and creates a freshly salted replacement when its parameters differ.</summary>
    /// <remarks>
    /// Persist ReplacementHash only when non-null. Any parameter difference triggers replacement, including lower costs.
    /// The same secret and associated data are used for both phases; this does not rotate peppers.
    /// Limits bound the stored hash; desired parameters may exceed them. MaxThreads caps both phases.
    /// Invalid options, malformed text, exceeded limits and resource failures throw. A replacement failure throws too.
    /// </remarks>
    public static Argon2VerificationResult VerifyAndUpgrade(ReadOnlySpan<char> encoded, ReadOnlySpan<byte> password,
        in Argon2VerificationLimits limits, in Argon2Parameters desired,
        Argon2AdditionalInputs inputs = default, int saltLength = 16)
    {
        ValidateUpgrade(desired, saltLength);
        Phc.Prepare(encoded, limits, out Argon2Parameters stored, out byte[] salt, out byte[] expected);
        return UpgradePrepared(password, limits, desired, inputs, saltLength, stored, salt, expected);
    }

    /// <summary>Verifies and optionally replaces a PHC string for a strict UTF-8 character password.</summary>
    /// <remarks>Has the same migration, limits and failure behavior as the byte overload.</remarks>
    public static Argon2VerificationResult VerifyAndUpgrade(ReadOnlySpan<char> encoded, ReadOnlySpan<char> password,
        in Argon2VerificationLimits limits, in Argon2Parameters desired,
        Argon2AdditionalInputs inputs = default, int saltLength = 16)
    {
        ValidateUpgrade(desired, saltLength);
        Phc.Prepare(encoded, limits, out Argon2Parameters stored, out byte[] salt, out byte[] expected);
        using NativeBuffer bytes = Sensitive.Encode(password);
        return UpgradePrepared(bytes.Span, limits, desired, inputs, saltLength, stored, salt, expected);
    }

    internal static void ValidateUpgrade(in Argon2Parameters desired, int saltLength)
    {
        desired.Validate();
        if (saltLength < 8)
            throw new ArgumentOutOfRangeException(nameof(saltLength), "Salt must contain at least eight bytes.");
    }

    private static Argon2VerificationResult UpgradePrepared(ReadOnlySpan<byte> password,
        in Argon2VerificationLimits limits, in Argon2Parameters desired, Argon2AdditionalInputs inputs,
        int saltLength, in Argon2Parameters stored, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> expected)
    {
        if (!Verify(stored, password, salt, expected, inputs, limits.MaxThreads)) return default;
        string? replacement = stored == desired ? null : HashToString(desired, password, inputs, saltLength, limits.MaxThreads);
        return new Argon2VerificationResult(true, replacement);
    }
}
