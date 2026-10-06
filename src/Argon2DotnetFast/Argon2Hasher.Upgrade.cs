using Argon2DotnetFast.Internal;

namespace Argon2DotnetFast;

public sealed partial class Argon2Hasher
{
    /// <summary>Verifies a PHC string and replaces it with a freshly salted hash when its parameters differ from Parameters.</summary>
    /// <remarks>
    /// Holds the instance's busy guard across both phases. Other stored parameters require a temporary verification arena
    /// in addition to the resident arena; replacement uses the resident arena. MaxThreads caps both phases.
    /// The same secret and associated data are used for both hashes. Any parameter difference triggers replacement,
    /// including lower costs; salt length alone does not. Limits bound the stored hash, not the desired profile.
    /// Invalid options, malformed text, exceeded limits and resource failures throw, including replacement failures.
    /// </remarks>
    public Argon2VerificationResult VerifyAndUpgrade(ReadOnlySpan<char> encoded, ReadOnlySpan<byte> password,
        in Argon2VerificationLimits limits, Argon2AdditionalInputs inputs = default, int saltLength = 16)
    {
        Enter();
        try
        {
            ThrowIfDisposed();
            Argon2.ValidateUpgrade(Parameters, saltLength);
            Phc.Prepare(encoded, limits, out Argon2Parameters stored, out byte[] salt, out byte[] expected);
            return UpgradePrepared(password, limits, inputs, saltLength, stored, salt, expected);
        }
        finally { Exit(); }
    }

    /// <summary>Verifies and optionally replaces a PHC string for a strict UTF-8 character password.</summary>
    /// <remarks>Has the same migration, limits and failure behavior as the byte overload.</remarks>
    public Argon2VerificationResult VerifyAndUpgrade(ReadOnlySpan<char> encoded, ReadOnlySpan<char> password,
        in Argon2VerificationLimits limits, Argon2AdditionalInputs inputs = default, int saltLength = 16)
    {
        Enter();
        try
        {
            ThrowIfDisposed();
            Argon2.ValidateUpgrade(Parameters, saltLength);
            Phc.Prepare(encoded, limits, out Argon2Parameters stored, out byte[] salt, out byte[] expected);
            using NativeBuffer bytes = Sensitive.Encode(password);
            return UpgradePrepared(bytes.Span, limits, inputs, saltLength, stored, salt, expected);
        }
        finally { Exit(); }
    }

    private Argon2VerificationResult UpgradePrepared(ReadOnlySpan<byte> password,
        in Argon2VerificationLimits limits, Argon2AdditionalInputs inputs, int saltLength,
        in Argon2Parameters stored, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> expected)
    {
        bool verified = stored == Parameters
            ? VerifyCore(password, salt, expected, inputs, limits.MaxThreads)
            : Argon2.Verify(stored, password, salt, expected, inputs, limits.MaxThreads);
        if (!verified) return default;
        if (stored == Parameters) return new Argon2VerificationResult(true, null);

        byte[] newSalt = Sensitive.Salt(saltLength);
        using var tag = new NativeBuffer(Parameters.OutputLength);
        HashCore(password, newSalt, tag.Span, inputs, Math.Min(ThreadCount, limits.MaxThreads));
        return new Argon2VerificationResult(true, Phc.Encode(Parameters, newSalt, tag.Span));
    }
}
