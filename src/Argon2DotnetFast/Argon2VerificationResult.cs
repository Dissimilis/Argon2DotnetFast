namespace Argon2DotnetFast;

/// <summary>The outcome of verifying a password and, when needed, creating a replacement PHC string.</summary>
public readonly struct Argon2VerificationResult
{
    /// <summary>Whether the password and additional inputs matched the stored hash.</summary>
    public bool Verified { get; }

    /// <summary>A newly salted PHC string to persist, or null on mismatch or when parameters already match.</summary>
    public string? ReplacementHash { get; }

    internal Argon2VerificationResult(bool verified, string? replacementHash)
    {
        Verified = verified;
        ReplacementHash = replacementHash;
    }
}
