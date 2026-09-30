namespace Argon2DotnetFast;

/// <summary>The optional secret (pepper) and associated data inputs of Argon2.</summary>
/// <remarks>
/// Borrows both spans for one call and copies nothing. Neither value is written into PHC text.
/// There is no conversion from arrays or spans, so a buffer passed in the wrong position does not compile.
/// </remarks>
public readonly ref struct Argon2AdditionalInputs
{
    /// <summary>Creates inputs from a secret and associated data. Either may be empty.</summary>
    /// <param name="secret">Secret value K, often called a pepper.</param>
    /// <param name="associatedData">Associated data X.</param>
    public Argon2AdditionalInputs(ReadOnlySpan<byte> secret = default, ReadOnlySpan<byte> associatedData = default)
    {
        Secret = secret;
        AssociatedData = associatedData;
    }

    /// <summary>Secret value K. Empty when absent.</summary>
    public ReadOnlySpan<byte> Secret { get; }

    /// <summary>Associated data X. Empty when absent.</summary>
    public ReadOnlySpan<byte> AssociatedData { get; }
}
