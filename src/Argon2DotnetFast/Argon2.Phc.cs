using Argon2DotnetFast.Internal;

namespace Argon2DotnetFast;

public static partial class Argon2
{

    /// <summary>Generates a random salt and returns a PHC string. Secret and associated data are not encoded.</summary>
    /// <remarks>To encode a tag computed with a known salt, use <see cref="Encode"/>.</remarks>
    public static string HashToString(in Argon2Parameters parameters, ReadOnlySpan<byte> password,
        Argon2AdditionalInputs inputs = default, int saltLength = 16, int threads = 0)
    {
        parameters.Validate();
        Validation.Threads(threads);
        byte[] salt = Sensitive.Salt(saltLength);
        byte[] tag = Hash(parameters, password, salt, inputs, threads);
        try { return Phc.Encode(parameters, salt, tag); }
        finally { Sensitive.Clear(tag); }
    }

    /// <summary>Generates a random salt and returns a PHC string. Secret and associated data are not encoded.</summary>
    /// <remarks>To encode a tag computed with a known salt, use <see cref="Encode"/>.</remarks>
    public static string HashToString(in Argon2Parameters parameters, ReadOnlySpan<char> password,
        Argon2AdditionalInputs inputs = default, int saltLength = 16, int threads = 0)
    {
        parameters.Validate();
        Validation.Threads(threads);
        byte[] salt = Sensitive.Salt(saltLength);
        byte[] tag = Hash(parameters, password, salt, inputs, threads);
        try { return Phc.Encode(parameters, salt, tag); }
        finally { Sensitive.Clear(tag); }
    }

    /// <summary>Verifies PHC text with explicit resource limits and a constant-time tag comparison.</summary>
    /// <remarks>False means an input mismatch. Malformed text, exceeded limits, and resource failures throw.</remarks>
    public static bool Verify(ReadOnlySpan<char> encoded, ReadOnlySpan<byte> password,
        in Argon2VerificationLimits limits, Argon2AdditionalInputs inputs = default)
    {
        Phc.Prepare(encoded, limits, out Argon2Parameters parameters, out byte[] salt, out byte[] expected);
        return Verify(parameters, password, salt, expected, inputs, limits.MaxThreads);
    }

    /// <summary>Verifies PHC text with explicit resource limits and a constant-time tag comparison.</summary>
    /// <remarks>False means an input mismatch. Malformed text, exceeded limits, and resource failures throw.</remarks>
    public static bool Verify(ReadOnlySpan<char> encoded, ReadOnlySpan<char> password,
        in Argon2VerificationLimits limits, Argon2AdditionalInputs inputs = default)
    {
        Phc.Prepare(encoded, limits, out Argon2Parameters parameters, out byte[] salt, out byte[] expected);
        return Verify(parameters, password, salt, expected, inputs, limits.MaxThreads);
    }

    /// <summary>Formats an existing raw tag as canonical PHC text without hashing.</summary>
    public static string Encode(in Argon2Parameters parameters, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> hash) =>
        Phc.Encode(parameters, salt, hash);

    /// <summary>Parses PHC text and allocates the decoded salt and tag, but never the hashing arena.</summary>
    /// <exception cref="FormatException">The PHC syntax is invalid.</exception>
    /// <exception cref="ArgumentOutOfRangeException">An algorithm parameter is outside its supported range.</exception>
    public static void Parse(ReadOnlySpan<char> encoded, out Argon2Parameters parameters,
        out byte[] salt, out byte[] hash)
    {
        parameters = default;
        salt = Array.Empty<byte>();
        hash = Array.Empty<byte>();
        ParsedPhc parsed = Phc.Scan(encoded);
        byte[] decodedSalt = Phc.Decode(parsed.Salt);
        byte[] decodedHash = Phc.Decode(parsed.Tag);
        parameters = parsed.Parameters;
        salt = decodedSalt;
        hash = decodedHash;
    }

    /// <summary>Parses valid PHC text. Returns false for syntax or parameter errors; allocation failures throw.</summary>
    /// <remarks>On false, parameters is default and both arrays are empty. For untrusted verification use Verify with limits.</remarks>
    public static bool TryParse(ReadOnlySpan<char> encoded, out Argon2Parameters parameters,
        out byte[] salt, out byte[] hash)
    {
        try { Parse(encoded, out parameters, out salt, out hash); return true; }
        catch (FormatException) { }
        catch (ArgumentOutOfRangeException) { }
        parameters = default;
        salt = Array.Empty<byte>();
        hash = Array.Empty<byte>();
        return false;
    }

    /// <summary>Reports any difference in algorithm parameters, including tag length, regardless of strength.</summary>
    /// <remarks>Does not verify a password or detect pepper rotation. Call after successful verification.</remarks>
    public static bool NeedsRehash(ReadOnlySpan<char> encoded, in Argon2Parameters desired)
    {
        desired.Validate();
        return Phc.Scan(encoded).Parameters != desired;
    }
}

