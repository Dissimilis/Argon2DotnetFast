using System.Globalization;

namespace Argon2DotnetFast.Internal;

internal readonly ref struct ParsedPhc
{
    internal Argon2Parameters Parameters { get; }
    internal ReadOnlySpan<char> Salt { get; }
    internal ReadOnlySpan<char> Tag { get; }

    internal ParsedPhc(Argon2Parameters parameters, ReadOnlySpan<char> salt, ReadOnlySpan<char> tag)
    {
        Parameters = parameters;
        Salt = salt;
        Tag = tag;
    }
}

internal static class Phc
{
    internal static string Encode(in Argon2Parameters parameters, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> hash)
    {
        Validation.Inputs(parameters, salt);
        Validation.ExactLength(hash.Length, parameters.OutputLength, nameof(hash));
        string type = parameters.Type switch
        {
            Argon2Type.D => "argon2d",
            Argon2Type.I => "argon2i",
            _ => "argon2id"
        };
        return string.Format(CultureInfo.InvariantCulture, "${0}$v={1}$m={2},t={3},p={4}${5}${6}",
            type, (int)parameters.Version, parameters.MemoryKiB, parameters.Iterations,
            parameters.Parallelism, Base64(salt), Base64(hash));
    }

    private static string Base64(ReadOnlySpan<byte> bytes)
    {
        byte[] copy = bytes.ToArray();
        try { return Convert.ToBase64String(copy).TrimEnd('='); }
        finally { Sensitive.Clear(copy); }
    }

    internal static ParsedPhc Scan(ReadOnlySpan<char> encoded)
    {
        if (encoded.IsEmpty || encoded[0] != '$') throw BadFormat();
        ReadOnlySpan<char> rest = encoded.Slice(1);
        ReadOnlySpan<char> algorithm = Take(ref rest, '$');
        Argon2Type type;
        if (algorithm.SequenceEqual("argon2d".AsSpan())) type = Argon2Type.D;
        else if (algorithm.SequenceEqual("argon2i".AsSpan())) type = Argon2Type.I;
        else if (algorithm.SequenceEqual("argon2id".AsSpan())) type = Argon2Type.Id;
        else throw BadFormat();
        ReadOnlySpan<char> costs = Take(ref rest, '$');
        Argon2Version version = Argon2Version.V10;
        if (costs.StartsWith("v=".AsSpan()))
        {
            version = (Argon2Version)Number(costs.Slice(2), "Version");
            costs = Take(ref rest, '$');
        }
        ReadOnlySpan<char> memoryField = Take(ref costs, ',');
        ReadOnlySpan<char> timeField = Take(ref costs, ',');
        if (!memoryField.StartsWith("m=".AsSpan()) || !timeField.StartsWith("t=".AsSpan()) ||
            !costs.StartsWith("p=".AsSpan())) throw BadFormat();
        int memory = Number(memoryField.Slice(2), "MemoryKiB");
        int iterations = Number(timeField.Slice(2), "Iterations");
        int lanes = Number(costs.Slice(2), "Parallelism");
        ReadOnlySpan<char> salt = Take(ref rest, '$');
        int saltLength = DecodedLength(salt);
        int tagLength = DecodedLength(rest);
        var parameters = new Argon2Parameters(type, memory, iterations, lanes, tagLength, version);
        parameters.Validate();
        if (saltLength < 8) throw new ArgumentOutOfRangeException("salt", "Salt must contain at least eight bytes.");
        return new ParsedPhc(parameters, salt, rest);
    }

    // Length and limits are checked before anything is decoded or a password is encoded.
    internal static void Prepare(ReadOnlySpan<char> encoded, in Argon2VerificationLimits limits,
        out Argon2Parameters parameters, out byte[] salt, out byte[] tag)
    {
        limits.CheckLength(encoded.Length);
        ParsedPhc parsed = Scan(encoded);
        limits.Check(parsed.Parameters);
        parameters = parsed.Parameters;
        salt = Decode(parsed.Salt);
        tag = Decode(parsed.Tag);
    }

    private static ReadOnlySpan<char> Take(scoped ref ReadOnlySpan<char> value, char delimiter)
    {
        int end = value.IndexOf(delimiter);
        if (end <= 0) throw BadFormat();
        ReadOnlySpan<char> field = value.Slice(0, end);
        value = value.Slice(end + 1);
        return field;
    }

    private static int Number(ReadOnlySpan<char> value, string name)
    {
        if (value.IsEmpty || (value.Length > 1 && value[0] == '0')) throw BadFormat();
        int result = 0;
        foreach (char c in value)
        {
            if (c is < '0' or > '9') throw BadFormat();
            int digit = c - '0';
            if (result > (int.MaxValue - digit) / 10) throw new ArgumentOutOfRangeException(name);
            result = result * 10 + digit;
        }
        return result;
    }

    private static int Digit(char c)
    {
        if (c is >= 'A' and <= 'Z') return c - 'A';
        if (c is >= 'a' and <= 'z') return c - 'a' + 26;
        if (c is >= '0' and <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        throw BadFormat();
    }

    private static int DecodedLength(ReadOnlySpan<char> value)
    {
        int remainder = value.Length % 4;
        if (value.IsEmpty || remainder == 1) throw BadFormat();
        foreach (char c in value) Digit(c);
        int last = Digit(value[value.Length - 1]);
        if ((remainder == 2 && (last & 15) != 0) || (remainder == 3 && (last & 3) != 0))
            throw BadFormat();
        return value.Length / 4 * 3 + (remainder == 0 ? 0 : remainder - 1);
    }

    internal static byte[] Decode(ReadOnlySpan<char> value)
    {
        byte[] result = new byte[DecodedLength(value)];
        int accumulator = 0, bits = 0, position = 0;
        foreach (char c in value)
        {
            accumulator = (accumulator << 6) | Digit(c);
            bits += 6;
            if (bits >= 8)
            {
                bits -= 8;
                result[position++] = (byte)(accumulator >> bits);
                accumulator &= (1 << bits) - 1;
            }
        }
        return result;
    }

    private static FormatException BadFormat() => new("Invalid Argon2 PHC string.");
}
