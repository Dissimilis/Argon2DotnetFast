using System.Text;
using Xunit.Abstractions;

namespace Argon2DotnetFast.Tests;

// A PHC string is the one place untrusted input reaches the library.
public class PhcTests(ITestOutputHelper output)
{
    private const string Digits = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    private const string Syntax = "$$$$,,,===argon2idvmtp0123456789";
    private static readonly string[] Numbers =
        { "0", "00", "01", "1", "8", "16", "19", "2147483647", "2147483648", "4294967296", "99999999999999999999", "-1", "" };

    // Whatever the text holds, TryParse returns, and Verify and NeedsRehash return or throw
    // FormatException or ArgumentOutOfRangeException. Text that TryParse refuses never verifies.
    [Fact]
    public void RandomAndMutatedTextOnlyParsesOrThrowsFormatOrRange()
    {
        var random = new Random(4242);
        var limits = new Argon2VerificationLimits(MaxMemoryKiB: 128, MaxIterations: 2, MaxParallelism: 4,
            MaxOutputLength: 64, MaxEncodedLength: 256);
        var desired = new Argon2Parameters(Argon2Type.Id, 64, 2, 2);
        byte[] password = "password"u8.ToArray();
        int parsed = 0, verified = 0;
        for (int n = 0; n < 10_000; n++)
        {
            string text = n % 5 == 0 ? RandomText(random) : Mutate(random, ValidText(random));
            bool ok = Argon2.TryParse(text, out Argon2Parameters parameters, out byte[] salt, out byte[] tag);
            if (ok)
            {
                parsed++;
                Argon2.Parse(Argon2.Encode(parameters, salt, tag), out Argon2Parameters again, out byte[] againSalt, out byte[] againTag);
                Assert.Equal(parameters, again);
                Assert.Equal(salt, againSalt);
                Assert.Equal(tag, againTag);
            }
            else
            {
                Assert.Equal(default, parameters);
                Assert.Empty(salt);
                Assert.Empty(tag);
            }

            Exception? rehash = Record.Exception(() => Argon2.NeedsRehash(text, desired));
            Exception? verify = Record.Exception(() => Argon2.Verify(text, password, limits));
            if (verify is null) verified++;
            string at = $"case {n}: {Escape(text)}";
            if (ok)
            {
                Assert.True(rehash is null, $"{at}: NeedsRehash threw {rehash}");
                Assert.True(verify is null or ArgumentOutOfRangeException, $"{at}: Verify threw {verify}");
            }
            else
            {
                Assert.True(rehash is FormatException or ArgumentOutOfRangeException, $"{at}: NeedsRehash gave {rehash?.ToString() ?? "no exception"}");
                Assert.True(verify is FormatException or ArgumentOutOfRangeException, $"{at}: Verify gave {verify?.ToString() ?? "no exception"}");
            }
        }
        // Enough of the mutants still parse, and enough fit the limits, to reach the hash.
        output.WriteLine($"{parsed} of 10000 parsed, {verified} verified");
        Assert.InRange(parsed, 1000, 9000);
        Assert.InRange(verified, 300, 9000);
    }

    [Fact]
    public void ParsingEncodedTextReturnsWhatWasEncoded()
    {
        var random = new Random(16);
        for (int n = 0; n < 3000; n++)
        {
            int lanes = n switch { 0 => 0xFFFFFF, 1 => 1, _ => random.Next(4) == 0 ? 1 + random.Next(0xFFFFFF) : 1 + random.Next(8) };
            int memory = n switch
            {
                0 => int.MaxValue,
                1 => 8,
                _ => random.Next(3) == 0 ? 8 * lanes : 8 * lanes + random.Next(int.MaxValue - 8 * lanes),
            };
            int iterations = n == 0 ? int.MaxValue : random.Next(4) == 0 ? 1 + random.Next(int.MaxValue - 1) : 1 + random.Next(10);
            int tagLength = n == 1 ? 4 : 4 + random.Next(random.Next(4) == 0 ? 2000 : 80);
            var version = random.Next(2) == 0 ? Argon2Version.V10 : Argon2Version.V13;
            var parameters = new Argon2Parameters((Argon2Type)random.Next(3), memory, iterations, lanes, tagLength, version);
            byte[] salt = DifferentialTests.Bytes(random, n == 1 ? 8 : 8 + random.Next(120));
            byte[] tag = DifferentialTests.Bytes(random, tagLength);

            string encoded = Argon2.Encode(parameters, salt, tag);
            Assert.True(Argon2.TryParse(encoded, out Argon2Parameters parsed, out byte[] parsedSalt, out byte[] parsedTag), encoded);
            Assert.Equal(parameters, parsed);
            Assert.Equal(salt, parsedSalt);
            Assert.Equal(tag, parsedTag);
            Assert.False(Argon2.NeedsRehash(encoded, parameters));
            if (version == Argon2Version.V10)
            {
                Argon2.Parse(encoded.Replace("$v=16$", "$"), out parsed, out _, out _);
                Assert.Equal(parameters, parsed);
            }
        }
    }

    // Parameters in and around the limits of the fuzz test, so mutants that still parse reach the hash.
    private static string ValidText(Random random)
    {
        int lanes = 1 + random.Next(5);
        var parameters = new Argon2Parameters((Argon2Type)random.Next(3), 8 * lanes + random.Next(100),
            1 + random.Next(3), lanes, 4 + random.Next(70), random.Next(3) == 0 ? Argon2Version.V10 : Argon2Version.V13);
        string text = Argon2.Encode(parameters, DifferentialTests.Bytes(random, 8 + random.Next(30)),
            DifferentialTests.Bytes(random, parameters.OutputLength));
        return random.Next(4) == 0 ? text.Replace("$v=16$", "$") : text;
    }

    private static string RandomText(Random random)
    {
        var text = new StringBuilder(random.Next(2) == 0 ? "$argon2" : "");
        int length = random.Next(100);
        for (int i = 0; i < length; i++) text.Append(RandomChar(random));
        return text.ToString();
    }

    private static char RandomChar(Random random) => random.Next(10) switch
    {
        < 4 => Syntax[random.Next(Syntax.Length)],
        < 9 => Digits[random.Next(Digits.Length)],
        _ => (char)random.Next(0x10000),
    };

    private static string Mutate(Random random, string text)
    {
        var s = new StringBuilder(text);
        int count = 1 + random.Next(3);
        for (int m = 0; m < count && s.Length > 0; m++)
        {
            int at = random.Next(s.Length);
            switch (random.Next(9))
            {
                case 0: s.Remove(at, 1); break;
                case 1: s.Insert(at, RandomChar(random)); break;
                case 2: s[at] = RandomChar(random); break;
                case 3: s.Insert(at, s.ToString(at, random.Next(s.Length - at + 1))); break;
                case 4: s.Remove(at, random.Next(s.Length - at + 1)); break;
                case 5:
                    if (at + 1 < s.Length) (s[at], s[at + 1]) = (s[at + 1], s[at]);
                    break;
                case 6: s.Length = at; break;
                case 7:
                    // Replaces a run of digits, so numbers at and past the int range occur.
                    while (at < s.Length && !char.IsAsciiDigit(s[at])) at++;
                    int end = at;
                    while (end < s.Length && char.IsAsciiDigit(s[end])) end++;
                    s.Remove(at, end - at).Insert(at, Numbers[random.Next(Numbers.Length)]);
                    break;
                default: s.Append('='); break;
            }
        }
        return s.ToString();
    }

    private static string Escape(string text)
    {
        var s = new StringBuilder();
        foreach (char c in text) s.Append(c is >= ' ' and <= '~' ? c.ToString() : $"\\u{(int)c:x4}");
        return s.ToString();
    }
}
