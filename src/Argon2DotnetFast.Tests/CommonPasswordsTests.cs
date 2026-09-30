using System.Text;
using Argon2DotnetFast.CommonPasswordsGenerator;
using Argon2DotnetFast.Internal;

namespace Argon2DotnetFast.Tests;

public class CommonPasswordsTests
{
    private static readonly Lazy<List<byte[]>> Entries =
        new(() => CommonPasswordSet.ReadEntries(Path.Combine(AppContext.BaseDirectory, "data")));

    private static readonly Lazy<CommonPasswordSet.Result> Built = new(() => CommonPasswordSet.Build(Entries.Value));

    private static readonly byte[] Alphabet = Encoding.ASCII.GetBytes("abcdefghijklmnopqrstuvwxyz0123456789");

    [Fact]
    public void CommittedDataMatchesAFreshBuild()
    {
        CommonPasswordSet.Result result = Built.Value;
        Assert.Equal(CommonPasswordData.Count, result.Count);
        Assert.Equal(CommonPasswordData.MaxLength, result.MaxLength);
        Assert.True(CommonPasswordData.Stream.SequenceEqual(result.Stream));
        Assert.InRange(CommonPasswordData.Stream.Length, 1, CommonPasswordSet.Budget);
    }

    [Fact]
    public void EveryListedEntryIsFound()
    {
        foreach (byte[] entry in Entries.Value.Take(CommonPasswordData.Count))
        {
            string text = Encoding.UTF8.GetString(entry);
            Assert.True(CommonPasswords.Contains(entry), text);
            Assert.True(CommonPasswords.Contains(text), text);

            // The list is ASCII, so this only changes a-z.
            string upper = text.ToUpperInvariant();
            if (upper == text) continue;
            Assert.True(CommonPasswords.Contains(upper), upper);
            Assert.True(CommonPasswords.Contains(Encoding.UTF8.GetBytes(upper)), upper);
        }
    }

    [Fact]
    public void EmptyPasswordIsListed()
    {
        Assert.True(CommonPasswords.Contains(""));
        Assert.True(CommonPasswords.Contains((string?)null));
        Assert.True(CommonPasswords.Contains(ReadOnlySpan<char>.Empty));
        Assert.True(CommonPasswords.Contains(ReadOnlySpan<byte>.Empty));
    }

    [Fact]
    public void FalsePositiveRateIsAboutOneIn4096()
    {
        var codes = new HashSet<ulong>(Built.Value.Codes);
        var random = new Random(20260930);
        int hits = 0, samples = 0;
        while (samples < 1_000_000)
        {
            // At eight characters and up, repeats are too rare to count one string twice.
            byte[] candidate = RandomText(random, 8, CommonPasswordData.MaxLength);
            if (Listed(candidate)) continue;
            samples++;
            if (codes.Contains(Code(candidate))) hits++;
        }

        // 244 expected. The seed is fixed; the band is about five standard deviations wide.
        Assert.InRange(hits, 170, 320);
    }

    [Fact]
    public void ContainsAgreesWithTheCodeSet()
    {
        var codes = new HashSet<ulong>(Built.Value.Codes);
        var random = new Random(7);
        for (int i = 0; i < 2000; i++)
        {
            byte[] candidate = RandomText(random, 1, CommonPasswordData.MaxLength);
            Assert.Equal(codes.Contains(Code(candidate)), CommonPasswords.Contains(candidate));
        }

        // Unlisted strings whose codes are in the set: the scan must report them too.
        for (int found = 0; found < 5;)
        {
            byte[] candidate = RandomText(random, 8, CommonPasswordData.MaxLength);
            if (Listed(candidate) || !codes.Contains(Code(candidate))) continue;
            Assert.True(CommonPasswords.Contains(candidate));
            found++;
        }
    }

    [Fact]
    public void LongerThanEveryEntryIsNotListed()
    {
        var codes = new HashSet<ulong>(Built.Value.Codes);
        var random = new Random(11);
        int length = CommonPasswordData.MaxLength + 1;
        byte[] candidate;
        do candidate = RandomText(random, length, length);
        while (!codes.Contains(Code(candidate)));

        // Its code is in the set, so without the length rule this would be a false positive.
        Assert.False(CommonPasswords.Contains(candidate));
        Assert.False(CommonPasswords.Contains(Encoding.ASCII.GetString(candidate)));
    }

    [Fact]
    public void FoldChangesOnlyAsciiCapitals()
    {
        byte[] all = Enumerable.Range(0, 256).Select(b => (byte)b).ToArray();
        CommonPasswords.Fold(all);
        for (int b = 0; b < 256; b++)
            Assert.Equal(b is >= 'A' and <= 'Z' ? b + 32 : b, all[b]);
    }

    [Theory]
    [InlineData("password")]
    [InlineData("PassWord")]
    [InlineData("Müller")]
    [InlineData("пароль")]
    [InlineData("密码")]
    [InlineData("pass\0word")]
    [InlineData("correct horse battery staple")]
    public void CharAndByteFormsAgree(string password)
    {
        Assert.Equal(CommonPasswords.Contains(password), CommonPasswords.Contains(Encoding.UTF8.GetBytes(password)));
    }

    // Built in code: xUnit's serialization of InlineData turns a lone surrogate into U+FFFD.
    [Fact]
    public void UnpairedSurrogateThrowsAtAnyLength()
    {
        foreach (string password in new[] { "\uD800", "pass\uDC00word", new string('a', 100) + "\uD800" })
            Assert.Throws<EncoderFallbackException>(() => CommonPasswords.Contains(password));
    }

    [Fact]
    public void CallerSpanIsNotWritten()
    {
        byte[] password = Encoding.ASCII.GetBytes("PASSWORD");
        Assert.True(CommonPasswords.Contains(password));
        Assert.Equal("PASSWORD", Encoding.ASCII.GetString(password));
    }

    // The data property must stay a span over the assembly image on both targets, not a new array per call.
    [Fact]
    public void DoesNotAllocate()
    {
        byte[] bytes = Encoding.ASCII.GetBytes("Dragon");
        string text = "Dragon", longText = "a password longer than every entry";
        Run();
        long before = GC.GetAllocatedBytesForCurrentThread();
        for (int i = 0; i < 100; i++) Run();
        Assert.Equal(0, GC.GetAllocatedBytesForCurrentThread() - before);

        void Run()
        {
            CommonPasswords.Contains(text);
            CommonPasswords.Contains(bytes);
            CommonPasswords.Contains(longText);
            CommonPasswords.Contains("");
        }
    }

    private static readonly Lazy<HashSet<string>> ListedHex =
        new(() => Entries.Value.Take(CommonPasswordData.Count).Select(entry => Convert.ToHexString(entry)).ToHashSet());

    private static bool Listed(byte[] folded) => ListedHex.Value.Contains(Convert.ToHexString(folded));

    private static ulong Code(byte[] folded) => CommonPasswords.Map(CommonPasswords.Digest(folded), CommonPasswordData.Count);

    // Lowercase letters and digits, so the text is already folded.
    private static byte[] RandomText(Random random, int minLength, int maxLength)
    {
        byte[] text = new byte[random.Next(minLength, maxLength + 1)];
        for (int i = 0; i < text.Length; i++) text[i] = Alphabet[random.Next(Alphabet.Length)];
        return text;
    }
}
