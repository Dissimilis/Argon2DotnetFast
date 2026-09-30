using System.Reflection;
using System.Text;
using Argon2DotnetFast.Internal;

namespace Argon2DotnetFast.Tests;

// Contract cases for the public API.
public class ApiContractTests
{
    private static readonly Argon2Parameters Small = new(Argon2Type.Id, 64, 2, 2);
    private static readonly byte[] Salt = KnownAnswerTests.Filled(16, 0x02);
    private static readonly byte[] Password = Encoding.UTF8.GetBytes("correct horse battery staple");
    private static readonly Argon2VerificationLimits Wide = new(1 << 16, 4, 8, 1024, 4096, MaxThreads: 2);

    [Fact]
    public void RequestedMemoryIsHashedEvenWhenTheArenaIsTheSame()
    {
        var m32 = new Argon2Parameters(Argon2Type.Id, 32, 1, 4);
        var m33 = m32 with { MemoryKiB = 33 };
        Assert.Equal(m32.BlockCount, m33.BlockCount);
        Assert.NotEqual(Argon2.Hash(m32, Password, Salt), Argon2.Hash(m33, Password, Salt));

        string encoded = Argon2.HashToString(m32, Password);
        Assert.False(Argon2.NeedsRehash(encoded, m32));
        Assert.True(Argon2.NeedsRehash(encoded, m33));
        Assert.True(Argon2.NeedsRehash(encoded, m32 with { OutputLength = 16 }));
        Assert.True(Argon2.NeedsRehash(encoded, m32 with { Iterations = 2 }));
        Assert.True(Argon2.NeedsRehash(encoded, m32 with { Parallelism = 2 }));
    }

    [Fact]
    public void MissingVersionMeansVersion16()
    {
        var v10 = Small with { Version = Argon2Version.V10 };
        string explicit16 = Argon2.HashToString(v10, Password);
        Assert.Contains("$v=16$", explicit16);
        string legacy = explicit16.Replace("$v=16$", "$");

        Argon2.Parse(legacy, out Argon2Parameters parsed, out _, out _);
        Assert.Equal(Argon2Version.V10, parsed.Version);
        Assert.True(Argon2.Verify(legacy, Password, Wide));
        Assert.True(Argon2.Verify(explicit16, Password, Wide));
        Assert.True(Argon2.Verify(Argon2.HashToString(Small, Password), Password, Wide));
    }

    [Theory]
    [InlineData(4)]
    [InlineData(31)]
    [InlineData(32)]
    [InlineData(63)]
    [InlineData(64)]
    [InlineData(65)]
    [InlineData(96)]
    [InlineData(97)]
    [InlineData(1024)]
    public void TagLengthsRoundTripThroughPhcWithSecretAndData(int tagLength)
    {
        var parameters = Small with { OutputLength = tagLength };
        byte[] pepper = KnownAnswerTests.Filled(32, 0x07);
        byte[] context = KnownAnswerTests.Filled(5, 0x09);
        var inputs = new Argon2AdditionalInputs(pepper, context);

        using var hasher = new Argon2Hasher(parameters);
        string encoded = hasher.HashToString(Password, inputs);
        Assert.True(Argon2.Verify(encoded, Password, Wide, inputs));
        Assert.True(hasher.Verify(encoded, Password, Wide, inputs));
        Assert.False(Argon2.Verify(encoded, Password, Wide, new Argon2AdditionalInputs(pepper)));

        Argon2.Parse(encoded, out Argon2Parameters parsed, out byte[] salt, out byte[] tag);
        Assert.Equal(parameters, parsed);
        var oracle = new DifferentialTests.Case(parameters, Password, salt, pepper, context);
        Assert.Equal(DifferentialTests.BouncyCastle(oracle), tag);
    }

    [Theory]
    [InlineData("")]
    [InlineData("pässwörd")]
    [InlineData("a\0b")]
    [InlineData("\U0001F600 emoji")]
    public void CharacterPasswordsAreStrictUtf8(string password)
    {
        byte[] utf8 = Encoding.UTF8.GetBytes(password);
        byte[] expected = Argon2.Hash(Small, utf8, Salt);
        Assert.Equal(expected, Argon2.Hash(Small, password, Salt));

        byte[] destination = new byte[32];
        Argon2.HashInto(Small, password, Salt, destination);
        Assert.Equal(expected, destination);
        Assert.True(Argon2.Verify(Small, password, Salt, expected));

        using var hasher = new Argon2Hasher(Small);
        Assert.Equal(expected, hasher.Hash(password, Salt));
        string encoded = hasher.HashToString(password);
        Assert.True(Argon2.Verify(encoded, utf8, Wide));
        Assert.True(hasher.Verify(encoded, password, Wide));
    }

    [Fact]
    public void UnpairedSurrogatesThrowAndLeaveTheHasherUsable()
    {
        const string invalid = "ab\uD800cd";
        using var hasher = new Argon2Hasher(Small);
        byte[] destination = new byte[32];
        Assert.Throws<EncoderFallbackException>(() => Argon2.Hash(Small, invalid, Salt));
        Assert.Throws<EncoderFallbackException>(() => Argon2.HashToString(Small, invalid));
        Assert.Throws<EncoderFallbackException>(() => hasher.HashInto(invalid, Salt, destination));
        Assert.All(destination, b => Assert.Equal(0, b));

        string encoded = Argon2.HashToString(Small, Password);
        Assert.Throws<EncoderFallbackException>(() => Argon2.Verify(encoded, invalid, Wide));
        Assert.Throws<EncoderFallbackException>(() => hasher.Verify(encoded, invalid, Wide));

        Assert.Equal(Argon2.Hash(Small, Password, Salt), hasher.Hash(Password, Salt));
    }

    [Fact]
    public void OversizedEncodedValuesAreRefusedBeforeAllocation()
    {
        string encoded = Argon2.HashToString(Small, Password);
        var limits = new Argon2VerificationLimits(Small, maxEncodedLength: 256);
        Assert.True(Argon2.Verify(encoded, Password, limits));

        Assert.Throws<ArgumentOutOfRangeException>(() =>
            Argon2.Verify(encoded, Password, limits with { MaxEncodedLength = encoded.Length - 1 }));
        // Two billion KiB could not be allocated; an OutOfMemoryException here would mean the limit ran too late.
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            Argon2.Verify(encoded.Replace("m=64,", "m=2000000000,"), Password, limits));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            Argon2.Verify(encoded.Replace(",t=2,", ",t=5,"), Password, limits));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            Argon2.Verify(encoded.Replace(",p=2$", ",p=4$"), Password, limits));
        string longTag = Argon2.HashToString(Small with { OutputLength = 33 }, Password);
        Assert.Throws<ArgumentOutOfRangeException>(() => Argon2.Verify(longTag, Password, limits));
        Assert.Throws<ArgumentOutOfRangeException>(() => Argon2.Verify(encoded, Password, default));
    }

    [Fact]
    public void ThreadCountNeverChangesTheTag()
    {
        var parameters = new Argon2Parameters(Argon2Type.Id, 64, 2, 4);
        byte[] expected = Argon2.Hash(parameters, Password, Salt, threads: 1);
        foreach (int threads in new[] { 0, 2, 4, 99 })
        {
            Assert.Equal(expected, Argon2.Hash(parameters, Password, Salt, threads: threads));
            using var hasher = new Argon2Hasher(parameters, threads);
            Assert.Equal(expected, hasher.Hash(Password, Salt));
        }

        string encoded = Argon2.Encode(parameters, Salt, expected);
        Assert.True(Argon2.Verify(encoded, Password, new Argon2VerificationLimits(parameters, 256, maxThreads: 1)));
    }

    [Fact]
    public void MalformedTextThrowsAndNeverReportsAMismatch()
    {
        string valid = Argon2.Encode(Small, Salt, Argon2.Hash(Small, Password, Salt));
        Assert.StartsWith("$argon2id$v=19$m=64,t=2,p=2$AgICAgICAgICAgICAgICAg$", valid);

        string[] malformed =
        {
            "",
            valid + "\0",
            valid + "$",
            valid.Replace("$argon2id$", "$Argon2id$"),
            valid.Replace("$argon2id$", "$argon2$"),
            valid.Replace("$v=19$", "$v=19$v=19$"),
            valid.Replace("m=64,t=2,p=2", "t=2,m=64,p=2"),
            valid.Replace("m=64,t=2,p=2", "m=64,t=2,p=2,keyid=abc"),
            valid.Replace("m=64,t=2,p=2", "m=64,t=2,p=2,data=abc"),
            valid.Replace("m=64,", "m=064,"),
            valid.Replace("m=64,", "m=+64,"),
            valid.Replace("m=64,", "m= 64,"),
            valid.Replace("AgICAgICAgICAgICAgICAg$", "AgICAgICAgICAgICAgICAg==$"),
            valid.Replace("AgICAgICAgICAgICAgICAg$", "AgICAgICAgICAgICAgICAh$"),
            valid.Replace("AgICAgICAgICAgICAgICAg$", "$"),
        };

        foreach (string text in malformed)
        {
            Assert.False(Argon2.TryParse(text, out Argon2Parameters parsed, out byte[] salt, out byte[] tag), text);
            Assert.Equal(default, parsed);
            Assert.Empty(salt);
            Assert.Empty(tag);
            Assert.Throws<FormatException>(() => Argon2.Verify(text, Password, Wide));
        }

        string unsupported = valid.Replace("$v=19$", "$v=20$");
        Assert.False(Argon2.TryParse(unsupported, out _, out _, out _));
        Assert.Throws<ArgumentOutOfRangeException>(() => Argon2.Verify(unsupported, Password, Wide));
    }

    [Fact]
    public void ReusedHasherMatchesFreshHashersAndWipesItsArena()
    {
        using var hasher = new Argon2Hasher(Small);
        byte[] destination = new byte[32];
        foreach (string password in new[] { "first", "second", "", "fourth" })
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => hasher.HashInto(password, new byte[7], destination));
            hasher.HashInto(password, Salt, destination);
            Assert.Equal(Argon2.Hash(Small, password, Salt), destination);
            AssertArenaIsZero(hasher);
        }
    }

    [Fact]
    public void InvalidParametersFailBeforeTouchingOutput()
    {
        byte[] destination = KnownAnswerTests.Filled(32, 0xAA);
        Argon2Parameters[] invalid =
        {
            default,
            Small with { MemoryKiB = 15 },
            Small with { Iterations = 0 },
            Small with { Parallelism = 0 },
            Small with { OutputLength = 3 },
            Small with { Type = (Argon2Type)3 },
            Small with { Version = (Argon2Version)0x11 },
        };
        foreach (Argon2Parameters parameters in invalid)
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => Argon2.HashInto(parameters, Password, Salt, destination));
            Assert.Throws<ArgumentOutOfRangeException>(() => new Argon2Hasher(parameters));
            Assert.Throws<ArgumentOutOfRangeException>(() => parameters.BlockCount);
        }
        Assert.Throws<ArgumentOutOfRangeException>(() => Argon2.HashInto(Small, Password, new byte[7], destination));
        Assert.Throws<ArgumentOutOfRangeException>(() => Argon2.HashToString(Small, Password, saltLength: 7));
        Assert.Throws<ArgumentOutOfRangeException>(() => Argon2.Hash(Small, Password, Salt, threads: -1));
        Assert.All(destination, b => Assert.Equal(0xAA, b));
    }

    [Fact]
    public void DestinationMustBeExactlyTheTagLength()
    {
        using var hasher = new Argon2Hasher(Small);
        foreach (int length in new[] { 31, 33 })
        {
            byte[] destination = KnownAnswerTests.Filled(length, 0xAA);
            Assert.Throws<ArgumentException>(() => Argon2.HashInto(Small, Password, Salt, destination));
            Assert.Throws<ArgumentException>(() => hasher.HashInto(Password, Salt, destination));
            Assert.Throws<ArgumentException>(() => Argon2.Verify(Small, Password, Salt, destination));
            Assert.All(destination, b => Assert.Equal(0xAA, b));
        }
    }

    [Fact]
    public void OutputMayNotOverlapAnyInput()
    {
        byte[] buffer = KnownAnswerTests.Filled(64, 0xAA);
        byte[] pepper = KnownAnswerTests.Filled(32, 0x07);
        using var hasher = new Argon2Hasher(Small);

        Assert.Throws<ArgumentException>(() => Argon2.HashInto(Small, buffer, Salt, buffer.AsSpan(0, 32)));
        Assert.Throws<ArgumentException>(() => Argon2.HashInto(Small, Password, buffer.AsSpan(16, 16), buffer.AsSpan(0, 32)));
        Assert.Throws<ArgumentException>(() =>
            Argon2.HashInto(Small, Password, Salt, pepper, new Argon2AdditionalInputs(pepper)));
        Assert.Throws<ArgumentException>(() =>
            hasher.HashInto(Password, Salt, buffer.AsSpan(0, 32), new Argon2AdditionalInputs(associatedData: buffer.AsSpan(31))));
        Assert.All(buffer, b => Assert.Equal(0xAA, b));
        Assert.All(pepper, b => Assert.Equal(0x07, b));
    }

    [Fact]
    public void DisposalIsIdempotentAndFinal()
    {
        var hasher = new Argon2Hasher(Small);
        string encoded = hasher.HashToString(Password);
        hasher.Dispose();
        hasher.Dispose();
        Assert.Throws<ObjectDisposedException>(() => hasher.Hash(Password, Salt));
        Assert.Throws<ObjectDisposedException>(() => hasher.HashInto(Password, Salt, new byte[32]));
        Assert.Throws<ObjectDisposedException>(() => hasher.HashToString(Password));
        Assert.Throws<ObjectDisposedException>(() => hasher.Verify(encoded, Password, Wide));
    }

    [Fact]
    public void HasherVerifiesOtherParametersOneShotUnderTheSameLimits()
    {
        var current = new Argon2Parameters(Argon2Type.Id, 128, 3, 1);
        var old = new Argon2Parameters(Argon2Type.Id, 64, 1, 4);
        string oldHash = Argon2.HashToString(old, Password);
        string currentHash = Argon2.HashToString(current, Password);
        using var hasher = new Argon2Hasher(current);

        var covering = new Argon2VerificationLimits(128, 3, 4, 32, 256);
        Assert.True(hasher.Verify(oldHash, Password, covering));
        Assert.False(hasher.Verify(oldHash, Encoding.UTF8.GetBytes("wrong"), covering));
        Assert.True(hasher.Verify(currentHash, Password, covering));
        AssertArenaIsZero(hasher);

        // Limits built from the current parameters alone refuse the four-lane hash. README.md says so.
        var currentOnly = new Argon2VerificationLimits(current, maxEncodedLength: 256);
        Assert.Throws<ArgumentOutOfRangeException>(() => hasher.Verify(oldHash, Password, currentOnly));
        Assert.True(hasher.Verify(currentHash, Password, currentOnly));
    }

    [Fact]
    public void AHashThatThrowsPartwayStillWipesTheArenaAndScratch()
    {
        using var hasher = new Argon2Hasher(Small);
        var core = (Argon2Core)typeof(Argon2Hasher).GetField("core", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(hasher)!;
        byte[] destination = new byte[32];
        core.SegmentFilled = segment =>
        {
            if (segment == 5) throw new InvalidDataException("injected");
        };
        Assert.Throws<InvalidDataException>(() => hasher.HashInto(Password, Salt, destination));
        AssertArenaIsZero(hasher);

        core.SegmentFilled = null;
        hasher.HashInto(Password, Salt, destination);
        Assert.Equal(Argon2.Hash(Small, Password, Salt), destination);
        AssertArenaIsZero(hasher);
    }

    internal static void AssertArenaIsZero(Argon2Hasher hasher)
    {
        var arena = (Arena)typeof(Argon2Hasher).GetField("arena", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(hasher)!;
        for (int block = 0; block < hasher.Parameters.BlockCount; block++)
            Assert.True(arena.Block(block).IndexOfAnyExcept(0UL) < 0, $"block {block} is not zero");
        for (int thread = 0; thread < arena.Threads; thread++)
            Assert.True(arena.Scratch(thread).IndexOfAnyExcept(0UL) < 0, $"scratch {thread} is not zero");
    }
}
