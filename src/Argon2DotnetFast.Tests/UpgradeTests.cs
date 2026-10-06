using System.Reflection;
using System.Text;
using Argon2DotnetFast.Internal;

namespace Argon2DotnetFast.Tests;

public class UpgradeTests
{
    private static readonly Argon2Parameters Original = new(Argon2Type.Id, 32, 1, 1);
    private static readonly Argon2VerificationLimits Limits = new(128, 3, 4, 128, 1024, 1);
    private const string Password = "pāss\0🔑";

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void EveryParameterDifferenceProducesAVerifiableFreshReplacement(bool instance, bool chars)
    {
        byte[] pepper = "pepper"u8.ToArray(), data = "account"u8.ToArray();
        var inputs = new Argon2AdditionalInputs(pepper, data);
        string encoded = Argon2.HashToString(Original, Password, inputs);
        Argon2.Parse(encoded, out _, out byte[] oldSalt, out _);
        var profiles = new[]
        {
            Original with { Type = Argon2Type.D }, Original with { Type = Argon2Type.I },
            Original with { Version = Argon2Version.V10 }, Original with { MemoryKiB = 33 },
            Original with { MemoryKiB = 16 }, Original with { Iterations = 2 },
            Original with { Parallelism = 2 }, Original with { OutputLength = 97 },
        };
        foreach (var desired in profiles)
        {
            using var hasher = new Argon2Hasher(desired);
            var result = Run(instance ? hasher : null, chars, encoded, Password, desired, inputs);
            Assert.True(result.Verified);
            Assert.NotNull(result.ReplacementHash);
            Argon2.Parse(result.ReplacementHash, out var actual, out byte[] salt, out _);
            Assert.Equal(desired, actual);
            Assert.Equal(16, salt.Length);
            Assert.False(oldSalt.SequenceEqual(salt));
            Assert.True(Argon2.Verify(result.ReplacementHash, Password, Limits, inputs));
            Assert.False(Argon2.Verify(result.ReplacementHash, Password, Limits));
            var again = Run(instance ? hasher : null, chars, result.ReplacementHash!, Password, desired, inputs);
            Assert.True(again.Verified);
            Assert.Null(again.ReplacementHash);
            ApiContractTests.AssertArenaIsZero(hasher);
        }
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void MismatchNeverCreatesReplacementAndSaltLengthAloneDoesNotTriggerIt(bool instance, bool chars)
    {
        string encoded = Argon2.HashToString(Original, Password);
        var desired = Original with { Iterations = 2 };
        using var hasher = new Argon2Hasher(desired);
        var mismatch = Run(instance ? hasher : null, chars, encoded, "wrong", desired);
        Assert.False(mismatch.Verified);
        Assert.Null(mismatch.ReplacementHash);
        string current = Argon2.HashToString(desired, Password, saltLength: 8);
        var matching = Run(instance ? hasher : null, chars, current, Password, desired);
        Assert.True(matching.Verified);
        Assert.Null(matching.ReplacementHash);
        var upgraded = Run(instance ? hasher : null, chars, encoded, Password, desired, saltLength: 24);
        Argon2.Parse(upgraded.ReplacementHash, out _, out var salt, out _);
        Assert.Equal(24, salt.Length);
        ApiContractTests.AssertArenaIsZero(hasher);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void LimitsPrecedeCharacterEncodingAndHasherRecoversFromErrors(bool instance)
    {
        string encoded = Argon2.HashToString(Original, Password);
        using var hasher = new Argon2Hasher(Original);
        var target = instance ? hasher : null;
        Assert.Throws<FormatException>(() => Run(target, true, "bad", "\ud800", Original));
        Assert.Throws<ArgumentOutOfRangeException>(() => Run(target, true, new string('x', 1025), "\ud800", Original));
        Assert.Throws<EncoderFallbackException>(() => Run(target, true, encoded, "\ud800", Original));
        Assert.Throws<ArgumentOutOfRangeException>(() => Run(target, true, encoded, Password, Original, saltLength: 7));
        Assert.Throws<ArgumentOutOfRangeException>(() => Run(target, false, encoded, "wrong", Original, saltLength: 7));
        var tooLarge = Argon2.HashToString(Original with { MemoryKiB = 256 }, Password);
        Assert.Throws<ArgumentOutOfRangeException>(() => Run(target, true, tooLarge, "\ud800", Original));
        Assert.True(Run(target, true, encoded, Password, Original).Verified);
        ApiContractTests.AssertArenaIsZero(hasher);
        hasher.Dispose();
        Assert.Throws<ObjectDisposedException>(() => hasher.VerifyAndUpgrade(encoded, Password, Limits));
        Assert.Throws<ObjectDisposedException>(() => hasher.VerifyAndUpgrade(encoded, "password"u8, Limits));
    }

    [Fact]
    public void WrongAdditionalInputsNeverProduceAReplacement()
    {
        byte[] secret = "pepper"u8.ToArray(), data = "account"u8.ToArray();
        string encoded = Argon2.HashToString(Original, Password, new(secret, data));
        var desired = Original with { Iterations = 2 };
        using var hasher = new Argon2Hasher(desired);
        foreach (bool chars in new[] { false, true })
        foreach (var target in new Argon2Hasher?[] { null, hasher })
        {
            var wrongSecret = Run(target, chars, encoded, Password, desired, new(default, data));
            var wrongData = Run(target, chars, encoded, Password, desired, new(secret));
            Assert.False(wrongSecret.Verified);
            Assert.Null(wrongSecret.ReplacementHash);
            Assert.False(wrongData.Verified);
            Assert.Null(wrongData.ReplacementHash);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void UpgradeHoldsTheGuardWhileUsingTheResidentArena(bool matching)
    {
        var desired = Original with { Iterations = 2 };
        string encoded = Argon2.HashToString(matching ? desired : Original, Password);
        using var hasher = new Argon2Hasher(desired);
        using var inside = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        Core(hasher).SegmentFilled = segment =>
        {
            if (segment != 0) return;
            inside.Set();
            if (!release.Wait(TimeSpan.FromSeconds(30))) throw new TimeoutException();
        };
        Exception? failure = null;
        Argon2VerificationResult result = default;
        var worker = new Thread(() =>
        {
            try { result = hasher.VerifyAndUpgrade(encoded, Password, Limits); }
            catch (Exception e) { failure = e; }
        }) { IsBackground = true };
        worker.Start();
        try
        {
            Assert.True(inside.Wait(TimeSpan.FromSeconds(30)));
            Assert.Throws<InvalidOperationException>(() => hasher.VerifyAndUpgrade(encoded, Password, Limits));
            Assert.Throws<InvalidOperationException>(() => hasher.HashToString(Password));
        }
        finally
        {
            release.Set();
            Assert.True(worker.Join(TimeSpan.FromSeconds(30)));
        }
        Assert.Null(failure);
        Assert.True(result.Verified);
        Assert.Equal(matching, result.ReplacementHash is null);
        ApiContractTests.AssertArenaIsZero(hasher);
    }

    [Fact]
    public void DesiredProfileMayExceedStoredHashLimits()
    {
        var desired = Original with { MemoryKiB = 256, Parallelism = 4 };
        var limits = new Argon2VerificationLimits(Original, 1024);
        string encoded = Argon2.HashToString(Original, Password);
        var result = Argon2.VerifyAndUpgrade(encoded, Password, limits, desired);
        Assert.True(Argon2.Verify(result.ReplacementHash, Password, new Argon2VerificationLimits(desired, 1024)));
        using var hasher = new Argon2Hasher(desired, threads: 4);
        result = hasher.VerifyAndUpgrade(encoded, Password, limits);
        Assert.True(result.Verified);
        Assert.Equal(1, Core(hasher).ThreadsUsed);
        Assert.True(Argon2.Verify(result.ReplacementHash, Password, new Argon2VerificationLimits(desired, 1024)));
    }

    [Fact]
    public void LegacyVersionAndEmptyPasswordCanBeMigrated()
    {
        var old = Original with { Version = Argon2Version.V10 };
        string encoded = Argon2.HashToString(old, "").Replace("$v=16", "");
        var result = Argon2.VerifyAndUpgrade(encoded, "", Limits, Original);
        Assert.True(result.Verified);
        Assert.True(Argon2.Verify(result.ReplacementHash, "", Limits));
    }

    [Fact]
    public void InvalidDesiredProfileThrowsEvenOnMismatch()
    {
        string encoded = Argon2.HashToString(Original, Password);
        Assert.Throws<ArgumentOutOfRangeException>(() => Argon2.VerifyAndUpgrade(encoded, "wrong", Limits, default));
        Assert.False(default(Argon2VerificationResult).Verified);
        Assert.Null(default(Argon2VerificationResult).ReplacementHash);
    }

    [Fact]
    public void ReplacementFailureThrowsClearsArenaAndReleasesGuard()
    {
        string encoded = Argon2.HashToString(Original, Password);
        using var hasher = new Argon2Hasher(Original with { Iterations = 2 });
        var injected = new InvalidOperationException("replacement fault");
        Core(hasher).SegmentFilled = _ => throw injected;
        Assert.Same(injected, Assert.Throws<InvalidOperationException>(() => hasher.VerifyAndUpgrade(encoded, Password, Limits)));
        ApiContractTests.AssertArenaIsZero(hasher);
        Core(hasher).SegmentFilled = null;
        Assert.True(hasher.VerifyAndUpgrade(encoded, Password, Limits).Verified);
    }

    private static Argon2Core Core(Argon2Hasher hasher) =>
        (Argon2Core)typeof(Argon2Hasher).GetField("core", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(hasher)!;

    private static Argon2VerificationResult Run(Argon2Hasher? hasher, bool chars, string encoded,
        string password, Argon2Parameters desired, Argon2AdditionalInputs inputs = default, int saltLength = 16) =>
        hasher is null
            ? chars ? Argon2.VerifyAndUpgrade(encoded, password, Limits, desired, inputs, saltLength)
                    : Argon2.VerifyAndUpgrade(encoded, Encoding.UTF8.GetBytes(password), Limits, desired, inputs, saltLength)
            : chars ? hasher.VerifyAndUpgrade(encoded, password, Limits, inputs, saltLength)
                    : hasher.VerifyAndUpgrade(encoded, Encoding.UTF8.GetBytes(password), Limits, inputs, saltLength);
}
