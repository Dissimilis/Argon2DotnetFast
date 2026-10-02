using System.Reflection;
using System.Text;
using Argon2DotnetFast.Internal;

namespace Argon2DotnetFast.Tests;

public class ConcurrencyTests
{
    // The worker's hash stops inside its first segment until every probe on this thread has been
    // refused, so the overlap does not depend on timing.
    [Fact]
    public void OverlappingCallsThrowInsteadOfSharingTheArena()
    {
        var parameters = new Argon2Parameters(Argon2Type.Id, 256, 2, 1);
        byte[] password = Encoding.UTF8.GetBytes("password");
        byte[] salt = KnownAnswerTests.Filled(16, 0x02);
        byte[] expected = Argon2.Hash(parameters, password, salt);
        string encoded = Argon2.Encode(parameters, salt, expected);
        var limits = new Argon2VerificationLimits(parameters, maxEncodedLength: 256);
        using var hasher = new Argon2Hasher(parameters);
        var core = (Argon2Core)typeof(Argon2Hasher).GetField("core", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(hasher)!;

        using var inside = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        core.SegmentFilled = segment =>
        {
            if (segment != 0) return;
            inside.Set();
            release.Wait(TimeSpan.FromSeconds(60));
        };
        byte[]? tag = null;
        Exception? failed = null;
        var worker = new Thread(() =>
        {
            try { tag = hasher.Hash(password, salt); }
            catch (Exception e) { failed = e; }
        }) { IsBackground = true };
        worker.Start();
        try
        {
            Assert.True(inside.Wait(TimeSpan.FromSeconds(60)), "the worker's hash did not start");
            Assert.Throws<InvalidOperationException>(() => hasher.HashInto(password, salt, new byte[32]));
            Assert.Throws<InvalidOperationException>(() => hasher.HashInto("password", salt, new byte[32]));
            Assert.Throws<InvalidOperationException>(() => hasher.Hash(password, salt));
            Assert.Throws<InvalidOperationException>(() => hasher.HashToString(password));
            Assert.Throws<InvalidOperationException>(() => hasher.Verify(encoded, password, limits));
            Assert.Throws<InvalidOperationException>(() => hasher.Verify(encoded, "password", limits));
        }
        finally { release.Set(); }
        Assert.True(worker.Join(TimeSpan.FromSeconds(60)), "the worker's hash did not finish");
        core.SegmentFilled = null;

        Assert.Null(failed);
        Assert.Equal(expected, tag);
        Assert.Equal(expected, hasher.Hash(password, salt));
        ApiContractTests.AssertArenaIsZero(hasher);
    }
}
