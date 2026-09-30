using System.Reflection;
using Argon2DotnetFast.Internal;

namespace Argon2DotnetFast.Tests;

public class ThreadTests
{
    private static readonly byte[] Password = KnownAnswerTests.Filled(32, 0x01);
    private static readonly byte[] Salt = KnownAnswerTests.Filled(16, 0x02);

    [Fact]
    public void ThreadCountIsCappedByLanesAndProcessors()
    {
        var one = new Argon2Parameters(Argon2Type.Id, 256, 1, 1);
        var four = new Argon2Parameters(Argon2Type.Id, 256, 1, 4);
        using (var hasher = new Argon2Hasher(one, threads: 8)) Assert.Equal(1, hasher.ThreadCount);
        using (var hasher = new Argon2Hasher(four, threads: 1)) Assert.Equal(1, hasher.ThreadCount);
        using (var hasher = new Argon2Hasher(four, threads: 2))
            Assert.Equal(Math.Min(2, Environment.ProcessorCount), hasher.ThreadCount);
        using (var hasher = new Argon2Hasher(four))
            Assert.Equal(Math.Min(4, Environment.ProcessorCount), hasher.ThreadCount);
    }

    [Fact]
    public void EveryThreadCountGivesTheSameTag()
    {
        var random = new Random(6);
        foreach (int lanes in new[] { 2, 3, 4, 5, 8 })
        {
            var parameters = new Argon2Parameters((Argon2Type)random.Next(3), 64 * lanes + random.Next(200), 2, lanes);
            byte[] expected = Argon2.Hash(parameters, Password, Salt, threads: 1);
            for (int threads = 0; threads <= lanes + 1; threads++)
            {
                using var hasher = new Argon2Hasher(parameters, threads);
                for (int repeat = 0; repeat < 3; repeat++)
                    Assert.Equal(expected, hasher.Hash(Password, Salt));
                ApiContractTests.AssertArenaIsZero(hasher);
            }
        }
    }

    [Fact]
    public void ReusedVerifyHonorsMaxThreads()
    {
        var parameters = new Argon2Parameters(Argon2Type.Id, 256, 2, 4);
        using var hasher = new Argon2Hasher(parameters, threads: 4);
        string encoded = hasher.HashToString(Password);
        foreach (int maxThreads in new[] { 1, 2, 4 })
            Assert.True(hasher.Verify(encoded, Password, new Argon2VerificationLimits(parameters, 256, maxThreads)));
    }

    [Fact]
    public void DisposeStopsTheWorkers()
    {
        var parameters = new Argon2Parameters(Argon2Type.Id, 256, 1, 4);
        var hasher = new Argon2Hasher(parameters, threads: 4);
        hasher.Hash(Password, Salt);
        var lanes = typeof(Argon2Hasher).GetField("lanes", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(hasher);
        hasher.Dispose();
        if (lanes is null) return;
        var workers = (Thread[])lanes.GetType().GetField("workers", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(lanes)!;
        Assert.All(workers, worker => Assert.False(worker.IsAlive));
    }
}
