using System.Reflection;
using Argon2DotnetFast.Internal;

namespace Argon2DotnetFast.Tests;

public class ThreadTests
{
    private static readonly byte[] Password = KnownAnswerTests.Filled(32, 0x01);
    private static readonly byte[] Salt = KnownAnswerTests.Filled(16, 0x02);

    // The tests that need worker threads ask for four lanes on four threads.
    private const string FourCpus = "needs four CPUs; on a smaller host set DOTNET_PROCESSOR_COUNT=4";

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

    // Verify returns true at every limit, so the thread count each hash ran on is read back.
    [Fact]
    public void ReusedVerifyHonorsMaxThreads()
    {
        var parameters = new Argon2Parameters(Argon2Type.Id, 256, 2, 4);
        using var hasher = new Argon2Hasher(parameters, threads: 4);
        Assert.True(hasher.ThreadCount == 4, FourCpus);
        Argon2Core core = Core(hasher);
        string encoded = hasher.HashToString(Password);
        Assert.Equal(4, core.ThreadsUsed);
        foreach (int maxThreads in new[] { 1, 2, 3, 4, 8 })
        {
            Assert.True(hasher.Verify(encoded, Password, new Argon2VerificationLimits(parameters, 256, maxThreads)));
            Assert.Equal(Math.Min(maxThreads, 4), core.ThreadsUsed);
        }
    }

    [Fact]
    public void DisposeStopsTheWorkers()
    {
        var parameters = new Argon2Parameters(Argon2Type.Id, 256, 1, 4);
        var hasher = new Argon2Hasher(parameters, threads: 4);
        Assert.True(hasher.ThreadCount == 4, FourCpus);
        hasher.Hash(Password, Salt);
        Thread[] workers = Workers(hasher);
        Assert.Equal(3, workers.Length);
        Assert.All(workers, worker => Assert.True(worker.IsAlive));
        hasher.Dispose();
        Assert.All(workers, worker => Assert.False(worker.IsAlive));
    }

    // Thread 0 is the caller, whose exception leaves Lanes.Run directly; a worker's goes through
    // Lanes.failure and the rethrow. The share throws once, so a failure left behind would surface
    // on the next hash.
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(3)]
    public void AShareThatThrowsReachesTheCallerAndLeavesTheHasherUsable(int thread)
    {
        var parameters = new Argon2Parameters(Argon2Type.Id, 256, 2, 4);
        byte[] expected = Argon2.Hash(parameters, Password, Salt, threads: 1);
        var hasher = new Argon2Hasher(parameters, threads: 4);
        Assert.True(hasher.ThreadCount == 4, FourCpus);
        Thread[] workers = Workers(hasher);
        var injected = new InvalidDataException($"injected on thread {thread}");
        int fired = 0;
        Core(hasher).ShareStarted = index =>
        {
            if (index == thread && Interlocked.Exchange(ref fired, 1) == 0) throw injected;
        };

        byte[] destination = new byte[32];
        Assert.Same(injected, Within(() => hasher.HashInto(Password, Salt, destination)));
        ApiContractTests.AssertArenaIsZero(hasher);

        Assert.Null(Within(() => hasher.HashInto(Password, Salt, destination)));
        Assert.Equal(expected, destination);
        ApiContractTests.AssertArenaIsZero(hasher);

        hasher.Dispose();
        Assert.All(workers, worker => Assert.False(worker.IsAlive));
    }

    // Runs a call on its own thread and returns what it threw. A call that never returns, as when a
    // worker misses done.Signal, fails here instead of at the run's 300 s hang timeout.
    private static Exception? Within(Action action)
    {
        Exception? thrown = null;
        var thread = new Thread(() =>
        {
            try { action(); }
            catch (Exception e) { thrown = e; }
        }) { IsBackground = true };
        thread.Start();
        Assert.True(thread.Join(TimeSpan.FromSeconds(60)), "the call did not return");
        return thrown;
    }

    private static Argon2Core Core(Argon2Hasher hasher) =>
        (Argon2Core)typeof(Argon2Hasher).GetField("core", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(hasher)!;

    private static Thread[] Workers(Argon2Hasher hasher)
    {
        var lanes = (Lanes?)typeof(Argon2Hasher).GetField("lanes", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(hasher);
        Assert.True(lanes is not null, FourCpus);
        return (Thread[])typeof(Lanes).GetField("workers", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(lanes)!;
    }
}
