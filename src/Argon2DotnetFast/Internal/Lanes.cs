using System.Runtime.ExceptionServices;

namespace Argon2DotnetFast.Internal;

internal interface ISliceWork
{
    // Runs the share of the current slice that belongs to thread index `thread` of `threads`.
    void RunShare(int thread, int threads);
}

// Persistent workers for the lanes of a slice. The caller is thread 0 and always works. Workers
// hold no reference to a hash between calls, so an undisposed hasher can still be collected.
internal sealed class Lanes : IDisposable
{
    private readonly Thread[] workers;
    private readonly SemaphoreSlim[] go;
    private readonly CountdownEvent done = new(1);
    private volatile bool stopping;
    private ISliceWork? work;
    private int threads;
    private Exception? failure;

    private Lanes(int requestedWorkers)
    {
        var started = new List<Thread>();
        var signals = new List<SemaphoreSlim>();
        for (int i = 0; i < requestedWorkers; i++)
        {
            var signal = new SemaphoreSlim(0);
            int index = i + 1;
            var thread = new Thread(() => Loop(index, signal)) { IsBackground = true, Name = "Argon2 lane " + index };
            try { thread.Start(); }
            catch (Exception e) when (e is OutOfMemoryException or ThreadStartException)
            {
                signal.Dispose();
                break;
            }
            started.Add(thread);
            signals.Add(signal);
        }
        workers = started.ToArray();
        go = signals.ToArray();
    }

    // Execution threads including the caller.
    internal int Count => workers.Length + 1;

    // Null when no worker could start, which leaves every lane on the caller.
    internal static Lanes? Start(int workers)
    {
        var lanes = new Lanes(workers);
        if (lanes.workers.Length > 0) return lanes;
        lanes.Dispose();
        return null;
    }

    // Runs one slice on `count` threads including the caller and returns when all of them finish.
    internal void Run(ISliceWork slice, int count)
    {
        work = slice;
        threads = count;
        done.Reset(count);
        for (int i = 0; i < count - 1; i++) go[i].Release();
        try { slice.RunShare(0, count); }
        finally
        {
            done.Signal();
            done.Wait();
            work = null;
        }
        if (failure is { } e)
        {
            failure = null;
            ExceptionDispatchInfo.Capture(e).Throw();
        }
    }

    private void Loop(int index, SemaphoreSlim signal)
    {
        while (true)
        {
            signal.Wait();
            if (stopping) return;
            try { work!.RunShare(index, threads); }
            catch (Exception e) { Interlocked.CompareExchange(ref failure, e, null); }
            finally { done.Signal(); }
        }
    }

    public void Dispose()
    {
        if (stopping) return;
        stopping = true;
        foreach (SemaphoreSlim signal in go) signal.Release();
        foreach (Thread worker in workers) worker.Join();
        foreach (SemaphoreSlim signal in go) signal.Dispose();
        done.Dispose();
    }

    // Called from the hasher's finalizer: wakes the workers so they exit, without waiting for them.
    internal void Abandon()
    {
        stopping = true;
        foreach (SemaphoreSlim signal in go) signal.Release();
    }
}
