#if LIBRARY_BODIES
using System.Runtime.InteropServices;
using Argon2DotnetFast.Internal;
using Xunit.Abstractions;

namespace Argon2DotnetFast.Tests;

// Kernel picks one body per process, so the known answers and the oracles only reach the body this
// CPU picked. Every other body the CPU can run is compared with Scalar here, one block at a time.
public sealed unsafe class KernelBodyTests(ITestOutputHelper output)
{
    private delegate void Body(ulong* previous, ulong* reference, ulong* destination, ulong* scratch, bool xor);

    // Scratch words FillSegment leaves for the kernel: the block to fetch when there is no hint, the
    // next block's geometry for NextReference, and the address it computed.
    private const int NextAt = Argon2Core.NextAt, HintAt = Argon2Core.HintAt, CheckAt = Argon2Core.CheckAt;

    // Blocks 0-2 are the inputs, 3 and 4 the outputs; every block can be a prefetch or hint target.
    private const int Blocks = 8;

    // Words where BlaMka's 32-bit products and the carries out of them are largest.
    private static readonly ulong[] Edges =
        { 0, ulong.MaxValue, uint.MaxValue, (ulong)uint.MaxValue << 32, 0x8000_0000_8000_0000, 0x0000_0001_0000_0001 };

    private static List<(string Name, Body Run)> SupportedBodies()
    {
        var bodies = new List<(string, Body)>();
        if (Avx512VlBody.IsSupported)
            bodies.Add(("avx512vl", (p, r, d, s, xor) => { if (xor) Avx512VlBody.FillXor(p, r, d, s); else Avx512VlBody.Fill(p, r, d, s); }));
        if (Avx2Body.IsSupported)
            bodies.Add(("avx2", (p, r, d, s, xor) => { if (xor) Avx2Body.FillXor(p, r, d, s); else Avx2Body.Fill(p, r, d, s); }));
        if (Neon.IsSupported) bodies.Add(("neon", Neon.FillNeon));
#if LIBRARY_SVE2
        if (Sve2Body.IsSupported)
            bodies.Add(("sve2", (p, r, d, s, xor) => { if (xor) Sve2Body.FillXor(p, r, d, s); else Sve2Body.Fill(p, r, d, s); }));
#endif
        return bodies;
    }

    [Fact]
    public void EverySupportedBodyMatchesScalar()
    {
        List<(string Name, Body Run)> bodies = Report();
        WithBuffers((blocks, scalarScratch, bodyScratch) =>
        {
            ulong* previous = blocks, reference = blocks + 128, old = blocks + 256;
            ulong* expected = blocks + 384, actual = blocks + 512;
            var random = new Random(1024);
            for (int n = 0; n < 64; n++)
            {
                for (int i = 0; i < Blocks * 128; i++) blocks[i] = (ulong)random.NextInt64();
                Fill(random, previous, n);
                Fill(random, reference, n + 1);
                Fill(random, old, n + 2);
                bool hint = n % 2 == 1;
                foreach (bool xor in new[] { false, true })
                {
                    Copy(old, expected);
                    ScalarBody(previous, reference, expected, scalarScratch, xor);
                    foreach ((string name, Body run) in bodies)
                    {
                        Copy(old, actual);
                        Prepare(random, bodyScratch, blocks, hint);
                        run(previous, reference, actual, bodyScratch, xor);
                        string at = $"{name} {(xor ? "FillXor" : "Fill")}, case {n}";
                        AssertSameBlock(expected, actual, at);
                        if (hint) AssertNextReference(bodyScratch, expected[0], at);
                    }
                }
            }
        });
    }

    // The address generator compresses the address block into itself, after the zero block.
    [Fact]
    public void EverySupportedBodyMatchesScalarWhenReferenceIsTheDestination()
    {
        List<(string Name, Body Run)> bodies = Report();
        bodies.Insert(0, ("scalar", ScalarBody));
        WithBuffers((blocks, scalarScratch, bodyScratch) =>
        {
            ulong* previous = blocks, reference = blocks + 128, expected = blocks + 384, actual = blocks + 512;
            var random = new Random(2048);
            for (int n = 0; n < 16; n++)
            {
                for (int i = 0; i < Blocks * 128; i++) blocks[i] = (ulong)random.NextInt64();
                if (n % 2 == 0) new Span<ulong>(previous, 128).Clear();
                else Fill(random, previous, n);
                Fill(random, reference, n + 3);
                ScalarBody(previous, reference, expected, scalarScratch, false);
                foreach ((string name, Body run) in bodies)
                {
                    Copy(reference, actual);
                    Prepare(random, bodyScratch, blocks, hint: n % 4 == 1);
                    run(previous, actual, actual, bodyScratch, false);
                    AssertSameBlock(expected, actual, $"{name} Fill into its reference, case {n}");
                }
            }
        });
    }

    private List<(string Name, Body Run)> Report()
    {
        List<(string Name, Body Run)> bodies = SupportedBodies();
        output.WriteLine($"Kernel.Name {Kernel.Name}; compared with scalar: " +
            (bodies.Count == 0 ? "no other body" : string.Join(", ", bodies.Select(b => b.Name))));
        // The body the dispatch picked must be one of them.
        if (Kernel.Name != "scalar") Assert.Contains(Kernel.Name, bodies.Select(b => b.Name));
        return bodies;
    }

    private delegate void WithBuffersAction(ulong* blocks, ulong* scalarScratch, ulong* bodyScratch);

    // The blocks and two scratch areas, 64-byte aligned like the arena.
    private static void WithBuffers(WithBuffersAction action)
    {
        int words = Blocks * 128 + 2 * Argon2Core.ScratchWords;
        ulong* buffer = (ulong*)NativeMemory.AlignedAlloc((nuint)words * 8, 64);
        try { action(buffer, buffer + Blocks * 128, buffer + Blocks * 128 + Argon2Core.ScratchWords); }
        finally { NativeMemory.AlignedFree(buffer); }
    }

    private static void ScalarBody(ulong* previous, ulong* reference, ulong* destination, ulong* scratch, bool xor)
    {
        var p = new ReadOnlySpan<ulong>(previous, 128);
        var r = new ReadOnlySpan<ulong>(reference, 128);
        var d = new Span<ulong>(destination, 128);
        var s = new Span<ulong>(scratch, Argon2Core.ScratchWords);
        if (xor) Scalar.FillXor(p, r, d, s);
        else Scalar.Fill(p, r, d, s);
    }

    // Edge words alone for the first cases, then random words with edge words mixed in.
    private static void Fill(Random random, ulong* block, int n)
    {
        for (int i = 0; i < 128; i++)
            block[i] = n < Edges.Length ? Edges[n]
                : random.Next(8) == 0 ? Edges[random.Next(Edges.Length)]
                : (ulong)random.NextInt64() ^ ((ulong)random.Next(2) << 63);
    }

    private static void Copy(ulong* from, ulong* to) => new ReadOnlySpan<ulong>(from, 128).CopyTo(new Span<ulong>(to, 128));

    // Junk everywhere a body must write before it reads. Without a hint the body fetches the block
    // at word 264; with one it computes the next reference inside the eight blocks.
    private static void Prepare(Random random, ulong* scratch, ulong* blocks, bool hint)
    {
        for (int i = 0; i < Argon2Core.ScratchWords; i++) scratch[i] = (ulong)random.NextInt64();
        scratch[NextAt] = (ulong)(blocks + 128 * random.Next(Blocks));
        ulong* h = scratch + HintAt;
        if (!hint)
        {
            h[0] = 0;
            return;
        }
        int lanes = 1 + random.Next(2), laneLength = Blocks / lanes;
        h[0] = (ulong)(1 + random.Next(laneLength - 1));
        h[1] = (ulong)random.Next(laneLength);
        h[2] = (ulong)lanes;
        h[3] = (ulong)random.Next(lanes);
        h[4] = (ulong)random.Next(2);
        h[5] = (ulong)laneLength;
        h[6] = (ulong)random.Next(laneLength);
        h[7] = (ulong)blocks;
        h[8] = 0;
    }

    private static void AssertSameBlock(ulong* expected, ulong* actual, string at)
    {
        for (int i = 0; i < 128; i++)
            if (expected[i] != actual[i])
                Assert.Fail($"{at}: word {i} is {actual[i]:x16}, scalar gives {expected[i]:x16}");
    }

    // The body must take the next reference from word 0 of the finished block.
    private static void AssertNextReference(ulong* scratch, ulong word, string at)
    {
        ulong* copy = stackalloc ulong[Argon2Core.ScratchWords];
        for (int i = HintAt; i < CheckAt; i++) copy[i] = scratch[i];
        ulong expected = (ulong)Argon2Core.NextReference(copy, word);
        Assert.True(scratch[CheckAt] == expected, $"{at}: next reference {scratch[CheckAt]:x}, expected {expected:x}");
    }
}
#endif
