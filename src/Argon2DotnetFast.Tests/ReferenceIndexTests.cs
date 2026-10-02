using Argon2DotnetFast.Internal;
using Xunit;

namespace Argon2DotnetFast.Tests;

public sealed class ReferenceIndexTests
{
    // NextReference, which the kernels inline to prefetch the next reference, must give what the
    // division form of RFC 9106's index mapping gives, for every geometry FillSegment can hand it.
    // It guards any division-free rewrite.
    [Fact]
    public unsafe void NextReferenceMatchesTheDivisionForm()
    {
        var random = new Random(9106);
        ulong[] scratch = new ulong[Argon2Core.ScratchWords];
        int[] lanes = { 1, 2, 3, 4, 5, 6, 7, 8, 12, 16 };
        int[] segments = { 3, 4, 5, 8, 17, 64, 1000, 4096, 65536 };
        ulong[] edges = { 0, 1, uint.MaxValue, (ulong)uint.MaxValue << 32, ulong.MaxValue, 0x8000_0000_8000_0000 };
        fixed (ulong* s = scratch)
        {
            ulong* h = s + Argon2Core.HintAt;
            for (int n = 0; n < 300_000; n++)
            {
                int p = lanes[random.Next(lanes.Length)];
                int segment = segments[random.Next(segments.Length)];
                int laneLength = 4 * segment;
                int pass = random.Next(3), slice = random.Next(4), lane = random.Next(p);
                int first = pass == 0 && slice == 0 ? 2 : 1;
                int index = first + random.Next(segment - first);
                ulong word = n < edges.Length ? edges[n] : (ulong)random.NextInt64() ^ ((ulong)random.Next() << 63);

                // As FillSegment leaves them, for the block at index.
                h[0] = (ulong)index;
                h[1] = (ulong)(pass == 0 ? slice * segment : laneLength - segment);
                h[2] = (ulong)p;
                h[3] = (ulong)lane;
                h[4] = pass == 0 && slice == 0 ? 1UL : 0UL;
                h[5] = (ulong)laneLength;
                h[6] = (ulong)(pass == 0 || slice == 3 ? 0 : (slice + 1) * segment);
                h[7] = 0;

                uint referenceLane = h[4] != 0 ? (uint)lane : (uint)(word >> 32) % (uint)p;
                uint area = (uint)h[1] + (referenceLane == lane ? (uint)index - 1 : 0);
                ulong relative = (ulong)(uint)word * (uint)word >> 32;
                relative = area - 1 - (area * relative >> 32);
                ulong expected = (referenceLane * (ulong)laneLength + (h[6] + relative) % (uint)laneLength) * 1024;

                string at = $"p={p} segment={segment} pass={pass} slice={slice} lane={lane} index={index} word={word:x16}";
                Assert.True(expected == (ulong)Argon2Core.NextReference(s, word), at);
            }
        }
    }
}
