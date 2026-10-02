using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Argon2DotnetFast.Internal;

internal sealed class Argon2Core : ISliceWork
{
    private readonly Argon2Parameters parameters;
    private readonly Arena arena;
    private readonly int blockCount;
    private readonly int segmentLength;
    private readonly int laneLength;

    // Scratch layout in words: the compression's temporaries, then the address generator's blocks.
    // Words 264-273 carry the next block's reference to the kernel: 264 its address when known in
    // advance; 265 the next block's index in the segment, or 0 for none; 266-272 the rest of the
    // geometry NextReference needs; 273 the address the kernel computed, for the debug check.
    internal const int NextAt = 264, HintAt = 265, CheckAt = HintAt + 8;
    private const int AddressesAt = 384, InputAt = 512, ZeroAt = 640;
    internal const int ScratchWords = 768;

    // Test hooks. SegmentFilled runs on the caller after each segment, so a test can make a hash fail
    // partway; ShareStarted runs on each thread as it starts its share of a slice.
    internal Action<int>? SegmentFilled;
    internal Action<int>? ShareStarted;

    // Execution threads, including the caller, that the last hash ran on. For the tests.
    internal int ThreadsUsed { get; private set; }

    // The slice that RunShare fills, set by Hash before the lanes start.
    private int currentPass, currentSlice;

    internal Argon2Core(in Argon2Parameters parameters, Arena arena)
    {
        this.parameters = parameters;
        this.arena = arena;
        blockCount = parameters.BlockCount;
        segmentLength = blockCount / (parameters.Parallelism * 4);
        laneLength = segmentLength * 4;
    }

    // threads counts the caller. Lanes of one slice are independent, so any split gives the same tag.
    internal void Hash(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, Span<byte> output,
        ReadOnlySpan<byte> secret, ReadOnlySpan<byte> associatedData, Lanes? lanes, int threads)
    {
        Initialize(password, salt, secret, associatedData);
        int count = lanes is null ? 1 : Math.Min(Math.Min(threads, lanes.Count), parameters.Parallelism);
        ThreadsUsed = count;
        int segment = 0;
        for (int pass = 0; pass < parameters.Iterations; pass++)
            for (int slice = 0; slice < 4; slice++)
            {
                if (count > 1)
                {
                    currentPass = pass;
                    currentSlice = slice;
                    lanes!.Run(this, count);
                }
                else
                {
                    for (int lane = 0; lane < parameters.Parallelism; lane++)
                        FillSegment(pass, slice, lane, arena.Scratch(0));
                }
                for (int lane = 0; lane < parameters.Parallelism; lane++) SegmentFilled?.Invoke(segment++);
            }
        Finish(output);
    }

    void ISliceWork.RunShare(int thread, int threads)
    {
        ShareStarted?.Invoke(thread);
        Span<ulong> scratch = arena.Scratch(thread);
        for (int lane = thread; lane < parameters.Parallelism; lane += threads)
            FillSegment(currentPass, currentSlice, lane, scratch);
    }

    private void Initialize(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> secret, ReadOnlySpan<byte> associatedData)
    {
        using var hash = new Blake2b(stackalloc ulong[8], stackalloc byte[128], 64);
        Span<byte> seed = stackalloc byte[72];
        Span<byte> block = stackalloc byte[1024];
        try
        {
            hash.UInt32(parameters.Parallelism);
            hash.UInt32(parameters.OutputLength);
            hash.UInt32(parameters.MemoryKiB);
            hash.UInt32(parameters.Iterations);
            hash.UInt32((int)parameters.Version);
            hash.UInt32((int)parameters.Type);
            hash.Field(password);
            hash.Field(salt);
            hash.Field(secret);
            hash.Field(associatedData);
            hash.Finish(seed.Slice(0, 64));
            for (int lane = 0; lane < parameters.Parallelism; lane++)
            {
                BinaryPrimitives.WriteInt32LittleEndian(seed.Slice(68), lane);
                for (int i = 0; i < 2; i++)
                {
                    BinaryPrimitives.WriteInt32LittleEndian(seed.Slice(64), i);
                    Blake2b.LongHash(seed, block);
                    Span<ulong> destination = arena.Block(lane * laneLength + i);
                    for (int word = 0; word < 128; word++)
                        destination[word] = BinaryPrimitives.ReadUInt64LittleEndian(block.Slice(word * 8));
                }
            }
        }
        finally
        {
            Sensitive.Clear(seed);
            Sensitive.Clear(block);
        }
    }

    private unsafe void FillSegment(int pass, int slice, int lane, Span<ulong> scratch)
    {
        bool independent = parameters.Type == Argon2Type.I ||
            (parameters.Type == Argon2Type.Id && pass == 0 && slice < 2);
        bool xor = pass != 0 && parameters.Version == Argon2Version.V13;
        Span<ulong> addresses = scratch.Slice(AddressesAt, 128);
        Span<ulong> input = scratch.Slice(InputAt, 128);
        ReadOnlySpan<ulong> zero = scratch.Slice(ZeroAt, 128);
        input.Clear();
        input[0] = (uint)pass;
        input[1] = (uint)lane;
        input[2] = (uint)slice;
        input[3] = (uint)blockCount;
        input[4] = (uint)parameters.Iterations;
        input[5] = (uint)parameters.Type;
        int start = pass == 0 && slice == 0 ? 2 : 0;
        // The kernel reads a block address from this word; it must be valid before the first call.
        scratch[NextAt] = (ulong)arena.BlockPointer(lane * laneLength);
        scratch[HintAt] = 0;
        scratch[HintAt + 1] = (ulong)(pass == 0 ? slice * segmentLength : laneLength - segmentLength);
        scratch[HintAt + 2] = (ulong)parameters.Parallelism;
        scratch[HintAt + 3] = (ulong)lane;
        scratch[HintAt + 4] = pass == 0 && slice == 0 ? 1UL : 0UL;
        scratch[HintAt + 5] = (ulong)laneLength;
        scratch[HintAt + 6] = (ulong)(pass == 0 || slice == 3 ? 0 : (slice + 1) * segmentLength);
        scratch[HintAt + 7] = (ulong)arena.BlockPointer(0);
        scratch[CheckAt] = 0;
        if (independent && start == 2) NextAddresses(zero, input, addresses, scratch);
        // On the data-independent path the next block's reference is found one block early, so the
        // kernel can start fetching it; -1 where the next address block does not exist yet.
        int carried = -1;
        for (int i = start; i < segmentLength; i++)
        {
            int position = slice * segmentLength + i;
            int current = lane * laneLength + position;
            int previous = lane * laneLength + (position == 0 ? laneLength - 1 : position - 1);
            int flat;
            if (independent)
            {
                if (i % 128 == 0) NextAddresses(zero, input, addresses, scratch);
                flat = carried >= 0 ? carried : ReferenceBlock(pass, slice, lane, i, addresses[i % 128]);
                carried = i + 1 < segmentLength && (i + 1) % 128 != 0
                    ? ReferenceBlock(pass, slice, lane, i + 1, addresses[(i + 1) % 128]) : -1;
            }
            else
            {
                flat = ReferenceBlock(pass, slice, lane, i, arena.Block(previous)[0]);
                Debug.Assert(scratch[CheckAt] == 0 || scratch[CheckAt] == (ulong)arena.BlockPointer(flat));
                scratch[HintAt] = i + 1 < segmentLength ? (ulong)(i + 1) : 0UL;
            }
            scratch[NextAt] = (ulong)arena.BlockPointer(carried >= 0 ? carried : previous);
            Span<ulong> reference = arena.Block(flat);
            if (xor) Kernel.FillXor(arena.Block(previous), reference, arena.Block(current), scratch);
            else Kernel.Fill(arena.Block(previous), reference, arena.Block(current), scratch);
        }
    }

    private static void NextAddresses(ReadOnlySpan<ulong> zero, Span<ulong> input, Span<ulong> addresses,
        Span<ulong> scratch)
    {
        input[6]++;
        Kernel.Fill(zero, input, addresses, scratch);
        Kernel.Fill(zero, addresses, addresses, scratch);
    }

    // ReferenceBlock for the next block, from the geometry FillSegment left in scratch and word 0
    // of the block the kernel is writing. Returns the block's address and records it for the check.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static unsafe ulong* NextReference(ulong* scratch, ulong word)
    {
        ulong* h = scratch + HintAt;
        uint lane = (uint)h[3];
        uint referenceLane = h[4] != 0 ? lane : (uint)(word >> 32) % (uint)h[2];
        uint area = (uint)h[1] + (referenceLane == lane ? (uint)h[0] - 1 : 0);
        ulong relative = (ulong)(uint)word * (uint)word >> 32;
        relative = area - 1 - (area * relative >> 32);
        ulong index = ((ulong)h[6] + relative) % (uint)h[5];
        ulong* block = (ulong*)h[7] + (referenceLane * h[5] + index) * 128;
        h[8] = (ulong)block;
        return block;
    }

    private int ReferenceBlock(int pass, int slice, int lane, int index, ulong random)
    {
        // 32-bit operands give a 32-bit div, which older Intel cores run several times faster than a 64-bit one.
        int referenceLane = (int)((uint)(random >> 32) % (uint)parameters.Parallelism);
        if (pass == 0 && slice == 0) referenceLane = lane;
        return referenceLane * laneLength + ReferenceIndex(pass, slice, index, (uint)random, referenceLane == lane);
    }

    private int ReferenceIndex(int pass, int slice, int index, uint random, bool sameLane)
    {
        int area;
        if (pass == 0)
            area = slice == 0 ? index - 1 : slice * segmentLength +
                (sameLane ? index - 1 : (index == 0 ? -1 : 0));
        else
            area = laneLength - segmentLength + (sameLane ? index - 1 : (index == 0 ? -1 : 0));
        ulong relative = (ulong)random * random >> 32;
        relative = (uint)area - 1 - ((uint)area * relative >> 32);
        int start = pass == 0 || slice == 3 ? 0 : (slice + 1) * segmentLength;
        // Below 1.75 lane lengths, so the sum fits in 32 bits and the remainder is a 32-bit div.
        return (int)(((uint)start + (uint)relative) % (uint)laneLength);
    }

    private void Finish(Span<byte> output)
    {
        Span<ulong> final = stackalloc ulong[128];
        Span<byte> bytes = stackalloc byte[1024];
        try
        {
            arena.Block(laneLength - 1).CopyTo(final);
            for (int lane = 1; lane < parameters.Parallelism; lane++)
            {
                Span<ulong> last = arena.Block((lane + 1) * laneLength - 1);
                for (int i = 0; i < 128; i++) final[i] ^= last[i];
            }
            for (int i = 0; i < 128; i++)
                BinaryPrimitives.WriteUInt64LittleEndian(bytes.Slice(8 * i), final[i]);
            Blake2b.LongHash(bytes, output);
        }
        finally
        {
            Sensitive.Clear(MemoryMarshal.AsBytes(final));
            Sensitive.Clear(bytes);
        }
    }
}
