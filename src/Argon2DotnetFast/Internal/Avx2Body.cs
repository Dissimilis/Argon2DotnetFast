#if NET
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace Argon2DotnetFast.Internal;

// The 256-bit round of phc-winner opt.c: a row unit is two rows of four words per register,
// a column unit is two columns, four words of each row. 2 chains per loop iteration,
// in opt.c macro order.
// The next block's reference is prefetched: at the top when FillSegment already knows it,
// and otherwise as soon as the first column iteration has made word 0 of this block final.
internal static unsafe class Avx2Body
{
    internal static bool IsSupported => Avx2.IsSupported;

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    internal static void Fill(ulong* previous, ulong* reference, ulong* destination, ulong* scratch) =>
        Compress(previous, reference, destination, scratch, false);

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    internal static void FillXor(ulong* previous, ulong* reference, ulong* destination, ulong* scratch) =>
        Compress(previous, reference, destination, scratch, true);

    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
    private static void Compress(ulong* previous, ulong* reference, ulong* destination, ulong* scratch, bool xor)
    {
        ulong* r = scratch, saved = scratch + 128;
        // Byte permutations for rotates by 24 and 16, per 64-bit lane.
        Vector256<byte> r24 = Vector256.Create((byte)3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10,
            3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10);
        Vector256<byte> r16 = Vector256.Create((byte)2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9,
            2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9);
        // The next block's reference when FillSegment knows it already (the data-independent
        // path), otherwise previous, which is in L1.
        byte* next = (byte*)scratch[264];
        Sse.Prefetch0(next);
        Sse.Prefetch0(next + 64);
        Sse.Prefetch0(next + 128);
        Sse.Prefetch0(next + 192);
        Sse.Prefetch0(next + 256);
        Sse.Prefetch0(next + 320);
        Sse.Prefetch0(next + 384);
        Sse.Prefetch0(next + 448);
        Sse.Prefetch0(next + 512);
        Sse.Prefetch0(next + 576);
        Sse.Prefetch0(next + 640);
        Sse.Prefetch0(next + 704);
        Sse.Prefetch0(next + 768);
        Sse.Prefetch0(next + 832);
        Sse.Prefetch0(next + 896);
        Sse.Prefetch0(next + 960);
        for (int k = 0; k < 4; k++)
        {
            nint row = 32 * k;
            ulong* pp = previous + row, pr = reference + row, pd = destination + row;
            ulong* ps = saved + row, pw = r + row;
            Vector256<ulong> a00 = Avx.LoadVector256(pp) ^ Avx.LoadVector256(pr);
            Vector256<ulong> b00 = Avx.LoadVector256(pp + 4) ^ Avx.LoadVector256(pr + 4);
            Vector256<ulong> c00 = Avx.LoadVector256(pp + 8) ^ Avx.LoadVector256(pr + 8);
            Vector256<ulong> d00 = Avx.LoadVector256(pp + 12) ^ Avx.LoadVector256(pr + 12);
            Vector256<ulong> a01 = Avx.LoadVector256(pp + 16) ^ Avx.LoadVector256(pr + 16);
            Vector256<ulong> b01 = Avx.LoadVector256(pp + 20) ^ Avx.LoadVector256(pr + 20);
            Vector256<ulong> c01 = Avx.LoadVector256(pp + 24) ^ Avx.LoadVector256(pr + 24);
            Vector256<ulong> d01 = Avx.LoadVector256(pp + 28) ^ Avx.LoadVector256(pr + 28);
            if (xor)
            {
                Avx.Store(ps, a00 ^ Avx.LoadVector256(pd));
                Avx.Store(ps + 4, b00 ^ Avx.LoadVector256(pd + 4));
                Avx.Store(ps + 8, c00 ^ Avx.LoadVector256(pd + 8));
                Avx.Store(ps + 12, d00 ^ Avx.LoadVector256(pd + 12));
                Avx.Store(ps + 16, a01 ^ Avx.LoadVector256(pd + 16));
                Avx.Store(ps + 20, b01 ^ Avx.LoadVector256(pd + 20));
                Avx.Store(ps + 24, c01 ^ Avx.LoadVector256(pd + 24));
                Avx.Store(ps + 28, d01 ^ Avx.LoadVector256(pd + 28));
            }
            else
            {
                Avx.Store(ps, a00);
                Avx.Store(ps + 4, b00);
                Avx.Store(ps + 8, c00);
                Avx.Store(ps + 12, d00);
                Avx.Store(ps + 16, a01);
                Avx.Store(ps + 20, b01);
                Avx.Store(ps + 24, c01);
                Avx.Store(ps + 28, d01);
            }
            a00 = BlaMka(a00, b00);
            d00 ^= a00;
            d00 = Avx2.Shuffle(d00.AsUInt32(), 0xB1).AsUInt64();
            c00 = BlaMka(c00, d00);
            b00 ^= c00;
            b00 = Avx2.Shuffle(b00.AsByte(), r24).AsUInt64();
            a01 = BlaMka(a01, b01);
            d01 ^= a01;
            d01 = Avx2.Shuffle(d01.AsUInt32(), 0xB1).AsUInt64();
            c01 = BlaMka(c01, d01);
            b01 ^= c01;
            b01 = Avx2.Shuffle(b01.AsByte(), r24).AsUInt64();
            a00 = BlaMka(a00, b00);
            d00 ^= a00;
            d00 = Avx2.Shuffle(d00.AsByte(), r16).AsUInt64();
            c00 = BlaMka(c00, d00);
            b00 ^= c00;
            b00 = Avx2.ShiftRightLogical(b00, 63) ^ (b00 + b00);
            a01 = BlaMka(a01, b01);
            d01 ^= a01;
            d01 = Avx2.Shuffle(d01.AsByte(), r16).AsUInt64();
            c01 = BlaMka(c01, d01);
            b01 ^= c01;
            b01 = Avx2.ShiftRightLogical(b01, 63) ^ (b01 + b01);
            Vector256<ulong> b00d = Avx2.Permute4x64(b00, 0x39), c00d = Avx2.Permute4x64(c00, 0x4E), d00d = Avx2.Permute4x64(d00, 0x93);
            Vector256<ulong> b01d = Avx2.Permute4x64(b01, 0x39), c01d = Avx2.Permute4x64(c01, 0x4E), d01d = Avx2.Permute4x64(d01, 0x93);
            a00 = BlaMka(a00, b00d);
            d00d ^= a00;
            d00d = Avx2.Shuffle(d00d.AsUInt32(), 0xB1).AsUInt64();
            c00d = BlaMka(c00d, d00d);
            b00d ^= c00d;
            b00d = Avx2.Shuffle(b00d.AsByte(), r24).AsUInt64();
            a01 = BlaMka(a01, b01d);
            d01d ^= a01;
            d01d = Avx2.Shuffle(d01d.AsUInt32(), 0xB1).AsUInt64();
            c01d = BlaMka(c01d, d01d);
            b01d ^= c01d;
            b01d = Avx2.Shuffle(b01d.AsByte(), r24).AsUInt64();
            a00 = BlaMka(a00, b00d);
            d00d ^= a00;
            d00d = Avx2.Shuffle(d00d.AsByte(), r16).AsUInt64();
            c00d = BlaMka(c00d, d00d);
            b00d ^= c00d;
            b00d = Avx2.ShiftRightLogical(b00d, 63) ^ (b00d + b00d);
            a01 = BlaMka(a01, b01d);
            d01d ^= a01;
            d01d = Avx2.Shuffle(d01d.AsByte(), r16).AsUInt64();
            c01d = BlaMka(c01d, d01d);
            b01d ^= c01d;
            b01d = Avx2.ShiftRightLogical(b01d, 63) ^ (b01d + b01d);
            Avx.Store(pw, a00);
            Avx.Store(pw + 4, Avx2.Permute4x64(b00d, 0x93));
            Avx.Store(pw + 8, Avx2.Permute4x64(c00d, 0x4E));
            Avx.Store(pw + 12, Avx2.Permute4x64(d00d, 0x39));
            Avx.Store(pw + 16, a01);
            Avx.Store(pw + 20, Avx2.Permute4x64(b01d, 0x93));
            Avx.Store(pw + 24, Avx2.Permute4x64(c01d, 0x4E));
            Avx.Store(pw + 28, Avx2.Permute4x64(d01d, 0x39));
        }
        byte* following = null;
        for (int k = 0; k < 4; k++)
        {
            nint column = 4 * k;
            ulong* p = r + column, pd = destination + column, ps = saved + column;
            Vector256<ulong> a00 = Avx.LoadVector256(p);
            Vector256<ulong> a01 = Avx.LoadVector256(p + 16);
            Vector256<ulong> b00 = Avx.LoadVector256(p + 32);
            Vector256<ulong> b01 = Avx.LoadVector256(p + 48);
            Vector256<ulong> c00 = Avx.LoadVector256(p + 64);
            Vector256<ulong> c01 = Avx.LoadVector256(p + 80);
            Vector256<ulong> d00 = Avx.LoadVector256(p + 96);
            Vector256<ulong> d01 = Avx.LoadVector256(p + 112);
            a00 = BlaMka(a00, b00);
            d00 ^= a00;
            d00 = Avx2.Shuffle(d00.AsUInt32(), 0xB1).AsUInt64();
            c00 = BlaMka(c00, d00);
            b00 ^= c00;
            b00 = Avx2.Shuffle(b00.AsByte(), r24).AsUInt64();
            a01 = BlaMka(a01, b01);
            d01 ^= a01;
            d01 = Avx2.Shuffle(d01.AsUInt32(), 0xB1).AsUInt64();
            c01 = BlaMka(c01, d01);
            b01 ^= c01;
            b01 = Avx2.Shuffle(b01.AsByte(), r24).AsUInt64();
            a00 = BlaMka(a00, b00);
            d00 ^= a00;
            d00 = Avx2.Shuffle(d00.AsByte(), r16).AsUInt64();
            c00 = BlaMka(c00, d00);
            b00 ^= c00;
            b00 = Avx2.ShiftRightLogical(b00, 63) ^ (b00 + b00);
            a01 = BlaMka(a01, b01);
            d01 ^= a01;
            d01 = Avx2.Shuffle(d01.AsByte(), r16).AsUInt64();
            c01 = BlaMka(c01, d01);
            b01 ^= c01;
            b01 = Avx2.ShiftRightLogical(b01, 63) ^ (b01 + b01);
            Vector256<ulong> b00d = Pair(b00, b01), b01d = Pair(b01, b00);
            Vector256<ulong> d00d = Pair(d01, d00), d01d = Pair(d00, d01);
            a00 = BlaMka(a00, b00d);
            d00d ^= a00;
            d00d = Avx2.Shuffle(d00d.AsUInt32(), 0xB1).AsUInt64();
            c01 = BlaMka(c01, d00d);
            b00d ^= c01;
            b00d = Avx2.Shuffle(b00d.AsByte(), r24).AsUInt64();
            a01 = BlaMka(a01, b01d);
            d01d ^= a01;
            d01d = Avx2.Shuffle(d01d.AsUInt32(), 0xB1).AsUInt64();
            c00 = BlaMka(c00, d01d);
            b01d ^= c00;
            b01d = Avx2.Shuffle(b01d.AsByte(), r24).AsUInt64();
            a00 = BlaMka(a00, b00d);
            d00d ^= a00;
            d00d = Avx2.Shuffle(d00d.AsByte(), r16).AsUInt64();
            c01 = BlaMka(c01, d00d);
            b00d ^= c01;
            b00d = Avx2.ShiftRightLogical(b00d, 63) ^ (b00d + b00d);
            a01 = BlaMka(a01, b01d);
            d01d ^= a01;
            d01d = Avx2.Shuffle(d01d.AsByte(), r16).AsUInt64();
            c00 = BlaMka(c00, d01d);
            b01d ^= c00;
            b01d = Avx2.ShiftRightLogical(b01d, 63) ^ (b01d + b01d);
            Avx.Store(pd, a00 ^ Avx.LoadVector256(ps));
            Avx.Store(pd + 16, a01 ^ Avx.LoadVector256(ps + 16));
            Avx.Store(pd + 32, Pair(b01d, b00d) ^ Avx.LoadVector256(ps + 32));
            Avx.Store(pd + 48, Pair(b00d, b01d) ^ Avx.LoadVector256(ps + 48));
            Avx.Store(pd + 64, c00 ^ Avx.LoadVector256(ps + 64));
            Avx.Store(pd + 80, c01 ^ Avx.LoadVector256(ps + 80));
            Avx.Store(pd + 96, Pair(d00d, d01d) ^ Avx.LoadVector256(ps + 96));
            Avx.Store(pd + 112, Pair(d01d, d00d) ^ Avx.LoadVector256(ps + 112));
            if (k == 0 && scratch[265] != 0)
            {
                // Word 0 of this block is final, so the next block's reference is known. Lines 0-7 now,
                // 8-15 one iteration later: Haswell has about ten L1 miss buffers.
                following = (byte*)Argon2Core.NextReference(scratch, destination[0]);
                Sse.Prefetch0(following);
                Sse.Prefetch0(following + 64);
                Sse.Prefetch0(following + 128);
                Sse.Prefetch0(following + 192);
                Sse.Prefetch0(following + 256);
                Sse.Prefetch0(following + 320);
                Sse.Prefetch0(following + 384);
                Sse.Prefetch0(following + 448);
            }
            else if (k == 1 && scratch[265] != 0)
            {
                Sse.Prefetch0(following + 512);
                Sse.Prefetch0(following + 576);
                Sse.Prefetch0(following + 640);
                Sse.Prefetch0(following + 704);
                Sse.Prefetch0(following + 768);
                Sse.Prefetch0(following + 832);
                Sse.Prefetch0(following + 896);
                Sse.Prefetch0(following + 960);
            }
        }
    }

    // x + y + 2 * lo32(x) * lo32(y) per 64-bit lane; vpmuludq takes the low half of each lane.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector256<ulong> BlaMka(Vector256<ulong> x, Vector256<ulong> y)
    {
        Vector256<ulong> m = Avx2.Multiply(x.AsUInt32(), y.AsUInt32());
        return x + y + (m + m);
    }

    // The high word of x, then the low word of y, in each 128-bit half: one vpalignr.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector256<ulong> Pair(Vector256<ulong> x, Vector256<ulong> y) =>
        Avx2.AlignRight(y.AsByte(), x.AsByte(), 8).AsUInt64();
}
#endif
