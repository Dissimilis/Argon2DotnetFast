#if NET
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace Argon2DotnetFast.Internal;

// The 256-bit round of phc-winner opt.c with the AVX-512 register file: ymm16 to ymm31 take the
// extra state, so each row-pass iteration runs two row units (four chains), every step written
// across all of them. The column pass keeps one unit (two chains) per iteration, so the prefetch
// after its first iteration still leads by three quarters of the pass; four chains there lost at
// p=4. Rotates are vprorq, and the column diagonal is vpalignr, which unlike vpblendd can reach
// the upper registers.
// The next block's reference is prefetched: at the top when FillSegment already knows it,
// and otherwise as soon as the first column iteration has made word 0 of this block final.
internal static unsafe class Avx512VlBody
{
    internal static bool IsSupported => Avx512F.VL.IsSupported;

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
        for (int k = 0; k < 2; k++)
        {
            nint row = 64 * k;
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
            Vector256<ulong> a10 = Avx.LoadVector256(pp + 32) ^ Avx.LoadVector256(pr + 32);
            Vector256<ulong> b10 = Avx.LoadVector256(pp + 36) ^ Avx.LoadVector256(pr + 36);
            Vector256<ulong> c10 = Avx.LoadVector256(pp + 40) ^ Avx.LoadVector256(pr + 40);
            Vector256<ulong> d10 = Avx.LoadVector256(pp + 44) ^ Avx.LoadVector256(pr + 44);
            Vector256<ulong> a11 = Avx.LoadVector256(pp + 48) ^ Avx.LoadVector256(pr + 48);
            Vector256<ulong> b11 = Avx.LoadVector256(pp + 52) ^ Avx.LoadVector256(pr + 52);
            Vector256<ulong> c11 = Avx.LoadVector256(pp + 56) ^ Avx.LoadVector256(pr + 56);
            Vector256<ulong> d11 = Avx.LoadVector256(pp + 60) ^ Avx.LoadVector256(pr + 60);
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
                Avx.Store(ps + 32, a10 ^ Avx.LoadVector256(pd + 32));
                Avx.Store(ps + 36, b10 ^ Avx.LoadVector256(pd + 36));
                Avx.Store(ps + 40, c10 ^ Avx.LoadVector256(pd + 40));
                Avx.Store(ps + 44, d10 ^ Avx.LoadVector256(pd + 44));
                Avx.Store(ps + 48, a11 ^ Avx.LoadVector256(pd + 48));
                Avx.Store(ps + 52, b11 ^ Avx.LoadVector256(pd + 52));
                Avx.Store(ps + 56, c11 ^ Avx.LoadVector256(pd + 56));
                Avx.Store(ps + 60, d11 ^ Avx.LoadVector256(pd + 60));
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
                Avx.Store(ps + 32, a10);
                Avx.Store(ps + 36, b10);
                Avx.Store(ps + 40, c10);
                Avx.Store(ps + 44, d10);
                Avx.Store(ps + 48, a11);
                Avx.Store(ps + 52, b11);
                Avx.Store(ps + 56, c11);
                Avx.Store(ps + 60, d11);
            }
            a00 = BlaMka(a00, b00);
            a01 = BlaMka(a01, b01);
            a10 = BlaMka(a10, b10);
            a11 = BlaMka(a11, b11);
            d00 ^= a00;
            d01 ^= a01;
            d10 ^= a10;
            d11 ^= a11;
            d00 = Avx512F.VL.RotateRight(d00, 32);
            d01 = Avx512F.VL.RotateRight(d01, 32);
            d10 = Avx512F.VL.RotateRight(d10, 32);
            d11 = Avx512F.VL.RotateRight(d11, 32);
            c00 = BlaMka(c00, d00);
            c01 = BlaMka(c01, d01);
            c10 = BlaMka(c10, d10);
            c11 = BlaMka(c11, d11);
            b00 ^= c00;
            b01 ^= c01;
            b10 ^= c10;
            b11 ^= c11;
            b00 = Avx512F.VL.RotateRight(b00, 24);
            b01 = Avx512F.VL.RotateRight(b01, 24);
            b10 = Avx512F.VL.RotateRight(b10, 24);
            b11 = Avx512F.VL.RotateRight(b11, 24);
            a00 = BlaMka(a00, b00);
            a01 = BlaMka(a01, b01);
            a10 = BlaMka(a10, b10);
            a11 = BlaMka(a11, b11);
            d00 ^= a00;
            d01 ^= a01;
            d10 ^= a10;
            d11 ^= a11;
            d00 = Avx512F.VL.RotateRight(d00, 16);
            d01 = Avx512F.VL.RotateRight(d01, 16);
            d10 = Avx512F.VL.RotateRight(d10, 16);
            d11 = Avx512F.VL.RotateRight(d11, 16);
            c00 = BlaMka(c00, d00);
            c01 = BlaMka(c01, d01);
            c10 = BlaMka(c10, d10);
            c11 = BlaMka(c11, d11);
            b00 ^= c00;
            b01 ^= c01;
            b10 ^= c10;
            b11 ^= c11;
            b00 = Avx512F.VL.RotateRight(b00, 63);
            b01 = Avx512F.VL.RotateRight(b01, 63);
            b10 = Avx512F.VL.RotateRight(b10, 63);
            b11 = Avx512F.VL.RotateRight(b11, 63);
            Vector256<ulong> b00d = Avx2.Permute4x64(b00, 0x39), c00d = Avx2.Permute4x64(c00, 0x4E), d00d = Avx2.Permute4x64(d00, 0x93);
            Vector256<ulong> b01d = Avx2.Permute4x64(b01, 0x39), c01d = Avx2.Permute4x64(c01, 0x4E), d01d = Avx2.Permute4x64(d01, 0x93);
            Vector256<ulong> b10d = Avx2.Permute4x64(b10, 0x39), c10d = Avx2.Permute4x64(c10, 0x4E), d10d = Avx2.Permute4x64(d10, 0x93);
            Vector256<ulong> b11d = Avx2.Permute4x64(b11, 0x39), c11d = Avx2.Permute4x64(c11, 0x4E), d11d = Avx2.Permute4x64(d11, 0x93);
            a00 = BlaMka(a00, b00d);
            a01 = BlaMka(a01, b01d);
            a10 = BlaMka(a10, b10d);
            a11 = BlaMka(a11, b11d);
            d00d ^= a00;
            d01d ^= a01;
            d10d ^= a10;
            d11d ^= a11;
            d00d = Avx512F.VL.RotateRight(d00d, 32);
            d01d = Avx512F.VL.RotateRight(d01d, 32);
            d10d = Avx512F.VL.RotateRight(d10d, 32);
            d11d = Avx512F.VL.RotateRight(d11d, 32);
            c00d = BlaMka(c00d, d00d);
            c01d = BlaMka(c01d, d01d);
            c10d = BlaMka(c10d, d10d);
            c11d = BlaMka(c11d, d11d);
            b00d ^= c00d;
            b01d ^= c01d;
            b10d ^= c10d;
            b11d ^= c11d;
            b00d = Avx512F.VL.RotateRight(b00d, 24);
            b01d = Avx512F.VL.RotateRight(b01d, 24);
            b10d = Avx512F.VL.RotateRight(b10d, 24);
            b11d = Avx512F.VL.RotateRight(b11d, 24);
            a00 = BlaMka(a00, b00d);
            a01 = BlaMka(a01, b01d);
            a10 = BlaMka(a10, b10d);
            a11 = BlaMka(a11, b11d);
            d00d ^= a00;
            d01d ^= a01;
            d10d ^= a10;
            d11d ^= a11;
            d00d = Avx512F.VL.RotateRight(d00d, 16);
            d01d = Avx512F.VL.RotateRight(d01d, 16);
            d10d = Avx512F.VL.RotateRight(d10d, 16);
            d11d = Avx512F.VL.RotateRight(d11d, 16);
            c00d = BlaMka(c00d, d00d);
            c01d = BlaMka(c01d, d01d);
            c10d = BlaMka(c10d, d10d);
            c11d = BlaMka(c11d, d11d);
            b00d ^= c00d;
            b01d ^= c01d;
            b10d ^= c10d;
            b11d ^= c11d;
            b00d = Avx512F.VL.RotateRight(b00d, 63);
            b01d = Avx512F.VL.RotateRight(b01d, 63);
            b10d = Avx512F.VL.RotateRight(b10d, 63);
            b11d = Avx512F.VL.RotateRight(b11d, 63);
            Avx.Store(pw, a00);
            Avx.Store(pw + 4, Avx2.Permute4x64(b00d, 0x93));
            Avx.Store(pw + 8, Avx2.Permute4x64(c00d, 0x4E));
            Avx.Store(pw + 12, Avx2.Permute4x64(d00d, 0x39));
            Avx.Store(pw + 16, a01);
            Avx.Store(pw + 20, Avx2.Permute4x64(b01d, 0x93));
            Avx.Store(pw + 24, Avx2.Permute4x64(c01d, 0x4E));
            Avx.Store(pw + 28, Avx2.Permute4x64(d01d, 0x39));
            Avx.Store(pw + 32, a10);
            Avx.Store(pw + 36, Avx2.Permute4x64(b10d, 0x93));
            Avx.Store(pw + 40, Avx2.Permute4x64(c10d, 0x4E));
            Avx.Store(pw + 44, Avx2.Permute4x64(d10d, 0x39));
            Avx.Store(pw + 48, a11);
            Avx.Store(pw + 52, Avx2.Permute4x64(b11d, 0x93));
            Avx.Store(pw + 56, Avx2.Permute4x64(c11d, 0x4E));
            Avx.Store(pw + 60, Avx2.Permute4x64(d11d, 0x39));
        }
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
            a01 = BlaMka(a01, b01);
            d00 ^= a00;
            d01 ^= a01;
            d00 = Avx512F.VL.RotateRight(d00, 32);
            d01 = Avx512F.VL.RotateRight(d01, 32);
            c00 = BlaMka(c00, d00);
            c01 = BlaMka(c01, d01);
            b00 ^= c00;
            b01 ^= c01;
            b00 = Avx512F.VL.RotateRight(b00, 24);
            b01 = Avx512F.VL.RotateRight(b01, 24);
            a00 = BlaMka(a00, b00);
            a01 = BlaMka(a01, b01);
            d00 ^= a00;
            d01 ^= a01;
            d00 = Avx512F.VL.RotateRight(d00, 16);
            d01 = Avx512F.VL.RotateRight(d01, 16);
            c00 = BlaMka(c00, d00);
            c01 = BlaMka(c01, d01);
            b00 ^= c00;
            b01 ^= c01;
            b00 = Avx512F.VL.RotateRight(b00, 63);
            b01 = Avx512F.VL.RotateRight(b01, 63);
            Vector256<ulong> b00d = Pair(b00, b01), b01d = Pair(b01, b00);
            Vector256<ulong> d00d = Pair(d01, d00), d01d = Pair(d00, d01);
            a00 = BlaMka(a00, b00d);
            a01 = BlaMka(a01, b01d);
            d00d ^= a00;
            d01d ^= a01;
            d00d = Avx512F.VL.RotateRight(d00d, 32);
            d01d = Avx512F.VL.RotateRight(d01d, 32);
            c01 = BlaMka(c01, d00d);
            c00 = BlaMka(c00, d01d);
            b00d ^= c01;
            b01d ^= c00;
            b00d = Avx512F.VL.RotateRight(b00d, 24);
            b01d = Avx512F.VL.RotateRight(b01d, 24);
            a00 = BlaMka(a00, b00d);
            a01 = BlaMka(a01, b01d);
            d00d ^= a00;
            d01d ^= a01;
            d00d = Avx512F.VL.RotateRight(d00d, 16);
            d01d = Avx512F.VL.RotateRight(d01d, 16);
            c01 = BlaMka(c01, d00d);
            c00 = BlaMka(c00, d01d);
            b00d ^= c01;
            b01d ^= c00;
            b00d = Avx512F.VL.RotateRight(b00d, 63);
            b01d = Avx512F.VL.RotateRight(b01d, 63);
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
                // Word 0 of this block is final, so the next block's reference is known.
                byte* following = (byte*)Argon2Core.NextReference(scratch, destination[0]);
                Sse.Prefetch0(following);
                Sse.Prefetch0(following + 64);
                Sse.Prefetch0(following + 128);
                Sse.Prefetch0(following + 192);
                Sse.Prefetch0(following + 256);
                Sse.Prefetch0(following + 320);
                Sse.Prefetch0(following + 384);
                Sse.Prefetch0(following + 448);
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

    // Lanes 0 and 2 from y, lanes 1 and 3 from x.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector256<ulong> Blend(Vector256<ulong> x, Vector256<ulong> y) =>
        Avx2.Blend(x.AsUInt32(), y.AsUInt32(), 0x33).AsUInt64();

    // Swaps the two words of each 128-bit half.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector256<ulong> Swap(Vector256<ulong> x) => Avx2.Shuffle(x.AsUInt32(), 0x4E).AsUInt64();
}
#endif
