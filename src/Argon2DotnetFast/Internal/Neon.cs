#if NET
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;

namespace Argon2DotnetFast.Internal;

// The 128-bit round of phc-winner opt.c on AdvSimd: two words per register, the block streamed
// through the scratch area one row or one column of pairs at a time.
internal static unsafe class Neon
{
    internal static bool IsSupported => AdvSimd.Arm64.IsSupported;

    // Forwards to the SVE2 body (.NET 10 only) before any NEON register is built, so this body's code
    // does not change.
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    internal static void Fill(ulong* previous, ulong* reference, ulong* destination, ulong* scratch)
    {
#if NET10_0_OR_GREATER
        if (Sve2Body.IsSupported) { Sve2Body.Fill(previous, reference, destination, scratch); return; }
#endif
        Compress(previous, reference, destination, scratch, false);
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    internal static void FillXor(ulong* previous, ulong* reference, ulong* destination, ulong* scratch)
    {
#if NET10_0_OR_GREATER
        if (Sve2Body.IsSupported) { Sve2Body.FillXor(previous, reference, destination, scratch); return; }
#endif
        Compress(previous, reference, destination, scratch, true);
    }

    // The row pass reads previous ^ reference straight into registers and keeps a copy in saved;
    // the column pass writes destination = state ^ saved. Every row is read before any column is
    // written, so reference and destination may be the same block.
    // Each iteration takes its own base pointers, so every load and store is a base plus a constant.
    // BlaMka and rotate 63 are written one step at a time across all four chains: the in-order A53
    // would otherwise issue each instruction right behind the one it waits for.
    // The column pass is unrolled. Once its first iteration has made word 0 final, the next block's
    // reference is known, and the other three iterations each load one word from five or six of its
    // lines and fold them only at their end, so the misses overlap this block's work.
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
    private static void Compress(ulong* previous, ulong* reference, ulong* destination, ulong* scratch, bool xor)
    {
        ulong* r = scratch, saved = scratch + 128;
        // Byte permutations for rotates by 24 and 16, per 64-bit lane.
        Vector128<byte> r24 = Vector128.Create((byte)3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10);
        Vector128<byte> r16 = Vector128.Create((byte)2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9);
        ulong touched = 0;
        ulong* following = previous;
        for (int k = 0; k < 4; k++)
        {
            nint row = 32 * k;
            ulong* pp = previous + row, pr = reference + row, pd = destination + row;
            ulong* ps = saved + row, pw = r + row;
            Vector128<ulong> a0 = AdvSimd.LoadVector128(pp) ^ AdvSimd.LoadVector128(pr);
            Vector128<ulong> a1 = AdvSimd.LoadVector128(pp + 2) ^ AdvSimd.LoadVector128(pr + 2);
            Vector128<ulong> b0 = AdvSimd.LoadVector128(pp + 4) ^ AdvSimd.LoadVector128(pr + 4);
            Vector128<ulong> b1 = AdvSimd.LoadVector128(pp + 6) ^ AdvSimd.LoadVector128(pr + 6);
            Vector128<ulong> c0 = AdvSimd.LoadVector128(pp + 8) ^ AdvSimd.LoadVector128(pr + 8);
            Vector128<ulong> c1 = AdvSimd.LoadVector128(pp + 10) ^ AdvSimd.LoadVector128(pr + 10);
            Vector128<ulong> d0 = AdvSimd.LoadVector128(pp + 12) ^ AdvSimd.LoadVector128(pr + 12);
            Vector128<ulong> d1 = AdvSimd.LoadVector128(pp + 14) ^ AdvSimd.LoadVector128(pr + 14);
            Vector128<ulong> e0 = AdvSimd.LoadVector128(pp + 16) ^ AdvSimd.LoadVector128(pr + 16);
            Vector128<ulong> e1 = AdvSimd.LoadVector128(pp + 18) ^ AdvSimd.LoadVector128(pr + 18);
            Vector128<ulong> f0 = AdvSimd.LoadVector128(pp + 20) ^ AdvSimd.LoadVector128(pr + 20);
            Vector128<ulong> f1 = AdvSimd.LoadVector128(pp + 22) ^ AdvSimd.LoadVector128(pr + 22);
            Vector128<ulong> g0 = AdvSimd.LoadVector128(pp + 24) ^ AdvSimd.LoadVector128(pr + 24);
            Vector128<ulong> g1 = AdvSimd.LoadVector128(pp + 26) ^ AdvSimd.LoadVector128(pr + 26);
            Vector128<ulong> h0 = AdvSimd.LoadVector128(pp + 28) ^ AdvSimd.LoadVector128(pr + 28);
            Vector128<ulong> h1 = AdvSimd.LoadVector128(pp + 30) ^ AdvSimd.LoadVector128(pr + 30);
            if (xor)
            {
                AdvSimd.Store(ps, a0 ^ AdvSimd.LoadVector128(pd));
                AdvSimd.Store(ps + 2, a1 ^ AdvSimd.LoadVector128(pd + 2));
                AdvSimd.Store(ps + 4, b0 ^ AdvSimd.LoadVector128(pd + 4));
                AdvSimd.Store(ps + 6, b1 ^ AdvSimd.LoadVector128(pd + 6));
                AdvSimd.Store(ps + 8, c0 ^ AdvSimd.LoadVector128(pd + 8));
                AdvSimd.Store(ps + 10, c1 ^ AdvSimd.LoadVector128(pd + 10));
                AdvSimd.Store(ps + 12, d0 ^ AdvSimd.LoadVector128(pd + 12));
                AdvSimd.Store(ps + 14, d1 ^ AdvSimd.LoadVector128(pd + 14));
                AdvSimd.Store(ps + 16, e0 ^ AdvSimd.LoadVector128(pd + 16));
                AdvSimd.Store(ps + 18, e1 ^ AdvSimd.LoadVector128(pd + 18));
                AdvSimd.Store(ps + 20, f0 ^ AdvSimd.LoadVector128(pd + 20));
                AdvSimd.Store(ps + 22, f1 ^ AdvSimd.LoadVector128(pd + 22));
                AdvSimd.Store(ps + 24, g0 ^ AdvSimd.LoadVector128(pd + 24));
                AdvSimd.Store(ps + 26, g1 ^ AdvSimd.LoadVector128(pd + 26));
                AdvSimd.Store(ps + 28, h0 ^ AdvSimd.LoadVector128(pd + 28));
                AdvSimd.Store(ps + 30, h1 ^ AdvSimd.LoadVector128(pd + 30));
            }
            else
            {
                AdvSimd.Store(ps, a0);
                AdvSimd.Store(ps + 2, a1);
                AdvSimd.Store(ps + 4, b0);
                AdvSimd.Store(ps + 6, b1);
                AdvSimd.Store(ps + 8, c0);
                AdvSimd.Store(ps + 10, c1);
                AdvSimd.Store(ps + 12, d0);
                AdvSimd.Store(ps + 14, d1);
                AdvSimd.Store(ps + 16, e0);
                AdvSimd.Store(ps + 18, e1);
                AdvSimd.Store(ps + 20, f0);
                AdvSimd.Store(ps + 22, f1);
                AdvSimd.Store(ps + 24, g0);
                AdvSimd.Store(ps + 26, g1);
                AdvSimd.Store(ps + 28, h0);
                AdvSimd.Store(ps + 30, h1);
            }

            {
                Vector64<uint> lx00 = AdvSimd.ExtractNarrowingLower(a0), ly00 = AdvSimd.ExtractNarrowingLower(b0);
                Vector64<uint> lx01 = AdvSimd.ExtractNarrowingLower(a1), ly01 = AdvSimd.ExtractNarrowingLower(b1);
                Vector64<uint> lx10 = AdvSimd.ExtractNarrowingLower(e0), ly10 = AdvSimd.ExtractNarrowingLower(f0);
                Vector64<uint> lx11 = AdvSimd.ExtractNarrowingLower(e1), ly11 = AdvSimd.ExtractNarrowingLower(f1);
                Vector128<ulong> s00 = AdvSimd.Add(a0, b0);
                Vector128<ulong> s01 = AdvSimd.Add(a1, b1);
                Vector128<ulong> s10 = AdvSimd.Add(e0, f0);
                Vector128<ulong> s11 = AdvSimd.Add(e1, f1);
                s00 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                s01 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                s10 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                s11 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
                a0 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                a1 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                e0 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                e1 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
            }
            d0 ^= a0; d1 ^= a1;
            h0 ^= e0; h1 ^= e1;
            d0 = Rotate32(d0); d1 = Rotate32(d1);
            h0 = Rotate32(h0); h1 = Rotate32(h1);
            {
                Vector64<uint> lx00 = AdvSimd.ExtractNarrowingLower(c0), ly00 = AdvSimd.ExtractNarrowingLower(d0);
                Vector64<uint> lx01 = AdvSimd.ExtractNarrowingLower(c1), ly01 = AdvSimd.ExtractNarrowingLower(d1);
                Vector64<uint> lx10 = AdvSimd.ExtractNarrowingLower(g0), ly10 = AdvSimd.ExtractNarrowingLower(h0);
                Vector64<uint> lx11 = AdvSimd.ExtractNarrowingLower(g1), ly11 = AdvSimd.ExtractNarrowingLower(h1);
                Vector128<ulong> s00 = AdvSimd.Add(c0, d0);
                Vector128<ulong> s01 = AdvSimd.Add(c1, d1);
                Vector128<ulong> s10 = AdvSimd.Add(g0, h0);
                Vector128<ulong> s11 = AdvSimd.Add(g1, h1);
                s00 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                s01 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                s10 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                s11 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
                c0 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                c1 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                g0 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                g1 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
            }
            b0 ^= c0; b1 ^= c1;
            f0 ^= g0; f1 ^= g1;
            b0 = Rotate24(b0, r24); b1 = Rotate24(b1, r24);
            f0 = Rotate24(f0, r24); f1 = Rotate24(f1, r24);
            {
                Vector64<uint> lx00 = AdvSimd.ExtractNarrowingLower(a0), ly00 = AdvSimd.ExtractNarrowingLower(b0);
                Vector64<uint> lx01 = AdvSimd.ExtractNarrowingLower(a1), ly01 = AdvSimd.ExtractNarrowingLower(b1);
                Vector64<uint> lx10 = AdvSimd.ExtractNarrowingLower(e0), ly10 = AdvSimd.ExtractNarrowingLower(f0);
                Vector64<uint> lx11 = AdvSimd.ExtractNarrowingLower(e1), ly11 = AdvSimd.ExtractNarrowingLower(f1);
                Vector128<ulong> s00 = AdvSimd.Add(a0, b0);
                Vector128<ulong> s01 = AdvSimd.Add(a1, b1);
                Vector128<ulong> s10 = AdvSimd.Add(e0, f0);
                Vector128<ulong> s11 = AdvSimd.Add(e1, f1);
                s00 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                s01 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                s10 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                s11 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
                a0 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                a1 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                e0 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                e1 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
            }
            d0 ^= a0; d1 ^= a1;
            h0 ^= e0; h1 ^= e1;
            d0 = Rotate16(d0, r16); d1 = Rotate16(d1, r16);
            h0 = Rotate16(h0, r16); h1 = Rotate16(h1, r16);
            {
                Vector64<uint> lx00 = AdvSimd.ExtractNarrowingLower(c0), ly00 = AdvSimd.ExtractNarrowingLower(d0);
                Vector64<uint> lx01 = AdvSimd.ExtractNarrowingLower(c1), ly01 = AdvSimd.ExtractNarrowingLower(d1);
                Vector64<uint> lx10 = AdvSimd.ExtractNarrowingLower(g0), ly10 = AdvSimd.ExtractNarrowingLower(h0);
                Vector64<uint> lx11 = AdvSimd.ExtractNarrowingLower(g1), ly11 = AdvSimd.ExtractNarrowingLower(h1);
                Vector128<ulong> s00 = AdvSimd.Add(c0, d0);
                Vector128<ulong> s01 = AdvSimd.Add(c1, d1);
                Vector128<ulong> s10 = AdvSimd.Add(g0, h0);
                Vector128<ulong> s11 = AdvSimd.Add(g1, h1);
                s00 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                s01 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                s10 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                s11 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
                c0 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                c1 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                g0 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                g1 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
            }
            b0 ^= c0; b1 ^= c1;
            f0 ^= g0; f1 ^= g1;
            {
                Vector128<ulong> hi00 = AdvSimd.ShiftRightLogical(b0, 63);
                Vector128<ulong> hi01 = AdvSimd.ShiftRightLogical(b1, 63);
                Vector128<ulong> hi10 = AdvSimd.ShiftRightLogical(f0, 63);
                Vector128<ulong> hi11 = AdvSimd.ShiftRightLogical(f1, 63);
                Vector128<ulong> tw00 = AdvSimd.Add(b0, b0);
                Vector128<ulong> tw01 = AdvSimd.Add(b1, b1);
                Vector128<ulong> tw10 = AdvSimd.Add(f0, f0);
                Vector128<ulong> tw11 = AdvSimd.Add(f1, f1);
                b0 = AdvSimd.Or(hi00, tw00);
                b1 = AdvSimd.Or(hi01, tw01);
                f0 = AdvSimd.Or(hi10, tw10);
                f1 = AdvSimd.Or(hi11, tw11);
            }

            Vector128<ulong> p00 = AdvSimd.ExtractVector128(b0, b1, 1);
            Vector128<ulong> p10 = AdvSimd.ExtractVector128(f0, f1, 1);
            Vector128<ulong> p01 = AdvSimd.ExtractVector128(b1, b0, 1);
            Vector128<ulong> p11 = AdvSimd.ExtractVector128(f1, f0, 1);
            Vector128<ulong> q00 = AdvSimd.ExtractVector128(d1, d0, 1);
            Vector128<ulong> q10 = AdvSimd.ExtractVector128(h1, h0, 1);
            Vector128<ulong> q01 = AdvSimd.ExtractVector128(d0, d1, 1);
            Vector128<ulong> q11 = AdvSimd.ExtractVector128(h0, h1, 1);

            {
                Vector64<uint> lx00 = AdvSimd.ExtractNarrowingLower(a0), ly00 = AdvSimd.ExtractNarrowingLower(p00);
                Vector64<uint> lx01 = AdvSimd.ExtractNarrowingLower(a1), ly01 = AdvSimd.ExtractNarrowingLower(p01);
                Vector64<uint> lx10 = AdvSimd.ExtractNarrowingLower(e0), ly10 = AdvSimd.ExtractNarrowingLower(p10);
                Vector64<uint> lx11 = AdvSimd.ExtractNarrowingLower(e1), ly11 = AdvSimd.ExtractNarrowingLower(p11);
                Vector128<ulong> s00 = AdvSimd.Add(a0, p00);
                Vector128<ulong> s01 = AdvSimd.Add(a1, p01);
                Vector128<ulong> s10 = AdvSimd.Add(e0, p10);
                Vector128<ulong> s11 = AdvSimd.Add(e1, p11);
                s00 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                s01 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                s10 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                s11 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
                a0 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                a1 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                e0 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                e1 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
            }
            q00 ^= a0; q01 ^= a1;
            q10 ^= e0; q11 ^= e1;
            q00 = Rotate32(q00); q01 = Rotate32(q01);
            q10 = Rotate32(q10); q11 = Rotate32(q11);
            {
                Vector64<uint> lx00 = AdvSimd.ExtractNarrowingLower(c1), ly00 = AdvSimd.ExtractNarrowingLower(q00);
                Vector64<uint> lx01 = AdvSimd.ExtractNarrowingLower(c0), ly01 = AdvSimd.ExtractNarrowingLower(q01);
                Vector64<uint> lx10 = AdvSimd.ExtractNarrowingLower(g1), ly10 = AdvSimd.ExtractNarrowingLower(q10);
                Vector64<uint> lx11 = AdvSimd.ExtractNarrowingLower(g0), ly11 = AdvSimd.ExtractNarrowingLower(q11);
                Vector128<ulong> s00 = AdvSimd.Add(c1, q00);
                Vector128<ulong> s01 = AdvSimd.Add(c0, q01);
                Vector128<ulong> s10 = AdvSimd.Add(g1, q10);
                Vector128<ulong> s11 = AdvSimd.Add(g0, q11);
                s00 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                s01 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                s10 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                s11 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
                c1 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                c0 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                g1 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                g0 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
            }
            p00 ^= c1; p01 ^= c0;
            p10 ^= g1; p11 ^= g0;
            p00 = Rotate24(p00, r24); p01 = Rotate24(p01, r24);
            p10 = Rotate24(p10, r24); p11 = Rotate24(p11, r24);
            {
                Vector64<uint> lx00 = AdvSimd.ExtractNarrowingLower(a0), ly00 = AdvSimd.ExtractNarrowingLower(p00);
                Vector64<uint> lx01 = AdvSimd.ExtractNarrowingLower(a1), ly01 = AdvSimd.ExtractNarrowingLower(p01);
                Vector64<uint> lx10 = AdvSimd.ExtractNarrowingLower(e0), ly10 = AdvSimd.ExtractNarrowingLower(p10);
                Vector64<uint> lx11 = AdvSimd.ExtractNarrowingLower(e1), ly11 = AdvSimd.ExtractNarrowingLower(p11);
                Vector128<ulong> s00 = AdvSimd.Add(a0, p00);
                Vector128<ulong> s01 = AdvSimd.Add(a1, p01);
                Vector128<ulong> s10 = AdvSimd.Add(e0, p10);
                Vector128<ulong> s11 = AdvSimd.Add(e1, p11);
                s00 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                s01 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                s10 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                s11 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
                a0 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                a1 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                e0 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                e1 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
            }
            q00 ^= a0; q01 ^= a1;
            q10 ^= e0; q11 ^= e1;
            q00 = Rotate16(q00, r16); q01 = Rotate16(q01, r16);
            q10 = Rotate16(q10, r16); q11 = Rotate16(q11, r16);
            {
                Vector64<uint> lx00 = AdvSimd.ExtractNarrowingLower(c1), ly00 = AdvSimd.ExtractNarrowingLower(q00);
                Vector64<uint> lx01 = AdvSimd.ExtractNarrowingLower(c0), ly01 = AdvSimd.ExtractNarrowingLower(q01);
                Vector64<uint> lx10 = AdvSimd.ExtractNarrowingLower(g1), ly10 = AdvSimd.ExtractNarrowingLower(q10);
                Vector64<uint> lx11 = AdvSimd.ExtractNarrowingLower(g0), ly11 = AdvSimd.ExtractNarrowingLower(q11);
                Vector128<ulong> s00 = AdvSimd.Add(c1, q00);
                Vector128<ulong> s01 = AdvSimd.Add(c0, q01);
                Vector128<ulong> s10 = AdvSimd.Add(g1, q10);
                Vector128<ulong> s11 = AdvSimd.Add(g0, q11);
                s00 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                s01 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                s10 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                s11 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
                c1 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                c0 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                g1 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                g0 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
            }
            p00 ^= c1; p01 ^= c0;
            p10 ^= g1; p11 ^= g0;
            {
                Vector128<ulong> hi00 = AdvSimd.ShiftRightLogical(p00, 63);
                Vector128<ulong> hi01 = AdvSimd.ShiftRightLogical(p01, 63);
                Vector128<ulong> hi10 = AdvSimd.ShiftRightLogical(p10, 63);
                Vector128<ulong> hi11 = AdvSimd.ShiftRightLogical(p11, 63);
                Vector128<ulong> tw00 = AdvSimd.Add(p00, p00);
                Vector128<ulong> tw01 = AdvSimd.Add(p01, p01);
                Vector128<ulong> tw10 = AdvSimd.Add(p10, p10);
                Vector128<ulong> tw11 = AdvSimd.Add(p11, p11);
                p00 = AdvSimd.Or(hi00, tw00);
                p01 = AdvSimd.Or(hi01, tw01);
                p10 = AdvSimd.Or(hi10, tw10);
                p11 = AdvSimd.Or(hi11, tw11);
            }

            AdvSimd.Store(pw, a0);
            AdvSimd.Store(pw + 2, a1);
            AdvSimd.Store(pw + 4, AdvSimd.ExtractVector128(p01, p00, 1));
            AdvSimd.Store(pw + 6, AdvSimd.ExtractVector128(p00, p01, 1));
            AdvSimd.Store(pw + 8, c0);
            AdvSimd.Store(pw + 10, c1);
            AdvSimd.Store(pw + 12, AdvSimd.ExtractVector128(q00, q01, 1));
            AdvSimd.Store(pw + 14, AdvSimd.ExtractVector128(q01, q00, 1));
            AdvSimd.Store(pw + 16, e0);
            AdvSimd.Store(pw + 18, e1);
            AdvSimd.Store(pw + 20, AdvSimd.ExtractVector128(p11, p10, 1));
            AdvSimd.Store(pw + 22, AdvSimd.ExtractVector128(p10, p11, 1));
            AdvSimd.Store(pw + 24, g0);
            AdvSimd.Store(pw + 26, g1);
            AdvSimd.Store(pw + 28, AdvSimd.ExtractVector128(q10, q11, 1));
            AdvSimd.Store(pw + 30, AdvSimd.ExtractVector128(q11, q10, 1));
        }
        {
            nint column = 0;
            ulong* p = r + column, pd = destination + column, ps = saved + column;
            Vector128<ulong> a0 = AdvSimd.LoadVector128(p);
            Vector128<ulong> a1 = AdvSimd.LoadVector128(p + 16);
            Vector128<ulong> b0 = AdvSimd.LoadVector128(p + 32);
            Vector128<ulong> b1 = AdvSimd.LoadVector128(p + 48);
            Vector128<ulong> c0 = AdvSimd.LoadVector128(p + 64);
            Vector128<ulong> c1 = AdvSimd.LoadVector128(p + 80);
            Vector128<ulong> d0 = AdvSimd.LoadVector128(p + 96);
            Vector128<ulong> d1 = AdvSimd.LoadVector128(p + 112);
            Vector128<ulong> e0 = AdvSimd.LoadVector128(p + 2);
            Vector128<ulong> e1 = AdvSimd.LoadVector128(p + 18);
            Vector128<ulong> f0 = AdvSimd.LoadVector128(p + 34);
            Vector128<ulong> f1 = AdvSimd.LoadVector128(p + 50);
            Vector128<ulong> g0 = AdvSimd.LoadVector128(p + 66);
            Vector128<ulong> g1 = AdvSimd.LoadVector128(p + 82);
            Vector128<ulong> h0 = AdvSimd.LoadVector128(p + 98);
            Vector128<ulong> h1 = AdvSimd.LoadVector128(p + 114);

            {
                Vector64<uint> lx00 = AdvSimd.ExtractNarrowingLower(a0), ly00 = AdvSimd.ExtractNarrowingLower(b0);
                Vector64<uint> lx01 = AdvSimd.ExtractNarrowingLower(a1), ly01 = AdvSimd.ExtractNarrowingLower(b1);
                Vector64<uint> lx10 = AdvSimd.ExtractNarrowingLower(e0), ly10 = AdvSimd.ExtractNarrowingLower(f0);
                Vector64<uint> lx11 = AdvSimd.ExtractNarrowingLower(e1), ly11 = AdvSimd.ExtractNarrowingLower(f1);
                Vector128<ulong> s00 = AdvSimd.Add(a0, b0);
                Vector128<ulong> s01 = AdvSimd.Add(a1, b1);
                Vector128<ulong> s10 = AdvSimd.Add(e0, f0);
                Vector128<ulong> s11 = AdvSimd.Add(e1, f1);
                s00 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                s01 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                s10 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                s11 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
                a0 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                a1 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                e0 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                e1 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
            }
            d0 ^= a0; d1 ^= a1;
            h0 ^= e0; h1 ^= e1;
            d0 = Rotate32(d0); d1 = Rotate32(d1);
            h0 = Rotate32(h0); h1 = Rotate32(h1);
            {
                Vector64<uint> lx00 = AdvSimd.ExtractNarrowingLower(c0), ly00 = AdvSimd.ExtractNarrowingLower(d0);
                Vector64<uint> lx01 = AdvSimd.ExtractNarrowingLower(c1), ly01 = AdvSimd.ExtractNarrowingLower(d1);
                Vector64<uint> lx10 = AdvSimd.ExtractNarrowingLower(g0), ly10 = AdvSimd.ExtractNarrowingLower(h0);
                Vector64<uint> lx11 = AdvSimd.ExtractNarrowingLower(g1), ly11 = AdvSimd.ExtractNarrowingLower(h1);
                Vector128<ulong> s00 = AdvSimd.Add(c0, d0);
                Vector128<ulong> s01 = AdvSimd.Add(c1, d1);
                Vector128<ulong> s10 = AdvSimd.Add(g0, h0);
                Vector128<ulong> s11 = AdvSimd.Add(g1, h1);
                s00 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                s01 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                s10 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                s11 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
                c0 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                c1 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                g0 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                g1 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
            }
            b0 ^= c0; b1 ^= c1;
            f0 ^= g0; f1 ^= g1;
            b0 = Rotate24(b0, r24); b1 = Rotate24(b1, r24);
            f0 = Rotate24(f0, r24); f1 = Rotate24(f1, r24);
            {
                Vector64<uint> lx00 = AdvSimd.ExtractNarrowingLower(a0), ly00 = AdvSimd.ExtractNarrowingLower(b0);
                Vector64<uint> lx01 = AdvSimd.ExtractNarrowingLower(a1), ly01 = AdvSimd.ExtractNarrowingLower(b1);
                Vector64<uint> lx10 = AdvSimd.ExtractNarrowingLower(e0), ly10 = AdvSimd.ExtractNarrowingLower(f0);
                Vector64<uint> lx11 = AdvSimd.ExtractNarrowingLower(e1), ly11 = AdvSimd.ExtractNarrowingLower(f1);
                Vector128<ulong> s00 = AdvSimd.Add(a0, b0);
                Vector128<ulong> s01 = AdvSimd.Add(a1, b1);
                Vector128<ulong> s10 = AdvSimd.Add(e0, f0);
                Vector128<ulong> s11 = AdvSimd.Add(e1, f1);
                s00 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                s01 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                s10 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                s11 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
                a0 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                a1 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                e0 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                e1 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
            }
            d0 ^= a0; d1 ^= a1;
            h0 ^= e0; h1 ^= e1;
            d0 = Rotate16(d0, r16); d1 = Rotate16(d1, r16);
            h0 = Rotate16(h0, r16); h1 = Rotate16(h1, r16);
            {
                Vector64<uint> lx00 = AdvSimd.ExtractNarrowingLower(c0), ly00 = AdvSimd.ExtractNarrowingLower(d0);
                Vector64<uint> lx01 = AdvSimd.ExtractNarrowingLower(c1), ly01 = AdvSimd.ExtractNarrowingLower(d1);
                Vector64<uint> lx10 = AdvSimd.ExtractNarrowingLower(g0), ly10 = AdvSimd.ExtractNarrowingLower(h0);
                Vector64<uint> lx11 = AdvSimd.ExtractNarrowingLower(g1), ly11 = AdvSimd.ExtractNarrowingLower(h1);
                Vector128<ulong> s00 = AdvSimd.Add(c0, d0);
                Vector128<ulong> s01 = AdvSimd.Add(c1, d1);
                Vector128<ulong> s10 = AdvSimd.Add(g0, h0);
                Vector128<ulong> s11 = AdvSimd.Add(g1, h1);
                s00 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                s01 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                s10 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                s11 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
                c0 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                c1 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                g0 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                g1 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
            }
            b0 ^= c0; b1 ^= c1;
            f0 ^= g0; f1 ^= g1;
            {
                Vector128<ulong> hi00 = AdvSimd.ShiftRightLogical(b0, 63);
                Vector128<ulong> hi01 = AdvSimd.ShiftRightLogical(b1, 63);
                Vector128<ulong> hi10 = AdvSimd.ShiftRightLogical(f0, 63);
                Vector128<ulong> hi11 = AdvSimd.ShiftRightLogical(f1, 63);
                Vector128<ulong> tw00 = AdvSimd.Add(b0, b0);
                Vector128<ulong> tw01 = AdvSimd.Add(b1, b1);
                Vector128<ulong> tw10 = AdvSimd.Add(f0, f0);
                Vector128<ulong> tw11 = AdvSimd.Add(f1, f1);
                b0 = AdvSimd.Or(hi00, tw00);
                b1 = AdvSimd.Or(hi01, tw01);
                f0 = AdvSimd.Or(hi10, tw10);
                f1 = AdvSimd.Or(hi11, tw11);
            }

            Vector128<ulong> p00 = AdvSimd.ExtractVector128(b0, b1, 1);
            Vector128<ulong> p10 = AdvSimd.ExtractVector128(f0, f1, 1);
            Vector128<ulong> p01 = AdvSimd.ExtractVector128(b1, b0, 1);
            Vector128<ulong> p11 = AdvSimd.ExtractVector128(f1, f0, 1);
            Vector128<ulong> q00 = AdvSimd.ExtractVector128(d1, d0, 1);
            Vector128<ulong> q10 = AdvSimd.ExtractVector128(h1, h0, 1);
            Vector128<ulong> q01 = AdvSimd.ExtractVector128(d0, d1, 1);
            Vector128<ulong> q11 = AdvSimd.ExtractVector128(h0, h1, 1);

            {
                Vector64<uint> lx00 = AdvSimd.ExtractNarrowingLower(a0), ly00 = AdvSimd.ExtractNarrowingLower(p00);
                Vector64<uint> lx01 = AdvSimd.ExtractNarrowingLower(a1), ly01 = AdvSimd.ExtractNarrowingLower(p01);
                Vector64<uint> lx10 = AdvSimd.ExtractNarrowingLower(e0), ly10 = AdvSimd.ExtractNarrowingLower(p10);
                Vector64<uint> lx11 = AdvSimd.ExtractNarrowingLower(e1), ly11 = AdvSimd.ExtractNarrowingLower(p11);
                Vector128<ulong> s00 = AdvSimd.Add(a0, p00);
                Vector128<ulong> s01 = AdvSimd.Add(a1, p01);
                Vector128<ulong> s10 = AdvSimd.Add(e0, p10);
                Vector128<ulong> s11 = AdvSimd.Add(e1, p11);
                s00 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                s01 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                s10 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                s11 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
                a0 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                a1 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                e0 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                e1 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
            }
            q00 ^= a0; q01 ^= a1;
            q10 ^= e0; q11 ^= e1;
            q00 = Rotate32(q00); q01 = Rotate32(q01);
            q10 = Rotate32(q10); q11 = Rotate32(q11);
            {
                Vector64<uint> lx00 = AdvSimd.ExtractNarrowingLower(c1), ly00 = AdvSimd.ExtractNarrowingLower(q00);
                Vector64<uint> lx01 = AdvSimd.ExtractNarrowingLower(c0), ly01 = AdvSimd.ExtractNarrowingLower(q01);
                Vector64<uint> lx10 = AdvSimd.ExtractNarrowingLower(g1), ly10 = AdvSimd.ExtractNarrowingLower(q10);
                Vector64<uint> lx11 = AdvSimd.ExtractNarrowingLower(g0), ly11 = AdvSimd.ExtractNarrowingLower(q11);
                Vector128<ulong> s00 = AdvSimd.Add(c1, q00);
                Vector128<ulong> s01 = AdvSimd.Add(c0, q01);
                Vector128<ulong> s10 = AdvSimd.Add(g1, q10);
                Vector128<ulong> s11 = AdvSimd.Add(g0, q11);
                s00 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                s01 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                s10 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                s11 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
                c1 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                c0 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                g1 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                g0 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
            }
            p00 ^= c1; p01 ^= c0;
            p10 ^= g1; p11 ^= g0;
            p00 = Rotate24(p00, r24); p01 = Rotate24(p01, r24);
            p10 = Rotate24(p10, r24); p11 = Rotate24(p11, r24);
            {
                Vector64<uint> lx00 = AdvSimd.ExtractNarrowingLower(a0), ly00 = AdvSimd.ExtractNarrowingLower(p00);
                Vector64<uint> lx01 = AdvSimd.ExtractNarrowingLower(a1), ly01 = AdvSimd.ExtractNarrowingLower(p01);
                Vector64<uint> lx10 = AdvSimd.ExtractNarrowingLower(e0), ly10 = AdvSimd.ExtractNarrowingLower(p10);
                Vector64<uint> lx11 = AdvSimd.ExtractNarrowingLower(e1), ly11 = AdvSimd.ExtractNarrowingLower(p11);
                Vector128<ulong> s00 = AdvSimd.Add(a0, p00);
                Vector128<ulong> s01 = AdvSimd.Add(a1, p01);
                Vector128<ulong> s10 = AdvSimd.Add(e0, p10);
                Vector128<ulong> s11 = AdvSimd.Add(e1, p11);
                s00 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                s01 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                s10 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                s11 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
                a0 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                a1 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                e0 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                e1 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
            }
            q00 ^= a0; q01 ^= a1;
            q10 ^= e0; q11 ^= e1;
            q00 = Rotate16(q00, r16); q01 = Rotate16(q01, r16);
            q10 = Rotate16(q10, r16); q11 = Rotate16(q11, r16);
            {
                Vector64<uint> lx00 = AdvSimd.ExtractNarrowingLower(c1), ly00 = AdvSimd.ExtractNarrowingLower(q00);
                Vector64<uint> lx01 = AdvSimd.ExtractNarrowingLower(c0), ly01 = AdvSimd.ExtractNarrowingLower(q01);
                Vector64<uint> lx10 = AdvSimd.ExtractNarrowingLower(g1), ly10 = AdvSimd.ExtractNarrowingLower(q10);
                Vector64<uint> lx11 = AdvSimd.ExtractNarrowingLower(g0), ly11 = AdvSimd.ExtractNarrowingLower(q11);
                Vector128<ulong> s00 = AdvSimd.Add(c1, q00);
                Vector128<ulong> s01 = AdvSimd.Add(c0, q01);
                Vector128<ulong> s10 = AdvSimd.Add(g1, q10);
                Vector128<ulong> s11 = AdvSimd.Add(g0, q11);
                s00 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                s01 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                s10 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                s11 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
                c1 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                c0 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                g1 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                g0 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
            }
            p00 ^= c1; p01 ^= c0;
            p10 ^= g1; p11 ^= g0;
            {
                Vector128<ulong> hi00 = AdvSimd.ShiftRightLogical(p00, 63);
                Vector128<ulong> hi01 = AdvSimd.ShiftRightLogical(p01, 63);
                Vector128<ulong> hi10 = AdvSimd.ShiftRightLogical(p10, 63);
                Vector128<ulong> hi11 = AdvSimd.ShiftRightLogical(p11, 63);
                Vector128<ulong> tw00 = AdvSimd.Add(p00, p00);
                Vector128<ulong> tw01 = AdvSimd.Add(p01, p01);
                Vector128<ulong> tw10 = AdvSimd.Add(p10, p10);
                Vector128<ulong> tw11 = AdvSimd.Add(p11, p11);
                p00 = AdvSimd.Or(hi00, tw00);
                p01 = AdvSimd.Or(hi01, tw01);
                p10 = AdvSimd.Or(hi10, tw10);
                p11 = AdvSimd.Or(hi11, tw11);
            }

            AdvSimd.Store(pd, a0 ^ AdvSimd.LoadVector128(ps));
            AdvSimd.Store(pd + 16, a1 ^ AdvSimd.LoadVector128(ps + 16));
            AdvSimd.Store(pd + 32, AdvSimd.ExtractVector128(p01, p00, 1) ^ AdvSimd.LoadVector128(ps + 32));
            AdvSimd.Store(pd + 48, AdvSimd.ExtractVector128(p00, p01, 1) ^ AdvSimd.LoadVector128(ps + 48));
            AdvSimd.Store(pd + 64, c0 ^ AdvSimd.LoadVector128(ps + 64));
            AdvSimd.Store(pd + 80, c1 ^ AdvSimd.LoadVector128(ps + 80));
            AdvSimd.Store(pd + 96, AdvSimd.ExtractVector128(q00, q01, 1) ^ AdvSimd.LoadVector128(ps + 96));
            AdvSimd.Store(pd + 112, AdvSimd.ExtractVector128(q01, q00, 1) ^ AdvSimd.LoadVector128(ps + 112));
            AdvSimd.Store(pd + 2, e0 ^ AdvSimd.LoadVector128(ps + 2));
            AdvSimd.Store(pd + 18, e1 ^ AdvSimd.LoadVector128(ps + 18));
            AdvSimd.Store(pd + 34, AdvSimd.ExtractVector128(p11, p10, 1) ^ AdvSimd.LoadVector128(ps + 34));
            AdvSimd.Store(pd + 50, AdvSimd.ExtractVector128(p10, p11, 1) ^ AdvSimd.LoadVector128(ps + 50));
            AdvSimd.Store(pd + 66, g0 ^ AdvSimd.LoadVector128(ps + 66));
            AdvSimd.Store(pd + 82, g1 ^ AdvSimd.LoadVector128(ps + 82));
            AdvSimd.Store(pd + 98, AdvSimd.ExtractVector128(q10, q11, 1) ^ AdvSimd.LoadVector128(ps + 98));
            AdvSimd.Store(pd + 114, AdvSimd.ExtractVector128(q11, q10, 1) ^ AdvSimd.LoadVector128(ps + 114));
            // Word 0 of this block is final, so the next block's reference is known.
            following = scratch[265] != 0 ? Argon2Core.NextReference(scratch, destination[0]) : (ulong*)scratch[264];
        }
        {
            nint column = 4;
            ulong* p = r + column, pd = destination + column, ps = saved + column;
            ulong u0 = following[0], u1 = following[8], u2 = following[16], u3 = following[24], u4 = following[32], u5 = following[40];
            Vector128<ulong> a0 = AdvSimd.LoadVector128(p);
            Vector128<ulong> a1 = AdvSimd.LoadVector128(p + 16);
            Vector128<ulong> b0 = AdvSimd.LoadVector128(p + 32);
            Vector128<ulong> b1 = AdvSimd.LoadVector128(p + 48);
            Vector128<ulong> c0 = AdvSimd.LoadVector128(p + 64);
            Vector128<ulong> c1 = AdvSimd.LoadVector128(p + 80);
            Vector128<ulong> d0 = AdvSimd.LoadVector128(p + 96);
            Vector128<ulong> d1 = AdvSimd.LoadVector128(p + 112);
            Vector128<ulong> e0 = AdvSimd.LoadVector128(p + 2);
            Vector128<ulong> e1 = AdvSimd.LoadVector128(p + 18);
            Vector128<ulong> f0 = AdvSimd.LoadVector128(p + 34);
            Vector128<ulong> f1 = AdvSimd.LoadVector128(p + 50);
            Vector128<ulong> g0 = AdvSimd.LoadVector128(p + 66);
            Vector128<ulong> g1 = AdvSimd.LoadVector128(p + 82);
            Vector128<ulong> h0 = AdvSimd.LoadVector128(p + 98);
            Vector128<ulong> h1 = AdvSimd.LoadVector128(p + 114);

            {
                Vector64<uint> lx00 = AdvSimd.ExtractNarrowingLower(a0), ly00 = AdvSimd.ExtractNarrowingLower(b0);
                Vector64<uint> lx01 = AdvSimd.ExtractNarrowingLower(a1), ly01 = AdvSimd.ExtractNarrowingLower(b1);
                Vector64<uint> lx10 = AdvSimd.ExtractNarrowingLower(e0), ly10 = AdvSimd.ExtractNarrowingLower(f0);
                Vector64<uint> lx11 = AdvSimd.ExtractNarrowingLower(e1), ly11 = AdvSimd.ExtractNarrowingLower(f1);
                Vector128<ulong> s00 = AdvSimd.Add(a0, b0);
                Vector128<ulong> s01 = AdvSimd.Add(a1, b1);
                Vector128<ulong> s10 = AdvSimd.Add(e0, f0);
                Vector128<ulong> s11 = AdvSimd.Add(e1, f1);
                s00 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                s01 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                s10 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                s11 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
                a0 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                a1 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                e0 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                e1 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
            }
            d0 ^= a0; d1 ^= a1;
            h0 ^= e0; h1 ^= e1;
            d0 = Rotate32(d0); d1 = Rotate32(d1);
            h0 = Rotate32(h0); h1 = Rotate32(h1);
            {
                Vector64<uint> lx00 = AdvSimd.ExtractNarrowingLower(c0), ly00 = AdvSimd.ExtractNarrowingLower(d0);
                Vector64<uint> lx01 = AdvSimd.ExtractNarrowingLower(c1), ly01 = AdvSimd.ExtractNarrowingLower(d1);
                Vector64<uint> lx10 = AdvSimd.ExtractNarrowingLower(g0), ly10 = AdvSimd.ExtractNarrowingLower(h0);
                Vector64<uint> lx11 = AdvSimd.ExtractNarrowingLower(g1), ly11 = AdvSimd.ExtractNarrowingLower(h1);
                Vector128<ulong> s00 = AdvSimd.Add(c0, d0);
                Vector128<ulong> s01 = AdvSimd.Add(c1, d1);
                Vector128<ulong> s10 = AdvSimd.Add(g0, h0);
                Vector128<ulong> s11 = AdvSimd.Add(g1, h1);
                s00 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                s01 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                s10 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                s11 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
                c0 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                c1 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                g0 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                g1 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
            }
            b0 ^= c0; b1 ^= c1;
            f0 ^= g0; f1 ^= g1;
            b0 = Rotate24(b0, r24); b1 = Rotate24(b1, r24);
            f0 = Rotate24(f0, r24); f1 = Rotate24(f1, r24);
            {
                Vector64<uint> lx00 = AdvSimd.ExtractNarrowingLower(a0), ly00 = AdvSimd.ExtractNarrowingLower(b0);
                Vector64<uint> lx01 = AdvSimd.ExtractNarrowingLower(a1), ly01 = AdvSimd.ExtractNarrowingLower(b1);
                Vector64<uint> lx10 = AdvSimd.ExtractNarrowingLower(e0), ly10 = AdvSimd.ExtractNarrowingLower(f0);
                Vector64<uint> lx11 = AdvSimd.ExtractNarrowingLower(e1), ly11 = AdvSimd.ExtractNarrowingLower(f1);
                Vector128<ulong> s00 = AdvSimd.Add(a0, b0);
                Vector128<ulong> s01 = AdvSimd.Add(a1, b1);
                Vector128<ulong> s10 = AdvSimd.Add(e0, f0);
                Vector128<ulong> s11 = AdvSimd.Add(e1, f1);
                s00 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                s01 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                s10 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                s11 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
                a0 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                a1 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                e0 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                e1 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
            }
            d0 ^= a0; d1 ^= a1;
            h0 ^= e0; h1 ^= e1;
            d0 = Rotate16(d0, r16); d1 = Rotate16(d1, r16);
            h0 = Rotate16(h0, r16); h1 = Rotate16(h1, r16);
            {
                Vector64<uint> lx00 = AdvSimd.ExtractNarrowingLower(c0), ly00 = AdvSimd.ExtractNarrowingLower(d0);
                Vector64<uint> lx01 = AdvSimd.ExtractNarrowingLower(c1), ly01 = AdvSimd.ExtractNarrowingLower(d1);
                Vector64<uint> lx10 = AdvSimd.ExtractNarrowingLower(g0), ly10 = AdvSimd.ExtractNarrowingLower(h0);
                Vector64<uint> lx11 = AdvSimd.ExtractNarrowingLower(g1), ly11 = AdvSimd.ExtractNarrowingLower(h1);
                Vector128<ulong> s00 = AdvSimd.Add(c0, d0);
                Vector128<ulong> s01 = AdvSimd.Add(c1, d1);
                Vector128<ulong> s10 = AdvSimd.Add(g0, h0);
                Vector128<ulong> s11 = AdvSimd.Add(g1, h1);
                s00 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                s01 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                s10 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                s11 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
                c0 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                c1 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                g0 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                g1 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
            }
            b0 ^= c0; b1 ^= c1;
            f0 ^= g0; f1 ^= g1;
            {
                Vector128<ulong> hi00 = AdvSimd.ShiftRightLogical(b0, 63);
                Vector128<ulong> hi01 = AdvSimd.ShiftRightLogical(b1, 63);
                Vector128<ulong> hi10 = AdvSimd.ShiftRightLogical(f0, 63);
                Vector128<ulong> hi11 = AdvSimd.ShiftRightLogical(f1, 63);
                Vector128<ulong> tw00 = AdvSimd.Add(b0, b0);
                Vector128<ulong> tw01 = AdvSimd.Add(b1, b1);
                Vector128<ulong> tw10 = AdvSimd.Add(f0, f0);
                Vector128<ulong> tw11 = AdvSimd.Add(f1, f1);
                b0 = AdvSimd.Or(hi00, tw00);
                b1 = AdvSimd.Or(hi01, tw01);
                f0 = AdvSimd.Or(hi10, tw10);
                f1 = AdvSimd.Or(hi11, tw11);
            }

            Vector128<ulong> p00 = AdvSimd.ExtractVector128(b0, b1, 1);
            Vector128<ulong> p10 = AdvSimd.ExtractVector128(f0, f1, 1);
            Vector128<ulong> p01 = AdvSimd.ExtractVector128(b1, b0, 1);
            Vector128<ulong> p11 = AdvSimd.ExtractVector128(f1, f0, 1);
            Vector128<ulong> q00 = AdvSimd.ExtractVector128(d1, d0, 1);
            Vector128<ulong> q10 = AdvSimd.ExtractVector128(h1, h0, 1);
            Vector128<ulong> q01 = AdvSimd.ExtractVector128(d0, d1, 1);
            Vector128<ulong> q11 = AdvSimd.ExtractVector128(h0, h1, 1);

            {
                Vector64<uint> lx00 = AdvSimd.ExtractNarrowingLower(a0), ly00 = AdvSimd.ExtractNarrowingLower(p00);
                Vector64<uint> lx01 = AdvSimd.ExtractNarrowingLower(a1), ly01 = AdvSimd.ExtractNarrowingLower(p01);
                Vector64<uint> lx10 = AdvSimd.ExtractNarrowingLower(e0), ly10 = AdvSimd.ExtractNarrowingLower(p10);
                Vector64<uint> lx11 = AdvSimd.ExtractNarrowingLower(e1), ly11 = AdvSimd.ExtractNarrowingLower(p11);
                Vector128<ulong> s00 = AdvSimd.Add(a0, p00);
                Vector128<ulong> s01 = AdvSimd.Add(a1, p01);
                Vector128<ulong> s10 = AdvSimd.Add(e0, p10);
                Vector128<ulong> s11 = AdvSimd.Add(e1, p11);
                s00 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                s01 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                s10 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                s11 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
                a0 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                a1 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                e0 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                e1 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
            }
            q00 ^= a0; q01 ^= a1;
            q10 ^= e0; q11 ^= e1;
            q00 = Rotate32(q00); q01 = Rotate32(q01);
            q10 = Rotate32(q10); q11 = Rotate32(q11);
            {
                Vector64<uint> lx00 = AdvSimd.ExtractNarrowingLower(c1), ly00 = AdvSimd.ExtractNarrowingLower(q00);
                Vector64<uint> lx01 = AdvSimd.ExtractNarrowingLower(c0), ly01 = AdvSimd.ExtractNarrowingLower(q01);
                Vector64<uint> lx10 = AdvSimd.ExtractNarrowingLower(g1), ly10 = AdvSimd.ExtractNarrowingLower(q10);
                Vector64<uint> lx11 = AdvSimd.ExtractNarrowingLower(g0), ly11 = AdvSimd.ExtractNarrowingLower(q11);
                Vector128<ulong> s00 = AdvSimd.Add(c1, q00);
                Vector128<ulong> s01 = AdvSimd.Add(c0, q01);
                Vector128<ulong> s10 = AdvSimd.Add(g1, q10);
                Vector128<ulong> s11 = AdvSimd.Add(g0, q11);
                s00 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                s01 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                s10 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                s11 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
                c1 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                c0 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                g1 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                g0 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
            }
            p00 ^= c1; p01 ^= c0;
            p10 ^= g1; p11 ^= g0;
            p00 = Rotate24(p00, r24); p01 = Rotate24(p01, r24);
            p10 = Rotate24(p10, r24); p11 = Rotate24(p11, r24);
            {
                Vector64<uint> lx00 = AdvSimd.ExtractNarrowingLower(a0), ly00 = AdvSimd.ExtractNarrowingLower(p00);
                Vector64<uint> lx01 = AdvSimd.ExtractNarrowingLower(a1), ly01 = AdvSimd.ExtractNarrowingLower(p01);
                Vector64<uint> lx10 = AdvSimd.ExtractNarrowingLower(e0), ly10 = AdvSimd.ExtractNarrowingLower(p10);
                Vector64<uint> lx11 = AdvSimd.ExtractNarrowingLower(e1), ly11 = AdvSimd.ExtractNarrowingLower(p11);
                Vector128<ulong> s00 = AdvSimd.Add(a0, p00);
                Vector128<ulong> s01 = AdvSimd.Add(a1, p01);
                Vector128<ulong> s10 = AdvSimd.Add(e0, p10);
                Vector128<ulong> s11 = AdvSimd.Add(e1, p11);
                s00 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                s01 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                s10 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                s11 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
                a0 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                a1 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                e0 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                e1 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
            }
            q00 ^= a0; q01 ^= a1;
            q10 ^= e0; q11 ^= e1;
            q00 = Rotate16(q00, r16); q01 = Rotate16(q01, r16);
            q10 = Rotate16(q10, r16); q11 = Rotate16(q11, r16);
            {
                Vector64<uint> lx00 = AdvSimd.ExtractNarrowingLower(c1), ly00 = AdvSimd.ExtractNarrowingLower(q00);
                Vector64<uint> lx01 = AdvSimd.ExtractNarrowingLower(c0), ly01 = AdvSimd.ExtractNarrowingLower(q01);
                Vector64<uint> lx10 = AdvSimd.ExtractNarrowingLower(g1), ly10 = AdvSimd.ExtractNarrowingLower(q10);
                Vector64<uint> lx11 = AdvSimd.ExtractNarrowingLower(g0), ly11 = AdvSimd.ExtractNarrowingLower(q11);
                Vector128<ulong> s00 = AdvSimd.Add(c1, q00);
                Vector128<ulong> s01 = AdvSimd.Add(c0, q01);
                Vector128<ulong> s10 = AdvSimd.Add(g1, q10);
                Vector128<ulong> s11 = AdvSimd.Add(g0, q11);
                s00 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                s01 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                s10 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                s11 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
                c1 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                c0 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                g1 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                g0 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
            }
            p00 ^= c1; p01 ^= c0;
            p10 ^= g1; p11 ^= g0;
            {
                Vector128<ulong> hi00 = AdvSimd.ShiftRightLogical(p00, 63);
                Vector128<ulong> hi01 = AdvSimd.ShiftRightLogical(p01, 63);
                Vector128<ulong> hi10 = AdvSimd.ShiftRightLogical(p10, 63);
                Vector128<ulong> hi11 = AdvSimd.ShiftRightLogical(p11, 63);
                Vector128<ulong> tw00 = AdvSimd.Add(p00, p00);
                Vector128<ulong> tw01 = AdvSimd.Add(p01, p01);
                Vector128<ulong> tw10 = AdvSimd.Add(p10, p10);
                Vector128<ulong> tw11 = AdvSimd.Add(p11, p11);
                p00 = AdvSimd.Or(hi00, tw00);
                p01 = AdvSimd.Or(hi01, tw01);
                p10 = AdvSimd.Or(hi10, tw10);
                p11 = AdvSimd.Or(hi11, tw11);
            }

            AdvSimd.Store(pd, a0 ^ AdvSimd.LoadVector128(ps));
            AdvSimd.Store(pd + 16, a1 ^ AdvSimd.LoadVector128(ps + 16));
            AdvSimd.Store(pd + 32, AdvSimd.ExtractVector128(p01, p00, 1) ^ AdvSimd.LoadVector128(ps + 32));
            AdvSimd.Store(pd + 48, AdvSimd.ExtractVector128(p00, p01, 1) ^ AdvSimd.LoadVector128(ps + 48));
            AdvSimd.Store(pd + 64, c0 ^ AdvSimd.LoadVector128(ps + 64));
            AdvSimd.Store(pd + 80, c1 ^ AdvSimd.LoadVector128(ps + 80));
            AdvSimd.Store(pd + 96, AdvSimd.ExtractVector128(q00, q01, 1) ^ AdvSimd.LoadVector128(ps + 96));
            AdvSimd.Store(pd + 112, AdvSimd.ExtractVector128(q01, q00, 1) ^ AdvSimd.LoadVector128(ps + 112));
            AdvSimd.Store(pd + 2, e0 ^ AdvSimd.LoadVector128(ps + 2));
            AdvSimd.Store(pd + 18, e1 ^ AdvSimd.LoadVector128(ps + 18));
            AdvSimd.Store(pd + 34, AdvSimd.ExtractVector128(p11, p10, 1) ^ AdvSimd.LoadVector128(ps + 34));
            AdvSimd.Store(pd + 50, AdvSimd.ExtractVector128(p10, p11, 1) ^ AdvSimd.LoadVector128(ps + 50));
            AdvSimd.Store(pd + 66, g0 ^ AdvSimd.LoadVector128(ps + 66));
            AdvSimd.Store(pd + 82, g1 ^ AdvSimd.LoadVector128(ps + 82));
            AdvSimd.Store(pd + 98, AdvSimd.ExtractVector128(q10, q11, 1) ^ AdvSimd.LoadVector128(ps + 98));
            AdvSimd.Store(pd + 114, AdvSimd.ExtractVector128(q11, q10, 1) ^ AdvSimd.LoadVector128(ps + 114));
            touched |= u0 | u1 | u2 | u3 | u4 | u5;
        }
        {
            nint column = 8;
            ulong* p = r + column, pd = destination + column, ps = saved + column;
            ulong u6 = following[48], u7 = following[56], u8 = following[64], u9 = following[72], u10 = following[80];
            Vector128<ulong> a0 = AdvSimd.LoadVector128(p);
            Vector128<ulong> a1 = AdvSimd.LoadVector128(p + 16);
            Vector128<ulong> b0 = AdvSimd.LoadVector128(p + 32);
            Vector128<ulong> b1 = AdvSimd.LoadVector128(p + 48);
            Vector128<ulong> c0 = AdvSimd.LoadVector128(p + 64);
            Vector128<ulong> c1 = AdvSimd.LoadVector128(p + 80);
            Vector128<ulong> d0 = AdvSimd.LoadVector128(p + 96);
            Vector128<ulong> d1 = AdvSimd.LoadVector128(p + 112);
            Vector128<ulong> e0 = AdvSimd.LoadVector128(p + 2);
            Vector128<ulong> e1 = AdvSimd.LoadVector128(p + 18);
            Vector128<ulong> f0 = AdvSimd.LoadVector128(p + 34);
            Vector128<ulong> f1 = AdvSimd.LoadVector128(p + 50);
            Vector128<ulong> g0 = AdvSimd.LoadVector128(p + 66);
            Vector128<ulong> g1 = AdvSimd.LoadVector128(p + 82);
            Vector128<ulong> h0 = AdvSimd.LoadVector128(p + 98);
            Vector128<ulong> h1 = AdvSimd.LoadVector128(p + 114);

            {
                Vector64<uint> lx00 = AdvSimd.ExtractNarrowingLower(a0), ly00 = AdvSimd.ExtractNarrowingLower(b0);
                Vector64<uint> lx01 = AdvSimd.ExtractNarrowingLower(a1), ly01 = AdvSimd.ExtractNarrowingLower(b1);
                Vector64<uint> lx10 = AdvSimd.ExtractNarrowingLower(e0), ly10 = AdvSimd.ExtractNarrowingLower(f0);
                Vector64<uint> lx11 = AdvSimd.ExtractNarrowingLower(e1), ly11 = AdvSimd.ExtractNarrowingLower(f1);
                Vector128<ulong> s00 = AdvSimd.Add(a0, b0);
                Vector128<ulong> s01 = AdvSimd.Add(a1, b1);
                Vector128<ulong> s10 = AdvSimd.Add(e0, f0);
                Vector128<ulong> s11 = AdvSimd.Add(e1, f1);
                s00 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                s01 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                s10 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                s11 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
                a0 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                a1 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                e0 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                e1 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
            }
            d0 ^= a0; d1 ^= a1;
            h0 ^= e0; h1 ^= e1;
            d0 = Rotate32(d0); d1 = Rotate32(d1);
            h0 = Rotate32(h0); h1 = Rotate32(h1);
            {
                Vector64<uint> lx00 = AdvSimd.ExtractNarrowingLower(c0), ly00 = AdvSimd.ExtractNarrowingLower(d0);
                Vector64<uint> lx01 = AdvSimd.ExtractNarrowingLower(c1), ly01 = AdvSimd.ExtractNarrowingLower(d1);
                Vector64<uint> lx10 = AdvSimd.ExtractNarrowingLower(g0), ly10 = AdvSimd.ExtractNarrowingLower(h0);
                Vector64<uint> lx11 = AdvSimd.ExtractNarrowingLower(g1), ly11 = AdvSimd.ExtractNarrowingLower(h1);
                Vector128<ulong> s00 = AdvSimd.Add(c0, d0);
                Vector128<ulong> s01 = AdvSimd.Add(c1, d1);
                Vector128<ulong> s10 = AdvSimd.Add(g0, h0);
                Vector128<ulong> s11 = AdvSimd.Add(g1, h1);
                s00 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                s01 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                s10 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                s11 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
                c0 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                c1 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                g0 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                g1 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
            }
            b0 ^= c0; b1 ^= c1;
            f0 ^= g0; f1 ^= g1;
            b0 = Rotate24(b0, r24); b1 = Rotate24(b1, r24);
            f0 = Rotate24(f0, r24); f1 = Rotate24(f1, r24);
            {
                Vector64<uint> lx00 = AdvSimd.ExtractNarrowingLower(a0), ly00 = AdvSimd.ExtractNarrowingLower(b0);
                Vector64<uint> lx01 = AdvSimd.ExtractNarrowingLower(a1), ly01 = AdvSimd.ExtractNarrowingLower(b1);
                Vector64<uint> lx10 = AdvSimd.ExtractNarrowingLower(e0), ly10 = AdvSimd.ExtractNarrowingLower(f0);
                Vector64<uint> lx11 = AdvSimd.ExtractNarrowingLower(e1), ly11 = AdvSimd.ExtractNarrowingLower(f1);
                Vector128<ulong> s00 = AdvSimd.Add(a0, b0);
                Vector128<ulong> s01 = AdvSimd.Add(a1, b1);
                Vector128<ulong> s10 = AdvSimd.Add(e0, f0);
                Vector128<ulong> s11 = AdvSimd.Add(e1, f1);
                s00 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                s01 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                s10 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                s11 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
                a0 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                a1 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                e0 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                e1 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
            }
            d0 ^= a0; d1 ^= a1;
            h0 ^= e0; h1 ^= e1;
            d0 = Rotate16(d0, r16); d1 = Rotate16(d1, r16);
            h0 = Rotate16(h0, r16); h1 = Rotate16(h1, r16);
            {
                Vector64<uint> lx00 = AdvSimd.ExtractNarrowingLower(c0), ly00 = AdvSimd.ExtractNarrowingLower(d0);
                Vector64<uint> lx01 = AdvSimd.ExtractNarrowingLower(c1), ly01 = AdvSimd.ExtractNarrowingLower(d1);
                Vector64<uint> lx10 = AdvSimd.ExtractNarrowingLower(g0), ly10 = AdvSimd.ExtractNarrowingLower(h0);
                Vector64<uint> lx11 = AdvSimd.ExtractNarrowingLower(g1), ly11 = AdvSimd.ExtractNarrowingLower(h1);
                Vector128<ulong> s00 = AdvSimd.Add(c0, d0);
                Vector128<ulong> s01 = AdvSimd.Add(c1, d1);
                Vector128<ulong> s10 = AdvSimd.Add(g0, h0);
                Vector128<ulong> s11 = AdvSimd.Add(g1, h1);
                s00 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                s01 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                s10 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                s11 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
                c0 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                c1 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                g0 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                g1 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
            }
            b0 ^= c0; b1 ^= c1;
            f0 ^= g0; f1 ^= g1;
            {
                Vector128<ulong> hi00 = AdvSimd.ShiftRightLogical(b0, 63);
                Vector128<ulong> hi01 = AdvSimd.ShiftRightLogical(b1, 63);
                Vector128<ulong> hi10 = AdvSimd.ShiftRightLogical(f0, 63);
                Vector128<ulong> hi11 = AdvSimd.ShiftRightLogical(f1, 63);
                Vector128<ulong> tw00 = AdvSimd.Add(b0, b0);
                Vector128<ulong> tw01 = AdvSimd.Add(b1, b1);
                Vector128<ulong> tw10 = AdvSimd.Add(f0, f0);
                Vector128<ulong> tw11 = AdvSimd.Add(f1, f1);
                b0 = AdvSimd.Or(hi00, tw00);
                b1 = AdvSimd.Or(hi01, tw01);
                f0 = AdvSimd.Or(hi10, tw10);
                f1 = AdvSimd.Or(hi11, tw11);
            }

            Vector128<ulong> p00 = AdvSimd.ExtractVector128(b0, b1, 1);
            Vector128<ulong> p10 = AdvSimd.ExtractVector128(f0, f1, 1);
            Vector128<ulong> p01 = AdvSimd.ExtractVector128(b1, b0, 1);
            Vector128<ulong> p11 = AdvSimd.ExtractVector128(f1, f0, 1);
            Vector128<ulong> q00 = AdvSimd.ExtractVector128(d1, d0, 1);
            Vector128<ulong> q10 = AdvSimd.ExtractVector128(h1, h0, 1);
            Vector128<ulong> q01 = AdvSimd.ExtractVector128(d0, d1, 1);
            Vector128<ulong> q11 = AdvSimd.ExtractVector128(h0, h1, 1);

            {
                Vector64<uint> lx00 = AdvSimd.ExtractNarrowingLower(a0), ly00 = AdvSimd.ExtractNarrowingLower(p00);
                Vector64<uint> lx01 = AdvSimd.ExtractNarrowingLower(a1), ly01 = AdvSimd.ExtractNarrowingLower(p01);
                Vector64<uint> lx10 = AdvSimd.ExtractNarrowingLower(e0), ly10 = AdvSimd.ExtractNarrowingLower(p10);
                Vector64<uint> lx11 = AdvSimd.ExtractNarrowingLower(e1), ly11 = AdvSimd.ExtractNarrowingLower(p11);
                Vector128<ulong> s00 = AdvSimd.Add(a0, p00);
                Vector128<ulong> s01 = AdvSimd.Add(a1, p01);
                Vector128<ulong> s10 = AdvSimd.Add(e0, p10);
                Vector128<ulong> s11 = AdvSimd.Add(e1, p11);
                s00 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                s01 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                s10 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                s11 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
                a0 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                a1 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                e0 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                e1 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
            }
            q00 ^= a0; q01 ^= a1;
            q10 ^= e0; q11 ^= e1;
            q00 = Rotate32(q00); q01 = Rotate32(q01);
            q10 = Rotate32(q10); q11 = Rotate32(q11);
            {
                Vector64<uint> lx00 = AdvSimd.ExtractNarrowingLower(c1), ly00 = AdvSimd.ExtractNarrowingLower(q00);
                Vector64<uint> lx01 = AdvSimd.ExtractNarrowingLower(c0), ly01 = AdvSimd.ExtractNarrowingLower(q01);
                Vector64<uint> lx10 = AdvSimd.ExtractNarrowingLower(g1), ly10 = AdvSimd.ExtractNarrowingLower(q10);
                Vector64<uint> lx11 = AdvSimd.ExtractNarrowingLower(g0), ly11 = AdvSimd.ExtractNarrowingLower(q11);
                Vector128<ulong> s00 = AdvSimd.Add(c1, q00);
                Vector128<ulong> s01 = AdvSimd.Add(c0, q01);
                Vector128<ulong> s10 = AdvSimd.Add(g1, q10);
                Vector128<ulong> s11 = AdvSimd.Add(g0, q11);
                s00 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                s01 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                s10 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                s11 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
                c1 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                c0 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                g1 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                g0 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
            }
            p00 ^= c1; p01 ^= c0;
            p10 ^= g1; p11 ^= g0;
            p00 = Rotate24(p00, r24); p01 = Rotate24(p01, r24);
            p10 = Rotate24(p10, r24); p11 = Rotate24(p11, r24);
            {
                Vector64<uint> lx00 = AdvSimd.ExtractNarrowingLower(a0), ly00 = AdvSimd.ExtractNarrowingLower(p00);
                Vector64<uint> lx01 = AdvSimd.ExtractNarrowingLower(a1), ly01 = AdvSimd.ExtractNarrowingLower(p01);
                Vector64<uint> lx10 = AdvSimd.ExtractNarrowingLower(e0), ly10 = AdvSimd.ExtractNarrowingLower(p10);
                Vector64<uint> lx11 = AdvSimd.ExtractNarrowingLower(e1), ly11 = AdvSimd.ExtractNarrowingLower(p11);
                Vector128<ulong> s00 = AdvSimd.Add(a0, p00);
                Vector128<ulong> s01 = AdvSimd.Add(a1, p01);
                Vector128<ulong> s10 = AdvSimd.Add(e0, p10);
                Vector128<ulong> s11 = AdvSimd.Add(e1, p11);
                s00 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                s01 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                s10 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                s11 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
                a0 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                a1 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                e0 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                e1 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
            }
            q00 ^= a0; q01 ^= a1;
            q10 ^= e0; q11 ^= e1;
            q00 = Rotate16(q00, r16); q01 = Rotate16(q01, r16);
            q10 = Rotate16(q10, r16); q11 = Rotate16(q11, r16);
            {
                Vector64<uint> lx00 = AdvSimd.ExtractNarrowingLower(c1), ly00 = AdvSimd.ExtractNarrowingLower(q00);
                Vector64<uint> lx01 = AdvSimd.ExtractNarrowingLower(c0), ly01 = AdvSimd.ExtractNarrowingLower(q01);
                Vector64<uint> lx10 = AdvSimd.ExtractNarrowingLower(g1), ly10 = AdvSimd.ExtractNarrowingLower(q10);
                Vector64<uint> lx11 = AdvSimd.ExtractNarrowingLower(g0), ly11 = AdvSimd.ExtractNarrowingLower(q11);
                Vector128<ulong> s00 = AdvSimd.Add(c1, q00);
                Vector128<ulong> s01 = AdvSimd.Add(c0, q01);
                Vector128<ulong> s10 = AdvSimd.Add(g1, q10);
                Vector128<ulong> s11 = AdvSimd.Add(g0, q11);
                s00 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                s01 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                s10 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                s11 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
                c1 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                c0 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                g1 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                g0 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
            }
            p00 ^= c1; p01 ^= c0;
            p10 ^= g1; p11 ^= g0;
            {
                Vector128<ulong> hi00 = AdvSimd.ShiftRightLogical(p00, 63);
                Vector128<ulong> hi01 = AdvSimd.ShiftRightLogical(p01, 63);
                Vector128<ulong> hi10 = AdvSimd.ShiftRightLogical(p10, 63);
                Vector128<ulong> hi11 = AdvSimd.ShiftRightLogical(p11, 63);
                Vector128<ulong> tw00 = AdvSimd.Add(p00, p00);
                Vector128<ulong> tw01 = AdvSimd.Add(p01, p01);
                Vector128<ulong> tw10 = AdvSimd.Add(p10, p10);
                Vector128<ulong> tw11 = AdvSimd.Add(p11, p11);
                p00 = AdvSimd.Or(hi00, tw00);
                p01 = AdvSimd.Or(hi01, tw01);
                p10 = AdvSimd.Or(hi10, tw10);
                p11 = AdvSimd.Or(hi11, tw11);
            }

            AdvSimd.Store(pd, a0 ^ AdvSimd.LoadVector128(ps));
            AdvSimd.Store(pd + 16, a1 ^ AdvSimd.LoadVector128(ps + 16));
            AdvSimd.Store(pd + 32, AdvSimd.ExtractVector128(p01, p00, 1) ^ AdvSimd.LoadVector128(ps + 32));
            AdvSimd.Store(pd + 48, AdvSimd.ExtractVector128(p00, p01, 1) ^ AdvSimd.LoadVector128(ps + 48));
            AdvSimd.Store(pd + 64, c0 ^ AdvSimd.LoadVector128(ps + 64));
            AdvSimd.Store(pd + 80, c1 ^ AdvSimd.LoadVector128(ps + 80));
            AdvSimd.Store(pd + 96, AdvSimd.ExtractVector128(q00, q01, 1) ^ AdvSimd.LoadVector128(ps + 96));
            AdvSimd.Store(pd + 112, AdvSimd.ExtractVector128(q01, q00, 1) ^ AdvSimd.LoadVector128(ps + 112));
            AdvSimd.Store(pd + 2, e0 ^ AdvSimd.LoadVector128(ps + 2));
            AdvSimd.Store(pd + 18, e1 ^ AdvSimd.LoadVector128(ps + 18));
            AdvSimd.Store(pd + 34, AdvSimd.ExtractVector128(p11, p10, 1) ^ AdvSimd.LoadVector128(ps + 34));
            AdvSimd.Store(pd + 50, AdvSimd.ExtractVector128(p10, p11, 1) ^ AdvSimd.LoadVector128(ps + 50));
            AdvSimd.Store(pd + 66, g0 ^ AdvSimd.LoadVector128(ps + 66));
            AdvSimd.Store(pd + 82, g1 ^ AdvSimd.LoadVector128(ps + 82));
            AdvSimd.Store(pd + 98, AdvSimd.ExtractVector128(q10, q11, 1) ^ AdvSimd.LoadVector128(ps + 98));
            AdvSimd.Store(pd + 114, AdvSimd.ExtractVector128(q11, q10, 1) ^ AdvSimd.LoadVector128(ps + 114));
            touched |= u6 | u7 | u8 | u9 | u10;
        }
        {
            nint column = 12;
            ulong* p = r + column, pd = destination + column, ps = saved + column;
            ulong u11 = following[88], u12 = following[96], u13 = following[104], u14 = following[112], u15 = following[120];
            Vector128<ulong> a0 = AdvSimd.LoadVector128(p);
            Vector128<ulong> a1 = AdvSimd.LoadVector128(p + 16);
            Vector128<ulong> b0 = AdvSimd.LoadVector128(p + 32);
            Vector128<ulong> b1 = AdvSimd.LoadVector128(p + 48);
            Vector128<ulong> c0 = AdvSimd.LoadVector128(p + 64);
            Vector128<ulong> c1 = AdvSimd.LoadVector128(p + 80);
            Vector128<ulong> d0 = AdvSimd.LoadVector128(p + 96);
            Vector128<ulong> d1 = AdvSimd.LoadVector128(p + 112);
            Vector128<ulong> e0 = AdvSimd.LoadVector128(p + 2);
            Vector128<ulong> e1 = AdvSimd.LoadVector128(p + 18);
            Vector128<ulong> f0 = AdvSimd.LoadVector128(p + 34);
            Vector128<ulong> f1 = AdvSimd.LoadVector128(p + 50);
            Vector128<ulong> g0 = AdvSimd.LoadVector128(p + 66);
            Vector128<ulong> g1 = AdvSimd.LoadVector128(p + 82);
            Vector128<ulong> h0 = AdvSimd.LoadVector128(p + 98);
            Vector128<ulong> h1 = AdvSimd.LoadVector128(p + 114);

            {
                Vector64<uint> lx00 = AdvSimd.ExtractNarrowingLower(a0), ly00 = AdvSimd.ExtractNarrowingLower(b0);
                Vector64<uint> lx01 = AdvSimd.ExtractNarrowingLower(a1), ly01 = AdvSimd.ExtractNarrowingLower(b1);
                Vector64<uint> lx10 = AdvSimd.ExtractNarrowingLower(e0), ly10 = AdvSimd.ExtractNarrowingLower(f0);
                Vector64<uint> lx11 = AdvSimd.ExtractNarrowingLower(e1), ly11 = AdvSimd.ExtractNarrowingLower(f1);
                Vector128<ulong> s00 = AdvSimd.Add(a0, b0);
                Vector128<ulong> s01 = AdvSimd.Add(a1, b1);
                Vector128<ulong> s10 = AdvSimd.Add(e0, f0);
                Vector128<ulong> s11 = AdvSimd.Add(e1, f1);
                s00 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                s01 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                s10 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                s11 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
                a0 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                a1 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                e0 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                e1 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
            }
            d0 ^= a0; d1 ^= a1;
            h0 ^= e0; h1 ^= e1;
            d0 = Rotate32(d0); d1 = Rotate32(d1);
            h0 = Rotate32(h0); h1 = Rotate32(h1);
            {
                Vector64<uint> lx00 = AdvSimd.ExtractNarrowingLower(c0), ly00 = AdvSimd.ExtractNarrowingLower(d0);
                Vector64<uint> lx01 = AdvSimd.ExtractNarrowingLower(c1), ly01 = AdvSimd.ExtractNarrowingLower(d1);
                Vector64<uint> lx10 = AdvSimd.ExtractNarrowingLower(g0), ly10 = AdvSimd.ExtractNarrowingLower(h0);
                Vector64<uint> lx11 = AdvSimd.ExtractNarrowingLower(g1), ly11 = AdvSimd.ExtractNarrowingLower(h1);
                Vector128<ulong> s00 = AdvSimd.Add(c0, d0);
                Vector128<ulong> s01 = AdvSimd.Add(c1, d1);
                Vector128<ulong> s10 = AdvSimd.Add(g0, h0);
                Vector128<ulong> s11 = AdvSimd.Add(g1, h1);
                s00 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                s01 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                s10 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                s11 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
                c0 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                c1 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                g0 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                g1 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
            }
            b0 ^= c0; b1 ^= c1;
            f0 ^= g0; f1 ^= g1;
            b0 = Rotate24(b0, r24); b1 = Rotate24(b1, r24);
            f0 = Rotate24(f0, r24); f1 = Rotate24(f1, r24);
            {
                Vector64<uint> lx00 = AdvSimd.ExtractNarrowingLower(a0), ly00 = AdvSimd.ExtractNarrowingLower(b0);
                Vector64<uint> lx01 = AdvSimd.ExtractNarrowingLower(a1), ly01 = AdvSimd.ExtractNarrowingLower(b1);
                Vector64<uint> lx10 = AdvSimd.ExtractNarrowingLower(e0), ly10 = AdvSimd.ExtractNarrowingLower(f0);
                Vector64<uint> lx11 = AdvSimd.ExtractNarrowingLower(e1), ly11 = AdvSimd.ExtractNarrowingLower(f1);
                Vector128<ulong> s00 = AdvSimd.Add(a0, b0);
                Vector128<ulong> s01 = AdvSimd.Add(a1, b1);
                Vector128<ulong> s10 = AdvSimd.Add(e0, f0);
                Vector128<ulong> s11 = AdvSimd.Add(e1, f1);
                s00 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                s01 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                s10 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                s11 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
                a0 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                a1 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                e0 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                e1 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
            }
            d0 ^= a0; d1 ^= a1;
            h0 ^= e0; h1 ^= e1;
            d0 = Rotate16(d0, r16); d1 = Rotate16(d1, r16);
            h0 = Rotate16(h0, r16); h1 = Rotate16(h1, r16);
            {
                Vector64<uint> lx00 = AdvSimd.ExtractNarrowingLower(c0), ly00 = AdvSimd.ExtractNarrowingLower(d0);
                Vector64<uint> lx01 = AdvSimd.ExtractNarrowingLower(c1), ly01 = AdvSimd.ExtractNarrowingLower(d1);
                Vector64<uint> lx10 = AdvSimd.ExtractNarrowingLower(g0), ly10 = AdvSimd.ExtractNarrowingLower(h0);
                Vector64<uint> lx11 = AdvSimd.ExtractNarrowingLower(g1), ly11 = AdvSimd.ExtractNarrowingLower(h1);
                Vector128<ulong> s00 = AdvSimd.Add(c0, d0);
                Vector128<ulong> s01 = AdvSimd.Add(c1, d1);
                Vector128<ulong> s10 = AdvSimd.Add(g0, h0);
                Vector128<ulong> s11 = AdvSimd.Add(g1, h1);
                s00 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                s01 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                s10 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                s11 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
                c0 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                c1 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                g0 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                g1 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
            }
            b0 ^= c0; b1 ^= c1;
            f0 ^= g0; f1 ^= g1;
            {
                Vector128<ulong> hi00 = AdvSimd.ShiftRightLogical(b0, 63);
                Vector128<ulong> hi01 = AdvSimd.ShiftRightLogical(b1, 63);
                Vector128<ulong> hi10 = AdvSimd.ShiftRightLogical(f0, 63);
                Vector128<ulong> hi11 = AdvSimd.ShiftRightLogical(f1, 63);
                Vector128<ulong> tw00 = AdvSimd.Add(b0, b0);
                Vector128<ulong> tw01 = AdvSimd.Add(b1, b1);
                Vector128<ulong> tw10 = AdvSimd.Add(f0, f0);
                Vector128<ulong> tw11 = AdvSimd.Add(f1, f1);
                b0 = AdvSimd.Or(hi00, tw00);
                b1 = AdvSimd.Or(hi01, tw01);
                f0 = AdvSimd.Or(hi10, tw10);
                f1 = AdvSimd.Or(hi11, tw11);
            }

            Vector128<ulong> p00 = AdvSimd.ExtractVector128(b0, b1, 1);
            Vector128<ulong> p10 = AdvSimd.ExtractVector128(f0, f1, 1);
            Vector128<ulong> p01 = AdvSimd.ExtractVector128(b1, b0, 1);
            Vector128<ulong> p11 = AdvSimd.ExtractVector128(f1, f0, 1);
            Vector128<ulong> q00 = AdvSimd.ExtractVector128(d1, d0, 1);
            Vector128<ulong> q10 = AdvSimd.ExtractVector128(h1, h0, 1);
            Vector128<ulong> q01 = AdvSimd.ExtractVector128(d0, d1, 1);
            Vector128<ulong> q11 = AdvSimd.ExtractVector128(h0, h1, 1);

            {
                Vector64<uint> lx00 = AdvSimd.ExtractNarrowingLower(a0), ly00 = AdvSimd.ExtractNarrowingLower(p00);
                Vector64<uint> lx01 = AdvSimd.ExtractNarrowingLower(a1), ly01 = AdvSimd.ExtractNarrowingLower(p01);
                Vector64<uint> lx10 = AdvSimd.ExtractNarrowingLower(e0), ly10 = AdvSimd.ExtractNarrowingLower(p10);
                Vector64<uint> lx11 = AdvSimd.ExtractNarrowingLower(e1), ly11 = AdvSimd.ExtractNarrowingLower(p11);
                Vector128<ulong> s00 = AdvSimd.Add(a0, p00);
                Vector128<ulong> s01 = AdvSimd.Add(a1, p01);
                Vector128<ulong> s10 = AdvSimd.Add(e0, p10);
                Vector128<ulong> s11 = AdvSimd.Add(e1, p11);
                s00 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                s01 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                s10 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                s11 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
                a0 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                a1 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                e0 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                e1 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
            }
            q00 ^= a0; q01 ^= a1;
            q10 ^= e0; q11 ^= e1;
            q00 = Rotate32(q00); q01 = Rotate32(q01);
            q10 = Rotate32(q10); q11 = Rotate32(q11);
            {
                Vector64<uint> lx00 = AdvSimd.ExtractNarrowingLower(c1), ly00 = AdvSimd.ExtractNarrowingLower(q00);
                Vector64<uint> lx01 = AdvSimd.ExtractNarrowingLower(c0), ly01 = AdvSimd.ExtractNarrowingLower(q01);
                Vector64<uint> lx10 = AdvSimd.ExtractNarrowingLower(g1), ly10 = AdvSimd.ExtractNarrowingLower(q10);
                Vector64<uint> lx11 = AdvSimd.ExtractNarrowingLower(g0), ly11 = AdvSimd.ExtractNarrowingLower(q11);
                Vector128<ulong> s00 = AdvSimd.Add(c1, q00);
                Vector128<ulong> s01 = AdvSimd.Add(c0, q01);
                Vector128<ulong> s10 = AdvSimd.Add(g1, q10);
                Vector128<ulong> s11 = AdvSimd.Add(g0, q11);
                s00 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                s01 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                s10 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                s11 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
                c1 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                c0 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                g1 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                g0 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
            }
            p00 ^= c1; p01 ^= c0;
            p10 ^= g1; p11 ^= g0;
            p00 = Rotate24(p00, r24); p01 = Rotate24(p01, r24);
            p10 = Rotate24(p10, r24); p11 = Rotate24(p11, r24);
            {
                Vector64<uint> lx00 = AdvSimd.ExtractNarrowingLower(a0), ly00 = AdvSimd.ExtractNarrowingLower(p00);
                Vector64<uint> lx01 = AdvSimd.ExtractNarrowingLower(a1), ly01 = AdvSimd.ExtractNarrowingLower(p01);
                Vector64<uint> lx10 = AdvSimd.ExtractNarrowingLower(e0), ly10 = AdvSimd.ExtractNarrowingLower(p10);
                Vector64<uint> lx11 = AdvSimd.ExtractNarrowingLower(e1), ly11 = AdvSimd.ExtractNarrowingLower(p11);
                Vector128<ulong> s00 = AdvSimd.Add(a0, p00);
                Vector128<ulong> s01 = AdvSimd.Add(a1, p01);
                Vector128<ulong> s10 = AdvSimd.Add(e0, p10);
                Vector128<ulong> s11 = AdvSimd.Add(e1, p11);
                s00 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                s01 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                s10 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                s11 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
                a0 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                a1 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                e0 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                e1 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
            }
            q00 ^= a0; q01 ^= a1;
            q10 ^= e0; q11 ^= e1;
            q00 = Rotate16(q00, r16); q01 = Rotate16(q01, r16);
            q10 = Rotate16(q10, r16); q11 = Rotate16(q11, r16);
            {
                Vector64<uint> lx00 = AdvSimd.ExtractNarrowingLower(c1), ly00 = AdvSimd.ExtractNarrowingLower(q00);
                Vector64<uint> lx01 = AdvSimd.ExtractNarrowingLower(c0), ly01 = AdvSimd.ExtractNarrowingLower(q01);
                Vector64<uint> lx10 = AdvSimd.ExtractNarrowingLower(g1), ly10 = AdvSimd.ExtractNarrowingLower(q10);
                Vector64<uint> lx11 = AdvSimd.ExtractNarrowingLower(g0), ly11 = AdvSimd.ExtractNarrowingLower(q11);
                Vector128<ulong> s00 = AdvSimd.Add(c1, q00);
                Vector128<ulong> s01 = AdvSimd.Add(c0, q01);
                Vector128<ulong> s10 = AdvSimd.Add(g1, q10);
                Vector128<ulong> s11 = AdvSimd.Add(g0, q11);
                s00 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                s01 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                s10 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                s11 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
                c1 = AdvSimd.MultiplyWideningLowerAndAdd(s00, lx00, ly00);
                c0 = AdvSimd.MultiplyWideningLowerAndAdd(s01, lx01, ly01);
                g1 = AdvSimd.MultiplyWideningLowerAndAdd(s10, lx10, ly10);
                g0 = AdvSimd.MultiplyWideningLowerAndAdd(s11, lx11, ly11);
            }
            p00 ^= c1; p01 ^= c0;
            p10 ^= g1; p11 ^= g0;
            {
                Vector128<ulong> hi00 = AdvSimd.ShiftRightLogical(p00, 63);
                Vector128<ulong> hi01 = AdvSimd.ShiftRightLogical(p01, 63);
                Vector128<ulong> hi10 = AdvSimd.ShiftRightLogical(p10, 63);
                Vector128<ulong> hi11 = AdvSimd.ShiftRightLogical(p11, 63);
                Vector128<ulong> tw00 = AdvSimd.Add(p00, p00);
                Vector128<ulong> tw01 = AdvSimd.Add(p01, p01);
                Vector128<ulong> tw10 = AdvSimd.Add(p10, p10);
                Vector128<ulong> tw11 = AdvSimd.Add(p11, p11);
                p00 = AdvSimd.Or(hi00, tw00);
                p01 = AdvSimd.Or(hi01, tw01);
                p10 = AdvSimd.Or(hi10, tw10);
                p11 = AdvSimd.Or(hi11, tw11);
            }

            AdvSimd.Store(pd, a0 ^ AdvSimd.LoadVector128(ps));
            AdvSimd.Store(pd + 16, a1 ^ AdvSimd.LoadVector128(ps + 16));
            AdvSimd.Store(pd + 32, AdvSimd.ExtractVector128(p01, p00, 1) ^ AdvSimd.LoadVector128(ps + 32));
            AdvSimd.Store(pd + 48, AdvSimd.ExtractVector128(p00, p01, 1) ^ AdvSimd.LoadVector128(ps + 48));
            AdvSimd.Store(pd + 64, c0 ^ AdvSimd.LoadVector128(ps + 64));
            AdvSimd.Store(pd + 80, c1 ^ AdvSimd.LoadVector128(ps + 80));
            AdvSimd.Store(pd + 96, AdvSimd.ExtractVector128(q00, q01, 1) ^ AdvSimd.LoadVector128(ps + 96));
            AdvSimd.Store(pd + 112, AdvSimd.ExtractVector128(q01, q00, 1) ^ AdvSimd.LoadVector128(ps + 112));
            AdvSimd.Store(pd + 2, e0 ^ AdvSimd.LoadVector128(ps + 2));
            AdvSimd.Store(pd + 18, e1 ^ AdvSimd.LoadVector128(ps + 18));
            AdvSimd.Store(pd + 34, AdvSimd.ExtractVector128(p11, p10, 1) ^ AdvSimd.LoadVector128(ps + 34));
            AdvSimd.Store(pd + 50, AdvSimd.ExtractVector128(p10, p11, 1) ^ AdvSimd.LoadVector128(ps + 50));
            AdvSimd.Store(pd + 66, g0 ^ AdvSimd.LoadVector128(ps + 66));
            AdvSimd.Store(pd + 82, g1 ^ AdvSimd.LoadVector128(ps + 82));
            AdvSimd.Store(pd + 98, AdvSimd.ExtractVector128(q10, q11, 1) ^ AdvSimd.LoadVector128(ps + 98));
            AdvSimd.Store(pd + 114, AdvSimd.ExtractVector128(q11, q10, 1) ^ AdvSimd.LoadVector128(ps + 114));
            touched |= u11 | u12 | u13 | u14 | u15;
        }
        scratch[257] = touched;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<ulong> Rotate32(Vector128<ulong> x) => AdvSimd.ReverseElement32(x);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<ulong> Rotate24(Vector128<ulong> x, Vector128<byte> table) =>
        AdvSimd.Arm64.VectorTableLookup(x.AsByte(), table).AsUInt64();

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<ulong> Rotate16(Vector128<ulong> x, Vector128<byte> table) =>
        AdvSimd.Arm64.VectorTableLookup(x.AsByte(), table).AsUInt64();
}
#endif
