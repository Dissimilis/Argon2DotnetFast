#if NET10_0_OR_GREATER
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;

#pragma warning disable SYSLIB5003 // Sve and Sve2 are experimental in .NET 10.

namespace Argon2DotnetFast.Internal;

// The NEON body with SVE2 instructions where they measured faster, 6 chains in flight
// (3+3+2 rounds per iteration of each pass).
// xar fuses the eor in front of the rotates by 63, 24 and 16.
// The next block's reference is prefetched: at the top when FillSegment already knows it,
// and otherwise as soon as the first column iteration has made word 0 of this block final.
// At the 128-bit vector length .NET 10 uses, a Vector<ulong> and a Vector128<ulong> are the
// same register, so AsVector and AsVector128 cost nothing.
internal static unsafe class Sve2Body
{
    internal static bool IsSupported => Sve2.IsSupported && Vector<byte>.Count == 16;

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
        ulong* next = (ulong*)scratch[264];
        Vector<ulong> one = Sve.CreateTrueMaskUInt64(SveMaskPattern.VectorCount1);
        Sve.Prefetch64Bit(one, next, SvePrefetchType.LoadL1Temporal);
        Sve.Prefetch64Bit(one, next + 8, SvePrefetchType.LoadL1Temporal);
        Sve.Prefetch64Bit(one, next + 16, SvePrefetchType.LoadL1Temporal);
        Sve.Prefetch64Bit(one, next + 24, SvePrefetchType.LoadL1Temporal);
        Sve.Prefetch64Bit(one, next + 32, SvePrefetchType.LoadL1Temporal);
        Sve.Prefetch64Bit(one, next + 40, SvePrefetchType.LoadL1Temporal);
        Sve.Prefetch64Bit(one, next + 48, SvePrefetchType.LoadL1Temporal);
        Sve.Prefetch64Bit(one, next + 56, SvePrefetchType.LoadL1Temporal);
        Sve.Prefetch64Bit(one, next + 64, SvePrefetchType.LoadL1Temporal);
        Sve.Prefetch64Bit(one, next + 72, SvePrefetchType.LoadL1Temporal);
        Sve.Prefetch64Bit(one, next + 80, SvePrefetchType.LoadL1Temporal);
        Sve.Prefetch64Bit(one, next + 88, SvePrefetchType.LoadL1Temporal);
        Sve.Prefetch64Bit(one, next + 96, SvePrefetchType.LoadL1Temporal);
        Sve.Prefetch64Bit(one, next + 104, SvePrefetchType.LoadL1Temporal);
        Sve.Prefetch64Bit(one, next + 112, SvePrefetchType.LoadL1Temporal);
        Sve.Prefetch64Bit(one, next + 120, SvePrefetchType.LoadL1Temporal);
        for (int k = 0; k < 2; k++)
        {
            nint row = 48 * k;
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
            Vector128<ulong> m0 = AdvSimd.LoadVector128(pp + 32) ^ AdvSimd.LoadVector128(pr + 32);
            Vector128<ulong> m1 = AdvSimd.LoadVector128(pp + 34) ^ AdvSimd.LoadVector128(pr + 34);
            Vector128<ulong> n0 = AdvSimd.LoadVector128(pp + 36) ^ AdvSimd.LoadVector128(pr + 36);
            Vector128<ulong> n1 = AdvSimd.LoadVector128(pp + 38) ^ AdvSimd.LoadVector128(pr + 38);
            Vector128<ulong> o0 = AdvSimd.LoadVector128(pp + 40) ^ AdvSimd.LoadVector128(pr + 40);
            Vector128<ulong> o1 = AdvSimd.LoadVector128(pp + 42) ^ AdvSimd.LoadVector128(pr + 42);
            Vector128<ulong> p0 = AdvSimd.LoadVector128(pp + 44) ^ AdvSimd.LoadVector128(pr + 44);
            Vector128<ulong> p1 = AdvSimd.LoadVector128(pp + 46) ^ AdvSimd.LoadVector128(pr + 46);
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
                AdvSimd.Store(ps + 32, m0 ^ AdvSimd.LoadVector128(pd + 32));
                AdvSimd.Store(ps + 34, m1 ^ AdvSimd.LoadVector128(pd + 34));
                AdvSimd.Store(ps + 36, n0 ^ AdvSimd.LoadVector128(pd + 36));
                AdvSimd.Store(ps + 38, n1 ^ AdvSimd.LoadVector128(pd + 38));
                AdvSimd.Store(ps + 40, o0 ^ AdvSimd.LoadVector128(pd + 40));
                AdvSimd.Store(ps + 42, o1 ^ AdvSimd.LoadVector128(pd + 42));
                AdvSimd.Store(ps + 44, p0 ^ AdvSimd.LoadVector128(pd + 44));
                AdvSimd.Store(ps + 46, p1 ^ AdvSimd.LoadVector128(pd + 46));
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
                AdvSimd.Store(ps + 32, m0);
                AdvSimd.Store(ps + 34, m1);
                AdvSimd.Store(ps + 36, n0);
                AdvSimd.Store(ps + 38, n1);
                AdvSimd.Store(ps + 40, o0);
                AdvSimd.Store(ps + 42, o1);
                AdvSimd.Store(ps + 44, p0);
                AdvSimd.Store(ps + 46, p1);
            }

            a0 = BlaMka(a0, b0); a1 = BlaMka(a1, b1);
            e0 = BlaMka(e0, f0); e1 = BlaMka(e1, f1);
            m0 = BlaMka(m0, n0); m1 = BlaMka(m1, n1);
            d0 ^= a0; d1 ^= a1;
            h0 ^= e0; h1 ^= e1;
            p0 ^= m0; p1 ^= m1;
            d0 = Rotate32(d0); d1 = Rotate32(d1);
            h0 = Rotate32(h0); h1 = Rotate32(h1);
            p0 = Rotate32(p0); p1 = Rotate32(p1);
            c0 = BlaMka(c0, d0); c1 = BlaMka(c1, d1);
            g0 = BlaMka(g0, h0); g1 = BlaMka(g1, h1);
            o0 = BlaMka(o0, p0); o1 = BlaMka(o1, p1);
            b0 = Sve2.XorRotateRight(b0.AsVector(), c0.AsVector(), 24).AsVector128(); b1 = Sve2.XorRotateRight(b1.AsVector(), c1.AsVector(), 24).AsVector128();
            f0 = Sve2.XorRotateRight(f0.AsVector(), g0.AsVector(), 24).AsVector128(); f1 = Sve2.XorRotateRight(f1.AsVector(), g1.AsVector(), 24).AsVector128();
            n0 = Sve2.XorRotateRight(n0.AsVector(), o0.AsVector(), 24).AsVector128(); n1 = Sve2.XorRotateRight(n1.AsVector(), o1.AsVector(), 24).AsVector128();
            a0 = BlaMka(a0, b0); a1 = BlaMka(a1, b1);
            e0 = BlaMka(e0, f0); e1 = BlaMka(e1, f1);
            m0 = BlaMka(m0, n0); m1 = BlaMka(m1, n1);
            d0 = Sve2.XorRotateRight(d0.AsVector(), a0.AsVector(), 16).AsVector128(); d1 = Sve2.XorRotateRight(d1.AsVector(), a1.AsVector(), 16).AsVector128();
            h0 = Sve2.XorRotateRight(h0.AsVector(), e0.AsVector(), 16).AsVector128(); h1 = Sve2.XorRotateRight(h1.AsVector(), e1.AsVector(), 16).AsVector128();
            p0 = Sve2.XorRotateRight(p0.AsVector(), m0.AsVector(), 16).AsVector128(); p1 = Sve2.XorRotateRight(p1.AsVector(), m1.AsVector(), 16).AsVector128();
            c0 = BlaMka(c0, d0); c1 = BlaMka(c1, d1);
            g0 = BlaMka(g0, h0); g1 = BlaMka(g1, h1);
            o0 = BlaMka(o0, p0); o1 = BlaMka(o1, p1);
            b0 = Sve2.XorRotateRight(b0.AsVector(), c0.AsVector(), 63).AsVector128(); b1 = Sve2.XorRotateRight(b1.AsVector(), c1.AsVector(), 63).AsVector128();
            f0 = Sve2.XorRotateRight(f0.AsVector(), g0.AsVector(), 63).AsVector128(); f1 = Sve2.XorRotateRight(f1.AsVector(), g1.AsVector(), 63).AsVector128();
            n0 = Sve2.XorRotateRight(n0.AsVector(), o0.AsVector(), 63).AsVector128(); n1 = Sve2.XorRotateRight(n1.AsVector(), o1.AsVector(), 63).AsVector128();

            Vector128<ulong> p00 = AdvSimd.ExtractVector128(b0, b1, 1);
            Vector128<ulong> p10 = AdvSimd.ExtractVector128(f0, f1, 1);
            Vector128<ulong> p20 = AdvSimd.ExtractVector128(n0, n1, 1);
            Vector128<ulong> p01 = AdvSimd.ExtractVector128(b1, b0, 1);
            Vector128<ulong> p11 = AdvSimd.ExtractVector128(f1, f0, 1);
            Vector128<ulong> p21 = AdvSimd.ExtractVector128(n1, n0, 1);
            Vector128<ulong> q00 = AdvSimd.ExtractVector128(d1, d0, 1);
            Vector128<ulong> q10 = AdvSimd.ExtractVector128(h1, h0, 1);
            Vector128<ulong> q20 = AdvSimd.ExtractVector128(p1, p0, 1);
            Vector128<ulong> q01 = AdvSimd.ExtractVector128(d0, d1, 1);
            Vector128<ulong> q11 = AdvSimd.ExtractVector128(h0, h1, 1);
            Vector128<ulong> q21 = AdvSimd.ExtractVector128(p0, p1, 1);

            a0 = BlaMka(a0, p00); a1 = BlaMka(a1, p01);
            e0 = BlaMka(e0, p10); e1 = BlaMka(e1, p11);
            m0 = BlaMka(m0, p20); m1 = BlaMka(m1, p21);
            q00 ^= a0; q01 ^= a1;
            q10 ^= e0; q11 ^= e1;
            q20 ^= m0; q21 ^= m1;
            q00 = Rotate32(q00); q01 = Rotate32(q01);
            q10 = Rotate32(q10); q11 = Rotate32(q11);
            q20 = Rotate32(q20); q21 = Rotate32(q21);
            c1 = BlaMka(c1, q00); c0 = BlaMka(c0, q01);
            g1 = BlaMka(g1, q10); g0 = BlaMka(g0, q11);
            o1 = BlaMka(o1, q20); o0 = BlaMka(o0, q21);
            p00 = Sve2.XorRotateRight(p00.AsVector(), c1.AsVector(), 24).AsVector128(); p01 = Sve2.XorRotateRight(p01.AsVector(), c0.AsVector(), 24).AsVector128();
            p10 = Sve2.XorRotateRight(p10.AsVector(), g1.AsVector(), 24).AsVector128(); p11 = Sve2.XorRotateRight(p11.AsVector(), g0.AsVector(), 24).AsVector128();
            p20 = Sve2.XorRotateRight(p20.AsVector(), o1.AsVector(), 24).AsVector128(); p21 = Sve2.XorRotateRight(p21.AsVector(), o0.AsVector(), 24).AsVector128();
            a0 = BlaMka(a0, p00); a1 = BlaMka(a1, p01);
            e0 = BlaMka(e0, p10); e1 = BlaMka(e1, p11);
            m0 = BlaMka(m0, p20); m1 = BlaMka(m1, p21);
            q00 = Sve2.XorRotateRight(q00.AsVector(), a0.AsVector(), 16).AsVector128(); q01 = Sve2.XorRotateRight(q01.AsVector(), a1.AsVector(), 16).AsVector128();
            q10 = Sve2.XorRotateRight(q10.AsVector(), e0.AsVector(), 16).AsVector128(); q11 = Sve2.XorRotateRight(q11.AsVector(), e1.AsVector(), 16).AsVector128();
            q20 = Sve2.XorRotateRight(q20.AsVector(), m0.AsVector(), 16).AsVector128(); q21 = Sve2.XorRotateRight(q21.AsVector(), m1.AsVector(), 16).AsVector128();
            c1 = BlaMka(c1, q00); c0 = BlaMka(c0, q01);
            g1 = BlaMka(g1, q10); g0 = BlaMka(g0, q11);
            o1 = BlaMka(o1, q20); o0 = BlaMka(o0, q21);
            p00 = Sve2.XorRotateRight(p00.AsVector(), c1.AsVector(), 63).AsVector128(); p01 = Sve2.XorRotateRight(p01.AsVector(), c0.AsVector(), 63).AsVector128();
            p10 = Sve2.XorRotateRight(p10.AsVector(), g1.AsVector(), 63).AsVector128(); p11 = Sve2.XorRotateRight(p11.AsVector(), g0.AsVector(), 63).AsVector128();
            p20 = Sve2.XorRotateRight(p20.AsVector(), o1.AsVector(), 63).AsVector128(); p21 = Sve2.XorRotateRight(p21.AsVector(), o0.AsVector(), 63).AsVector128();

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
            AdvSimd.Store(pw + 32, m0);
            AdvSimd.Store(pw + 34, m1);
            AdvSimd.Store(pw + 36, AdvSimd.ExtractVector128(p21, p20, 1));
            AdvSimd.Store(pw + 38, AdvSimd.ExtractVector128(p20, p21, 1));
            AdvSimd.Store(pw + 40, o0);
            AdvSimd.Store(pw + 42, o1);
            AdvSimd.Store(pw + 44, AdvSimd.ExtractVector128(q20, q21, 1));
            AdvSimd.Store(pw + 46, AdvSimd.ExtractVector128(q21, q20, 1));
        }
        {
            nint row = 96;
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

            a0 = BlaMka(a0, b0); a1 = BlaMka(a1, b1);
            e0 = BlaMka(e0, f0); e1 = BlaMka(e1, f1);
            d0 ^= a0; d1 ^= a1;
            h0 ^= e0; h1 ^= e1;
            d0 = Rotate32(d0); d1 = Rotate32(d1);
            h0 = Rotate32(h0); h1 = Rotate32(h1);
            c0 = BlaMka(c0, d0); c1 = BlaMka(c1, d1);
            g0 = BlaMka(g0, h0); g1 = BlaMka(g1, h1);
            b0 = Sve2.XorRotateRight(b0.AsVector(), c0.AsVector(), 24).AsVector128(); b1 = Sve2.XorRotateRight(b1.AsVector(), c1.AsVector(), 24).AsVector128();
            f0 = Sve2.XorRotateRight(f0.AsVector(), g0.AsVector(), 24).AsVector128(); f1 = Sve2.XorRotateRight(f1.AsVector(), g1.AsVector(), 24).AsVector128();
            a0 = BlaMka(a0, b0); a1 = BlaMka(a1, b1);
            e0 = BlaMka(e0, f0); e1 = BlaMka(e1, f1);
            d0 = Sve2.XorRotateRight(d0.AsVector(), a0.AsVector(), 16).AsVector128(); d1 = Sve2.XorRotateRight(d1.AsVector(), a1.AsVector(), 16).AsVector128();
            h0 = Sve2.XorRotateRight(h0.AsVector(), e0.AsVector(), 16).AsVector128(); h1 = Sve2.XorRotateRight(h1.AsVector(), e1.AsVector(), 16).AsVector128();
            c0 = BlaMka(c0, d0); c1 = BlaMka(c1, d1);
            g0 = BlaMka(g0, h0); g1 = BlaMka(g1, h1);
            b0 = Sve2.XorRotateRight(b0.AsVector(), c0.AsVector(), 63).AsVector128(); b1 = Sve2.XorRotateRight(b1.AsVector(), c1.AsVector(), 63).AsVector128();
            f0 = Sve2.XorRotateRight(f0.AsVector(), g0.AsVector(), 63).AsVector128(); f1 = Sve2.XorRotateRight(f1.AsVector(), g1.AsVector(), 63).AsVector128();

            Vector128<ulong> p00 = AdvSimd.ExtractVector128(b0, b1, 1);
            Vector128<ulong> p10 = AdvSimd.ExtractVector128(f0, f1, 1);
            Vector128<ulong> p01 = AdvSimd.ExtractVector128(b1, b0, 1);
            Vector128<ulong> p11 = AdvSimd.ExtractVector128(f1, f0, 1);
            Vector128<ulong> q00 = AdvSimd.ExtractVector128(d1, d0, 1);
            Vector128<ulong> q10 = AdvSimd.ExtractVector128(h1, h0, 1);
            Vector128<ulong> q01 = AdvSimd.ExtractVector128(d0, d1, 1);
            Vector128<ulong> q11 = AdvSimd.ExtractVector128(h0, h1, 1);

            a0 = BlaMka(a0, p00); a1 = BlaMka(a1, p01);
            e0 = BlaMka(e0, p10); e1 = BlaMka(e1, p11);
            q00 ^= a0; q01 ^= a1;
            q10 ^= e0; q11 ^= e1;
            q00 = Rotate32(q00); q01 = Rotate32(q01);
            q10 = Rotate32(q10); q11 = Rotate32(q11);
            c1 = BlaMka(c1, q00); c0 = BlaMka(c0, q01);
            g1 = BlaMka(g1, q10); g0 = BlaMka(g0, q11);
            p00 = Sve2.XorRotateRight(p00.AsVector(), c1.AsVector(), 24).AsVector128(); p01 = Sve2.XorRotateRight(p01.AsVector(), c0.AsVector(), 24).AsVector128();
            p10 = Sve2.XorRotateRight(p10.AsVector(), g1.AsVector(), 24).AsVector128(); p11 = Sve2.XorRotateRight(p11.AsVector(), g0.AsVector(), 24).AsVector128();
            a0 = BlaMka(a0, p00); a1 = BlaMka(a1, p01);
            e0 = BlaMka(e0, p10); e1 = BlaMka(e1, p11);
            q00 = Sve2.XorRotateRight(q00.AsVector(), a0.AsVector(), 16).AsVector128(); q01 = Sve2.XorRotateRight(q01.AsVector(), a1.AsVector(), 16).AsVector128();
            q10 = Sve2.XorRotateRight(q10.AsVector(), e0.AsVector(), 16).AsVector128(); q11 = Sve2.XorRotateRight(q11.AsVector(), e1.AsVector(), 16).AsVector128();
            c1 = BlaMka(c1, q00); c0 = BlaMka(c0, q01);
            g1 = BlaMka(g1, q10); g0 = BlaMka(g0, q11);
            p00 = Sve2.XorRotateRight(p00.AsVector(), c1.AsVector(), 63).AsVector128(); p01 = Sve2.XorRotateRight(p01.AsVector(), c0.AsVector(), 63).AsVector128();
            p10 = Sve2.XorRotateRight(p10.AsVector(), g1.AsVector(), 63).AsVector128(); p11 = Sve2.XorRotateRight(p11.AsVector(), g0.AsVector(), 63).AsVector128();

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
        for (int k = 0; k < 2; k++)
        {
            nint column = 6 * k;
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
            Vector128<ulong> m0 = AdvSimd.LoadVector128(p + 4);
            Vector128<ulong> m1 = AdvSimd.LoadVector128(p + 20);
            Vector128<ulong> n0 = AdvSimd.LoadVector128(p + 36);
            Vector128<ulong> n1 = AdvSimd.LoadVector128(p + 52);
            Vector128<ulong> o0 = AdvSimd.LoadVector128(p + 68);
            Vector128<ulong> o1 = AdvSimd.LoadVector128(p + 84);
            Vector128<ulong> p0 = AdvSimd.LoadVector128(p + 100);
            Vector128<ulong> p1 = AdvSimd.LoadVector128(p + 116);

            a0 = BlaMka(a0, b0); a1 = BlaMka(a1, b1);
            e0 = BlaMka(e0, f0); e1 = BlaMka(e1, f1);
            m0 = BlaMka(m0, n0); m1 = BlaMka(m1, n1);
            d0 ^= a0; d1 ^= a1;
            h0 ^= e0; h1 ^= e1;
            p0 ^= m0; p1 ^= m1;
            d0 = Rotate32(d0); d1 = Rotate32(d1);
            h0 = Rotate32(h0); h1 = Rotate32(h1);
            p0 = Rotate32(p0); p1 = Rotate32(p1);
            c0 = BlaMka(c0, d0); c1 = BlaMka(c1, d1);
            g0 = BlaMka(g0, h0); g1 = BlaMka(g1, h1);
            o0 = BlaMka(o0, p0); o1 = BlaMka(o1, p1);
            b0 = Sve2.XorRotateRight(b0.AsVector(), c0.AsVector(), 24).AsVector128(); b1 = Sve2.XorRotateRight(b1.AsVector(), c1.AsVector(), 24).AsVector128();
            f0 = Sve2.XorRotateRight(f0.AsVector(), g0.AsVector(), 24).AsVector128(); f1 = Sve2.XorRotateRight(f1.AsVector(), g1.AsVector(), 24).AsVector128();
            n0 = Sve2.XorRotateRight(n0.AsVector(), o0.AsVector(), 24).AsVector128(); n1 = Sve2.XorRotateRight(n1.AsVector(), o1.AsVector(), 24).AsVector128();
            a0 = BlaMka(a0, b0); a1 = BlaMka(a1, b1);
            e0 = BlaMka(e0, f0); e1 = BlaMka(e1, f1);
            m0 = BlaMka(m0, n0); m1 = BlaMka(m1, n1);
            d0 = Sve2.XorRotateRight(d0.AsVector(), a0.AsVector(), 16).AsVector128(); d1 = Sve2.XorRotateRight(d1.AsVector(), a1.AsVector(), 16).AsVector128();
            h0 = Sve2.XorRotateRight(h0.AsVector(), e0.AsVector(), 16).AsVector128(); h1 = Sve2.XorRotateRight(h1.AsVector(), e1.AsVector(), 16).AsVector128();
            p0 = Sve2.XorRotateRight(p0.AsVector(), m0.AsVector(), 16).AsVector128(); p1 = Sve2.XorRotateRight(p1.AsVector(), m1.AsVector(), 16).AsVector128();
            c0 = BlaMka(c0, d0); c1 = BlaMka(c1, d1);
            g0 = BlaMka(g0, h0); g1 = BlaMka(g1, h1);
            o0 = BlaMka(o0, p0); o1 = BlaMka(o1, p1);
            b0 = Sve2.XorRotateRight(b0.AsVector(), c0.AsVector(), 63).AsVector128(); b1 = Sve2.XorRotateRight(b1.AsVector(), c1.AsVector(), 63).AsVector128();
            f0 = Sve2.XorRotateRight(f0.AsVector(), g0.AsVector(), 63).AsVector128(); f1 = Sve2.XorRotateRight(f1.AsVector(), g1.AsVector(), 63).AsVector128();
            n0 = Sve2.XorRotateRight(n0.AsVector(), o0.AsVector(), 63).AsVector128(); n1 = Sve2.XorRotateRight(n1.AsVector(), o1.AsVector(), 63).AsVector128();

            Vector128<ulong> p00 = AdvSimd.ExtractVector128(b0, b1, 1);
            Vector128<ulong> p10 = AdvSimd.ExtractVector128(f0, f1, 1);
            Vector128<ulong> p20 = AdvSimd.ExtractVector128(n0, n1, 1);
            Vector128<ulong> p01 = AdvSimd.ExtractVector128(b1, b0, 1);
            Vector128<ulong> p11 = AdvSimd.ExtractVector128(f1, f0, 1);
            Vector128<ulong> p21 = AdvSimd.ExtractVector128(n1, n0, 1);
            Vector128<ulong> q00 = AdvSimd.ExtractVector128(d1, d0, 1);
            Vector128<ulong> q10 = AdvSimd.ExtractVector128(h1, h0, 1);
            Vector128<ulong> q20 = AdvSimd.ExtractVector128(p1, p0, 1);
            Vector128<ulong> q01 = AdvSimd.ExtractVector128(d0, d1, 1);
            Vector128<ulong> q11 = AdvSimd.ExtractVector128(h0, h1, 1);
            Vector128<ulong> q21 = AdvSimd.ExtractVector128(p0, p1, 1);

            a0 = BlaMka(a0, p00); a1 = BlaMka(a1, p01);
            e0 = BlaMka(e0, p10); e1 = BlaMka(e1, p11);
            m0 = BlaMka(m0, p20); m1 = BlaMka(m1, p21);
            q00 ^= a0; q01 ^= a1;
            q10 ^= e0; q11 ^= e1;
            q20 ^= m0; q21 ^= m1;
            q00 = Rotate32(q00); q01 = Rotate32(q01);
            q10 = Rotate32(q10); q11 = Rotate32(q11);
            q20 = Rotate32(q20); q21 = Rotate32(q21);
            c1 = BlaMka(c1, q00); c0 = BlaMka(c0, q01);
            g1 = BlaMka(g1, q10); g0 = BlaMka(g0, q11);
            o1 = BlaMka(o1, q20); o0 = BlaMka(o0, q21);
            p00 = Sve2.XorRotateRight(p00.AsVector(), c1.AsVector(), 24).AsVector128(); p01 = Sve2.XorRotateRight(p01.AsVector(), c0.AsVector(), 24).AsVector128();
            p10 = Sve2.XorRotateRight(p10.AsVector(), g1.AsVector(), 24).AsVector128(); p11 = Sve2.XorRotateRight(p11.AsVector(), g0.AsVector(), 24).AsVector128();
            p20 = Sve2.XorRotateRight(p20.AsVector(), o1.AsVector(), 24).AsVector128(); p21 = Sve2.XorRotateRight(p21.AsVector(), o0.AsVector(), 24).AsVector128();
            a0 = BlaMka(a0, p00); a1 = BlaMka(a1, p01);
            e0 = BlaMka(e0, p10); e1 = BlaMka(e1, p11);
            m0 = BlaMka(m0, p20); m1 = BlaMka(m1, p21);
            q00 = Sve2.XorRotateRight(q00.AsVector(), a0.AsVector(), 16).AsVector128(); q01 = Sve2.XorRotateRight(q01.AsVector(), a1.AsVector(), 16).AsVector128();
            q10 = Sve2.XorRotateRight(q10.AsVector(), e0.AsVector(), 16).AsVector128(); q11 = Sve2.XorRotateRight(q11.AsVector(), e1.AsVector(), 16).AsVector128();
            q20 = Sve2.XorRotateRight(q20.AsVector(), m0.AsVector(), 16).AsVector128(); q21 = Sve2.XorRotateRight(q21.AsVector(), m1.AsVector(), 16).AsVector128();
            c1 = BlaMka(c1, q00); c0 = BlaMka(c0, q01);
            g1 = BlaMka(g1, q10); g0 = BlaMka(g0, q11);
            o1 = BlaMka(o1, q20); o0 = BlaMka(o0, q21);
            p00 = Sve2.XorRotateRight(p00.AsVector(), c1.AsVector(), 63).AsVector128(); p01 = Sve2.XorRotateRight(p01.AsVector(), c0.AsVector(), 63).AsVector128();
            p10 = Sve2.XorRotateRight(p10.AsVector(), g1.AsVector(), 63).AsVector128(); p11 = Sve2.XorRotateRight(p11.AsVector(), g0.AsVector(), 63).AsVector128();
            p20 = Sve2.XorRotateRight(p20.AsVector(), o1.AsVector(), 63).AsVector128(); p21 = Sve2.XorRotateRight(p21.AsVector(), o0.AsVector(), 63).AsVector128();

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
            AdvSimd.Store(pd + 4, m0 ^ AdvSimd.LoadVector128(ps + 4));
            AdvSimd.Store(pd + 20, m1 ^ AdvSimd.LoadVector128(ps + 20));
            AdvSimd.Store(pd + 36, AdvSimd.ExtractVector128(p21, p20, 1) ^ AdvSimd.LoadVector128(ps + 36));
            AdvSimd.Store(pd + 52, AdvSimd.ExtractVector128(p20, p21, 1) ^ AdvSimd.LoadVector128(ps + 52));
            AdvSimd.Store(pd + 68, o0 ^ AdvSimd.LoadVector128(ps + 68));
            AdvSimd.Store(pd + 84, o1 ^ AdvSimd.LoadVector128(ps + 84));
            AdvSimd.Store(pd + 100, AdvSimd.ExtractVector128(q20, q21, 1) ^ AdvSimd.LoadVector128(ps + 100));
            AdvSimd.Store(pd + 116, AdvSimd.ExtractVector128(q21, q20, 1) ^ AdvSimd.LoadVector128(ps + 116));
            if (k == 0 && scratch[265] != 0)
            {
                // Word 0 of this block is final, so the next block's reference is known.
                ulong* following = Argon2Core.NextReference(scratch, destination[0]);
                Sve.Prefetch64Bit(one, following, SvePrefetchType.LoadL1Temporal);
                Sve.Prefetch64Bit(one, following + 8, SvePrefetchType.LoadL1Temporal);
                Sve.Prefetch64Bit(one, following + 16, SvePrefetchType.LoadL1Temporal);
                Sve.Prefetch64Bit(one, following + 24, SvePrefetchType.LoadL1Temporal);
                Sve.Prefetch64Bit(one, following + 32, SvePrefetchType.LoadL1Temporal);
                Sve.Prefetch64Bit(one, following + 40, SvePrefetchType.LoadL1Temporal);
                Sve.Prefetch64Bit(one, following + 48, SvePrefetchType.LoadL1Temporal);
                Sve.Prefetch64Bit(one, following + 56, SvePrefetchType.LoadL1Temporal);
                Sve.Prefetch64Bit(one, following + 64, SvePrefetchType.LoadL1Temporal);
                Sve.Prefetch64Bit(one, following + 72, SvePrefetchType.LoadL1Temporal);
                Sve.Prefetch64Bit(one, following + 80, SvePrefetchType.LoadL1Temporal);
                Sve.Prefetch64Bit(one, following + 88, SvePrefetchType.LoadL1Temporal);
                Sve.Prefetch64Bit(one, following + 96, SvePrefetchType.LoadL1Temporal);
                Sve.Prefetch64Bit(one, following + 104, SvePrefetchType.LoadL1Temporal);
                Sve.Prefetch64Bit(one, following + 112, SvePrefetchType.LoadL1Temporal);
                Sve.Prefetch64Bit(one, following + 120, SvePrefetchType.LoadL1Temporal);
            }
        }
        {
            nint column = 12;
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

            a0 = BlaMka(a0, b0); a1 = BlaMka(a1, b1);
            e0 = BlaMka(e0, f0); e1 = BlaMka(e1, f1);
            d0 ^= a0; d1 ^= a1;
            h0 ^= e0; h1 ^= e1;
            d0 = Rotate32(d0); d1 = Rotate32(d1);
            h0 = Rotate32(h0); h1 = Rotate32(h1);
            c0 = BlaMka(c0, d0); c1 = BlaMka(c1, d1);
            g0 = BlaMka(g0, h0); g1 = BlaMka(g1, h1);
            b0 = Sve2.XorRotateRight(b0.AsVector(), c0.AsVector(), 24).AsVector128(); b1 = Sve2.XorRotateRight(b1.AsVector(), c1.AsVector(), 24).AsVector128();
            f0 = Sve2.XorRotateRight(f0.AsVector(), g0.AsVector(), 24).AsVector128(); f1 = Sve2.XorRotateRight(f1.AsVector(), g1.AsVector(), 24).AsVector128();
            a0 = BlaMka(a0, b0); a1 = BlaMka(a1, b1);
            e0 = BlaMka(e0, f0); e1 = BlaMka(e1, f1);
            d0 = Sve2.XorRotateRight(d0.AsVector(), a0.AsVector(), 16).AsVector128(); d1 = Sve2.XorRotateRight(d1.AsVector(), a1.AsVector(), 16).AsVector128();
            h0 = Sve2.XorRotateRight(h0.AsVector(), e0.AsVector(), 16).AsVector128(); h1 = Sve2.XorRotateRight(h1.AsVector(), e1.AsVector(), 16).AsVector128();
            c0 = BlaMka(c0, d0); c1 = BlaMka(c1, d1);
            g0 = BlaMka(g0, h0); g1 = BlaMka(g1, h1);
            b0 = Sve2.XorRotateRight(b0.AsVector(), c0.AsVector(), 63).AsVector128(); b1 = Sve2.XorRotateRight(b1.AsVector(), c1.AsVector(), 63).AsVector128();
            f0 = Sve2.XorRotateRight(f0.AsVector(), g0.AsVector(), 63).AsVector128(); f1 = Sve2.XorRotateRight(f1.AsVector(), g1.AsVector(), 63).AsVector128();

            Vector128<ulong> p00 = AdvSimd.ExtractVector128(b0, b1, 1);
            Vector128<ulong> p10 = AdvSimd.ExtractVector128(f0, f1, 1);
            Vector128<ulong> p01 = AdvSimd.ExtractVector128(b1, b0, 1);
            Vector128<ulong> p11 = AdvSimd.ExtractVector128(f1, f0, 1);
            Vector128<ulong> q00 = AdvSimd.ExtractVector128(d1, d0, 1);
            Vector128<ulong> q10 = AdvSimd.ExtractVector128(h1, h0, 1);
            Vector128<ulong> q01 = AdvSimd.ExtractVector128(d0, d1, 1);
            Vector128<ulong> q11 = AdvSimd.ExtractVector128(h0, h1, 1);

            a0 = BlaMka(a0, p00); a1 = BlaMka(a1, p01);
            e0 = BlaMka(e0, p10); e1 = BlaMka(e1, p11);
            q00 ^= a0; q01 ^= a1;
            q10 ^= e0; q11 ^= e1;
            q00 = Rotate32(q00); q01 = Rotate32(q01);
            q10 = Rotate32(q10); q11 = Rotate32(q11);
            c1 = BlaMka(c1, q00); c0 = BlaMka(c0, q01);
            g1 = BlaMka(g1, q10); g0 = BlaMka(g0, q11);
            p00 = Sve2.XorRotateRight(p00.AsVector(), c1.AsVector(), 24).AsVector128(); p01 = Sve2.XorRotateRight(p01.AsVector(), c0.AsVector(), 24).AsVector128();
            p10 = Sve2.XorRotateRight(p10.AsVector(), g1.AsVector(), 24).AsVector128(); p11 = Sve2.XorRotateRight(p11.AsVector(), g0.AsVector(), 24).AsVector128();
            a0 = BlaMka(a0, p00); a1 = BlaMka(a1, p01);
            e0 = BlaMka(e0, p10); e1 = BlaMka(e1, p11);
            q00 = Sve2.XorRotateRight(q00.AsVector(), a0.AsVector(), 16).AsVector128(); q01 = Sve2.XorRotateRight(q01.AsVector(), a1.AsVector(), 16).AsVector128();
            q10 = Sve2.XorRotateRight(q10.AsVector(), e0.AsVector(), 16).AsVector128(); q11 = Sve2.XorRotateRight(q11.AsVector(), e1.AsVector(), 16).AsVector128();
            c1 = BlaMka(c1, q00); c0 = BlaMka(c0, q01);
            g1 = BlaMka(g1, q10); g0 = BlaMka(g0, q11);
            p00 = Sve2.XorRotateRight(p00.AsVector(), c1.AsVector(), 63).AsVector128(); p01 = Sve2.XorRotateRight(p01.AsVector(), c0.AsVector(), 63).AsVector128();
            p10 = Sve2.XorRotateRight(p10.AsVector(), g1.AsVector(), 63).AsVector128(); p11 = Sve2.XorRotateRight(p11.AsVector(), g0.AsVector(), 63).AsVector128();

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
        }
    }

    // x + y + 2 * lo32(x) * lo32(y) per 64-bit lane: two umlal in series onto x + y.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<ulong> BlaMka(Vector128<ulong> x, Vector128<ulong> y)
    {
        Vector64<uint> lx = AdvSimd.ExtractNarrowingLower(x), ly = AdvSimd.ExtractNarrowingLower(y);
        Vector128<ulong> sum = AdvSimd.MultiplyWideningLowerAndAdd(AdvSimd.Add(x, y), lx, ly);
        return AdvSimd.MultiplyWideningLowerAndAdd(sum, lx, ly);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<ulong> Rotate32(Vector128<ulong> x) => AdvSimd.ReverseElement32(x);
}
#endif
