using System.Runtime.CompilerServices;

namespace Argon2DotnetFast.Internal;

// Runtime choice of the compression body. One binary; scalar wherever no measured body applies.
internal static unsafe class Kernel
{
#if NET
    private static readonly bool UseNeon = Neon.IsSupported;
    private static readonly bool UseAvx512Vl = Avx512VlBody.IsSupported;
    private static readonly bool UseAvx2 = Avx2Body.IsSupported;

#if NET10_0_OR_GREATER
    internal static string Name =>
        UseNeon ? (Sve2Body.IsSupported ? "sve2" : "neon") : UseAvx512Vl ? "avx512vl" : UseAvx2 ? "avx2" : "scalar";
#else
    internal static string Name =>
        UseNeon ? "neon" : UseAvx512Vl ? "avx512vl" : UseAvx2 ? "avx2" : "scalar";
#endif
#else
    internal static string Name => "scalar";
#endif

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static void Fill(ReadOnlySpan<ulong> previous, ReadOnlySpan<ulong> reference,
        Span<ulong> destination, Span<ulong> scratch)
    {
#if NET
        if (UseNeon)
        {
            fixed (ulong* p = previous, r = reference, d = destination, s = scratch) Neon.Fill(p, r, d, s);
            return;
        }
        if (UseAvx512Vl)
        {
            fixed (ulong* p = previous, r = reference, d = destination, s = scratch) Avx512VlBody.Fill(p, r, d, s);
            return;
        }
        if (UseAvx2)
        {
            fixed (ulong* p = previous, r = reference, d = destination, s = scratch) Avx2Body.Fill(p, r, d, s);
            return;
        }
#endif
        Scalar.Fill(previous, reference, destination, scratch);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static void FillXor(ReadOnlySpan<ulong> previous, ReadOnlySpan<ulong> reference,
        Span<ulong> destination, Span<ulong> scratch)
    {
#if NET
        if (UseNeon)
        {
            fixed (ulong* p = previous, r = reference, d = destination, s = scratch) Neon.FillXor(p, r, d, s);
            return;
        }
        if (UseAvx512Vl)
        {
            fixed (ulong* p = previous, r = reference, d = destination, s = scratch) Avx512VlBody.FillXor(p, r, d, s);
            return;
        }
        if (UseAvx2)
        {
            fixed (ulong* p = previous, r = reference, d = destination, s = scratch) Avx2Body.FillXor(p, r, d, s);
            return;
        }
#endif
        Scalar.FillXor(previous, reference, destination, scratch);
    }
}
