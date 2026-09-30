using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
#if NET
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
#endif
using System.Security.Cryptography;
using System.Text;

namespace Argon2DotnetFast.Internal;

internal static class Sensitive
{
    private static readonly UTF8Encoding Utf8 = new(false, true);

    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    internal static void Clear(Span<byte> value)
    {
#if NETSTANDARD2_0
        for (int i = 0; i < value.Length; i++) value[i] = 0;
#else
        CryptographicOperations.ZeroMemory(value);
#endif
    }

#if NET
    // For large wipes: non-temporal stores do not read each line before writing it. p is 32-byte
    // aligned and length a multiple of 128. The fence completes the stores before the call returns.
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
    internal static unsafe void ClearNonTemporal(byte* p, long length)
    {
        Vector256<byte> zero = Vector256<byte>.Zero;
        for (long offset = 0; offset < length; offset += 128)
        {
            Avx.StoreAlignedNonTemporal(p + offset, zero);
            Avx.StoreAlignedNonTemporal(p + offset + 32, zero);
            Avx.StoreAlignedNonTemporal(p + offset + 64, zero);
            Avx.StoreAlignedNonTemporal(p + offset + 96, zero);
        }
        Sse.StoreFence();
    }
#endif

    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    internal static bool Equals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
#if NETSTANDARD2_0
        if (left.Length != right.Length) return false;
        int difference = 0;
        for (int i = 0; i < left.Length; i++) difference |= left[i] ^ right[i];
        return difference == 0;
#else
        return CryptographicOperations.FixedTimeEquals(left, right);
#endif
    }

    // Unmanaged memory is never moved by the GC, so no stale copy of the password outlives the clear.
    internal static unsafe NativeBuffer Encode(ReadOnlySpan<char> password)
    {
        if (password.IsEmpty) return default;
        fixed (char* chars = password)
        {
            var buffer = new NativeBuffer(Utf8.GetByteCount(chars, password.Length));
            try
            {
                fixed (byte* destination = buffer.Span)
                    Utf8.GetBytes(chars, password.Length, destination, buffer.Span.Length);
                return buffer;
            }
            catch { buffer.Dispose(); throw; }
        }
    }

    // Throws EncoderFallbackException on an unpaired surrogate, like Encode.
    internal static unsafe int ByteCount(ReadOnlySpan<char> password)
    {
        if (password.IsEmpty) return 0;
        fixed (char* chars = password) return Utf8.GetByteCount(chars, password.Length);
    }

    // destination must hold ByteCount(password) bytes. The caller clears it.
    internal static unsafe int EncodeInto(ReadOnlySpan<char> password, Span<byte> destination)
    {
        if (password.IsEmpty) return 0;
        fixed (char* chars = password)
        fixed (byte* bytes = destination)
            return Utf8.GetBytes(chars, password.Length, bytes, destination.Length);
    }

    internal static byte[] Salt(int length)
    {
        if (length < 8) throw new ArgumentOutOfRangeException("saltLength", "Salt must contain at least eight bytes.");
        byte[] salt = new byte[length];
        using (RandomNumberGenerator rng = RandomNumberGenerator.Create()) rng.GetBytes(salt);
        return salt;
    }
}

// Cleared and freed on dispose. Readonly, so dispose exactly once.
internal readonly unsafe ref struct NativeBuffer
{
    private readonly IntPtr pointer;
    private readonly int length;

    internal NativeBuffer(int length)
    {
        if (length < 0) throw new ArgumentOutOfRangeException(nameof(length));
        pointer = length == 0 ? IntPtr.Zero : Marshal.AllocHGlobal(length);
        this.length = length;
    }

    internal Span<byte> Span => new((void*)pointer, length);

    public void Dispose()
    {
        if (pointer == IntPtr.Zero) return;
        Sensitive.Clear(Span);
        Marshal.FreeHGlobal(pointer);
    }
}
