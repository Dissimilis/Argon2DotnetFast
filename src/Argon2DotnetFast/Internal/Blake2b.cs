using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace Argon2DotnetFast.Internal;

internal ref struct Blake2b
{
    private readonly Span<ulong> state;
    private readonly Span<byte> buffer;
    private int buffered;
    private ulong count;

    private static readonly ulong[] Iv =
    {
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
    };

    private static readonly byte[] Sigma =
    {
         0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,
        14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3,
        11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4,
         7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8,
         9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13,
         2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9,
        12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11,
        13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10,
         6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5,
        10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0
    };

    internal Blake2b(Span<ulong> state, Span<byte> buffer, int outputLength)
    {
        this.state = state;
        this.buffer = buffer;
        buffered = 0;
        count = 0;
        Iv.AsSpan().CopyTo(state);
        state[0] ^= 0x01010000UL ^ (uint)outputLength;
    }

    internal void Update(scoped ReadOnlySpan<byte> input)
    {
        while (!input.IsEmpty)
        {
            // Keep the last full block buffered so finalization marks it correctly.
            if (buffered == 128)
            {
                count += 128;
                Compress(buffer, false);
                buffered = 0;
            }
            int take = Math.Min(128 - buffered, input.Length);
            input.Slice(0, take).CopyTo(buffer.Slice(buffered));
            buffered += take;
            input = input.Slice(take);
        }
    }

    internal void UInt32(int value)
    {
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(bytes, (uint)value);
        Update(bytes);
    }

    internal void Field(scoped ReadOnlySpan<byte> value)
    {
        UInt32(value.Length);
        Update(value);
    }

    internal void Finish(scoped Span<byte> output)
    {
        count += (uint)buffered;
        buffer.Slice(buffered).Clear();
        Compress(buffer, true);
        Span<byte> result = stackalloc byte[64];
        try
        {
            for (int i = 0; i < 8; i++)
                BinaryPrimitives.WriteUInt64LittleEndian(result.Slice(i * 8), state[i]);
            result.Slice(0, output.Length).CopyTo(output);
        }
        finally { Sensitive.Clear(result); }
    }

    public void Dispose()
    {
        Sensitive.Clear(MemoryMarshal.AsBytes(state));
        Sensitive.Clear(buffer);
        count = 0;
        buffered = 0;
    }

    private void Compress(ReadOnlySpan<byte> block, bool final)
    {
        Span<ulong> words = stackalloc ulong[16];
        Span<ulong> v = stackalloc ulong[16];
        try
        {
            for (int i = 0; i < 16; i++)
                words[i] = BinaryPrimitives.ReadUInt64LittleEndian(block.Slice(8 * i));
            state.CopyTo(v);
            Iv.AsSpan().CopyTo(v.Slice(8));
            v[12] ^= count;
            if (final) v[14] = ~v[14];
            for (int round = 0; round < 12; round++)
            {
                ReadOnlySpan<byte> s = Sigma.AsSpan((round % 10) * 16, 16);
                Mix(ref v[0], ref v[4], ref v[8], ref v[12], words[s[0]], words[s[1]]);
                Mix(ref v[1], ref v[5], ref v[9], ref v[13], words[s[2]], words[s[3]]);
                Mix(ref v[2], ref v[6], ref v[10], ref v[14], words[s[4]], words[s[5]]);
                Mix(ref v[3], ref v[7], ref v[11], ref v[15], words[s[6]], words[s[7]]);
                Mix(ref v[0], ref v[5], ref v[10], ref v[15], words[s[8]], words[s[9]]);
                Mix(ref v[1], ref v[6], ref v[11], ref v[12], words[s[10]], words[s[11]]);
                Mix(ref v[2], ref v[7], ref v[8], ref v[13], words[s[12]], words[s[13]]);
                Mix(ref v[3], ref v[4], ref v[9], ref v[14], words[s[14]], words[s[15]]);
            }
            for (int i = 0; i < 8; i++) state[i] ^= v[i] ^ v[i + 8];
        }
        finally
        {
            Sensitive.Clear(MemoryMarshal.AsBytes(words));
            Sensitive.Clear(MemoryMarshal.AsBytes(v));
        }
    }

    internal static ulong Rotate(ulong value, int bits) => (value >> bits) | (value << (64 - bits));

    private static void Mix(ref ulong a, ref ulong b, ref ulong c, ref ulong d, ulong x, ulong y)
    {
        unchecked
        {
            a += b + x;
            d = Rotate(d ^ a, 32);
            c += d;
            b = Rotate(b ^ c, 24);
            a += b + y;
            d = Rotate(d ^ a, 16);
            c += d;
            b = Rotate(b ^ c, 63);
        }
    }

    private static void Hash(ReadOnlySpan<byte> input, Span<byte> output)
    {
        using var hash = new Blake2b(stackalloc ulong[8], stackalloc byte[128], output.Length);
        hash.Update(input);
        hash.Finish(output);
    }

    internal static void LongHash(ReadOnlySpan<byte> input, Span<byte> output)
    {
        using var hash = new Blake2b(stackalloc ulong[8], stackalloc byte[128], Math.Min(output.Length, 64));
        hash.UInt32(output.Length);
        hash.Update(input);
        if (output.Length <= 64)
        {
            hash.Finish(output);
            return;
        }
        Span<byte> chain = stackalloc byte[64];
        try
        {
            hash.Finish(chain);
            chain.Slice(0, 32).CopyTo(output);
            output = output.Slice(32);
            while (output.Length > 64)
            {
                Hash(chain, chain);
                chain.Slice(0, 32).CopyTo(output);
                output = output.Slice(32);
            }
            Hash(chain, output);
        }
        finally { Sensitive.Clear(chain); }
    }
}
