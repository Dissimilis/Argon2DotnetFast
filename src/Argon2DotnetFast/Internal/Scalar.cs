namespace Argon2DotnetFast.Internal;

internal static class Scalar
{
    // r and saved. The caller holds them for the whole hash; the arena wipe clears them, so no
    // block pays for a stack frame or a clear.
    internal const int ScratchWords = 128 + 128;

    internal static void Fill(ReadOnlySpan<ulong> previous, ReadOnlySpan<ulong> reference,
        Span<ulong> destination, Span<ulong> scratch) => Compress(previous, reference, destination, scratch, false);

    // Version 19 after the first pass: the new block is XORed into the one it replaces.
    internal static void FillXor(ReadOnlySpan<ulong> previous, ReadOnlySpan<ulong> reference,
        Span<ulong> destination, Span<ulong> scratch) => Compress(previous, reference, destination, scratch, true);

    // Every row reads its input before any column writes the destination, so this also holds when
    // destination aliases reference in the address generator.
    private static void Compress(ReadOnlySpan<ulong> previous, ReadOnlySpan<ulong> reference,
        Span<ulong> destination, Span<ulong> scratch, bool xor)
    {
        Span<ulong> r = scratch.Slice(0, 128);
        Span<ulong> saved = scratch.Slice(128, 128);
        for (int row = 0; row < 8; row++)
        {
            int at = row * 16;
            RoundIn(previous.Slice(at, 16), reference.Slice(at, 16), destination.Slice(at, 16),
                r.Slice(at, 16), saved.Slice(at, 16), xor);
        }
        for (int col = 0; col < 8; col++) RoundOut(r.Slice(col * 2), saved.Slice(col * 2), destination.Slice(col * 2));
    }

    // One BLAKE2b round without the message words. The four G's of each half are independent, so
    // each step is written across all four before the next one: RyuJIT emits in source order.
    // A row round that reads its input as previous ^ reference and writes the saved copy (R, or
    // R ^ old in XOR mode) on the way in, so Fill makes no separate pass over the block.
    private static void RoundIn(ReadOnlySpan<ulong> p, ReadOnlySpan<ulong> q, ReadOnlySpan<ulong> old,
        Span<ulong> v, Span<ulong> saved, bool xor)
    {
        ulong v15 = p[15] ^ q[15], v0 = p[0] ^ q[0], v1 = p[1] ^ q[1], v2 = p[2] ^ q[2], v3 = p[3] ^ q[3],
            v4 = p[4] ^ q[4], v5 = p[5] ^ q[5], v6 = p[6] ^ q[6], v7 = p[7] ^ q[7], v8 = p[8] ^ q[8],
            v9 = p[9] ^ q[9], v10 = p[10] ^ q[10], v11 = p[11] ^ q[11], v12 = p[12] ^ q[12],
            v13 = p[13] ^ q[13], v14 = p[14] ^ q[14];
        if (xor)
        {
            saved[15] = v15 ^ old[15]; saved[0] = v0 ^ old[0]; saved[1] = v1 ^ old[1]; saved[2] = v2 ^ old[2];
            saved[3] = v3 ^ old[3]; saved[4] = v4 ^ old[4]; saved[5] = v5 ^ old[5]; saved[6] = v6 ^ old[6];
            saved[7] = v7 ^ old[7]; saved[8] = v8 ^ old[8]; saved[9] = v9 ^ old[9];
            saved[10] = v10 ^ old[10]; saved[11] = v11 ^ old[11]; saved[12] = v12 ^ old[12];
            saved[13] = v13 ^ old[13]; saved[14] = v14 ^ old[14];
        }
        else
        {
            saved[15] = v15; saved[0] = v0; saved[1] = v1; saved[2] = v2; saved[3] = v3; saved[4] = v4;
            saved[5] = v5; saved[6] = v6; saved[7] = v7; saved[8] = v8; saved[9] = v9; saved[10] = v10;
            saved[11] = v11; saved[12] = v12; saved[13] = v13; saved[14] = v14;
        }

        v0 = Add(v0, v4); v1 = Add(v1, v5); v2 = Add(v2, v6); v3 = Add(v3, v7);
        v12 = Blake2b.Rotate(v12 ^ v0, 32); v13 = Blake2b.Rotate(v13 ^ v1, 32);
        v14 = Blake2b.Rotate(v14 ^ v2, 32); v15 = Blake2b.Rotate(v15 ^ v3, 32);
        v8 = Add(v8, v12); v9 = Add(v9, v13); v10 = Add(v10, v14); v11 = Add(v11, v15);
        v4 = Blake2b.Rotate(v4 ^ v8, 24); v5 = Blake2b.Rotate(v5 ^ v9, 24);
        v6 = Blake2b.Rotate(v6 ^ v10, 24); v7 = Blake2b.Rotate(v7 ^ v11, 24);
        v0 = Add(v0, v4); v1 = Add(v1, v5); v2 = Add(v2, v6); v3 = Add(v3, v7);
        v12 = Blake2b.Rotate(v12 ^ v0, 16); v13 = Blake2b.Rotate(v13 ^ v1, 16);
        v14 = Blake2b.Rotate(v14 ^ v2, 16); v15 = Blake2b.Rotate(v15 ^ v3, 16);
        v8 = Add(v8, v12); v9 = Add(v9, v13); v10 = Add(v10, v14); v11 = Add(v11, v15);
        v4 = Blake2b.Rotate(v4 ^ v8, 63); v5 = Blake2b.Rotate(v5 ^ v9, 63);
        v6 = Blake2b.Rotate(v6 ^ v10, 63); v7 = Blake2b.Rotate(v7 ^ v11, 63);

        v0 = Add(v0, v5); v1 = Add(v1, v6); v2 = Add(v2, v7); v3 = Add(v3, v4);
        v15 = Blake2b.Rotate(v15 ^ v0, 32); v12 = Blake2b.Rotate(v12 ^ v1, 32);
        v13 = Blake2b.Rotate(v13 ^ v2, 32); v14 = Blake2b.Rotate(v14 ^ v3, 32);
        v10 = Add(v10, v15); v11 = Add(v11, v12); v8 = Add(v8, v13); v9 = Add(v9, v14);
        v5 = Blake2b.Rotate(v5 ^ v10, 24); v6 = Blake2b.Rotate(v6 ^ v11, 24);
        v7 = Blake2b.Rotate(v7 ^ v8, 24); v4 = Blake2b.Rotate(v4 ^ v9, 24);
        v0 = Add(v0, v5); v1 = Add(v1, v6); v2 = Add(v2, v7); v3 = Add(v3, v4);
        v15 = Blake2b.Rotate(v15 ^ v0, 16); v12 = Blake2b.Rotate(v12 ^ v1, 16);
        v13 = Blake2b.Rotate(v13 ^ v2, 16); v14 = Blake2b.Rotate(v14 ^ v3, 16);
        v10 = Add(v10, v15); v11 = Add(v11, v12); v8 = Add(v8, v13); v9 = Add(v9, v14);
        v5 = Blake2b.Rotate(v5 ^ v10, 63); v6 = Blake2b.Rotate(v6 ^ v11, 63);
        v7 = Blake2b.Rotate(v7 ^ v8, 63); v4 = Blake2b.Rotate(v4 ^ v9, 63);

        v[15] = v15; v[0] = v0; v[1] = v1; v[2] = v2; v[3] = v3; v[4] = v4; v[5] = v5; v[6] = v6; v[7] = v7;
        v[8] = v8; v[9] = v9; v[10] = v10; v[11] = v11; v[12] = v12; v[13] = v13; v[14] = v14;
    }

    // A column round on r (word i of the column at 16 * (i / 2) + i % 2) that stores saved ^ result
    // straight to the destination.
    private static void RoundOut(ReadOnlySpan<ulong> v, ReadOnlySpan<ulong> saved, Span<ulong> d)
    {
        ulong v15 = v[113], v0 = v[0], v1 = v[1], v2 = v[16], v3 = v[17], v4 = v[32], v5 = v[33], v6 = v[48],
            v7 = v[49], v8 = v[64], v9 = v[65], v10 = v[80], v11 = v[81], v12 = v[96], v13 = v[97],
            v14 = v[112];

        v0 = Add(v0, v4); v1 = Add(v1, v5); v2 = Add(v2, v6); v3 = Add(v3, v7);
        v12 = Blake2b.Rotate(v12 ^ v0, 32); v13 = Blake2b.Rotate(v13 ^ v1, 32);
        v14 = Blake2b.Rotate(v14 ^ v2, 32); v15 = Blake2b.Rotate(v15 ^ v3, 32);
        v8 = Add(v8, v12); v9 = Add(v9, v13); v10 = Add(v10, v14); v11 = Add(v11, v15);
        v4 = Blake2b.Rotate(v4 ^ v8, 24); v5 = Blake2b.Rotate(v5 ^ v9, 24);
        v6 = Blake2b.Rotate(v6 ^ v10, 24); v7 = Blake2b.Rotate(v7 ^ v11, 24);
        v0 = Add(v0, v4); v1 = Add(v1, v5); v2 = Add(v2, v6); v3 = Add(v3, v7);
        v12 = Blake2b.Rotate(v12 ^ v0, 16); v13 = Blake2b.Rotate(v13 ^ v1, 16);
        v14 = Blake2b.Rotate(v14 ^ v2, 16); v15 = Blake2b.Rotate(v15 ^ v3, 16);
        v8 = Add(v8, v12); v9 = Add(v9, v13); v10 = Add(v10, v14); v11 = Add(v11, v15);
        v4 = Blake2b.Rotate(v4 ^ v8, 63); v5 = Blake2b.Rotate(v5 ^ v9, 63);
        v6 = Blake2b.Rotate(v6 ^ v10, 63); v7 = Blake2b.Rotate(v7 ^ v11, 63);

        v0 = Add(v0, v5); v1 = Add(v1, v6); v2 = Add(v2, v7); v3 = Add(v3, v4);
        v15 = Blake2b.Rotate(v15 ^ v0, 32); v12 = Blake2b.Rotate(v12 ^ v1, 32);
        v13 = Blake2b.Rotate(v13 ^ v2, 32); v14 = Blake2b.Rotate(v14 ^ v3, 32);
        v10 = Add(v10, v15); v11 = Add(v11, v12); v8 = Add(v8, v13); v9 = Add(v9, v14);
        v5 = Blake2b.Rotate(v5 ^ v10, 24); v6 = Blake2b.Rotate(v6 ^ v11, 24);
        v7 = Blake2b.Rotate(v7 ^ v8, 24); v4 = Blake2b.Rotate(v4 ^ v9, 24);
        v0 = Add(v0, v5); v1 = Add(v1, v6); v2 = Add(v2, v7); v3 = Add(v3, v4);
        v15 = Blake2b.Rotate(v15 ^ v0, 16); v12 = Blake2b.Rotate(v12 ^ v1, 16);
        v13 = Blake2b.Rotate(v13 ^ v2, 16); v14 = Blake2b.Rotate(v14 ^ v3, 16);
        v10 = Add(v10, v15); v11 = Add(v11, v12); v8 = Add(v8, v13); v9 = Add(v9, v14);
        v5 = Blake2b.Rotate(v5 ^ v10, 63); v6 = Blake2b.Rotate(v6 ^ v11, 63);
        v7 = Blake2b.Rotate(v7 ^ v8, 63); v4 = Blake2b.Rotate(v4 ^ v9, 63);

        d[113] = saved[113] ^ v15; d[0] = saved[0] ^ v0; d[1] = saved[1] ^ v1; d[16] = saved[16] ^ v2;
        d[17] = saved[17] ^ v3; d[32] = saved[32] ^ v4; d[33] = saved[33] ^ v5; d[48] = saved[48] ^ v6;
        d[49] = saved[49] ^ v7; d[64] = saved[64] ^ v8; d[65] = saved[65] ^ v9; d[80] = saved[80] ^ v10;
        d[81] = saved[81] ^ v11; d[96] = saved[96] ^ v12; d[97] = saved[97] ^ v13;
        d[112] = saved[112] ^ v14;
    }

    private static ulong Add(ulong a, ulong b) => unchecked(a + b + 2UL * (uint)a * (uint)b);
}
