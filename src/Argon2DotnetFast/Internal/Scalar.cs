namespace Argon2DotnetFast.Internal;

internal static class Scalar
{
    // r, saved, and the 16-word column. The caller holds them for the whole hash; the arena wipe
    // clears them, so no block pays for a stack frame or a clear.
    internal const int ScratchWords = 128 + 128 + 16;

    internal static void Fill(ReadOnlySpan<ulong> previous, ReadOnlySpan<ulong> reference,
        Span<ulong> destination, Span<ulong> scratch)
    {
        Span<ulong> r = scratch.Slice(0, 128);
        Span<ulong> saved = scratch.Slice(128, 128);
        for (int i = 0; i < 128; i++) saved[i] = r[i] = previous[i] ^ reference[i];
        Permute(r, scratch.Slice(256, 16));
        for (int i = 0; i < 128; i++) destination[i] = saved[i] ^ r[i];
    }

    // Version 19 after the first pass: the new block is XORed into the one it replaces.
    internal static void FillXor(ReadOnlySpan<ulong> previous, ReadOnlySpan<ulong> reference,
        Span<ulong> destination, Span<ulong> scratch)
    {
        Span<ulong> r = scratch.Slice(0, 128);
        Span<ulong> saved = scratch.Slice(128, 128);
        for (int i = 0; i < 128; i++)
        {
            r[i] = previous[i] ^ reference[i];
            saved[i] = r[i] ^ destination[i];
        }
        Permute(r, scratch.Slice(256, 16));
        for (int i = 0; i < 128; i++) destination[i] = saved[i] ^ r[i];
    }

    private static void Permute(Span<ulong> r, Span<ulong> column)
    {
        for (int row = 0; row < 8; row++) Round(r.Slice(row * 16, 16));
        for (int col = 0; col < 8; col++)
        {
            for (int row = 0; row < 8; row++)
            {
                column[row * 2] = r[row * 16 + col * 2];
                column[row * 2 + 1] = r[row * 16 + col * 2 + 1];
            }
            Round(column);
            for (int row = 0; row < 8; row++)
            {
                r[row * 16 + col * 2] = column[row * 2];
                r[row * 16 + col * 2 + 1] = column[row * 2 + 1];
            }
        }
    }

    // One BLAKE2b round without the message words. The four G's of each half are independent, so
    // each step is written across all four before the next one: RyuJIT emits in source order.
    private static void Round(Span<ulong> v)
    {
        ulong v15 = v[15], v0 = v[0], v1 = v[1], v2 = v[2], v3 = v[3], v4 = v[4], v5 = v[5], v6 = v[6],
            v7 = v[7], v8 = v[8], v9 = v[9], v10 = v[10], v11 = v[11], v12 = v[12], v13 = v[13], v14 = v[14];

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

        v[15] = v15; v[0] = v0; v[1] = v1; v[2] = v2; v[3] = v3; v[4] = v4; v[5] = v5; v[6] = v6;
        v[7] = v7; v[8] = v8; v[9] = v9; v[10] = v10; v[11] = v11; v[12] = v12; v[13] = v13; v[14] = v14;
    }

    private static ulong Add(ulong a, ulong b) => unchecked(a + b + 2UL * (uint)a * (uint)b);
}
