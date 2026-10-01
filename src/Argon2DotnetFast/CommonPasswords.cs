using System.Buffers.Binary;
using Argon2DotnetFast.Internal;

namespace Argon2DotnetFast;

/// <summary>
/// Checks a password against a built-in list of the most common leaked passwords, for refusing one at
/// sign-up or password change. Hashing and verification never call it.
/// </summary>
/// <remarks>
/// The list is the top 10,000 of Mark Burnett's 10 million password set (Public Domain Mark 1.0) as ranked by
/// SecLists, with ASCII A-Z folded to lowercase, stored in about 17 KB. A <see langword="true"/> result is a
/// false positive for about one in 4,096 unlisted passwords. <see langword="false"/> is exact, but it does
/// not mean the password is strong.
/// </remarks>
public static class CommonPasswords
{
    private const int RemainderBits = 12;

    private static ReadOnlySpan<byte> Domain => "Argon2DotnetFast.CommonPasswords.v1"u8;

    /// <summary>
    /// Returns true when the password, with A-Z folded to lowercase, is in the list or is a false positive.
    /// </summary>
    /// <remarks>
    /// The password is encoded as strict UTF-8, as for hashing. The empty password is listed. A password
    /// longer than every listed entry returns false without being hashed.
    /// </remarks>
    /// <exception cref="System.Text.EncoderFallbackException">The password contains an unpaired surrogate.</exception>
    public static bool Contains(ReadOnlySpan<char> password)
    {
        int length = Sensitive.ByteCount(password);
        if (length > CommonPasswordData.MaxLength) return false;
        Span<byte> folded = stackalloc byte[CommonPasswordData.MaxLength];
        try
        {
            Sensitive.EncodeInto(password, folded);
            return Listed(folded.Slice(0, length));
        }
        finally { Sensitive.Clear(folded); }
    }

    /// <summary>
    /// Returns true when the UTF-8 password, with A-Z folded to lowercase, is in the list or is a false positive.
    /// </summary>
    /// <remarks>
    /// The bytes are used without UTF-8 validation, and the span is not written. The empty password is listed.
    /// A password longer than every listed entry returns false without being hashed.
    /// </remarks>
    public static bool Contains(ReadOnlySpan<byte> password)
    {
        if (password.Length > CommonPasswordData.MaxLength) return false;
        Span<byte> folded = stackalloc byte[CommonPasswordData.MaxLength];
        try
        {
            password.CopyTo(folded);
            return Listed(folded.Slice(0, password.Length));
        }
        finally { Sensitive.Clear(folded); }
    }

    private static bool Listed(Span<byte> password)
    {
        Fold(password);
        ulong target = Map(Digest(password), CommonPasswordData.Count);
        return Scan(CommonPasswordData.Stream, CommonPasswordData.Count, target);
    }

    // Bytes of a multi-byte UTF-8 sequence are all 0x80 or above, so only ASCII letters change.
    internal static void Fold(Span<byte> text)
    {
        for (int i = 0; i < text.Length; i++)
            if ((uint)(text[i] - 'A') <= 'Z' - 'A') text[i] |= 0x20;
    }

    internal static ulong Digest(ReadOnlySpan<byte> folded)
    {
        using var hash = new Blake2b(stackalloc ulong[8], stackalloc byte[128], 8);
        hash.Field(Domain);
        hash.Field(folded);
        Span<byte> digest = stackalloc byte[8];
        hash.Finish(digest);
        ulong value = BinaryPrimitives.ReadUInt64LittleEndian(digest);
        Sensitive.Clear(digest);
        return value;
    }

    // count * 4096 is below 2^32, so the product fits in 64 bits without a 128-bit multiply.
    internal static ulong Map(ulong digest, int count) => ((digest >> 32) * ((ulong)count << RemainderBits)) >> 32;

    private static bool Scan(ReadOnlySpan<byte> stream, int count, ulong target)
    {
        ulong value = 0, found = 0;
        int bit = 0;
        for (int i = 0; i < count; i++)
        {
            ulong quotient = 0;
            while ((stream[bit >> 3] & (0x80 >> (bit & 7))) != 0) { quotient++; bit++; }
            bit++;
            ulong remainder = 0;
            for (int j = 0; j < RemainderBits; j++, bit++)
                remainder = (remainder << 1) | (uint)((stream[bit >> 3] >> (7 - (bit & 7))) & 1);
            value += (quotient << RemainderBits) | remainder;

            // No branch on the match, so the time follows the public stream, not where the target falls.
            ulong difference = value ^ target;
            found |= ((difference | (0 - difference)) >> 63) ^ 1;
        }
        return found != 0;
    }
}
