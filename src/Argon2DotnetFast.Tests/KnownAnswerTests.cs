using System.Reflection;
using Argon2DotnetFast.Internal;

namespace Argon2DotnetFast.Tests;

// RFC 9106 section 5 and phc-winner-argon2 kats/. The version 19 files are the RFC vectors.
// Inputs are shared: m=32 KiB, t=3, p=4, 32-byte tag, password 32 x 0x01, salt 16 x 0x02,
// secret 8 x 0x03, associated data 12 x 0x04.
public class KnownAnswerTests
{
    private static readonly byte[] Password = Filled(32, 0x01);
    private static readonly byte[] Salt = Filled(16, 0x02);
    private static readonly byte[] Secret = Filled(8, 0x03);
    private static readonly byte[] AssociatedData = Filled(12, 0x04);

    public static TheoryData<Argon2Type, Argon2Version, string> Vectors => new()
    {
        { Argon2Type.D, Argon2Version.V13, "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb" },
        { Argon2Type.I, Argon2Version.V13, "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8" },
        { Argon2Type.Id, Argon2Version.V13, "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659" },
        { Argon2Type.D, Argon2Version.V10, "96a9d4e5a1734092c85e29f410a45914a5dd1f5cbf08b2670da68a0285abf32b" },
        { Argon2Type.I, Argon2Version.V10, "87aeedd6517ab830cd9765cd8231abb2e647a5dee08f7c05e02fcb763335d0fd" },
        { Argon2Type.Id, Argon2Version.V10, "b64615f07789b66b645b67ee9ed3b377ae350b6bfcbb0fc95141ea8f322613c0" },
    };

    [Theory, MemberData(nameof(Vectors))]
    public void EveryHashingEntryPointMatches(Argon2Type type, Argon2Version version, string tagHex)
    {
        var parameters = new Argon2Parameters(type, 32, 3, 4, 32, version);
        byte[] expected = Convert.FromHexString(tagHex);
        var inputs = new Argon2AdditionalInputs(Secret, AssociatedData);

        Assert.Equal(expected, Argon2.Hash(parameters, Password, Salt, inputs));
        Assert.Equal(expected, Argon2.Hash(parameters, Password, Salt, inputs, threads: 1));

        byte[] destination = new byte[32];
        Argon2.HashInto(parameters, Password, Salt, destination, inputs, threads: 4);
        Assert.Equal(expected, destination);

        using var hasher = new Argon2Hasher(parameters);
        Assert.Equal(expected, hasher.Hash(Password, Salt, inputs));
        Array.Clear(destination);
        hasher.HashInto(Password, Salt, destination, inputs);
        Assert.Equal(expected, destination);
    }

    // A hash writes every block before it reads it, so whatever the blocks held before the first
    // hash cannot reach the tag. The constructor relies on that when it only faults the pages in.
    [Theory, MemberData(nameof(Vectors))]
    public void JunkInTheBlocksBeforeTheFirstHashDoesNotChangeTheTag(Argon2Type type, Argon2Version version, string tagHex)
    {
        var parameters = new Argon2Parameters(type, 32, 3, 4, 32, version);
        foreach (int threads in new[] { 1, 4 })
        {
            using var hasher = new Argon2Hasher(parameters, threads);
            var arena = (Arena)typeof(Argon2Hasher).GetField("arena", BindingFlags.NonPublic | BindingFlags.Instance)!
                .GetValue(hasher)!;
            for (int block = 0; block < parameters.BlockCount; block++)
                arena.Block(block).Fill(0xA5A5_5A5A_DEAD_BEEFUL ^ (ulong)block);
            Assert.Equal(Convert.FromHexString(tagHex),
                hasher.Hash(Password, Salt, new Argon2AdditionalInputs(Secret, AssociatedData)));
        }
    }

    [Theory, MemberData(nameof(Vectors))]
    public void EncodedVectorVerifiesOnlyWithTheSameSecretAndData(Argon2Type type, Argon2Version version, string tagHex)
    {
        var parameters = new Argon2Parameters(type, 32, 3, 4, 32, version);
        string encoded = Argon2.Encode(parameters, Salt, Convert.FromHexString(tagHex));
        var limits = new Argon2VerificationLimits(parameters, maxEncodedLength: 256);

        Assert.True(Argon2.Verify(encoded, Password, limits, new Argon2AdditionalInputs(Secret, AssociatedData)));
        Assert.False(Argon2.Verify(encoded, Password, limits, new Argon2AdditionalInputs(Secret)));
        Assert.False(Argon2.Verify(encoded, Password, limits, new Argon2AdditionalInputs(associatedData: AssociatedData)));

        using var hasher = new Argon2Hasher(parameters);
        Assert.True(hasher.Verify(encoded, Password, limits, new Argon2AdditionalInputs(Secret, AssociatedData)));
        Assert.False(hasher.Verify(encoded, Filled(32, 0x02), limits, new Argon2AdditionalInputs(Secret, AssociatedData)));
    }

    internal static byte[] Filled(int length, byte value)
    {
        byte[] bytes = new byte[length];
        Array.Fill(bytes, value);
        return bytes;
    }
}
