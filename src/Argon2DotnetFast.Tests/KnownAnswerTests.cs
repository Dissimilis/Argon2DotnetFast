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

    // phc-winner src/test.c at 256 KiB and t=2, password "password", salt "somesalt", no secret or
    // data; its version 16 strings carry no v= field. The 1 MiB rows were made once with phc-winner
    // f57e61e built from ref.c, for example `printf password | argon2 somesalt -i -t 1 -k 1024 -p 1`:
    // 256 blocks per segment, so the data-independent rows need a second address block.
    public static TheoryData<Argon2Type, Argon2Version, int, int, int, string, string> Reference => new()
    {
        { Argon2Type.I, Argon2Version.V10, 256, 2, 1, "fd4dd83d762c49bdeaf57c47bdcd0c2f1babf863fdeb490df63ede9975fccf06",
            "$argon2i$m=256,t=2,p=1$c29tZXNhbHQ$/U3YPXYsSb3q9XxHvc0MLxur+GP960kN9j7emXX8zwY" },
        { Argon2Type.I, Argon2Version.V10, 256, 2, 2, "b6c11560a6a9d61eac706b79a2f97d68b4463aa3ad87e00c07e2b01e90c564fb",
            "$argon2i$m=256,t=2,p=2$c29tZXNhbHQ$tsEVYKap1h6scGt5ovl9aLRGOqOth+AMB+KwHpDFZPs" },
        { Argon2Type.I, Argon2Version.V13, 256, 2, 1, "89e9029f4637b295beb027056a7336c414fadd43f6b208645281cb214a56452f",
            "$argon2i$v=19$m=256,t=2,p=1$c29tZXNhbHQ$iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8" },
        { Argon2Type.I, Argon2Version.V13, 256, 2, 2, "4ff5ce2769a1d7f4c8a491df09d41a9fbe90e5eb02155a13e4c01e20cd4eab61",
            "$argon2i$v=19$m=256,t=2,p=2$c29tZXNhbHQ$T/XOJ2mh1/TIpJHfCdQan76Q5esCFVoT5MAeIM1Oq2E" },
        { Argon2Type.Id, Argon2Version.V13, 256, 2, 1, "9dfeb910e80bad0311fee20f9c0e2b12c17987b4cac90c2ef54d5b3021c68bfe",
            "$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4" },
        { Argon2Type.Id, Argon2Version.V13, 256, 2, 2, "6d093c501fd5999645e0ea3bf620d7b8be7fd2db59c20d9fff9539da2bf57037",
            "$argon2id$v=19$m=256,t=2,p=2$c29tZXNhbHQ$bQk8UB/VmZZF4Oo79iDXuL5/0ttZwg2f/5U52iv1cDc" },
        { Argon2Type.I, Argon2Version.V13, 1024, 1, 1, "95466cc4f92f874954617eec0aa1195d22980abd625e5cac44763ae3a9cb6ab7",
            "$argon2i$v=19$m=1024,t=1,p=1$c29tZXNhbHQ$lUZsxPkvh0lUYX7sCqEZXSKYCr1iXlysRHY646nLarc" },
        { Argon2Type.Id, Argon2Version.V13, 1024, 1, 1, "c8e9aedc956f6a7dff0a4d42940df628623f328ea1235005abac933c57093e23",
            "$argon2id$v=19$m=1024,t=1,p=1$c29tZXNhbHQ$yOmu3JVvan3/Ck1ClA32KGI/Mo6hI1AFq6yTPFcJPiM" },
        { Argon2Type.D, Argon2Version.V13, 1024, 2, 2, "4145a7f3e95bfc3a8b4ce1f23ded3143739270632e6b3276749973f641fa7d07",
            "$argon2d$v=19$m=1024,t=2,p=2$c29tZXNhbHQ$QUWn8+lb/DqLTOHyPe0xQ3OScGMuazJ2dJlz9kH6fQc" },
        { Argon2Type.D, Argon2Version.V10, 1024, 2, 2, "82137b3eb52d1908df20116a40b60f43bdf9d8b792cfa85ea24736ff4802fbe6",
            "$argon2d$v=16$m=1024,t=2,p=2$c29tZXNhbHQ$ghN7PrUtGQjfIBFqQLYPQ7352LeSz6heokc2/0gC++Y" },
    };

    [Theory, MemberData(nameof(Vectors))]
    public void EveryHashingEntryPointMatches(Argon2Type type, Argon2Version version, string tagHex) =>
        AssertEveryEntryPoint(new Argon2Parameters(type, 32, 3, 4, 32, version), Password, Salt,
            new Argon2AdditionalInputs(Secret, AssociatedData), Convert.FromHexString(tagHex));

    [Theory, MemberData(nameof(Reference))]
    public void ReferenceVectorsMatchThroughHashAndVerify(Argon2Type type, Argon2Version version, int memoryKiB,
        int iterations, int lanes, string tagHex, string encoded)
    {
        var parameters = new Argon2Parameters(type, memoryKiB, iterations, lanes, 32, version);
        byte[] password = "password"u8.ToArray();
        byte[] salt = "somesalt"u8.ToArray();
        byte[] expected = Convert.FromHexString(tagHex);
        AssertEveryEntryPoint(parameters, password, salt, default, expected);

        Argon2.Parse(encoded, out Argon2Parameters parsed, out byte[] parsedSalt, out byte[] parsedTag);
        Assert.Equal(parameters, parsed);
        Assert.Equal(salt, parsedSalt);
        Assert.Equal(expected, parsedTag);
        Assert.False(Argon2.NeedsRehash(encoded, parameters));
        string canonical = Argon2.Encode(parameters, salt, expected);
        Assert.Equal(encoded.Contains("$v=") ? canonical : canonical.Replace("$v=16$", "$"), encoded);

        var limits = new Argon2VerificationLimits(parameters, maxEncodedLength: 256);
        Assert.True(Argon2.Verify(encoded, "password", limits));
        Assert.True(Argon2.Verify(encoded, password, limits));
        Assert.False(Argon2.Verify(encoded, "differentpassword", limits));
        using var hasher = new Argon2Hasher(parameters);
        Assert.True(hasher.Verify(encoded, password, limits));
        Assert.False(hasher.Verify(encoded, "Password", limits));
    }

    private static void AssertEveryEntryPoint(in Argon2Parameters parameters, byte[] password, byte[] salt,
        Argon2AdditionalInputs inputs, byte[] expected)
    {
        Assert.Equal(expected, Argon2.Hash(parameters, password, salt, inputs));
        Assert.Equal(expected, Argon2.Hash(parameters, password, salt, inputs, threads: 1));

        byte[] destination = new byte[expected.Length];
        Argon2.HashInto(parameters, password, salt, destination, inputs, threads: 4);
        Assert.Equal(expected, destination);

        using var hasher = new Argon2Hasher(parameters);
        Assert.Equal(expected, hasher.Hash(password, salt, inputs));
        Array.Clear(destination);
        hasher.HashInto(password, salt, destination, inputs);
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
