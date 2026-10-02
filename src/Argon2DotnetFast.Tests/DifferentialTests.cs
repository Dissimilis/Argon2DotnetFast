using Org.BouncyCastle.Crypto.Generators;
using BcParameters = Org.BouncyCastle.Crypto.Parameters.Argon2Parameters;

namespace Argon2DotnetFast.Tests;

// Second implementations on random parameters. When one disagrees with KnownAnswerTests,
// the known answers win: Konscious has had BLAKE2b boundary bugs.
public class DifferentialTests
{
    private static readonly int[] InterestingTagLengths = { 4, 16, 31, 32, 63, 64, 65, 96, 97, 128, 129, 1024 };

    // BouncyCastle covers every type, both versions, p > 1, secret, and associated data.
    [Fact]
    public void BouncyCastleOnRandomSmallParameters()
    {
        var random = new Random(9106);
        for (int i = 0; i < 2000; i++)
        {
            Case c = Case.Random(random, maxLanes: 6, versions: true);
            AssertSameTag(BouncyCastle(c), c.Ours(i), c);
        }
    }

    // Past 128 blocks per segment the data-independent path generates a second address block.
    [Theory]
    [InlineData(511)]
    [InlineData(512)]
    [InlineData(513)]
    [InlineData(1024)]
    [InlineData(2051)]
    public void BouncyCastleAcrossAddressBlockBoundaries(int memoryKiB)
    {
        var random = new Random(memoryKiB);
        foreach (Argon2Type type in new[] { Argon2Type.D, Argon2Type.I, Argon2Type.Id })
        foreach (Argon2Version version in new[] { Argon2Version.V10, Argon2Version.V13 })
        {
            Case c = Case.Random(random, maxLanes: 2, versions: false) with
            {
                Parameters = new Argon2Parameters(type, memoryKiB, 2, 1 + random.Next(2), 32, version),
            };
            AssertSameTag(BouncyCastle(c), c.Ours(memoryKiB), c);
        }
    }

    // libsodium through NSec: argon2id, version 19, p=1, 16-byte salt, no secret or data, tag >= 16.
    [Fact]
    public void NSecOnArgon2idSingleLane()
    {
        var random = new Random(19);
        for (int i = 0; i < 300; i++)
        {
            int memory = 8 + random.Next(120);
            int tagLength = 16 + random.Next(200);
            byte[] password = Bytes(random, random.Next(200));
            byte[] salt = Bytes(random, 16);
            var parameters = new Argon2Parameters(Argon2Type.Id, memory, 1 + random.Next(3), 1, tagLength);

            var algorithm = NSec.Cryptography.PasswordBasedKeyDerivationAlgorithm.Argon2id(
                new NSec.Cryptography.Argon2Parameters
                {
                    DegreeOfParallelism = 1,
                    MemorySize = parameters.MemoryKiB,
                    NumberOfPasses = parameters.Iterations,
                });
            byte[] expected = algorithm.DeriveBytes(password, salt, tagLength);

            AssertSameTag(expected, Argon2.Hash(parameters, password, salt), parameters);
        }
    }

    // Konscious: every type, p > 1, secret, and associated data. It implements version 19 only
    // and rejects an empty password, so those cases stay with BouncyCastle.
    [Fact]
    public void KonsciousOnRandomParameters()
    {
        var random = new Random(4);
        for (int i = 0; i < 300; i++)
        {
            Case c = Case.Random(random, maxLanes: 4, versions: false);
            if (c.Password.Length == 0) c = c with { Password = Bytes(random, 1 + random.Next(300)) };
            using Konscious.Security.Cryptography.Argon2 konscious = c.Parameters.Type switch
            {
                Argon2Type.D => new Konscious.Security.Cryptography.Argon2d(c.Password),
                Argon2Type.I => new Konscious.Security.Cryptography.Argon2i(c.Password),
                _ => new Konscious.Security.Cryptography.Argon2id(c.Password),
            };
            konscious.Salt = c.Salt;
            konscious.DegreeOfParallelism = c.Parameters.Parallelism;
            konscious.MemorySize = c.Parameters.MemoryKiB;
            konscious.Iterations = c.Parameters.Iterations;
            if (c.Secret.Length > 0) konscious.KnownSecret = c.Secret;
            if (c.AssociatedData.Length > 0) konscious.AssociatedData = c.AssociatedData;
            byte[] expected = konscious.GetBytes(c.Parameters.OutputLength);

            AssertSameTag(expected, c.Ours(i), c);
        }
    }

    private static void AssertSameTag(byte[] oracle, byte[] ours, object context)
    {
        string expected = Convert.ToHexString(oracle), actual = Convert.ToHexString(ours);
        Assert.True(expected == actual, $"{context}\noracle {expected}\nours   {actual}");
    }

    internal static byte[] BouncyCastle(Case c)
    {
        int type = c.Parameters.Type switch
        {
            Argon2Type.D => BcParameters.Argon2d,
            Argon2Type.I => BcParameters.Argon2i,
            _ => BcParameters.Argon2id,
        };
        var builder = new BcParameters.Builder(type)
            .WithVersion(c.Parameters.Version == Argon2Version.V10 ? BcParameters.Version10 : BcParameters.Version13)
            .WithMemoryAsKB(c.Parameters.MemoryKiB)
            .WithIterations(c.Parameters.Iterations)
            .WithParallelism(c.Parameters.Parallelism)
            .WithSalt(c.Salt);
        if (c.Secret.Length > 0) builder.WithSecret(c.Secret);
        if (c.AssociatedData.Length > 0) builder.WithAdditional(c.AssociatedData);
        var generator = new Argon2BytesGenerator();
        generator.Init(builder.Build());
        byte[] output = new byte[c.Parameters.OutputLength];
        generator.GenerateBytes(c.Password, output);
        return output;
    }

    internal static byte[] Bytes(Random random, int length)
    {
        byte[] bytes = new byte[length];
        random.NextBytes(bytes);
        return bytes;
    }

    internal sealed record Case(Argon2Parameters Parameters, byte[] Password, byte[] Salt, byte[] Secret, byte[] AssociatedData)
    {
        internal static Case Random(Random random, int maxLanes, bool versions)
        {
            int lanes = 1 + random.Next(maxLanes);
            // Minimum memory, and memory that does not divide into whole slices, both occur.
            int memory = 8 * lanes + (random.Next(3) == 0 ? 0 : random.Next(48));
            int tagLength = random.Next(2) == 0
                ? InterestingTagLengths[random.Next(InterestingTagLengths.Length)]
                : 4 + random.Next(300);
            var version = versions && random.Next(2) == 0 ? Argon2Version.V10 : Argon2Version.V13;
            var parameters = new Argon2Parameters((Argon2Type)random.Next(3), memory, 1 + random.Next(3), lanes,
                tagLength, version);
            // Password lengths cross the 128-byte BLAKE2b block several times, and empty passwords occur.
            return new Case(parameters, Bytes(random, random.Next(300)), Bytes(random, 8 + random.Next(56)),
                Bytes(random, random.Next(2) == 0 ? 0 : random.Next(64)),
                Bytes(random, random.Next(2) == 0 ? 0 : random.Next(64)));
        }

        // Rotates through the public entry points and thread counts; none of them may change the tag.
        internal byte[] Ours(int selector)
        {
            var inputs = new Argon2AdditionalInputs(Secret, AssociatedData);
            switch (selector % 4)
            {
                case 0:
                    return Argon2.Hash(Parameters, Password, Salt, inputs);
                case 1:
                    byte[] destination = new byte[Parameters.OutputLength];
                    Argon2.HashInto(Parameters, Password, Salt, destination, inputs, threads: 1 + selector % 7);
                    return destination;
                case 2:
                    using (var hasher = new Argon2Hasher(Parameters, threads: 1))
                        return hasher.Hash(Password, Salt, inputs);
                default:
                    using (var hasher = new Argon2Hasher(Parameters))
                    {
                        byte[] output = new byte[Parameters.OutputLength];
                        hasher.HashInto(Password, Salt, output, inputs);
                        return output;
                    }
            }
        }

        public override string ToString() =>
            $"{Parameters}, password {Password.Length} B, salt {Salt.Length} B, secret {Secret.Length} B, data {AssociatedData.Length} B";
    }
}
