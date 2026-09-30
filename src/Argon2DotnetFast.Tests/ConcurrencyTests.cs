using System.Text;

namespace Argon2DotnetFast.Tests;

public class ConcurrencyTests
{
    // The prober's call has a destination of the wrong length. When the guard lets it in, it fails
    // validation without hashing. When another call holds the instance, it gets InvalidOperationException.
    [Fact]
    public void OverlappingCallsThrowInsteadOfSharingTheArena()
    {
        var parameters = new Argon2Parameters(Argon2Type.Id, 4096, 2, 1);
        byte[] password = Encoding.UTF8.GetBytes("password");
        byte[] salt = KnownAnswerTests.Filled(16, 0x02);
        byte[] expected = Argon2.Hash(parameters, password, salt);
        using var hasher = new Argon2Hasher(parameters);

        int rejected = 0;
        byte[]? tag = null;
        var worker = new Thread(() =>
        {
            for (int attempt = 0; attempt < 1000 && tag is null; attempt++)
            {
                try { tag = hasher.Hash(password, salt); }
                catch (InvalidOperationException) { }
            }
        });
        worker.Start();
        while (worker.IsAlive)
        {
            try { hasher.HashInto(password, salt, new byte[1]); }
            catch (InvalidOperationException) { rejected++; }
            catch (ArgumentException) { }
        }
        worker.Join();

        Assert.True(rejected > 0, "no overlapping call was observed");
        Assert.Equal(expected, tag);
        Assert.Equal(expected, hasher.Hash(password, salt));
        ApiContractTests.AssertArenaIsZero(hasher);
    }
}
