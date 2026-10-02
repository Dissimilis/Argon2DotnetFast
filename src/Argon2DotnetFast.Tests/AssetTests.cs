using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Argon2DotnetFast.Internal;
using Xunit.Abstractions;

namespace Argon2DotnetFast.Tests;

public class AssetTests(ITestOutputHelper output)
{
    // Fails if a run meant for one library build loaded the other.
    [Fact]
    public void LoadedLibraryIsTheConfiguredTarget()
    {
        string configured = typeof(AssetTests).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
            .Single(a => a.Key == "LibraryTarget").Value!;
        string loaded = typeof(Argon2).Assembly.GetCustomAttribute<TargetFrameworkAttribute>()!.FrameworkName;
        string expected = configured switch
        {
            "net10.0" => ".NETCoreApp,Version=v10.0",
            "net8.0" => ".NETCoreApp,Version=v8.0",
            "netstandard2.0" => ".NETStandard,Version=v2.0",
            _ => throw new InvalidOperationException($"Unknown LibraryTarget {configured}."),
        };
        Assert.Equal(expected, loaded);
    }

    // .NET Framework callers that are strong-named themselves can only reference a strong-named
    // assembly. The token must not change between releases.
    [Fact]
    public void LibraryIsStrongNamedWithTheReleaseKey()
    {
        byte[]? token = typeof(Argon2).Assembly.GetName().GetPublicKeyToken();
        Assert.Equal("6321ed566a278b44", Convert.ToHexString(token ?? []).ToLowerInvariant());
    }

    // Writes the body the dispatch picked to the test log; hosted runners change CPUs without
    // notice. A job that sets an ISA knob also sets ARGON2_EXPECTED_KERNEL, because a knob the
    // runtime ignores fails silently.
    [Fact]
    public void WritesTheKernelToTheLog()
    {
        output.WriteLine($"Kernel.Name {Kernel.Name}, {RuntimeInformation.ProcessArchitecture}, " +
            $"{RuntimeInformation.FrameworkDescription}, {Environment.ProcessorCount} CPUs");
        if (Environment.GetEnvironmentVariable("ARGON2_EXPECTED_KERNEL") is { Length: > 0 } expected)
            Assert.Equal(expected, Kernel.Name);
    }
}
