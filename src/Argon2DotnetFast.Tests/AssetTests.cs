using System.Reflection;
using System.Runtime.Versioning;

namespace Argon2DotnetFast.Tests;

public class AssetTests
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
}
