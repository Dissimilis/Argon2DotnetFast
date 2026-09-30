using System.Text;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

namespace Argon2DotnetFast.Tests;

// A byte[] converts to both ReadOnlySpan<byte> and Span<byte>. These calls compile the misplaced
// arguments from the review against the library under test and require a compiler error.
public class OverloadTests
{
    [Theory]
    // The original bug: the pepper bound as the output span and was overwritten with the tag.
    [InlineData("Argon2.Hash(p, pw, salt, pepper);")]
    [InlineData("hasher.Hash(pw, salt, pepper);")]
    // HashToString order carried over to HashInto: pepper would become the destination.
    [InlineData("Argon2.HashInto(p, pw, salt, pepper, ad, output);")]
    [InlineData("hasher.HashInto(pw, salt, pepper, output);")]
    // SHA256.HashData(source, destination) habit: the key would bind as the secret and stay zero.
    [InlineData("byte[] key = new byte[32]; Argon2.Hash(p, pw, salt, key);")]
    // A salt, or a raw pepper, where the generated-salt HashToString takes its inputs.
    [InlineData("Argon2.HashToString(p, pw, salt);")]
    [InlineData("Argon2.HashToString(p, pw, pepper);")]
    [InlineData("Argon2.Verify(encoded, pw, limits, pepper);")]
    [InlineData("Argon2.Verify(p, pw, salt, output, pepper);")]
    public void MisplacedBuffersDoNotCompile(string statement)
    {
        // CS1503: argument cannot convert. Any other error would mean the probe itself is broken.
        var errors = Errors(statement).ToList();
        Assert.NotEmpty(errors);
        Assert.All(errors, error => Assert.Equal("CS1503", error.Id));
    }

    [Theory]
    [InlineData("Argon2.Hash(p, pw, salt, new(pepper));")]
    [InlineData("Argon2.Hash(p, pw, salt, new Argon2AdditionalInputs(pepper, ad), threads: 1);")]
    [InlineData("Argon2.HashInto(p, pw, salt, output, new(pepper, ad));")]
    [InlineData("Argon2.HashToString(p, pw, new(pepper));")]
    [InlineData("Argon2.HashToString(p, \"text\", saltLength: 24);")]
    [InlineData("Argon2.Verify(encoded, \"text\", limits, new(pepper));")]
    [InlineData("Argon2.Verify(p, pw, salt, output, new(pepper));")]
    [InlineData("hasher.Hash(pw, salt, new(pepper));")]
    [InlineData("hasher.HashInto(pw, salt, output, new(associatedData: ad));")]
    [InlineData("hasher.Verify(encoded, pw, limits, new(pepper));")]
    [InlineData("CommonPasswords.Contains(pw); CommonPasswords.Contains(\"text\"); CommonPasswords.Contains(encoded);")]
    [InlineData("CommonPasswords.Contains(\"\"); CommonPasswords.Contains(stackalloc char[4]);")]
    public void IntendedCallsCompile(string statement)
    {
        Assert.Empty(Errors(statement));
    }

    // The empty check is written Contains(""), since default fits both overloads.
    [Fact]
    public void CommonPasswordsDefaultIsAmbiguous()
    {
        Assert.Equal("CS0121", Assert.Single(Errors("CommonPasswords.Contains(default);")).Id);
    }

    [Fact]
    public void TargetTypedPepperBindsAsTheSecret()
    {
        var parameters = new Argon2Parameters(Argon2Type.Id, 64, 1, 1);
        byte[] password = Encoding.UTF8.GetBytes("password");
        byte[] pepper = KnownAnswerTests.Filled(16, 0x05);
        var limits = new Argon2VerificationLimits(parameters, 256);

        string encoded = Argon2.HashToString(parameters, password, new(pepper));
        Argon2.Parse(encoded, out _, out byte[] salt, out _);
        Assert.NotEqual(pepper, salt);
        Assert.True(Argon2.Verify(encoded, password, limits, new(pepper)));
        Assert.False(Argon2.Verify(encoded, password, limits));
    }

    private static IEnumerable<Diagnostic> Errors(string statement)
    {
        string source = $$"""
            using System;
            using Argon2DotnetFast;

            static class Probe
            {
                static void Run(Argon2Parameters p, Argon2Hasher hasher, Argon2VerificationLimits limits, string encoded,
                    byte[] pw, byte[] salt, byte[] pepper, byte[] ad, byte[] output)
                {
                    {{statement}}
                }
            }
            """;

        string library = typeof(Argon2).Assembly.Location;
        IEnumerable<MetadataReference> references = ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!)
            .Split(Path.PathSeparator)
            .Where(path => !string.Equals(Path.GetFileName(path), Path.GetFileName(library), StringComparison.OrdinalIgnoreCase))
            .Append(library)
            .Select(path => MetadataReference.CreateFromFile(path));

        var compilation = CSharpCompilation.Create("Probe", new[] { CSharpSyntaxTree.ParseText(source) }, references,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        return compilation.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error).ToList();
    }
}
