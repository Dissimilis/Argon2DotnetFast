using System.Runtime.CompilerServices;
using System.Text;
using Argon2DotnetFast.CommonPasswordsGenerator;

string project = ProjectDirectory();
string output = Path.GetFullPath(Path.Combine(project, "..", "Argon2DotnetFast", "Internal", "CommonPasswordData.g.cs"));

List<byte[]> entries = CommonPasswordSet.ReadEntries(Path.Combine(project, "data"));
CommonPasswordSet.Result result = CommonPasswordSet.Build(entries);
File.WriteAllText(output, CommonPasswordSet.Source(result), new UTF8Encoding(false));

Console.WriteLine($"{result.Count} of {entries.Count} distinct entries, longest {result.MaxLength} bytes, " +
    $"{result.Stream.Length} of {CommonPasswordSet.Budget} bytes, false-positive rate about 1/4096.");
Console.WriteLine($"Wrote {output}");

static string ProjectDirectory([CallerFilePath] string path = "") => Path.GetDirectoryName(path)!;
