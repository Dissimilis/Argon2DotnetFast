![Argon2DotnetFast](https://raw.githubusercontent.com/Dissimilis/Argon2DotnetFast/main/img/logo.png)

# Argon2DotnetFast: Argon2 password hashing for .NET

A managed C# implementation of [Argon2](https://www.rfc-editor.org/rfc/rfc9106) (RFC 9106) for .NET: Argon2id, Argon2i and Argon2d, versions 1.0 and 1.3. No native library to ship and no `DllImport`. Targets .NET 10, .NET 8 and .NET Standard 2.0.

It is one of the fastest Argon2 hashers in the world, in any language: on the machine in [Performance](#performance) it was faster than every other Argon2 measured, .NET or native, libsodium, argon2-rust and the reference C implementation included. On .NET 8 and later it compresses blocks with AVX-512, AVX2 or NEON code chosen at run time, and with SVE2 on .NET 10. An `Argon2Hasher` keeps one memory arena and its lane threads between calls; the one-shot methods set both up for each call. If you need an implementation someone else has audited, use libsodium through [NSec](https://github.com/ektrah/nsec) instead.

[![NuGet](https://img.shields.io/nuget/v/Argon2DotnetFast.svg)](https://www.nuget.org/packages/Argon2DotnetFast)
[![NuGet Downloads](https://img.shields.io/nuget/dt/Argon2DotnetFast.svg)](https://www.nuget.org/packages/Argon2DotnetFast)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/Dissimilis/Argon2DotnetFast/blob/main/LICENSE)
[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-donate-yellow.svg)](https://buymeacoffee.com/dissimilis)

## Features

- All three types and both versions, with a secret (pepper) and associated data, and any tag length from 4 bytes
- PHC strings through `HashToString`, `Verify`, `Parse`, `Encode` and `NeedsRehash`, with unpadded Base64, a missing version read as 1.0, and unknown fields rejected
- Bounded verification: limits on memory, passes, lanes, tag length, text length and threads, checked before a stored hash's salt and tag are decoded or an arena is allocated
- A reusable `Argon2Hasher` that keeps one aligned arena and its lane threads between calls and wipes the arena after every call
- Vector compression on .NET 8 and later for AVX-512VL, AVX2 and NEON, and SVE2 on .NET 10, picked at run time, with a scalar fallback
- `CommonPasswords.Contains`, a built-in check against the 10,000 most common leaked passwords
- `net10.0` and `net8.0` (which .NET 9 also uses) with no package dependencies, and `netstandard2.0` for .NET Framework, Mono and Unity, which always runs the scalar body

## Other Argon2 packages

The most used managed packages, [Konscious.Security.Cryptography.Argon2](https://www.nuget.org/packages/Konscious.Security.Cryptography.Argon2), [Isopoh.Cryptography.Argon2](https://www.nuget.org/packages/Isopoh.Cryptography.Argon2) and BouncyCastle's `Argon2BytesGenerator`, compress blocks in scalar code. [Bodu.Security.Cryptography](https://www.nuget.org/packages/Bodu.Security.Cryptography) is managed and has AVX2, SSSE3 and NEON kernels.

[NSec](https://www.nuget.org/packages/NSec.Cryptography), [Sodium.Core](https://www.nuget.org/packages/Sodium.Core) and [Geralt](https://www.nuget.org/packages/Geralt) call the native libsodium. It has fast x86 code, but it computes a single lane only (`p = 1`) and has no NEON body. [Argon2Sharp](https://www.nuget.org/packages/Argon2Sharp) and [Argon2.Bindings](https://www.nuget.org/packages/Argon2.Bindings) call Rust and C through P/Invoke and ship native binaries; Argon2.Bindings 1.20.0 has none for Linux.

This library is managed, computes any number of lanes, and keeps its memory between calls when you ask it to. [Performance](#performance) compares it with all of them except Argon2.Bindings, and [Moving from Konscious or Isopoh](#moving-from-konscious-or-isopoh) shows that their stored hashes keep verifying.

## Correctness

Argon2 has one right answer. The tests check the RFC 9106 vectors for all three types and the phc-winner-argon2 known answers for version 1.0. Differential tests compare random parameter sets with three other implementations. BouncyCastle covers every type, both versions, several lanes, secret and associated data, and the memory sizes where data-independent addressing moves to its second address block. Konscious covers every type, several lanes, secret and associated data on version 1.3. libsodium, through NSec, covers Argon2id with one lane. Every thread count has to give the same tag.

The current suite passes against the .NET 10, .NET 8 and .NET Standard 2.0 assemblies on:

- Windows 11 x64, AMD Zen 4 (AVX-512VL body)
- Fedora 44, Linux x64 with glibc, AMD Zen 4 (AVX-512VL body)
- Alpine 3.24, Linux x64 with musl, Intel Haswell in a virtual machine (AVX2 body)
- Armbian (Debian 13), Linux ARM64, Cortex-A73 and A53 (NEON body)

The .NET 8 assembly ran on the .NET 8 runtime on Windows and on the ARM64 board; the two Linux x64 machines have no .NET 8 runtime, so there it ran on .NET 10. An earlier version of the suite passed on AWS Graviton4 with Ubuntu 26.04 (SVE2 body). In a 32-bit process on Windows, under the 32-bit .NET 10 runtime, the .NET Standard 2.0 assembly passed the benchmark harness's known-answer check (the RFC 9106 and phc-winner vectors, and the 64 MiB ones from phc-winner's `test.c`); the test suite itself has not run there.

## Installation

```bash
dotnet add package Argon2DotnetFast
```

## Quick start

```csharp
using Argon2DotnetFast;

var parameters = Argon2Parameters.OwaspMinimum;
string encoded = Argon2.HashToString(parameters, "correct horse battery staple");

// Limits must cover every parameter set still stored, not only the current one.
var limits = new Argon2VerificationLimits(parameters, maxEncodedLength: 1024);
bool matches = Argon2.Verify(encoded, "correct horse battery staple", limits);

if (matches && Argon2.NeedsRehash(encoded, parameters))
{
    encoded = Argon2.HashToString(parameters, "correct horse battery staple");
}
```

`HashToString` generates a fresh 16-byte salt and returns the algorithm, version, costs, salt and tag in one PHC string.

## Usage

### Password storage

`Verify` returns false for a password, pepper or associated-data mismatch. Malformed PHC text throws `FormatException`. Unsupported parameters, a salt under 8 bytes and exceeded limits throw `ArgumentOutOfRangeException`, and allocation failures throw `OutOfMemoryException`.

Each limit is checked on its own. Building limits from the current parameters, as above, is only right while every stored hash uses those parameters or lower ones. If you move from `p=4, t=1` to `p=1, t=3`, keep `MaxParallelism` at 4 until the last four-lane hash has been rehashed, or every old hash will throw. `MaxThreads` defaults to 1, so verification runs on the calling thread alone unless you raise it.

```csharp
var limits = new Argon2VerificationLimits(
    MaxMemoryKiB: 65536, MaxIterations: 3, MaxParallelism: 4,
    MaxOutputLength: 32, MaxEncodedLength: 1024);
```

The named profiles are fixed values, all Argon2id version 1.3 with a 32-byte tag:

| Profile | Total memory | Passes | Lanes |
|---|---:|---:|---:|
| `OwaspMinimum` | 19 MiB | 2 | 1 |
| `Rfc9106Low` | 64 MiB | 3 | 4 |
| `Rfc9106High` | 2 GiB | 1 | 4 |

RFC 9106 recommends `Rfc9106High` first, and `Rfc9106Low` when much less memory is available. `OwaspMinimum` is the smallest setting OWASP accepts for Argon2id. `Rfc9106High` needs a 64-bit process.

`NeedsRehash` means any parameter differs, including version or tag length, so it also reports a move to lower costs. Call it after successful verification. It cannot detect pepper rotation, because the pepper is not in the PHC string.

### ASP.NET Core Identity

Identity hashes through an `IPasswordHasher<TUser>`. This one stores Argon2id PHC strings and still accepts hashes made by Identity's default hasher:

```csharp
using Argon2DotnetFast;
using Microsoft.AspNetCore.Identity;

public sealed class Argon2PasswordHasher<TUser> : IPasswordHasher<TUser> where TUser : class
{
    private static readonly Argon2Parameters Parameters = Argon2Parameters.OwaspMinimum;

    // Must cover every parameter set still stored, not only the current one.
    private static readonly Argon2VerificationLimits Limits = new(Parameters, maxEncodedLength: 256);

    private readonly PasswordHasher<TUser> identityDefault = new();

    public string HashPassword(TUser user, string password) =>
        Argon2.HashToString(Parameters, password);

    public PasswordVerificationResult VerifyHashedPassword(TUser user, string hashedPassword, string providedPassword)
    {
        if (!hashedPassword.StartsWith("$argon2", StringComparison.Ordinal))
        {
            // Made by Identity's default hasher. Identity rehashes it with this class after a successful sign-in.
            return identityDefault.VerifyHashedPassword(user, hashedPassword, providedPassword) == PasswordVerificationResult.Failed
                ? PasswordVerificationResult.Failed
                : PasswordVerificationResult.SuccessRehashNeeded;
        }

        if (!Argon2.Verify(hashedPassword, providedPassword, Limits))
            return PasswordVerificationResult.Failed;

        return Argon2.NeedsRehash(hashedPassword, Parameters)
            ? PasswordVerificationResult.SuccessRehashNeeded
            : PasswordVerificationResult.Success;
    }
}
```

Register it next to `AddIdentity` or `AddDefaultIdentity`:

```csharp
builder.Services.AddScoped<IPasswordHasher<ApplicationUser>, Argon2PasswordHasher<ApplicationUser>>();
```

When a user with an old hash signs in, Identity sees `SuccessRehashNeeded` and stores a new Argon2 hash. The same happens after you change `Parameters`. The class calls the static `Argon2` methods, so one instance can serve concurrent requests.

### Moving from Konscious or Isopoh

Isopoh stores PHC strings, and `Argon2.Verify` reads them as they are. That includes hashes made with a secret or associated data, when you pass the same bytes in `Argon2AdditionalInputs`.

Konscious returns raw bytes, so the salt and parameters were stored separately. Its settings map one to one:

| Konscious | Argon2DotnetFast |
|---|---|
| `new Argon2id(...)`, `Argon2i`, `Argon2d` | `Argon2Type.Id`, `I`, `D` |
| `MemorySize` | `MemoryKiB` |
| `Iterations` | `Iterations` |
| `DegreeOfParallelism` | `Parallelism` |
| `GetBytes(n)` | `OutputLength` of `n` |
| `KnownSecret`, `AssociatedData` | `new Argon2AdditionalInputs(secret, associatedData)` |

Konscious computes version 1.3 only, which is the default here, and its tags are byte for byte what `Argon2.Hash` returns. Pass the same password bytes you gave Konscious; for text encoded with `Encoding.UTF8`, the string overloads give the same bytes. A stored tag verifies with `Argon2.Verify(parameters, password, salt, tag)`, and `Argon2.Encode` turns a stored salt and tag into a PHC string without the password, so a whole table can move to PHC strings in one pass:

```csharp
var parameters = new Argon2Parameters(
    Type: Argon2Type.Id, MemoryKiB: 65536, Iterations: 3,
    Parallelism: 4, OutputLength: 32);

string encoded = Argon2.Encode(parameters, row.Salt, row.Hash);
```

### Raw tags and key derivation

```csharp
using System.Security.Cryptography;
using Argon2DotnetFast;

var parameters = new Argon2Parameters(
    Type: Argon2Type.Id, MemoryKiB: 65536, Iterations: 3,
    Parallelism: 4, OutputLength: 32);

byte[] salt = new byte[16];
using (var random = RandomNumberGenerator.Create())
    random.GetBytes(salt);

byte[] key = Argon2.Hash(parameters, "password", salt);

Span<byte> destination = stackalloc byte[32];
Argon2.HashInto(parameters, "password", salt, destination);

bool matches = Argon2.Verify(parameters, "password", salt, key);
```

Store the salt and parameters alongside a derived key's metadata. `HashInto` requires a destination of exactly `OutputLength` bytes, and output must not overlap any input. The salt must be at least 8 bytes, memory at least 8 KiB per lane, and the tag at least 4 bytes; `Parallelism` runs from 1 to 16,777,215. A value outside those ranges throws `ArgumentOutOfRangeException` before the arena is allocated.

### Reusing memory and threads

```csharp
using var hasher = new Argon2Hasher(parameters, threads: 1);

string encoded = hasher.HashToString("password");
bool matches = hasher.Verify(encoded, "password", limits);

byte[] tag = hasher.Hash("password", salt);
hasher.HashInto("password", salt, destination);
```

The constructor allocates and clears one aligned arena. Every call wipes the arena before returning, and disposal releases it. The object keeps no password, pepper or associated data between calls, and a safe handle releases the allocation if disposal is forgotten.

Use one `Argon2Hasher` per concurrent caller. A call that starts while another call is running on the same instance throws `InvalidOperationException`; it does not wait. The static `Argon2` methods are safe from any number of threads, since each call allocates, wipes and frees its own arena.

`Parallelism` is the algorithm's lane count and changes the tag. `threads` is an execution cap, counting the calling thread, and never changes the tag. Zero means `min(Parallelism, Environment.ProcessorCount)`, and a larger value is capped the same way. The constructor starts `ThreadCount - 1` worker threads once and keeps them until `Dispose`; `Parallelism = 1` starts none. `ThreadCount` reads lower if a worker could not start, and the tag stays the same.

`hasher.Verify` hashes in the resident arena when the stored parameters equal `hasher.Parameters`. Any other stored hash is verified with a temporary arena under the same limits, and that call holds both arenas at once. `parameters.MemoryBytes` reports the size of the arena's blocks before allocation; the arena adds 6 KiB of scratch per thread. Requested memory is rounded down to complete slices for allocation, but its original value remains part of the hash.

### Server sizing

Every hash in flight holds its arena. A hundred logins at once hold about 1.9 GiB with `OwaspMinimum` and 6.25 GiB with `Rfc9106Low`. Cap the number of hashes running at once and let the rest wait, instead of letting a burst of logins allocate:

```csharp
public static class PasswordCheck
{
    private static readonly Argon2VerificationLimits Limits =
        new(Argon2Parameters.OwaspMinimum, maxEncodedLength: 256);

    // At most one hash per core; the rest wait here instead of allocating.
    private static readonly SemaphoreSlim HashSlots = new(Environment.ProcessorCount);

    public static async Task<bool> VerifyAsync(string stored, string password, CancellationToken cancellationToken)
    {
        await HashSlots.WaitAsync(cancellationToken);
        try
        {
            return Argon2.Verify(stored, password, Limits);
        }
        finally
        {
            HashSlots.Release();
        }
    }
}
```

On the machine in [Performance](#performance), an `OwaspMinimum` hash took 4.6-5.3 ms on one core, about 200 a second per core, and a one-lane 64 MiB hash took 31-33 ms. Hashes running at once also share memory bandwidth, so measure your own peak before choosing the cap. A server that already runs one hash per core can give each hasher `threads: 1`.

### Pepper and associated data

The pepper (Argon2's secret input) and associated data are passed together as `Argon2AdditionalInputs`. Both are accepted by hashing and verification, and neither is stored in PHC text.

```csharp
var inputs = new Argon2AdditionalInputs(secret: pepper, associatedData: context);

string encoded = Argon2.HashToString(parameters, "password", inputs);
bool matches = Argon2.Verify(encoded, "password", limits, inputs);
byte[] tag = Argon2.Hash(parameters, "password", salt, inputs);
```

A byte array converts to both `ReadOnlySpan<byte>` and `Span<byte>`, so an API that took the pepper as a plain span could bind it to an output buffer and overwrite it. The wrapper type has no conversion from arrays, so a misplaced pepper or output buffer is a compiler error. Write the type out or name the argument (`inputs: new(pepper)`). It is a ref struct, so build it at the call: it cannot be stored in a field or kept across an `await`.

### Text and encoding

Character passwords use strict UTF-8, with no BOM and no Unicode normalization. Empty passwords and embedded NUL characters are allowed, and invalid UTF-16 throws `EncoderFallbackException`. Byte passwords are used verbatim. Caller strings and buffers are never changed. As with other span APIs, a null array or string converted to a span is empty.

`Parse` and `TryParse` expose the parameters, salt and tag; `TryParse` returns false where `Parse` would throw `FormatException` or `ArgumentOutOfRangeException`. `Encode` serializes an existing raw tag without hashing it. Parsing does not allocate an arena, but successful parsing allocates its output arrays. Use bounded `Verify` for untrusted PHC text.

### Common passwords

`CommonPasswords.Contains` checks a new password against a built-in list of the most common leaked passwords, so a sign-up or password-change form can refuse one. It needs no network access or data file, and hashing never calls it.

```csharp
if (CommonPasswords.Contains(newPassword))
    return "That password appears in leaked-password lists. Choose another.";
```

The list is all of `xato-net-10-million-passwords-10000.txt` from [SecLists](https://github.com/danielmiessler/SecLists) (MIT), the top 10,000 of Mark Burnett's 2015 set of ten million leaked passwords (Public Domain Mark 1.0). ASCII `A`-`Z` are folded to lowercase on both sides, so `PASSWORD` matches; nothing else is folded, trimmed or normalized. Folding leaves 9,917 distinct entries. The empty password is on the list.

The set is 16,839 bytes of Rice-coded hashes, so the answer can be wrong in one direction only. `false` is exact. `true` is wrong for about one in 4,096 unlisted passwords of 16 bytes or less, and longer passwords return `false` without being hashed. A `false` result says the password is not common, not that it is strong. A lookup allocates nothing.

## Security notes

- Use Argon2id for passwords. RFC 9106 recommends it whenever side channels could matter: Argon2d's memory access depends on the password.
- `Verify` compares tags with `CryptographicOperations.FixedTimeEquals`, on every path.
- The arena and scratch are wiped after every call, including one that throws. A character password's UTF-8 copy lives in unmanaged memory and is cleared after the call. Memory is not locked, so the operating system may still page it out.
- A `string` password stays in managed memory until the garbage collector reclaims it. To clear a password yourself, pass it as a span over a buffer you own.
- Bounded verification refuses a stored hash that would cost more than your limits before its arena is allocated.
- It has not had an independent security audit.

Report a vulnerability privately with the Report a vulnerability button on the repository's [Security tab](https://github.com/Dissimilis/Argon2DotnetFast/security), not in a public issue.

## Public API

| Type | Description |
|------|-------------|
| `Argon2` | Static one-shot calls: `Hash`, `HashInto`, `HashToString`, `Verify` for a raw tag or a PHC string, `Parse`, `TryParse`, `Encode`, `NeedsRehash`. |
| `Argon2Hasher` | One parameter set with its own arena and worker threads: `Hash`, `HashInto`, `HashToString`, `Verify`, `Dispose`; `Parameters` and `ThreadCount`. One call at a time per instance. |
| `Argon2Parameters` | `Type`, `MemoryKiB`, `Iterations`, `Parallelism`, `OutputLength` (default 32), `Version` (default 1.3); `BlockCount`, `MemoryBytes`, `Validate`; the profiles `OwaspMinimum`, `Rfc9106Low` and `Rfc9106High`. |
| `Argon2VerificationLimits` | `MaxMemoryKiB`, `MaxIterations`, `MaxParallelism`, `MaxOutputLength`, `MaxEncodedLength`, `MaxThreads` (default 1). A constructor builds them from a parameter set. |
| `Argon2AdditionalInputs` | The secret (pepper) and associated data, passed together and never written to PHC text. |
| `Argon2Type`, `Argon2Version` | `D`, `I` and `Id`; `V10` (0x10) and `V13` (0x13). |
| `CommonPasswords` | `Contains` for character and byte passwords. |

## Performance

![Argon2id at 64 MiB and three passes: milliseconds per hash for each implementation, one lane and four lanes](https://raw.githubusercontent.com/Dissimilis/Argon2DotnetFast/main/img/benchmark.png)

Measured on 2026-09-30:

```text
AMD Ryzen 7 8845HS (Zen 4, AVX-512), pinned to 4 of its 16 logical CPUs
Fedora Linux 44, .NET SDK 10.0.111, .NET 10.0.11
Argon2id version 1.3, 32-byte password, 16-byte salt, 32-byte tag
Median of 7 rounds, every implementation in one process, taking turns
```

Milliseconds per hash, lower is better. KiB and MiB are powers of 1,024. The OWASP column is 19 MiB with two passes and one lane.

| Implementation | Memory between calls | 64 MiB t=3 p=1 | 256 MiB t=3 p=1 | OWASP | 64 MiB t=3 p=4 | 256 MiB t=3 p=4 |
|---|---|---:|---:|---:|---:|---:|
| Argon2DotnetFast, `Argon2Hasher.HashInto` | kept | 31.1 | 140.5 | 4.6 | 15.9 | 68.7 |
| Argon2DotnetFast, `Argon2.Hash` | allocated per call | 32.8 | 146.8 | 5.3 | 17.5 | 74.3 |
| [argon2-rust](https://github.com/Brooooooklyn/argon2-rust) 1.1.0 (Rust, AVX-512) | kept | 36.6 | 165.9 | 5.1 | 17.6 | 77.0 |
| [yandex/argon2](https://github.com/yandex/argon2) c31f3b2 (C++, AVX2) | kept | 53.5 | 248.2 | refused | 17.5 | 78.0 |
| [WOnder93/argon2](https://github.com/WOnder93/argon2) 49cbc23 (C, AVX2) | kept | 46.4 | 224.5 | 7.2 | 18.8 | 80.3 |
| [phc-winner-argon2](https://github.com/P-H-C/phc-winner-argon2) f57e61e (C `opt.c`, AVX-512F) | kept | 46.9 | 220.6 | 7.0 | 18.9 | 83.0 |
| [RustCrypto argon2](https://crates.io/crates/argon2) 0.6.0 (Rust) | kept | 56.1 | 261.5 | 8.9 | 19.2 | 84.2 |
| Bodu.Security.Cryptography 1.1.0 (.NET, managed) | pooled | 44.4 | 209.9 | 6.7 | 20.6 | 81.9 |
| libsodium, best of NSec 26.4.0, Geralt 4.4.0 and Sodium.Core 1.4.1 (.NET) | allocated per call | 58.6 | 270.6 | 11.5 | one lane only | one lane only |
| [golang.org/x/crypto/argon2](https://pkg.go.dev/golang.org/x/crypto/argon2) v0.57.0 (Go) | allocated per call | 83.6 | 352.0 | 16.8 | 25.8 | 113.2 |
| [Botan](https://botan.randombit.net) 3.13.0 (C++) | allocated per call | 80.9 | 369.4 | 9.9 | 50.4 | 189.6 |
| [OpenSSL](https://docs.openssl.org/3.5/man7/EVP_KDF-ARGON2/) 3.5.8 (C) | allocated per call | 100.5 | 437.6 | 14.2 | 49.5 | 202.4 |

Compare a library that keeps its memory with the `Argon2Hasher` row, and one that allocates per call with the `Argon2.Hash` row. Bodu keeps a process-wide pool of memory between calls. The C, C++, Rust and Go libraries were built on this machine for its CPU, except OpenSSL, which is the system's `libcrypto`, and each was called in the same process through a thin C wrapper. Each implementation's tag was checked against this library's at every row before timing. yandex/argon2 compiles a fixed list of memory sizes and refuses 19 MiB.

In a run on the same machine the day before, with an earlier build of this library, the most used managed packages took several times as long at 64 MiB with one lane, even against a one-shot `Argon2.Hash` call: Konscious 5.0 times as long, BouncyCastle 6.1 times and Isopoh 7.7 times (versions 1.3.1, 2.7.0 and 2.0.0). Argon2Sharp 4.0.1, which calls Rust, took 2.2 times.

Only this machine, on Linux, was measured against the whole field; Windows and macOS were not. The margins depend on the CPU. In earlier runs on an AVX2-only Intel Core i5-4460, libsodium took 1.20 to 1.26 times as long as a reused hasher and 1.06 to 1.11 times as long as a one-shot call; that machine is a virtual machine that gives huge pages to every allocation, libsodium's included. On a Cortex-A73 at 64 MiB with one lane (2026-10-01, seven rounds), NSec took 1.68 times as long as a reused hasher, since libsodium has no NEON body. The scalar body, which the .NET Standard 2.0 assembly runs, beat libsodium there too: NSec took 1.40 times as long as it, Argon2Sharp 1.16 times, and Konscious, BouncyCastle and Isopoh 2.8 to 3.8 times.

### Hardware intrinsics tiering

The compression body is chosen once, at run time:

| Tier | Where it runs | Shape |
|------|---------------|-------|
| AVX-512VL | x64 with AVX-512VL, .NET 8 and later | 256-bit vectors that use the upper 16 registers; four BlaMka chains per row-pass iteration, `vprorq` rotates |
| AVX2 | other x64 with AVX2, .NET 8 and later | 256-bit vectors in the round order of phc-winner `opt.c`, two chains per iteration |
| SVE2 | ARM64 with SVE2 at a 128-bit vector length, .NET 10 | the NEON body with `xar` fused xor-and-rotate, six chains in flight |
| NEON | other ARM64, .NET 8 and later | 128-bit vectors, four chains written one step at a time |
| Scalar | everything else, and the .NET Standard 2.0 assembly | portable C# |

In a 32-bit process the scalar body writes the BlaMka product as one 32-by-32-bit multiply. Written the usual way, `2UL * (uint)a * (uint)b` is a 64-bit multiply, and the 32-bit .NET 10 JIT calls a helper for each of the 512 multiplies in a block, which made hashes take 1.5 to 1.6 times as long. .NET Framework's 32-bit JIT was not measured. 64-bit code is unchanged.

Every vector body starts loading the next block's reference while the current block is still being compressed. SVE2 uses `System.Runtime.Intrinsics.Arm.Sve2`, which .NET 10 marks experimental and .NET 8 does not have; other ARM64 CPUs, SVE2 at a wider vector length included, and every ARM64 CPU on .NET 8 run the NEON body.

Native AOT compiles for a fixed instruction set, and its default for x64 has no AVX2, so a published app runs the scalar body there. The tags are the same; hashing is slower. Set `<IlcInstructionSet>` in the app's project file: `x86-64-v3` gives the AVX2 body and `x86-64-v4` the AVX-512VL body. An app built for `x86-64-v4` stops at startup on a CPU without AVX-512, so `x86-64-v3` is the safer choice for an app that runs on machines you don't control. On ARM64 the default includes NEON, and the NEON body runs, also on CPUs that have SVE2.

On Linux the .NET 8 and .NET 10 assemblies ask for transparent huge pages for any arena of 2 MiB or more, through libc's `madvise`, since a random 1 KiB block in a 64 MiB arena of 4 KiB pages misses the TLB almost every time. A host that refuses keeps small pages. On x64 Linux with glibc it wipes the arena's blocks with non-temporal stores, because glibc's `memset` reads every line before it writes it at these sizes.

## Building from source

```bash
# Requires the .NET 10 SDK
dotnet build Argon2DotnetFast.slnx -c Release

# Run the tests against the .NET 10, .NET 8 and .NET Standard 2.0 assemblies
dotnet test src/Argon2DotnetFast.Tests -c Release
dotnet test src/Argon2DotnetFast.Tests -c Release -p:LibraryTarget=net8.0
dotnet test src/Argon2DotnetFast.Tests -c Release -p:LibraryTarget=netstandard2.0

# Create the NuGet package
dotnet pack src/Argon2DotnetFast -c Release
```

The `net8.0` command builds the tests for .NET 8 too, so they run on the .NET 8 runtime. The `netstandard2.0` command runs the .NET Standard 2.0 assembly on the .NET 10 runtime; it does not show that older runtimes work. Only that target depends on `System.Memory`.

The assemblies are strong-named with `src/Argon2DotnetFast.snk`. A local build is public-signed: it has the same name and public key token as the published package, but no signature, because OpenSSL on Fedora and RHEL refuses the SHA-1 signature a strong name uses. Builds in GitHub Actions, which set `CI=true`, are fully signed, and the package on nuget.org comes from the release workflow. The version comes from the latest `vX.Y.Z` git tag.

After changing the common-password list, regenerate its data and commit that on its own:

```bash
dotnet run -c Release --project src/Argon2DotnetFast.CommonPasswords.Generator
```

The generator's `data/SOURCE.md` records where the list came from, and the tests rebuild the data and fail if the committed copy differs.

## License

MIT, in [LICENSE](https://github.com/Dissimilis/Argon2DotnetFast/blob/main/LICENSE). The common-password data comes from SecLists under the MIT License, and the vector bodies follow the Argon2 reference implementation; [THIRD-PARTY-NOTICES.md](https://github.com/Dissimilis/Argon2DotnetFast/blob/main/THIRD-PARTY-NOTICES.md) has both notices.

## Acknowledgments

- [phc-winner-argon2](https://github.com/P-H-C/phc-winner-argon2), the reference implementation, for the algorithm, the `opt.c` round structure the vector bodies follow, and the known-answer vectors (CC0)
- [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106) by Alex Biryukov, Daniel Dinu, Dmitry Khovratovich and Simon Josefsson
- [argon2-rust](https://github.com/Brooooooklyn/argon2-rust), whose notes on huge-page arenas and on which thread takes the page faults shaped the arena here
- [SecLists](https://github.com/danielmiessler/SecLists) by Daniel Miessler, and Mark Burnett's ten million passwords, for the common-password list
- [BouncyCastle](https://github.com/bcgit/bc-csharp), [Konscious](https://github.com/kmaragon/Konscious.Security.Cryptography) and [NSec](https://github.com/ektrah/nsec), the second implementations in the differential tests
