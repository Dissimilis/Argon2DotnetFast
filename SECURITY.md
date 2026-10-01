# Security policy

## Reporting a vulnerability

Report it privately with the Report a vulnerability button on the repository's
[Security tab](https://github.com/Dissimilis/Argon2DotnetFast/security), not in a public issue.
Say how to reproduce it and what an attacker gains. A wrong tag for some parameter set counts, as
does a stored hash that gets past the verification limits or a path that leaves the arena unwiped.

Fixes go into the latest release. Older versions do not get backports.

## What the library does and does not do

The [Security notes](README.md#security-notes) in the README list what the library does with
passwords, memory and stored hashes. It has not had an independent audit. If you need an
implementation someone else has audited, use libsodium through
[NSec](https://github.com/ektrah/nsec), which computes Argon2id with one lane.
