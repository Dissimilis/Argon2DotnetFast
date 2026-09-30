# Source of the common-password list

`xato-net-10-million-passwords-10000.txt` is copied unchanged from SecLists:

- URL: https://github.com/danielmiessler/SecLists/blob/e749176aa4e3261ff41f7d197d7a01a0a705030e/Passwords/Common-Credentials/xato-net-10-million-passwords-10000.txt
- Commit: `e749176aa4e3261ff41f7d197d7a01a0a705030e`, fetched 2026-09-30
- SHA-256: `c63d5e4ccc31344d662583cc39ca4bd5bd20517ff1d24501f0c4e0c22d9b722a`
- 10,000 lines, ASCII, LF line endings. Line 43 is empty: the empty password.

Before May 2025 SecLists named this file `10-million-password-list-top-10000.txt`.
`Pwdb_top-10000.txt` and `10k-most-common.txt` in the same directory are different lists.

The passwords come from Mark Burnett's set of ten million usernames and passwords,
published in February 2015 under the Creative Commons Public Domain Mark 1.0:
https://archive.org/details/10MillionPasswords

SecLists is distributed under the MIT License, copyright (c) 2018 Daniel Miessler:
https://github.com/danielmiessler/SecLists/blob/master/LICENSE

The generator refuses a file with a different SHA-256. To move to a newer copy, replace
the file, update the hash here and in `CommonPasswordSet.cs`, run the generator, and
commit the regenerated data on its own.
