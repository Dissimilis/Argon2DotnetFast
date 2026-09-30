# Third-party notices

Argon2DotnetFast is licensed under the MIT License in [LICENSE](LICENSE). It includes or
derives from the works below.

## SecLists

The common-password data compiled into the library
(`src/Argon2DotnetFast/Internal/CommonPasswordData.g.cs`) is built from
`xato-net-10-million-passwords-10000.txt` in SecLists, a copy of which is in
`src/Argon2DotnetFast.CommonPasswords.Generator/data`.

https://github.com/danielmiessler/SecLists

```text
MIT License

Copyright (c) 2018 Daniel Miessler

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

The passwords in that list come from Mark Burnett's set of ten million usernames and
passwords, published in February 2015 under the Creative Commons Public Domain Mark 1.0:
https://archive.org/details/10MillionPasswords

## Argon2 reference implementation

The vector compression bodies follow the round structure of `opt.c` in the Argon2
reference implementation, and the known-answer tests use vectors from its `kats`
directory.

https://github.com/P-H-C/phc-winner-argon2

Copyright 2015 Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves.
Available under the Creative Commons CC0 1.0 Universal waiver or the Apache License 2.0,
at the user's option. It is used here under CC0 1.0.
