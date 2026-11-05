# kingfisher-secret-scanner-win32-x64-msvc

Internal optional native package for `kingfisher-secret-scanner`, Windows x64 (MSVC).
Install the main SDK package rather than this package directly.

Requires Node.js 22.13.0+ (22.x), 24.x or 26.x and the architecture-matching **x64
Microsoft Visual C++ v14 Redistributable, version 14.44 or newer** (VS 2022
17.14 baseline). Compatible newer v14 runtimes, including VS 2026, are supported.
Install or repair the runtime from
[Microsoft](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist?view=msvc-170)
if addon loading reports a missing runtime DLL. No compiler is needed at install time.

See the [SDK guide](https://github.com/mongodb/kingfisher/blob/main/docs/JAVASCRIPT.md).
All required license and attribution files are included alongside the native addon.
