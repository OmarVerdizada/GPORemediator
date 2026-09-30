# Packaged Windows runtime

`GpoRemediator-runtime-win-x64.zip` is the prebuilt self-contained runtime used by normal `Auto` startup. The launcher verifies its SHA-256 manifest and backend source fingerprint before atomically installing it into the ignored local `runtime/` directory.

Operators do not need the .NET SDK and no source code is compiled during production startup. Developers regenerate both the runtime and this archive with `Build-Portable.ps1` in the approved build environment.
