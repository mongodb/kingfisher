@echo off
REM This script builds a Windows x64 release binary and creates a tarball with checksum.
REM It requires vcpkg to be installed at root of C: drive (https://github.com/microsoft/vcpkg).
REM This script will install Rust (using chocolatey) if it is not already installed.
REM
REM Call with -force to clone and bootstrap vcpkg if it is not found
REM

setlocal

REM Set your Cargo project name manually here if desired:
set "PROJECT_NAME=kingfisher"

REM Optional check for OS:
if NOT "%OS%"=="Windows_NT" (
    echo This script must be run on Windows.
    exit /b 1
)
if "%VCINSTALLDIR%"=="" (
    echo VCINSTALLDIR not set - attempting auto-detection…
    for %%P in (
        "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC"
        "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC"
        "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC"
        "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC"
    ) do (
        if exist "%%~P\Auxiliary\Build\vcvars64.bat" (
            set "VCINSTALLDIR=%%~P"
            echo Found Visual C++ Build Tools at: %%~P
            goto :vc_found
        )
    )
    echo ERROR: Could not find a suitable Visual Studio installation.
    echo        Install “Desktop development with C++” or set VCINSTALLDIR.
    exit /b 1
)
:vc_found

REM Strip trailing backslash if present
if "%VCINSTALLDIR:~-1%"=="\" set "VCINSTALLDIR=%VCINSTALLDIR:~0,-1%"

echo Initialising MSVC environment…
call "%VCINSTALLDIR%\Auxiliary\Build\vcvars64.bat" || (
    echo ERROR: Failed to initialise MSVC toolchain.
    exit /b 1
)

REM Locate vcpkg.exe
where vcpkg.exe >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    if exist "%HOMEDRIVE%\vcpkg\vcpkg.exe" (
        set "VCPKG_EXE=%HOMEDRIVE%\vcpkg\vcpkg.exe"
        echo Found vcpkg at: %VCPKG_EXE%
    ) else (
        if "%~1"=="-force" (
            echo Cloning and bootstrapping vcpkg...
            if exist "%HOMEDRIVE%\vcpkg" (
                rmdir /s /q "%HOMEDRIVE%\vcpkg"
            )
            git clone https://github.com/microsoft/vcpkg.git "%HOMEDRIVE%\vcpkg"
            pushd "%HOMEDRIVE%\vcpkg"
            dir
            call .\bootstrap-vcpkg.bat
            set "VCPKG_EXE=%CD%\vcpkg.exe"
            popd
            echo Installed vcpkg at: %VCPKG_EXE%
        ) else (
            echo ERROR: vcpkg not found. Please install it or re-run script with -force.
            exit /b 1
        )
    )
) else (
    for /f "tokens=*" %%i in ('where vcpkg.exe') do (
        set "VCPKG_EXE=%%i"
        goto :found_vcpkg
    )
    :found_vcpkg
    echo Found vcpkg at: %VCPKG_EXE%
)

REM Check if LOCALAPPDATA starts with a drive letter, if not set it to APPDATA
if /I not "%LOCALAPPDATA:~1,1%"==":" (
    echo LOCALAPPDATA does not start with a drive letter. Setting it to APPDATA.
    set "LOCALAPPDATA=%APPDATA%"
)

echo Installing hyperscan via vcpkg...
set
"%HOMEDRIVE%\vcpkg\vcpkg.exe" install hyperscan:x64-windows
set "LIBHS_NO_PKG_CONFIG=1"

REM Point vectorscan-rs-sys at the Hyperscan install from vcpkg
set "HYPERSCAN_ROOT=%HOMEDRIVE%\vcpkg\installed\x64-windows"
set "LIB=%HYPERSCAN_ROOT%\lib;%LIB%"
set "INCLUDE=%HYPERSCAN_ROOT%\include;%INCLUDE%"

REM Check for Rust, install if missing
where rustc.exe >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo Installing Rust...
    choco install rust-ms -y
    choco install cmake -y --installargs "ADD_CMAKE_TO_PATH=System"
    call refreshenv

) else (
    echo Rust is already installed.
)

echo Building for Windows x64...
cargo build --release --target x86_64-pc-windows-msvc || (
    echo Cargo build failed.
    exit /b 1
)

echo Generating CHECKSUM.txt...
powershell -Command ^
  "Get-FileHash .\target\x86_64-pc-windows-msvc\release\%PROJECT_NAME%.exe -Algorithm SHA256 | Out-File .\target\x86_64-pc-windows-msvc\release\CHECKSUM.txt"

if not exist "target\release" mkdir "target\release"
copy /Y "target\x86_64-pc-windows-msvc\release\%PROJECT_NAME%.exe" "target\release\" >nul
copy /Y "target\x86_64-pc-windows-msvc\release\CHECKSUM.txt" "target\release\CHECKSUM-windows-x64.txt" >nul

cd target\release
echo Creating archive: %PROJECT_NAME%-windows-x64.zip
if exist "%PROJECT_NAME%-windows-x64.zip" del /f /q "%PROJECT_NAME%-windows-x64.zip"
powershell -Command "Compress-Archive -Path '%PROJECT_NAME%.exe','CHECKSUM-windows-x64.txt' -DestinationPath '%PROJECT_NAME%-windows-x64.zip' -Force"

if exist "%PROJECT_NAME%-windows-x64.zip" (
    REM -- append the ZIP’s SHA-256 to the existing checksum file ----
    certutil -hashfile "%PROJECT_NAME%-windows-x64.zip" SHA256 >> "CHECKSUM-windows-x64.txt"
    echo Created: %PROJECT_NAME%-windows-x64.zip
) else (
    echo ERROR: Archive not created.
)

echo Archives in target\release:
dir /b *.zip 2>nul || echo None found.

endlocal
exit /b 0
