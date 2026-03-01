@echo off
setlocal enabledelayedexpansion
title lancer-wireshark Build

REM ============================================================
REM  build.bat -- Build all lancer-wireshark binaries for Windows.
REM  Output: build\*.exe (lancer-wireshark.exe, editcap.exe,
REM          mergecap.exe, capinfos.exe, text2pcap.exe, randpkt.exe,
REM          rawshark.exe, sharkd.exe, dumpcap.exe,
REM          lancer-wireshark-cli.exe)
REM
REM  Requirements:
REM    - Rust / Cargo            https://rustup.rs
REM    - Visual C++ Build Tools  (2019 / 2022)
REM    - Npcap SDK installed; set LIB / INCLUDE to its lib/include dirs
REM      so the `pcap` crate can link against `wpcap.lib`.
REM ============================================================

set "REPO=%~dp0"
set "REPO=%REPO:~0,-1%"
set "BUILD=%REPO%\build"

echo.
echo  ================================================
echo    lancer-wireshark  Workspace Build
echo  ================================================
echo.
echo  Repo   : %REPO%
echo  Output : %BUILD%
echo.

REM Locate cargo
where cargo >/dev/null 2>&1
if errorlevel 1 (
    set "CARGO=%USERPROFILE%\.cargo\bin\cargo.exe"
    if not exist "!CARGO!" (
        echo  ERROR: cargo not found.
        echo  Install Rust from https://rustup.rs then re-run.
        pause
        exit /b 1
    )
) else (
    set "CARGO=cargo"
)

echo  [1/2]  Building workspace (release)...
"!CARGO!" build --release --workspace
if errorlevel 1 (
    echo  ERROR: cargo build failed
    pause
    exit /b 1
)

echo  [2/2]  Copying binaries to build\...
if not exist "%BUILD%" mkdir "%BUILD%"
for %%B in (
    lancer-wireshark.exe
    lancer-wireshark-cli.exe
    editcap.exe
    mergecap.exe
    capinfos.exe
    text2pcap.exe
    randpkt.exe
    rawshark.exe
    sharkd.exe
    dumpcap.exe
) do (
    if exist "%REPO%\target\release\%%B" (
        copy /Y "%REPO%\target\release\%%B" "%BUILD%\" >/dev/null
        echo    + %%B
    )
)

echo.
echo  ================================================
echo    Done!  Binaries in %BUILD%\
echo  ================================================
echo.
pause
endlocal
