@echo off
REM Windows release build for the full lancer-wireshark workspace.
REM Output: dist\lancer-wireshark-windows-x86_64\bin\*.exe

echo === Building lancer-wireshark workspace (release) for Windows x86_64 ===
cargo build --release --workspace
if errorlevel 1 exit /b 1

echo === Packaging ===
set DIST=dist\lancer-wireshark-windows-x86_64
if exist "%DIST%" rmdir /s /q "%DIST%"
mkdir "%DIST%"
mkdir "%DIST%\bin"

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
    if exist "target\release\%%B" copy /Y "target\release\%%B" "%DIST%\bin\" >/dev/null
)

if exist LICENSE copy /Y LICENSE "%DIST%\" >/dev/null
if exist README.md copy /Y README.md "%DIST%\" >/dev/null

echo === Done. Binaries in %DIST%\bin ===
dir "%DIST%\bin"
exit /b 0
