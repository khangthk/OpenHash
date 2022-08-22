@echo off
call msvc.bat x64
if errorlevel 1 (pause && exit)
cd openssl
set prefix=%cd%\..\bin\x64\debug\openssl
perl Configure VC-WIN64A --debug no-shared no-tests no-unit-test --prefix=%prefix%
nmake install_dev
nmake clean
set prefix=%cd%\..\bin\x64\release\openssl
perl Configure VC-WIN64A --release no-shared no-tests no-unit-test --prefix=%prefix%
nmake install_dev
nmake clean
pause