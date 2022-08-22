@echo off
call msvc.bat x86
if errorlevel 1 (pause && exit)
cd openssl
set prefix=%cd%\..\bin\x86\debug\openssl
perl Configure VC-WIN32 --debug no-shared no-tests no-unit-test --prefix=%prefix%
nmake install_dev
nmake clean
set prefix=%cd%\..\bin\x86\release\openssl
perl Configure VC-WIN32 --release no-shared no-tests no-unit-test --prefix=%prefix%
nmake install_dev
nmake clean
pause