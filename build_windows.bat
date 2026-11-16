@echo off
setlocal EnableExtensions EnableDelayedExpansion

rem Copyright  : Copyright (C) 2017 ~ 2035 SupersocksR ORG. All rights reserved.
rem Description: Build openppp2 Debug/Release for x86/x64 using custom CMakeLists.txt files.
rem Author     : Kyou
rem Date       : 2026-04-12

set "ROOT_DIR=%~dp0"
set "BUILD_ROOT=%ROOT_DIR%build"
set "CONFIG=Release"
set "TARGET=all"
set "BUILD_JOBS=%NUMBER_OF_PROCESSORS%"
set "SHOW_HELP=0"
set "ENABLE_XTCP=OFF"

call :parse_args %*
if errorlevel 1 goto :help
if "%SHOW_HELP%"=="1" goto :help
goto :start

:help
echo Usage:
echo   build_windows.bat help
echo   build_windows.bat /?
echo   build_windows.bat [Debug^|Release] [x86^|x64^|arm64^|all]
echo   build_windows.bat [x86^|x64^|arm64^|all] [Debug^|Release]
echo   build_windows.bat [Debug^|Release] [x86^|x64^|arm64^|all] xtcp
echo.
echo Examples:
echo   build_windows.bat
echo   build_windows.bat Debug
echo   build_windows.bat Release
echo   build_windows.bat x86
echo   build_windows.bat x64
echo   build_windows.bat arm64
echo   build_windows.bat all
echo   build_windows.bat Debug x86
echo   build_windows.bat x86 Release
echo   build_windows.bat Release x64
echo   build_windows.bat Release arm64
echo   build_windows.bat help
echo   build_windows.bat /?
echo.
echo Notes:
echo   - Running with no arguments builds the default Release all targets.
echo   - Argument order is flexible.
echo   - Debug/Release are case-insensitive.
echo   - Output goes to bin\Debug or bin\Release.
echo   - Build directories are temporary and removed after success.
echo   - Default behavior is Release all.
echo   - XTCP is opt-in: append xtcp (requires third-party\xtcp prepared).
echo   - vcpkg discovery prefers environment variables first.
echo.
echo vcpkg discovery priority:
echo   1. VCPKG_CMAKE_TOOLCHAIN_FILE
echo   2. VCPKG_ROOT
echo   3. %%LOCALAPPDATA%%\vcpkg\vcpkg.path.txt
echo   4. ..\vcpkg next to the project
echo   5. Visual Studio integrated vcpkg
echo.
echo Environment variables:
echo   - VCPKG_ROOT must point to a vcpkg root containing scripts\buildsystems\vcpkg.cmake.
echo   - VCPKG_CMAKE_TOOLCHAIN_FILE must point directly to vcpkg.cmake.
echo.
exit /b 0

:start
if /I not "%CONFIG%"=="Debug" if /I not "%CONFIG%"=="Release" (
    echo Build configuration must be Debug or Release.
    exit /b 1
)

if /I not "%TARGET%"=="x86" if /I not "%TARGET%"=="x64" if /I not "%TARGET%"=="arm64" if /I not "%TARGET%"=="all" (
    echo Build target must be x86, x64, arm64, or all.
    exit /b 1
)

call :find_vs_install
if errorlevel 1 exit /b 1

if /I "%TARGET%"=="x86" goto :x86
if /I "%TARGET%"=="x64" goto :x64
if /I "%TARGET%"=="arm64" goto :arm64

:x86
echo Building x86 %CONFIG%
call :prepare_env x86
if errorlevel 1 exit /b 1
call :build_one x86 x86-windows-static
if errorlevel 1 exit /b 1
if /I not "%TARGET%"=="all" exit /b 0
goto :x64

:x64
echo Building x64 %CONFIG%
call :prepare_env x64
if errorlevel 1 exit /b 1
call :build_one x64 x64-windows-static
if errorlevel 1 exit /b 1
if /I not "%TARGET%"=="all" exit /b 0
goto :arm64

:arm64
echo Building arm64 %CONFIG%
call :prepare_env arm64
if errorlevel 1 exit /b 1
call :build_one arm64 arm64-windows-static
exit /b %errorlevel%

:parse_args
set "ARG_COUNT=0"
:parse_args_loop
if "%~1"=="" goto :parse_args_done
set /a ARG_COUNT+=1

if /I "%~1"=="help" (
    set "SHOW_HELP=1"
    exit /b 0
)

if /I "%~1"=="/?" (
    set "SHOW_HELP=1"
    exit /b 0
)

if /I "%~1"=="debug" (
    set "CONFIG=Debug"
    shift
    goto :parse_args_loop
)

if /I "%~1"=="release" (
    set "CONFIG=Release"
    shift
    goto :parse_args_loop
)

if /I "%~1"=="x86" (
    set "TARGET=x86"
    shift
    goto :parse_args_loop
)

if /I "%~1"=="x64" (
    set "TARGET=x64"
    shift
    goto :parse_args_loop
)

if /I "%~1"=="all" (
    set "TARGET=all"
    shift
    goto :parse_args_loop
)

if /I "%~1"=="xtcp" (
    set "ENABLE_XTCP=ON"
    shift
    goto :parse_args_loop
)

exit /b 1

:parse_args_done
if %ARG_COUNT%==0 (
    exit /b 0
)
if %ARG_COUNT% gtr 3 exit /b 1
exit /b 0

:build_one
set "ARCH=%~1"
set "TRIPLET=%~2"
set "BUILD_DIR=%BUILD_ROOT%\%ARCH%"
set "OUTPUT_DIR=%ROOT_DIR%bin\%CONFIG%\%ARCH%"
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

set "VCPKG_INSTALLED_DIR=%VCPKG_ROOT_DIR%\installed"

echo TOOLCHAIN_FILE=%TOOLCHAIN_FILE%
echo VCPKG_ROOT_DIR=%VCPKG_ROOT_DIR%
echo VCPKG_INSTALLED_DIR=%VCPKG_INSTALLED_DIR%

pushd "%BUILD_DIR%"
echo Configuring %ARCH% %CONFIG%
cmake -G Ninja -DCMAKE_BUILD_TYPE=%CONFIG% "-DCMAKE_TOOLCHAIN_FILE=%TOOLCHAIN_FILE%" -DVCPKG_INSTALLED_DIR="%VCPKG_INSTALLED_DIR%" -DVCPKG_TARGET_TRIPLET=%TRIPLET% -DVCPKG_HOST_TRIPLET=x64-windows -DPPP_OUTPUT_DIR=%OUTPUT_DIR% -DENABLE_XTCP=%ENABLE_XTCP% -DCMAKE_CXX_STANDARD=17 "%ROOT_DIR%"
if errorlevel 1 (
    popd
    exit /b 1
)

cmake --build . -- -j %BUILD_JOBS%
set "BUILD_ERROR=%errorlevel%"
popd

if %BUILD_ERROR%==0 (
    echo Finished %ARCH% %CONFIG%
    if exist "%BUILD_DIR%" rmdir /s /q "%BUILD_DIR%"
)

exit /b %BUILD_ERROR%

:prepare_env
set "TARGET_ARCH=%~1"
set "TOOLCHAIN_FILE="
set "VCPKG_ROOT_DIR="

if exist "%LOCALAPPDATA%\vcpkg\vcpkg.path.txt" (
    set /p VCPKG_ROOT_DIR=<"%LOCALAPPDATA%\vcpkg\vcpkg.path.txt"
)

if not defined VCPKG_ROOT_DIR if defined VCPKG_ROOT (
    set "VCPKG_ROOT_DIR=%VCPKG_ROOT%"
)

if not defined TOOLCHAIN_FILE if defined VCPKG_CMAKE_TOOLCHAIN_FILE (
    if exist "%VCPKG_CMAKE_TOOLCHAIN_FILE%" set "TOOLCHAIN_FILE=%VCPKG_CMAKE_TOOLCHAIN_FILE%"
)

if not defined VCPKG_ROOT_DIR (
    if exist "%ROOT_DIR%..\vcpkg\scripts\buildsystems\vcpkg.cmake" set "VCPKG_ROOT_DIR=%ROOT_DIR%..\vcpkg"
)

if defined VCPKG_ROOT_DIR set "VCPKG_ROOT_DIR=%VCPKG_ROOT_DIR:/=\%"

if not defined TOOLCHAIN_FILE if defined VCPKG_ROOT_DIR (
    if exist "%VCPKG_ROOT_DIR%\scripts\buildsystems\vcpkg.cmake" set "TOOLCHAIN_FILE=%VCPKG_ROOT_DIR%\scripts\buildsystems\vcpkg.cmake"
)

if not defined TOOLCHAIN_FILE if defined VCPKG_ROOT (
    if exist "%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake" set "TOOLCHAIN_FILE=%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake"
)

if not defined TOOLCHAIN_FILE (
    call :find_vs_install
    if defined VS_INSTALL if not defined VCPKG_ROOT_DIR if exist "%VS_INSTALL%\VC\vcpkg" set "VCPKG_ROOT_DIR=%VS_INSTALL%\VC\vcpkg"
    if defined VCPKG_ROOT_DIR if exist "%VCPKG_ROOT_DIR%\scripts\buildsystems\vcpkg.cmake" set "TOOLCHAIN_FILE=%VCPKG_ROOT_DIR%\scripts\buildsystems\vcpkg.cmake"
)

if not defined TOOLCHAIN_FILE if defined VS_INSTALL (
    if exist "%VS_INSTALL%\VC\vcpkg\scripts\buildsystems\vcpkg.cmake" set "TOOLCHAIN_FILE=%VS_INSTALL%\VC\vcpkg\scripts\buildsystems\vcpkg.cmake"
)

if not defined TOOLCHAIN_FILE (
    echo Unable to locate vcpkg toolchain.
    exit /b 1
)

if not defined VCPKG_ROOT_DIR (
    for %%I in ("%TOOLCHAIN_FILE%") do set "TOOLCHAIN_DIR=%%~dpI"
    for %%I in ("%TOOLCHAIN_DIR%..\..") do set "VCPKG_ROOT_DIR=%%~fI"
)

call :run_vs_dev_cmd %TARGET_ARCH%
exit /b %errorlevel%

:run_vs_dev_cmd
set "TARGET_ARCH=%~1"
set "VCVARS="

if defined VSINSTALLDIR (
    if exist "%VSINSTALLDIR%VC\Auxiliary\Build\vcvarsall.bat" set "VCVARS=%VSINSTALLDIR%VC\Auxiliary\Build\vcvarsall.bat"
)

if not defined VCVARS (
    if defined VS_INSTALL if exist "%VS_INSTALL%\VC\Auxiliary\Build\vcvarsall.bat" set "VCVARS=%VS_INSTALL%\VC\Auxiliary\Build\vcvarsall.bat"
)

if not defined VCVARS (
    echo Unable to locate vcvarsall.bat.
    exit /b 1
)

rem Map target architecture to vcvarsall argument
rem For ARM64 cross-compilation from x64 host, use amd64_arm64
if /I "%TARGET_ARCH%"=="arm64" (
    call "%VCVARS%" amd64_arm64
) else (
    call "%VCVARS%" %TARGET_ARCH%
)
exit /b %errorlevel%

:find_vs_install
set "VS_INSTALL="
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" exit /b 0

for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.Component.MSBuild -property installationPath 2^>nul`) do set "VS_INSTALL=%%i"
exit /b 0
