@echo off
cls

set GIT=X:\Git\bin
set GOROOT=X:\Go\64
set MINGW=X:\TDM-GCC-64\
set PATH=%GOROOT%\bin;%MINGW%\bin;%GIT%;%GOPATH%\bin

set GOOS=windows
set GOARCH=amd64
set GOCACHE=C:\Users\%username%\AppData\Local\go-build\x64
set PKG_CONFIG_PATH=%GOPATH%\pkgconfig\%GOOS%_%GOARCH%
set PKG_CONFIG_LIBDIR=%MINGW%\lib64\pkgconfig

@echo on
rem call X:\TDM-GCC-64\mingwvars.bat
go build -trimpath -ldflags "-s -w" -buildmode=c-shared -o ./cryptojs.dll ./src

