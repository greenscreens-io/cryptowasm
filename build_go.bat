@echo off
cls
set GIT=X:\Git\bin
set GOROOT=X:\Go\64
set MINGW=X:\mingw\64
set BINARYEN=X:\binaryen
set PATH=%GOROOT%\bin;%MINGW%\bin;%GIT%;%GOPATH%\bin;%BINARYEN%\bin

set GOOS=js
set GOARCH=wasm
set GOCACHE=C:\Users\%username%\AppData\Local\go-build\x64
set PKG_CONFIG_PATH=%GOPATH%\pkgconfig\%GOOS%_%GOARCH%
set PKG_CONFIG_LIBDIR=%MINGW%\lib64\pkgconfig

rem copy /Y %GOROOT%\misc\wasm\wasm_exec.min.js .\static\lib
copy /Y %GOROOT%\misc\wasm\wasm_exec.js .\static\release   

@echo on
go build -o ./static/release/cryptojs.wasm ./src

rem wasm-opt static/release/cryptojs.wasm -o static/release/cryptojs.wasm -Os --strip-debug --enable-bulk-memory --precompute
