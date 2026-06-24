@echo off
rem Build myatg.exe with the in-box .NET Framework C# compiler (no SDK required).
setlocal
set CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe
if not exist "%CSC%" (
  echo error: csc.exe not found at %CSC% -- needs .NET Framework 4.x ^(x64^) >&2
  exit /b 1
)
"%CSC%" /nologo /r:System.Security.dll /out:myatg.exe myatg.cs rdp_validate.cs
endlocal
