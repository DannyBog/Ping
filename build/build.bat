@echo off

set "app=Ping"

if "%1" equ "debug" (
	set "cl=/MTd /Od /D_DEBUG /Zi /RTC1 /Fd%app%.pdb /fsanitize=address"
	set "link=/DEBUG libucrtd.lib"
) else (
	set "cl=/GL /O1 /DNDEBUG /GS-"
	set "link=/LTCG /OPT:REF /OPT:ICF libvcruntime.lib"
)

set "warnings=/wd4100 /wd4706"

if not exist "%~dp0..\output" mkdir "%~dp0..\output"

pushd "%~dp0..\output"
cl /nologo /WX /W4 %warnings% /MP "..\src\ping.c" /Fe%app% /link /INCREMENTAL:NO /SUBSYSTEM:CONSOLE /FIXED /merge:_RDATA=.rdata

del *.obj *.res >nul
popd