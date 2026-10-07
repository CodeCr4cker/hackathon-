@echo off
setlocal EnableExtensions DisableDelayedExpansion
title Secure Folder Lock
color 0B

rem ===========================================================================
rem  Lock.bat - basic folder locking utility (single file, pure batch)
rem
rem  IMPORTANT LIMITATIONS - PLEASE READ
rem  * A pure batch file CANNOT provide cryptographically secure password
rem    storage. The password check uses a custom salted and stretched hash
rem    built from batch integer math. It only avoids storing the password in
rem    plain text. It is NOT a vetted algorithm such as SHA-256 or bcrypt,
rem    and it is not a security guarantee.
rem  * This is a basic folder-locking utility, not a replacement for
rem    professional encryption software such as BitLocker, VeraCrypt or
rem    7-Zip with AES encryption. Locked files are NOT encrypted.
rem  * The lock works by hiding the folder and adding a deny rule for
rem    Everyone through icacls. The folder owner or an administrator can
rem    remove that rule manually at any time, for example with:
rem        icacls "Private" /remove:d *S-1-1-0
rem        attrib -h -s "Private"
rem    The password prompt only controls access through this script.
rem  * This file is plain text. Anyone who can edit it can change its logic
rem    or replace the stored password data line at the bottom of the file.
rem  * The limit of 5 failed attempts applies per session only. Restarting
rem    the script resets the counter. There is no master password or
rem    hidden bypass in this script.
rem  * Password input is hidden using ANSI escape codes (black text on a
rem    black background), which works on Windows 10 and 11 consoles. In a
rem    console without ANSI support the typed text may be visible until the
rem    screen is cleared.
rem  * Allowed password characters: letters, digits and the symbols
rem    @ # $ _ - + . ~   (length 4 to 32).
rem
rem  HOW PASSWORD DATA IS STORED
rem  * The last line of this file holds the salt and the two hash values.
rem    Do not move or edit it by hand. When the password is created or
rem    changed, the script rewrites this same file: it copies every line
rem    except the data line to a short-lived temporary file next to this
rem    script, appends the new data line, then moves that file over this
rem    one. No other file is left behind. Because the data line is the last
rem    line, the lines above it never move while the script is running.
rem  * The only delete command in this script removes that temporary file
rem    if the final move fails. Nothing of the user is ever deleted.
rem  * Save this file with ANSI or ASCII encoding and Windows (CRLF) line
rem    endings.
rem
rem  FOLDER LOCATION
rem  * The protected folder named Private is created in the same folder as
rem    this script, found through the script's own drive and path. No user
rem    name or drive letter is hard-coded.
rem ===========================================================================

set "SELF=%~f0"
set "BASE=%~dp0"
set "FOLDERNAME=Private"
set "FOLDER=%BASE%%FOLDERNAME%"
set "DENYACE=*S-1-1-0:(OI)(CI)F"
set "MAXTRIES=5"
set "FAILS=0"
set "CHARSET=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$_-+.~"

rem Create an ESC character for ANSI sequences (used to hide password input).
for /f %%E in ('echo prompt $E^| cmd') do set "ESC=%%E"

call :LoadData
if errorlevel 1 goto :DataError
if /i "%D_H1%"=="NONE" goto :FirstRun
goto :MainMenu


rem ===========================================================================
rem  FIRST RUN
rem ===========================================================================
:FirstRun
call :Banner
echo   FIRST-TIME SETUP
echo.
echo   No password has been set yet. Please create one now.
echo   The password is never shown on screen.
echo.
pause
:FirstRunAsk
call :ReadNewPassword
if errorlevel 1 (
    choice /c YN /n /m "  Try again? [Y/N]: "
    if errorlevel 2 (
        endlocal
        exit /b 1
    )
    goto :FirstRunAsk
)
call :SaveData
if errorlevel 1 (
    call :Msg 0C "Could not write the password data into Lock.bat. Is the file writable?"
    endlocal
    exit /b 1
)
call :CheckState
if "%EXISTS%"=="0" md "%FOLDER%" 2>nul
call :CheckState
if "%EXISTS%"=="0" (
    call :Msg 0C "Password saved, but the Private folder could not be created."
    goto :MainMenu
)
call :Msg 0A "Setup complete. Password saved and the Private folder was created."
goto :MainMenu


rem ===========================================================================
rem  MAIN MENU
rem ===========================================================================
:MainMenu
call :Banner
echo [1] Lock Folder
echo [2] Unlock Folder
echo [3] Change Password
echo [4] Security Status
echo [5] Exit
echo.
choice /c 12345 /n /m "Select an option [1-5]: "
if errorlevel 5 goto :Quit
if errorlevel 4 goto :DoStatus
if errorlevel 3 goto :DoChange
if errorlevel 2 goto :DoUnlock
if errorlevel 1 goto :DoLock
goto :MainMenu


rem ===========================================================================
rem  [1] LOCK FOLDER
rem ===========================================================================
:DoLock
call :Banner
call :CheckState
if "%EXISTS%"=="0" (
    echo   The "%FOLDERNAME%" folder does not exist.
    echo.
    choice /c YN /n /m "  Create it now? [Y/N]: "
    if errorlevel 2 goto :MainMenu
    md "%FOLDER%" 2>nul
    call :CheckState
)
if "%EXISTS%"=="0" (
    call :Msg 0C "The folder could not be created."
    goto :MainMenu
)
if "%LOCKED%"=="1" (
    call :Msg 0E "The folder is already locked."
    goto :MainMenu
)
echo   Locking folder, please wait...
rem Hide first: after the deny rule is applied, attributes can no longer change.
attrib +h +s "%FOLDER%" >nul 2>&1
icacls "%FOLDER%" /deny "%DENYACE%" >nul 2>&1
if errorlevel 1 (
    attrib -h -s "%FOLDER%" >nul 2>&1
    call :Msg 0C "Failed to lock the folder. Run this script as the user who owns it."
    goto :MainMenu
)
call :Msg 0A "Folder locked successfully."
goto :MainMenu


rem ===========================================================================
rem  [2] UNLOCK FOLDER
rem ===========================================================================
:DoUnlock
call :Banner
call :CheckState
if "%EXISTS%"=="0" (
    call :Msg 0C "The Private folder does not exist."
    goto :MainMenu
)
if "%LOCKED%"=="0" (
    call :Msg 0E "The folder is not currently locked."
    goto :MainMenu
)
call :Authenticate
if errorlevel 2 goto :Lockout
if errorlevel 1 goto :MainMenu
echo   Unlocking folder, please wait...
icacls "%FOLDER%" /remove:d "*S-1-1-0" >nul 2>&1
if errorlevel 1 (
    call :Msg 0C "Failed to restore access to the folder."
    goto :MainMenu
)
attrib -h -s "%FOLDER%" >nul 2>&1
call :Msg 0A "Folder unlocked successfully."
goto :MainMenu


rem ===========================================================================
rem  [3] CHANGE PASSWORD
rem ===========================================================================
:DoChange
call :Banner
echo   CHANGE PASSWORD
echo.
echo   Step 1: verify your current password.
echo.
call :Authenticate
if errorlevel 2 goto :Lockout
if errorlevel 1 goto :MainMenu
:DoChangeNew
call :ReadNewPassword
if errorlevel 1 (
    choice /c YN /n /m "  Try again? [Y/N]: "
    if errorlevel 2 goto :MainMenu
    goto :DoChangeNew
)
call :SaveData
if errorlevel 1 (
    call :Msg 0C "Could not update the password data inside Lock.bat."
    goto :MainMenu
)
call :Msg 0A "Password changed successfully."
goto :MainMenu


rem ===========================================================================
rem  [4] SECURITY STATUS
rem ===========================================================================
:DoStatus
call :Banner
call :CheckState
set "S_EXISTS=NO"
if "%EXISTS%"=="1" set "S_EXISTS=YES"
set "S_LOCK=N/A"
if "%EXISTS%"=="1" set "S_LOCK=UNLOCKED"
if "%LOCKED%"=="1" set "S_LOCK=LOCKED"
echo   SECURITY STATUS
echo   ------------------------------
echo   Folder exists ........ %S_EXISTS%
echo   Folder state ......... %S_LOCK%
echo   Failed attempts ...... %FAILS% of %MAXTRIES% (this session)
echo.
pause
goto :MainMenu


rem ===========================================================================
rem  EXIT / TERMINATION
rem ===========================================================================
:Quit
color
cls
endlocal
exit /b 0

:Lockout
color 0C
echo.
echo   The program will now close.
echo.
pause
endlocal
exit /b 1

:DataError
call :Msg 0C "Password data is missing or corrupted in Lock.bat. Exiting."
endlocal
exit /b 1


rem ===========================================================================
rem  SUBROUTINES (reached only through CALL)
rem ===========================================================================

:Banner
color 0B
cls
echo ==============================
echo       SECURE FOLDER LOCK
echo ==============================
echo.
exit /b 0


rem  Msg: colour code in argument 1, message text in argument 2
:Msg
color %~1
echo.
echo   %~2
echo.
pause
color 0B
exit /b 0


rem  ReadHidden: prompt text in argument 1, result goes into INPUT_PW.
rem  Input is typed as black on black, then the screen is cleared.
:ReadHidden
set "INPUT_PW="
<nul set /p "=  %~1"
<nul set /p "=%ESC%[30;40m"
set /p "INPUT_PW="
<nul set /p "=%ESC%[0m"
cls
exit /b 0


rem  NewSalt: generates a random salt into HP_SALT
:NewSalt
set /a "HP_SALT=(%RANDOM%*32768)+%RANDOM%"
exit /b 0


rem  Hash: input INPUT_PW and HP_SALT, output HP_H1 and HP_H2
rem  Exit code 0 = ok, 1 = invalid character found, 2 = bad length (4 to 32)
:Hash
setlocal EnableDelayedExpansion
if not defined INPUT_PW (
    endlocal
    exit /b 2
)
set "len=0"
:hash_len
if "!INPUT_PW:~%len%,1!"=="" goto :hash_len_done
set /a len+=1
goto :hash_len
:hash_len_done
if %len% LSS 4 (
    endlocal
    exit /b 2
)
if %len% GTR 32 (
    endlocal
    exit /b 2
)
set "cl=0"
:hash_cs
if "!CHARSET:~%cl%,1!"=="" goto :hash_cs_done
set /a cl+=1
goto :hash_cs
:hash_cs_done
set /a "cmax=cl-1, last=len-1"
set /a "h1=HP_SALT, h2=HP_SALT^1515870810"
set "bad="
for /l %%p in (0,1,%last%) do (
    set "idx=-1"
    for /l %%j in (0,1,%cmax%) do (
        if "!INPUT_PW:~%%p,1!"=="!CHARSET:~%%j,1!" set "idx=%%j"
    )
    if "!idx!"=="-1" set "bad=1"
    set /a "v=idx+33"
    set /a "h1=((h1*33)^v)+(h2>>5)+%%p+1, h2=((h2*65599)+(v*131))^(h1>>3)"
)
if defined bad (
    endlocal
    exit /b 1
)
rem Key stretching: many mixing rounds make each guess slightly slower.
for /l %%i in (1,1,3000) do set /a "h1=((h1^h2)*16777619)+%%i, h2=((h2+h1)*2654435)^(h1>>7)"
endlocal & set "HP_H1=%h1%" & set "HP_H2=%h2%" & exit /b 0


rem  LoadData: reads the data line at the bottom of this file
rem  Sets D_SALT, D_H1, D_H2. Exit code 1 if the line is missing.
:LoadData
set "D_SALT="
set "D_H1="
set "D_H2="
for /f "usebackq tokens=2,3,4 delims=:" %%A in (`findstr /b /c:"::LOCKDATA:" "%SELF%"`) do (
    set "D_SALT=%%A"
    set "D_H1=%%B"
    set "D_H2=%%C"
)
if not defined D_H1 exit /b 1
if not defined D_H2 exit /b 1
exit /b 0


rem  SaveData: writes HP_SALT, HP_H1, HP_H2 into the data line of this file
:SaveData
set "TMPF=%SELF%.pwdwrite.tmp"
findstr /v /b /c:"::LOCKDATA:" "%SELF%" >"%TMPF%" 2>nul
if errorlevel 1 (
    if exist "%TMPF%" del /q "%TMPF%" >nul 2>&1
    exit /b 1
)
>>"%TMPF%" echo ::LOCKDATA:%HP_SALT%:%HP_H1%:%HP_H2%
move /y "%TMPF%" "%SELF%" >nul 2>&1
if errorlevel 1 (
    if exist "%TMPF%" del /q "%TMPF%" >nul 2>&1
    exit /b 1
)
exit /b 0


rem  CheckState: sets EXISTS (0 or 1) and LOCKED (0 or 1)
:CheckState
set "EXISTS=0"
set "LOCKED=0"
dir /b /a:d "%BASE%" 2>nul | findstr /i /x /c:"%FOLDERNAME%" >nul && set "EXISTS=1"
if "%EXISTS%"=="1" (
    dir "%FOLDER%" >nul 2>&1 || set "LOCKED=1"
    icacls "%FOLDER%" 2>nul | findstr /i /c:"(DENY)" >nul && set "LOCKED=1"
)
exit /b 0


rem  Authenticate: asks for the current password
rem  Exit code 0 = correct, 1 = wrong (counter increased), 2 = terminate program
:Authenticate
call :LoadData
if errorlevel 1 (
    call :Msg 0C "Password data is missing or corrupted."
    exit /b 2
)
call :ReadHidden "Enter password: "
set "HP_SALT=%D_SALT%"
call :Hash
set "AUTH_RC=%errorlevel%"
set "INPUT_PW="
set "AUTH_OK=0"
if "%AUTH_RC%"=="0" if "%HP_H1%"=="%D_H1%" if "%HP_H2%"=="%D_H2%" set "AUTH_OK=1"
call :Banner
if "%AUTH_OK%"=="1" exit /b 0
set /a FAILS+=1
color 0C
echo   Incorrect password.
echo   Failed attempts this session: %FAILS% of %MAXTRIES%
if %FAILS% GEQ %MAXTRIES% (
    echo.
    echo   Maximum number of failed attempts reached.
    echo.
    pause
    color 0B
    exit /b 2
)
echo.
pause
color 0B
exit /b 1


rem  ReadNewPassword: asks twice for a new password
rem  On success HP_SALT, HP_H1 and HP_H2 hold the new values (exit code 0)
:ReadNewPassword
call :Banner
echo   Password rules:
echo     - 4 to 32 characters
echo     - Letters, digits and these symbols only:  @ # $ _ - + . ~
echo.
call :ReadHidden "Enter new password  : "
call :NewSalt
call :Hash
set "NP_RC=%errorlevel%"
set "INPUT_PW="
call :Banner
if "%NP_RC%"=="1" (
    call :Msg 0C "The password contains characters that are not allowed."
    exit /b 1
)
if "%NP_RC%"=="2" (
    call :Msg 0C "The password must be 4 to 32 characters long."
    exit /b 1
)
set "NP_H1=%HP_H1%"
set "NP_H2=%HP_H2%"
echo   Re-enter the password to confirm it.
echo.
call :ReadHidden "Confirm new password: "
call :Hash
set "NP_RC=%errorlevel%"
set "INPUT_PW="
call :Banner
set "NP_OK=0"
if "%NP_RC%"=="0" if "%HP_H1%"=="%NP_H1%" if "%HP_H2%"=="%NP_H2%" set "NP_OK=1"
if "%NP_OK%"=="0" (
    call :Msg 0C "The passwords do not match."
    exit /b 1
)
exit /b 0


rem  Safety stop: execution must never run into the data line below.
exit /b 0

::LOCKDATA:NONE:NONE:NONE
