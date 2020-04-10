#NoEnv  ; Recommended for performance and compatibility with future AutoHotkey releases.
; #Warn  ; Enable warnings to assist with detecting common errors.
SendMode Input  ; Recommended for new scripts due to its superior speed and reliability.
SetWorkingDir %A_ScriptDir%  ; Ensures a consistent starting directory.

Loop 5 {
	ImageSearch, FoundX1, FoundY1, 0,0,A_ScreenWidth, A_ScreenHeight, loggedin.png
	ImageSearch, FoundX2, FoundY2, 0,0,A_ScreenWidth, A_ScreenHeight, loggedin2.png

	If (FoundX1 is integer or FoundX2 is integer)
	{
		ExitApp
	}

	Process, Close, parsecd.exe
	Sleep 1000
	Run parsecd.exe, C:\Program Files\Parsec, max
	Sleep 1000
	Send, parsec@ds-fix.com
	Send, {TAB}
	Sleep 500
	Send, pineappleexpress2008
	Send, {ENTER}
	Sleep 10000
}
return