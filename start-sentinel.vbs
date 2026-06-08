Set WshShell = CreateObject("WScript.Shell")
WshShell.Run Chr(34) & WshShell.CurrentDirectory & "\start.bat" & Chr(34), 0
Set WshShell = Nothing