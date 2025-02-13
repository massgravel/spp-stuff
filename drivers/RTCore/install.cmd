copy "%~dp0RTCore64.sys" %systemdrive%\RTCore64.sys
sc.exe create RTCore64 type= kernel start= auto binPath= %systemdrive%\RTCore64.sys DisplayName= "Micro - Star MSI Afterburner"
net.exe start RTCore64
pause
