copy "%~dp0StartSuspended.sys" %systemdrive%\StartSuspended.sys
sc.exe create StartSuspended type= kernel start= auto binPath= %systemdrive%\StartSuspended.sys
reg.exe add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\StartSuspended /v Target /t REG_SZ /d sppsvc.exe /f
net.exe start StartSuspended
pause
