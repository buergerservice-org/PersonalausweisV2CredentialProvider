cd /D %systemdrive%\.
rd Programme
mklink /J Programme "%ProgramFiles%"
mklink /J "Programme (x86)" "%ProgramFiles (x86)%"
