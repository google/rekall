echo off

rem This batch script installs Rekall Agent as a windows service using
rem the nssm tool which was originally downloaded from http://nssm.cc/

rem Edit the following if needed.
set "service=RekallAgent"
set "RekallPath=%PROGRAMFILES%\Rekall"
set "nssm=%RekallPath%\resources\nssm.exe"

rem Make sure to edit this before deployment.
set "RekallAgentConfig=%RekallPath%\resources\rekall-agent.yaml"

"%nssm%" stop "%service%" confirm
"%nssm%" remove "%service%" confirm
"%nssm%" install "%service%" "%RekallPath%\rekal.exe"
"%nssm%" set "%service%" AppParameters agent --agent_config """%RekallAgentConfig%"""

rem This is a log file of Rekall Agent messages.
"%nssm%" set "%service%" AppStdout "%RekallPath%\RekallAgent.log"
"%nssm%" set "%service%" AppStderr "%RekallPath%\RekallAgent.log"

rem This will rotate the log files.
"%nssm%" set "%service%" AppRotateFiles 1
"%nssm%" set "%service%" AppRotateBytes 10000000

rem Service must be running at least this long to be considered healthy.
"%nssm%" set "%service%" AppThrottle 30000

rem Service may not be restarted more frequently than this many ms.
"%nssm%" set "%service%" AppRestartDelay 60000

"%nssm%" start "%service%"
