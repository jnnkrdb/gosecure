@echo off
git add .

set /p commitgmsg=CommitMessage:

git commit -m "%commitgmsg%"

git push origin master

git tag

set /p tag=NewTag:

if "%tag%" == "" goto END

git tag %tag%

git push origin %tag%

:END