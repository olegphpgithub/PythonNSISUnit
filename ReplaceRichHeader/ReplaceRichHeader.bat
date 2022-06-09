FOR /r %~dp0MultyHash %%a in (*.exe) do call "python.exe" "%~dp0RichReplacer.py" -rich "%~dp0nsis308.rich" -in "%%a" -out "%%a"
