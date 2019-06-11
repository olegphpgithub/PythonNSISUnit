Name "setup"

OutFile "example.exe"

InstallDir $PROGRAMFILES\example


CRCCheck off

RequestExecutionLevel user


SetCompressor /SOLID lzma

Page components
Page instfiles


UninstPage instfiles

Section "example"
SectionEnd

Function .onInit
    
    
FunctionEnd


