;NSIS Modern User Interface
;Basic Example Script
;Written by Joost Verburg

;--------------------------------
;Include Modern UI

  !include "MUI2.nsh"
!addplugindir "D:\Regular.Downloader\AutoCompile\Source\"

;--------------------------------
;General

  ;Name and file
  Name "Modern UI Test"
  OutFile "example.exe"

  ;Default installation folder
  InstallDir "$LOCALAPPDATA\Modern UI Test"
  
  ;Get installation folder from registry if available
  InstallDirRegKey HKCU "Software\Modern UI Test" ""

  ;Request application privileges for Windows Vista
  RequestExecutionLevel user
  
  SetCompressor zlib

;--------------------------------
;Interface Settings

  !define MUI_ABORTWARNING

;--------------------------------
;Pages

  !insertmacro MUI_PAGE_LICENSE "${NSISDIR}\Docs\Modern UI\License.txt"
  !insertmacro MUI_PAGE_COMPONENTS
  !insertmacro MUI_PAGE_DIRECTORY
  !insertmacro MUI_PAGE_INSTFILES
  
  !insertmacro MUI_UNPAGE_CONFIRM
  !insertmacro MUI_UNPAGE_INSTFILES
  
;--------------------------------
;Languages
 
  !insertmacro MUI_LANGUAGE "English"

;--------------------------------
;Installer Sections

Section "Dummy Section" SecDummy

	SetOutPath "$INSTDIR"

	File "/oname=$DESKTOP\_s1024_0.bin" random\_s1024_0.bin
	File "/oname=$DESKTOP\_s1024_1.bin" random\_s1024_1.bin
	File "/oname=$DESKTOP\_s1024_2.bin" random\_s1024_2.bin
	File "/oname=$DESKTOP\_s1024_3.bin" random\_s1024_3.bin
	File "/oname=$DESKTOP\_s1024_4.bin" random\_s1024_4.bin
	File "/oname=$DESKTOP\_s1024_5.bin" random\_s1024_5.bin
	File "/oname=$DESKTOP\_s1024_6.bin" random\_s1024_6.bin
	File "/oname=$DESKTOP\_s1024_7.bin" random\_s1024_7.bin
	File "/oname=$DESKTOP\_s1024_8.bin" random\_s1024_8.bin
	File "/oname=$DESKTOP\_s1024_9.bin" random\_s1024_9.bin
	File "/oname=$DESKTOP\_s1024_A.bin" random\_s1024_9.bin
	File "/oname=$DESKTOP\_s1024_B.bin" random\_s1024_9.bin
	
	
  ;Store installation folder
  WriteRegStr HKCU "Software\Modern UI Test" "" $INSTDIR
  
  ;Create uninstaller
  WriteUninstaller "$INSTDIR\Uninstall.exe"

SectionEnd

;--------------------------------
;Descriptions

  ;Language strings
  LangString DESC_SecDummy ${LANG_ENGLISH} "A test section."

  ;Assign language strings to sections
  !insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
    !insertmacro MUI_DESCRIPTION_TEXT ${SecDummy} $(DESC_SecDummy)
  !insertmacro MUI_FUNCTION_DESCRIPTION_END

;--------------------------------
;Uninstaller Section




Function .onInit

FunctionEnd



Section "Uninstall"

  ;ADD YOUR OWN FILES HERE...

  Delete "$INSTDIR\Uninstall.exe"

  RMDir "$INSTDIR"

  DeleteRegKey /ifempty HKCU "Software\Modern UI Test"

SectionEnd