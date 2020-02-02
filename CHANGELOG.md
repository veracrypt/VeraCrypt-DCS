# DCS 2.00 Changelog

- Moved DcsConfig.h from VeraCryptLib to DcsCfgLib and using it to preset compile time options
-- DCS_CAPTION defines the loader name string as used in various places for display
-- DCS_DIRECTORY defines the sub folder inside the EFI folder into which DCS is being installed
-- DCS_VERSION defines the version as integer that for display is parsed like "%d.%02d%", DCS_VERSION / 100, DCS_VERSION % 100
-- See the file for more options...

- Added Visual Studio project files for a more convenient editing

- Added ability for a basic key remapping to support keyboards other than QWERTY, now supporting also QWERTZ and AZERTY

- Added support for wchar passwords

- Added new DcsProp value VerboseDebug enabling a lot of useful debut output

- Addes support for wchar values in DcsProp ConfigReadStringW

- Added option to display the letters in picture password but not the entered password to use the feature as on-screen keyboard

- Separated VeraCrypt specific code from DcsInt into VeraCryptLib/DcsVeraCryptImpl.c
-- Split IO Hooking code into a separate library DcsIntlib
-- Moved Xml.c/h to DcsCfgLib
-- Added ability to hook more than one disk drive AddCryptoMount
-- Added support for DiskCryptor in DiskCryptorLib
-- Added mechanism to select Disk Encryption support modules VeraCrypt/DiskCryptor

- Fixed a few minor bugs...
