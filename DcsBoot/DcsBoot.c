/** @file
  This is DCS boot loader application

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI 

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Uefi.h>
#include <Library/CommonLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DevicePathLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PrintLib.h>
#include "DcsConfig.h"
#include <Guid/Gpt.h>
#include <Guid/GlobalVariable.h>

EFI_GUID          ImagePartGuid;
EFI_GUID          *gEfiExecPartGuid = &ImagePartGuid;
CHAR16            *gEfiExecCmdDefault = L"\\EFI\\Microsoft\\Boot\\Bootmgfw.efi";
CHAR16            *gEfiExecCmd = NULL;
CHAR8             gDoExecCmdMsg[256];

EFI_STATUS
DoExecCmd() 
{
	EFI_STATUS          res;
	gDoExecCmdMsg[0] = 0;
	res = EfiFindPartByGUID(gEfiExecPartGuid, &gFileRootHandle);
	if (!EFI_ERROR(res)) {
		res = FileOpenRoot(gFileRootHandle, &gFileRoot);
		if (!EFI_ERROR(res)) {
			res = EfiExec(NULL, gEfiExecCmd);
			AsciiSPrint(gDoExecCmdMsg, sizeof(gDoExecCmdMsg), "\nCan't exec %s start partition %g\n", gEfiExecCmd, gEfiExecPartGuid);
		}	else {
			AsciiSPrint(gDoExecCmdMsg, sizeof(gDoExecCmdMsg), "\nCan't open start partition %g\n", gEfiExecPartGuid);
		}
	}	else {
		AsciiSPrint(gDoExecCmdMsg, sizeof(gDoExecCmdMsg), "\nCan't find start partition %g\n", gEfiExecPartGuid);
	}
	return res;
}

CHAR16* sDcsBootEfi = L"EFI\\VeraCrypt\\DcsBoot.efi";
CHAR16* sDcsDriverEfiDesc = L"VeraCrypt(DCS) driver";
/**
The actual entry point for the application.

@param[in] ImageHandle    The firmware allocated handle for the EFI image.
@param[in] SystemTable    A pointer to the EFI System Table.

@retval EFI_SUCCESS       The entry point executed successfully.
@retval other             Some error occur when executing this entry point.

**/
EFI_STATUS
EFIAPI
DcsBootMain(
   IN EFI_HANDLE        ImageHandle,
   IN EFI_SYSTEM_TABLE  *SystemTable
   )
{
   EFI_STATUS          res;
	UINTN               len;
	UINT32              attr;
	int                 drvInst;
	BOOLEAN             searchOnESP = FALSE;
	EFI_INPUT_KEY       key;

	InitBio();
   res = InitFS();
   if (EFI_ERROR(res)) {
      ERR_PRINT(L"InitFS %r\n", res);
   }
	// Check multiple execution
	res = EfiGetVar(L"DcsExecPartGuid", NULL, &gEfiExecPartGuid, &len, &attr);
	if (!EFI_ERROR(res)) {
		// DcsBoot executed already.
		ERR_PRINT(L"Multiple execution of DcsBoot\n");
		MEM_FREE(gEfiExecPartGuid);
		return EFI_INVALID_PARAMETER;
	}

	// Driver load selected?
	drvInst = ConfigReadInt("DcsDriver", 0);
	if (drvInst) {
		CHAR16* tmp = NULL;
		// Driver installed?
		res = EfiGetVar(L"DriverDC5B", &gEfiGlobalVariableGuid, &tmp, &len, &attr);
		if (EFI_ERROR(res)) {
			// No - install and reboot.
			res = BootMenuItemCreate(L"DriverDC5B", sDcsDriverEfiDesc, gFileRootHandle, sDcsBootEfi, FALSE);
			if (!EFI_ERROR(res)) {
				len = 0;
				res = EfiGetVar(L"DriverOrder", &gEfiGlobalVariableGuid, &tmp, &len, &attr);
				if (!EFI_ERROR(res)) len = len / 2;
				res = BootOrderInsert(L"DriverOrder", len, 0x0DC5B);
				OUT_PRINT(L"DcsBoot driver installed, %r\n", res);
				key = KeyWait(L"%2d   \r", 10, 0, 0);
				gST->RuntimeServices->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);
				return res;
			}
			ERR_PRINT(L"Failed to install DcsBoot driver. %r\n", res);
			key = KeyWait(L"%2d   \r", 10, 0, 0);
		}
		MEM_FREE(tmp);
	}	else {
		CHAR16* tmp = NULL;
		// Try uninstall driver
		res = EfiGetVar(L"DriverDC5B", &gEfiGlobalVariableGuid, &tmp, &len, &attr);
		if (!EFI_ERROR(res)) {
			BootMenuItemRemove(L"DriverDC5B");
			BootOrderRemove(L"DriverOrder", 0x0DC5B);
			OUT_PRINT(L"DcsBoot driver uninstalled\n");
			key = KeyWait(L"%2d   \r", 10, 0, 0);
			gST->RuntimeServices->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);
		}
	}

	// Try platform info
	if (EFI_ERROR(FileExist(NULL, L"\\EFI\\VeraCrypt\\PlatformInfo")) &&
		!EFI_ERROR(FileExist(NULL, L"\\EFI\\VeraCrypt\\DcsInfo.dcs"))) {
		res = EfiExec(NULL, L"\\EFI\\VeraCrypt\\DcsInfo.dcs");
		if (!EFI_ERROR(res) && 
			!EFI_ERROR(FileExist(NULL, L"\\EFI\\VeraCrypt\\PlatformInfo"))) {
			gST->RuntimeServices->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);
		}
	}

	// Load all drivers
	res = EfiExec(NULL, L"\\EFI\\VeraCrypt\\LegacySpeaker.dcs");

	res = EfiGetPartGUID(gFileRootHandle, &ImagePartGuid);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"\nStart partition %r\n", res);
		return res;
	}

	EfiSetVar(L"DcsExecPartGuid", NULL, &ImagePartGuid, sizeof(EFI_GUID), EFI_VARIABLE_BOOTSERVICE_ACCESS);
	EfiSetVar(L"DcsExecCmd", NULL, gEfiExecCmdDefault, (StrLen(gEfiExecCmdDefault) + 1) * 2, EFI_VARIABLE_BOOTSERVICE_ACCESS);
	// Authorize
	res = EfiExec(NULL, L"\\EFI\\VeraCrypt\\DcsInt.dcs");
   if (EFI_ERROR(res)) {
      // ERR_PRINT(L"\nDcsInt.efi %r\n",res);
      return res;
   }

	res = EfiGetVar(L"DcsExecPartGuid", NULL, &gEfiExecPartGuid, &len, &attr);
	if (EFI_ERROR(res)) {
		gEfiExecPartGuid = &ImagePartGuid;
	}

	res = EfiGetVar(L"DcsExecCmd", NULL, &gEfiExecCmd, &len, &attr);
	if (EFI_ERROR(res)) {
		gEfiExecCmd = gEfiExecCmdDefault;
	}

	searchOnESP = CompareGuid(gEfiExecPartGuid, &ImagePartGuid) &&
		EFI_ERROR(FileExist(NULL, gEfiExecCmd));

	// Find new start partition
   ConnectAllEfi();
	InitBio();
	res = InitFS();

	// Default load of bootmgfw?
	if (searchOnESP) {
		// gEfiExecCmd is not found on start partition. Try from ESP
		EFI_BLOCK_IO_PROTOCOL *bio = NULL;
		EFI_PARTITION_TABLE_HEADER *gptHdr = NULL;
		EFI_PARTITION_ENTRY        *gptEntry = NULL;
		HARDDRIVE_DEVICE_PATH hdp;
		EFI_HANDLE disk;
		if (!EFI_ERROR(res = EfiGetPartDetails(gFileRootHandle, &hdp, &disk))) {
			if ((bio = EfiGetBlockIO(disk)) != NULL) {
				if (!EFI_ERROR(res = GptReadHeader(bio, 1, &gptHdr)) &&
					!EFI_ERROR(res = GptReadEntryArray(bio, gptHdr, &gptEntry))) {
					UINT32 i;
					for (i = 0; i < gptHdr->NumberOfPartitionEntries; ++i) {
						if (CompareGuid(&gptEntry[i].PartitionTypeGUID, &gEfiPartTypeSystemPartGuid)) {
							// select ESP GUID
							CopyGuid(gEfiExecPartGuid, &gptEntry[i].UniquePartitionGUID);
							res = DoExecCmd();
							if(EFI_ERROR(res)) continue;
						}
					}
				}
			}
		}
	}	else {
		res = DoExecCmd();
	}

	ERR_PRINT(L"%a\nStatus -  %r", gDoExecCmdMsg, res);
	EfiCpuHalt();
   return EFI_INVALID_PARAMETER;
}
