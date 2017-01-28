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
#include "DcsConfig.h"
#include <Guid/Gpt.h>

EFI_GUID          ImagePartGuid;
EFI_GUID          *gEfiExecPartGuid = &ImagePartGuid;
CHAR16            *gEfiExecCmdDefault = L"\\EFI\\Microsoft\\Boot\\Bootmgfw.efi";
CHAR16            *gEfiExecCmd = NULL;
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
	InitBio();
   res = InitFS();
   if (EFI_ERROR(res)) {
      ERR_PRINT(L"InitFS %r\n", res);
   }

	drvInst = ConfigReadInt("DcsDriver", 0);

	if (EFI_ERROR(FileExist(NULL, L"\\EFI\\VeraCrypt\\PlatformInfo")) &&
		!EFI_ERROR(FileExist(NULL, L"\\EFI\\VeraCrypt\\DcsInfo.dcs"))) {
		res = EfiExec(NULL, L"\\EFI\\VeraCrypt\\DcsInfo.dcs");
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
							break;
						}
					}
				}
			}
		}
	}

	//	OUT_PRINT(L".");
	res = EfiFindPartByGUID(gEfiExecPartGuid, &gFileRootHandle);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"\nCan't find start partition %g\n", gEfiExecPartGuid);
		EfiCpuHalt();
	}
//	OUT_PRINT(L".");
	res = FileOpenRoot(gFileRootHandle, &gFileRoot);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"\nCan't open start partition\n");
		EfiCpuHalt();
	}
//	OUT_PRINT(L".");
	// Try to exec windows loader...
   res = EfiExec(NULL, gEfiExecCmd);
   if (EFI_ERROR(res)) {
      ERR_PRINT(L"\nStart %s - %r\n", gEfiExecCmd, res);
		EfiCpuHalt();
   }
	ERR_PRINT(L"???%r");
	EfiCpuHalt();
   return EFI_INVALID_PARAMETER;
}
