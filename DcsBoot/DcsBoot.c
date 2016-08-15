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
	InitBio();
   res = InitFS();
   if (EFI_ERROR(res)) {
      ERR_PRINT(L"InitFS %r\n", res);
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

	// Find new start partition
   ConnectAllEfi();
	InitBio();
	res = InitFS();
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
