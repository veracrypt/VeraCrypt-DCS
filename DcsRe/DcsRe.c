/** @file
  This is DCS recovery loader application

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
#include <Guid/GlobalVariable.h>
#include "common/Tcdefs.h"

//////////////////////////////////////////////////////////////////////////
// Menu
//////////////////////////////////////////////////////////////////////////
typedef EFI_STATUS(*MENU_ACTION)();

typedef struct _MENU_ITEM MENU_ITEM;
typedef struct _MENU_ITEM {
	CHAR16         Text[128];
	CHAR16         Select;
	MENU_ACTION    Action;
	MENU_ITEM      *Next;
} MENU_ITEM, *PMENU_ITEM;

BOOLEAN    gContiniue = TRUE;
PMENU_ITEM gMenu = NULL;

PMENU_ITEM
AppendMenu(
	IN PMENU_ITEM  menu,
	IN CHAR16     *text,
	IN CHAR16     select,
	IN MENU_ACTION action
	) {
	PMENU_ITEM item;
	item = (PMENU_ITEM)MEM_ALLOC(sizeof(MENU_ITEM));
	if (item == NULL) return item;
	item->Action = action;
	StrCatS(item->Text, sizeof (item->Text) / sizeof (CHAR16), text);
	item->Select = select;
	if (menu != NULL) {
		menu->Next = item;
	}
	return item;
}

VOID
PrintMenu(
	PMENU_ITEM head) {
	PMENU_ITEM menu;
	UINTN i = 0;
	menu = head;
	while (menu != NULL) {
		OUT_PRINT(L"%H%c%N) %s\n", menu->Select, &menu->Text);
		i++;
		if (i == 22) {
			ConsoleShowTip(L"Pause 60s", 60000000);
			i = 0;
		}
		menu = menu->Next;
	}
	OUT_PRINT(L"[");
	menu = head;
	while (menu != NULL) {
		OUT_PRINT(L"%H%c%N", menu->Select);
		menu = menu->Next;
	}
	OUT_PRINT(L"]:");
}
//////////////////////////////////////////////////////////////////////////
// EFI volume
//////////////////////////////////////////////////////////////////////////
UINTN        EfiBootVolumeIndex = 0;
EFI_FILE     *EfiBootVolume = NULL;
VOID
SelectEfiVolume() 
{
	UINTN        i;
	EFI_STATUS   res;
	EFI_FILE     *file;
	EFI_FILE     **efiVolumes;
	UINTN        efiVolumesCount = 0;
	EFI_HANDLE   startHandle;
	if (EfiBootVolume != NULL) return;
	res = EfiGetStartDevice(&startHandle);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"GetStartDevice %r", res);
		return;
	}
	efiVolumes = MEM_ALLOC(sizeof(EFI_FILE*) * gFSCount);
	for (i = 0; i < gFSCount; ++i) {
		res = FileOpenRoot(gFSHandles[i], &file);
		if(EFI_ERROR(res)) continue;
#ifdef _M_X64
		if (!EFI_ERROR(FileExist(file, L"EFI\\Boot\\bootx64.efi"))) {
#else
		if (!EFI_ERROR(FileExist(file, L"EFI\\Boot\\bootia32.efi"))) {
#endif
			efiVolumesCount++;
			efiVolumes[i] = file;
			if (gFSHandles[i] != startHandle) {
				EfiBootVolumeIndex = i;
				EfiBootVolume = file;
			}
		}	else {
			FileClose(file);
		}
	}

	for (i = 0; i < gFSCount; ++i) {
		OUT_PRINT(L"%H%d)%N ", i);
		if (efiVolumes[i] != NULL) {
			if (gFSHandles[i] == startHandle) {
				OUT_PRINT(L"%V [Boot Rescue] %N");
			}
			else {
				OUT_PRINT(L"%V [Boot] %N");
			}
			EfiPrintDevicePath(gFSHandles[i]);
		}
		OUT_PRINT(L"\n");
	}

	do {
		EfiBootVolumeIndex = AskUINTN("Select EFI boot volume:", EfiBootVolumeIndex);
		if (EfiBootVolumeIndex >= gFSCount) continue;
		EfiBootVolume = efiVolumes[EfiBootVolumeIndex];
	} while (EfiBootVolume == NULL);
	MEM_FREE(efiVolumes);
}

//////////////////////////////////////////////////////////////////////////
// Actions
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
ActionBootWinPE() {
#ifdef _M_X64
	return EfiExec(NULL, L"EFI\\Boot\\WinPE_bootx64.efi");
#else
	return EfiExec(NULL, L"EFI\\Boot\\WinPE_bootia32.efi");
#endif
}

EFI_STATUS
ActionShell() {
	return EfiExec(NULL, L"EFI\\Shell\\Shell.efi");
}

EFI_STATUS
ActionDcsBoot() {
	SelectEfiVolume();
	if (EfiBootVolume == NULL) return EFI_NOT_READY;
	return EfiExec(gFSHandles[EfiBootVolumeIndex], L"EFI\\VeraCrypt\\DcsBoot.efi");
}

CHAR16* DcsBootBins[] = {
	L"EFI\\VeraCrypt\\DcsBoot.efi",
	L"EFI\\VeraCrypt\\DcsInt.dcs",
	L"EFI\\VeraCrypt\\DcsBml.dcs",
	L"EFI\\VeraCrypt\\DcsCfg.dcs",
	L"EFI\\VeraCrypt\\LegacySpeaker.dcs"
};

/**
Copy DCS binaries from rescue disk to EFI boot volume
*/
EFI_STATUS
ActionRestoreDcsLoader() {
	EFI_STATUS res = EFI_NOT_READY;
	UINTN i;
	SelectEfiVolume();
	if (EfiBootVolume == NULL) return EFI_NOT_READY;
	for (i = 0; i < sizeof(DcsBootBins) / sizeof(CHAR16*); ++i) {
		res = FileCopy(NULL, DcsBootBins[i], EfiBootVolume, DcsBootBins[i], 1024 * 1024);
		if (EFI_ERROR(res)) return res;
	}
	return res;
}

CHAR16* sDcsBootEfi = L"EFI\\VeraCrypt\\DcsBoot.efi";
CHAR16* sDcsBootEfiDesc = L"VeraCrypt(DCS) loader";
/**
Update boot menu
*/
EFI_STATUS
ActionRestoreDcsBootMenu() 
{
	EFI_STATUS res = EFI_NOT_READY;
	SelectEfiVolume();
	if (EfiBootVolume == NULL) return EFI_NOT_READY;
	// Prepare BootDC5B
	res = BootMenuItemCreate(L"BootDC5B", sDcsBootEfiDesc, gFSHandles[EfiBootVolumeIndex], sDcsBootEfi, TRUE);
	if (EFI_ERROR(res)) return res;
	res = BootOrderInsert(L"BootOrder", 0, 0x0DC5B);
	return res;
}

EFI_STATUS
ActionRemoveDcsBootMenu()
{
	EFI_STATUS res = EFI_NOT_READY;
	BootMenuItemRemove(L"BootDC5B");
	res = BootOrderRemove(L"BootOrder", 0x0DC5B);
	return res;
}

/** 
Copy DcsProp from rescue disk to EFI boot volume
*/
EFI_STATUS
ActionRestoreDcsProp() {
	SelectEfiVolume();
	if (EfiBootVolume == NULL) return EFI_NOT_READY;
	return FileCopy(NULL, L"EFI\\VeraCrypt\\DcsProp", EfiBootVolume, L"EFI\\VeraCrypt\\DcsProp", 1024*1024);
}

#define OPT_OS_DECRYPT L"-osdecrypt"
#define OPT_OS_RESTORE_KEY L"-osrestorekey"

CHAR16* sOSDecrypt = OPT_OS_DECRYPT;
CHAR16* sOSRestoreKey = OPT_OS_RESTORE_KEY;
CHAR16* sDcsCfg = L"EFI\\VeraCrypt\\DcsCfg.dcs";

EFI_STATUS
ActionRestoreHeader() {
	EFI_STATUS res = EFI_NOT_READY;
	res = EfiSetVar(L"dcscfgcmd", NULL, sOSRestoreKey, StrSize(sOSRestoreKey), EFI_VARIABLE_BOOTSERVICE_ACCESS);
	return EfiExec(NULL, sDcsCfg);
}

EFI_STATUS
ActionDecryptOS() {
	EFI_STATUS res = EFI_NOT_READY;
	res = EfiSetVar(L"dcscfgcmd", NULL, sOSDecrypt, StrSize(sOSDecrypt), EFI_VARIABLE_BOOTSERVICE_ACCESS);
	return EfiExec(NULL, sDcsCfg);
}

EFI_STATUS
ActionExit() {
	gContiniue = FALSE;
	return EFI_SUCCESS;
}

EFI_STATUS
ActionHelp() {
OUT_PRINT(L"\
%HRescue disk for VeraCrypt OS encryption%N\n\r\
Help message to be defined\n\r\
");
	return EFI_SUCCESS;
}

/**
The actual entry point for the application.

@param[in] ImageHandle    The firmware allocated handle for the EFI image.
@param[in] SystemTable    A pointer to the EFI System Table.

@retval EFI_SUCCESS       The entry point executed successfully.
@retval other             Some error occur when executing this entry point.

**/
EFI_STATUS
EFIAPI
DcsReMain(
   IN EFI_HANDLE        ImageHandle,
   IN EFI_SYSTEM_TABLE  *SystemTable
   )
{
   EFI_STATUS          res;
	EFI_INPUT_KEY       key;
	PMENU_ITEM          item = gMenu;
	InitBio();
   res = InitFS();
   if (EFI_ERROR(res)) {
      ERR_PRINT(L"InitFS %r\n", res);
		return res;
   }

	item = AppendMenu(NULL, L"Decrypt OS", 'd', ActionDecryptOS);
	gMenu = item;
	item = AppendMenu(item, L"Restore VeraCrypt loader to boot menu", 'm', ActionRestoreDcsBootMenu);
	item = AppendMenu(item, L"Remove VeraCrypt loader from boot menu", 'z' , ActionRemoveDcsBootMenu);

	if (!EFI_ERROR(FileExist(NULL, L"EFI\\VeraCrypt\\DcsProp"))) {
		item = AppendMenu(item, L"Restore VeraCrypt loader configuration to system disk", 'c', ActionRestoreDcsProp);
	}

	if (!EFI_ERROR(FileExist(NULL, L"EFI\\VeraCrypt\\svh_bak"))) {
		item = AppendMenu(item, L"Restore OS header keys", 'k', ActionRestoreHeader);
	}

	if (!EFI_ERROR(FileExist(NULL, L"EFI\\VeraCrypt\\DcsBoot.efi"))) {
		item = AppendMenu(item, L"Restore VeraCrypt loader binaries to system disk", 'r', ActionRestoreDcsLoader);
		item = AppendMenu(item, L"Boot VeraCrypt loader from rescue disk", 'v', ActionDcsBoot);
	}

#ifdef _M_X64
	if (!EFI_ERROR(FileExist(NULL, L"EFI\\Boot\\WinPE_bootx64.efi"))) {
#else
	if (!EFI_ERROR(FileExist(NULL, L"EFI\\Boot\\WinPE_bootia32.efi"))) {
#endif
		item = AppendMenu(item, L"Boot Windows PE from rescue disk", 'w', ActionBootWinPE);
	}

	if (!EFI_ERROR(FileExist(NULL, L"EFI\\Shell\\Shell.efi"))) {
		item = AppendMenu(item, L"Boot Shell.efi from rescue disk", 's', ActionShell);
	}

	item = AppendMenu(item, L"Help", 'h', ActionHelp);
	item = AppendMenu(item, L"Exit", 'e', ActionExit);
	OUT_PRINT(L"%V%a rescue disk %a%N\n", TC_APP_NAME, VERSION_STRING);
	gBS->SetWatchdogTimer(0, 0, 0, NULL);
	do {
		PrintMenu(gMenu);
		item = NULL;
		key.UnicodeChar = 0;
		while (item == NULL) {
			item = gMenu;
			key = GetKey();
			while (item != NULL) {
				if (item->Select == key.UnicodeChar) break;
				item = item->Next;
			}
		}
		OUT_PRINT(L"%c\n",key.UnicodeChar);
		res = item->Action();
		if (EFI_ERROR(res)) {
			ERR_PRINT(L"%r\n", res);
		}
	} while (gContiniue);
	return EFI_INVALID_PARAMETER;
}
