/** @file
  This is DCS boot menu lock application

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Uefi.h>
#include <Guid/EventGroup.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeLib.h>
#include <Library/BaseLib.h>
#include <Library/UefiLib.h>

typedef struct _BML_GLOBALS {
	UINT64		Signature;
	UINTN			size;
} BML_GLOBALS, *PBML_GLOBALS;

STATIC PBML_GLOBALS   gBmlData = NULL;
STATIC BOOLEAN        BootMenuLocked = TRUE;
EFI_EVENT             mBmlVirtualAddrChangeEvent;
EFI_SET_VARIABLE      orgSetVariable = NULL;

EFI_STATUS
BmlSetVaribale(
	IN  CHAR16                       *VariableName,
	IN  EFI_GUID                     *VendorGuid,
	IN  UINT32                       Attributes,
	IN  UINTN                        DataSize,
	IN  VOID                         *Data
	) {
	// DcsBoot remove?
	if (VariableName != NULL && StrStr(VariableName, L"BootDC5B") == VariableName && DataSize == 0) {
		BootMenuLocked = FALSE;
	}

	if (BootMenuLocked) {
		// Block all Boot*
		if (VariableName != NULL && StrStr(VariableName, L"Boot") == VariableName) {
			return EFI_ACCESS_DENIED;
		}
	}
	return orgSetVariable(VariableName, VendorGuid, Attributes, DataSize, Data);
}

/**
Fixup internal data so that EFI can be call in virtual mode.
Call the passed in Child Notify event and convert any pointers in
lib to virtual mode.

@param[in]    Event   The Event that is being processed
@param[in]    Context Event Context
**/

VOID
EFIAPI
BmlVirtualNotifyEvent(
	IN EFI_EVENT        Event,
	IN VOID             *Context
	)
{
	EfiConvertPointer(0x0, (VOID**)&gBmlData);
	EfiConvertPointer(0x0, (VOID**)&orgSetVariable);
	return;
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
DcsBmlMain(
   IN EFI_HANDLE        ImageHandle,
   IN EFI_SYSTEM_TABLE  *SystemTable
   )
{
   EFI_STATUS          res;

	res = gBS->AllocatePool(
		EfiRuntimeServicesData,
		(UINTN) sizeof(BML_GLOBALS),
		(VOID**)&gBmlData
		);

	if (EFI_ERROR(res)) {
		Print(L"Allocate runtime globals %r\n", res);
		return res;
	}

	//
	// Register for the virtual address change event
	//
	res = gBS->CreateEventEx(
		EVT_NOTIFY_SIGNAL,
		TPL_NOTIFY,
		BmlVirtualNotifyEvent,
		NULL,
		&gEfiEventVirtualAddressChangeGuid,
		&mBmlVirtualAddrChangeEvent
		);

   if (EFI_ERROR(res)) {
		Print(L"Register notify %r\n", res);
		return res;
   }

	orgSetVariable = gST->RuntimeServices->SetVariable;
	gST->RuntimeServices->SetVariable = BmlSetVaribale;
	return EFI_SUCCESS;
}
