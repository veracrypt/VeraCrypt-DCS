
/** @file
This is DCS configuration tool. (EFI shell application/wizard)

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI 

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#ifndef __DcsCfg_h__
#define __DcsCfg_h__

#include <Uefi.h>
#include <Uefi/UefiGpt.h>

//////////////////////////////////////////////////////////////////////////
// Block I/O
//////////////////////////////////////////////////////////////////////////
extern UINTN             BioIndexStart;
extern UINTN             BioIndexEnd;
extern BOOLEAN           BioSkipPartitions;

void
BioPrintDevicePath(
	UINTN bioIndex
	);

VOID
PrintBioList();

EFI_STATUS
BlockRangeWipe(
	IN EFI_HANDLE h,
	IN UINT64 start,
	IN UINT64 end
	);

//////////////////////////////////////////////////////////////////////////
// System crypt
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
VolumeEncrypt(
	IN UINTN index);

EFI_STATUS
VolumeDecrypt(
	IN UINTN index);

EFI_STATUS
OSRestoreKey();

EFI_STATUS
OSDecrypt();

EFI_STATUS
OSUndecrypt();

EFI_STATUS
VolumeChangePassword(
	IN UINTN index);

EFI_STATUS
CreateVolumeHeaderOnDisk(
	IN UINTN          index,
	OUT VOID          **pinfo,
	OUT EFI_HANDLE    *phDisk,
	OUT UINT64        *sector
	);

EFI_STATUS
GptCryptFile(
	IN BOOLEAN  crypt
	);

EFI_STATUS
GptEdit(
	IN UINTN index
	);

EFI_STATUS
OuterInit();

//////////////////////////////////////////////////////////////////////////
// Security regions
//////////////////////////////////////////////////////////////////////////
extern UINTN gSecRigonCount;

EFI_STATUS
SecRegionMark();

EFI_STATUS
SecRegionWipe();

EFI_STATUS
SecRegionAdd(
	IN UINTN       regIdx
	);

EFI_STATUS
SecRegionDump(
	IN EFI_HANDLE   hBio,
	IN CHAR16       *prefix
	);

//////////////////////////////////////////////////////////////////////////
// Set DcsInt parameters
//////////////////////////////////////////////////////////////////////////
VOID
UpdateDcsBoot();

//////////////////////////////////////////////////////////////////////////
// DCS authorization check
//////////////////////////////////////////////////////////////////////////

EFI_STATUS 
IntCheckVolume(
	UINTN index
	);

VOID
DisksAuthCheck();

VOID
TestAuthAsk();


//////////////////////////////////////////////////////////////////////////
// RUD / USB
//////////////////////////////////////////////////////////////////////////
extern UINTN             UsbIndex;

VOID
PrintUsbList();

EFI_STATUS
UsbScApdu(
	IN CHAR16* hexString);

//////////////////////////////////////////////////////////////////////////
// Beep
//////////////////////////////////////////////////////////////////////////
VOID
PrintSpeakerList();

VOID
TestSpeaker();

//////////////////////////////////////////////////////////////////////////
// Graphics
//////////////////////////////////////////////////////////////////////////
VOID
PrintGraphList();

//////////////////////////////////////////////////////////////////////////
// Touch
//////////////////////////////////////////////////////////////////////////
extern UINTN       TouchIndex;

VOID
PrintTouchList();

VOID
TestTouch();

//////////////////////////////////////////////////////////////////////////
// Interactive setup
//////////////////////////////////////////////////////////////////////////

EFI_STATUS
DcsInteractiveSetup();

//////////////////////////////////////////////////////////////////////////
// TPM
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
Tpm12ListPcrs(
	UINT32 sPcr,
	UINT32 ePcr
	);

EFI_STATUS
Tpm12NvList();

EFI_STATUS
TpmDcsConfigure();

EFI_STATUS
Tpm2ListPcrs(
	UINT32 sPcr,
	UINT32 ePcr
	);


#endif // DcsCfg_h__
