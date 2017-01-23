/** @file
Platform Id based on SMBIOS structures

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Uefi.h>
#include <Guid/SmBios.h>
#include <IndustryStandard\SmBios.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/BaseMemoryLib.h>

#include "Library/CommonLib.h"

SMBIOS_TABLE_ENTRY_POINT*     gSmbTable = NULL;
EFI_GUID*                     gSmbSystemUUID = NULL;           // Universal unique ID 
CHAR8*                        gSmbSystemSerial = NULL;         // System serial
CHAR8*                        gSmbSystemSKU = NULL;            // SKU number
CHAR8*                        gSmbSystemManufacture = NULL;    // computer manufacture
CHAR8*                        gSmbSystemModel = NULL;          // computer model
CHAR8*                        gSmbSystemVersion = NULL;        // computer version

CHAR8*                        gSmbBaseBoardSerial = NULL;      // Base board serial
UINT64*                       gSmbProcessorID = NULL;          // Processor ID

CHAR8*                        gSmbBiosVendor = NULL;           // BIOS vendor
CHAR8*                        gSmbBiosVersion = NULL;          // BIOS version
CHAR8*                        gSmbBiosDate = NULL;             // BIOS date



UINTN        gBioIndexAuth = 0;
typedef struct _DCS_AUTH_DATA_MARK {
	UINT32     HeaderCrc;
	UINT32     PlatformCrc;
	UINT32     AuthDataSize;
	UINT32     Reserved;
} DCS_AUTH_DATA_MARK;

CHAR8* SMBIOSGetString(UINTN StringNumber, SMBIOS_STRUCTURE* smbtbl, CHAR8* lastAddr) {
	CHAR8* String;
	UINTN Index;
	String = ((UINT8*)smbtbl) + smbtbl->Length;
	for (Index = 1; Index <= StringNumber; Index++) {
		if (StringNumber == Index) {
			return String;
		}
		//
		// Skip string
		//
		while (*String != 0) {
			String++;
			if (String > lastAddr) {
				return NULL;
			}
		}
		String++;
// 		if (*String == 0) {
// 			return NULL;
// 		}
	}
	return NULL;
}

/**
* Get SMBIOS serial data
*/
EFI_STATUS
SMBIOSGetSerials()
{
	EFI_STATUS                    res;
	SMBIOS_STRUCTURE_POINTER      pSMBIOS;
	CHAR8*                        pos = NULL;
	CHAR8*                        endOfTable;

	// Get SMBIOS tables pointer from System Configure table
	res = EfiGetSystemConfigurationTable(&gEfiSmbiosTableGuid, (VOID**)&gSmbTable);
	if (EFI_ERROR(res)) {
		return res;
	}
	pSMBIOS.Raw = (UINT8 *)(UINTN)(gSmbTable->TableAddress);
	pos = pSMBIOS.Raw;
	endOfTable = pSMBIOS.Raw + gSmbTable->TableLength;
	do {
		SMBIOS_STRUCTURE* smbtbl = (SMBIOS_STRUCTURE*)pos;
		// BIOS information
		if (smbtbl->Type == 0) {
			gSmbBiosVendor = SMBIOSGetString(1, smbtbl, endOfTable);
			gSmbBiosVersion = SMBIOSGetString(2, smbtbl, endOfTable);
			gSmbBiosDate = SMBIOSGetString(3, smbtbl, endOfTable);
		}
		// System info
		if (smbtbl->Type == 1) {
			gSmbSystemUUID = (EFI_GUID*)&pos[8];
			gSmbSystemManufacture = SMBIOSGetString(1, smbtbl, endOfTable);
			gSmbSystemModel = SMBIOSGetString(2, smbtbl, endOfTable);
			gSmbSystemVersion = SMBIOSGetString(3, smbtbl, endOfTable);
			gSmbSystemSerial = SMBIOSGetString(4, smbtbl, endOfTable);
			gSmbSystemSKU = SMBIOSGetString(5, smbtbl, endOfTable);
		}
		// Base board
		if (smbtbl->Type == 2) {
			gSmbBaseBoardSerial = SMBIOSGetString(4, smbtbl, endOfTable);
		}
		// Processor
		if (smbtbl->Type == 4) {
			gSmbProcessorID = (UINT64*)&pos[8];
		}
		pos += smbtbl->Length;
		while (((pos[0] != 0) || (pos[1] != 0)) && (pos < endOfTable)) pos++;
		pos += 2;
	} while (pos < endOfTable);

	return EFI_SUCCESS;
}

EFI_STATUS
PlatformGetID(
	IN  EFI_HANDLE  handle,
	OUT CHAR8       **id,
	OUT UINTN       *idlength
	) 
{
	EFI_STATUS                    res = EFI_SUCCESS;
	UINTN                         idLen = 0;
	CHAR8*                        idBuf = NULL;
	CHAR8*                        handleSerial = NULL;

	UsbGetId(handle, &handleSerial);
	if (gSmbSystemUUID == NULL) SMBIOSGetSerials();
	idLen += (gSmbSystemUUID == NULL) ? 0 : sizeof(*gSmbSystemUUID);
	idLen += (gSmbSystemSerial == NULL) ? 0 : AsciiStrLen((char*)gSmbSystemSerial) + 1;
	idLen += (gSmbSystemSKU == NULL) ? 0 : AsciiStrLen((char*)gSmbSystemSKU) + 1;
	idLen += (gSmbBaseBoardSerial == NULL) ? 0 : AsciiStrLen((char*)gSmbBaseBoardSerial) + 1;
	idLen += (gSmbProcessorID == NULL) ? 0 : sizeof(*gSmbProcessorID);
	idLen += (handleSerial == NULL) ? 0 : AsciiStrLen((char*)handleSerial) + 1;

	idBuf = MEM_ALLOC(idLen);
	if (idBuf == NULL) {
		res = EFI_BUFFER_TOO_SMALL;
		goto error;
	}

	*id = idBuf;
	*idlength = idLen;

	if (gSmbSystemUUID != NULL) {
		CopyMem(idBuf, gSmbSystemUUID, sizeof(*gSmbSystemUUID));
		idBuf += sizeof(*gSmbSystemUUID);
	}

	if (gSmbSystemSerial != NULL) {
		UINTN ssz;
		ssz = AsciiStrLen((char*)gSmbSystemSerial) + 1;
		CopyMem(idBuf, gSmbSystemSerial, ssz);
		idBuf += ssz;
	}

	if (gSmbSystemSKU != NULL) {
		UINTN ssz;
		ssz = AsciiStrLen((char*)gSmbSystemSKU) + 1;
		CopyMem(idBuf, gSmbSystemSKU, ssz);
		idBuf += ssz;
	}

	if (gSmbBaseBoardSerial != NULL) {
		UINTN ssz;
		ssz = AsciiStrLen((char*)gSmbBaseBoardSerial) + 1;
		CopyMem(idBuf, gSmbBaseBoardSerial, ssz);
		idBuf += ssz;
	}

	if (gSmbProcessorID != NULL) {
		CopyMem(idBuf, gSmbProcessorID, sizeof(*gSmbProcessorID));
		idBuf += sizeof(*gSmbProcessorID);
	}

	if (handleSerial != NULL) {
		UINTN ssz;
		ssz = AsciiStrLen((char*)handleSerial) + 1;
		CopyMem(idBuf, handleSerial, ssz);
		idBuf += ssz;
		MEM_FREE(handleSerial);
	}

	return res;

error:
	MEM_FREE(handleSerial);
	MEM_FREE(idBuf);
	return res;
}


EFI_STATUS
PlatformGetIDCRC(
	IN  EFI_HANDLE  handle,
	OUT UINT32      *crc32
	) 
{
	EFI_STATUS                    res;
	UINTN                         crcLen;
	CHAR8*                        crcBuf = NULL;
	res = PlatformGetID(handle, &crcBuf, &crcLen);
	if (EFI_ERROR(res)) {
		return res;
	}
	res = gBS->CalculateCrc32(crcBuf, crcLen, crc32);
	MEM_FREE(crcBuf);
	return res;
}

EFI_STATUS
PlatformGetAuthDataByType(
	OUT UINT8        **data, 
	OUT UINTN        *len,
	OUT EFI_HANDLE   *secRegionHandle,
	IN  BOOLEAN      RemovableMedia)
{
	EFI_STATUS                    res;
	UINT32                        crc;
	CHAR8*                        buf = NULL;
	EFI_BLOCK_IO_PROTOCOL*        bio;
	DCS_AUTH_DATA_MARK*           mark = NULL;
	mark = (DCS_AUTH_DATA_MARK*)MEM_ALLOC(512);
	for (; gBioIndexAuth < gBIOCount; ++gBioIndexAuth) {
		bio = EfiGetBlockIO(gBIOHandles[gBioIndexAuth]);
		if (bio == NULL) 	continue;
		if(bio->Media->RemovableMedia != RemovableMedia) continue;
		res = bio->ReadBlocks(bio, bio->Media->MediaId, 61, 512, mark);
		if (EFI_ERROR(res)) continue;
		
		res = gBS->CalculateCrc32(&mark->PlatformCrc, sizeof(*mark) - 4, &crc);
		if (EFI_ERROR(res)) continue;
		if( crc != mark->HeaderCrc) continue;
		
		res = PlatformGetIDCRC(gBIOHandles[gBioIndexAuth], &crc);
		if (EFI_ERROR(res)) continue;
		if (crc != mark->PlatformCrc) continue;
		
		buf = MEM_ALLOC(mark->AuthDataSize * 1024 * 128);
		if (buf == NULL) continue;
		
		res = bio->ReadBlocks(bio, bio->Media->MediaId, 62, mark->AuthDataSize * 1024 * 128, buf);
		if (EFI_ERROR(res)) {
			MEM_FREE(buf);
			continue;
		}
		*data = buf;
		*len = ((UINTN) mark->AuthDataSize) * 1024 * 128;
		*secRegionHandle = gBIOHandles[gBioIndexAuth];
		return EFI_SUCCESS;
	}
	return EFI_NOT_FOUND;
}

BOOLEAN gBioIndexAuthOnRemovable = TRUE;

EFI_STATUS
PlatformGetAuthData(
	OUT UINT8      **data,
	OUT UINTN      *len,
	OUT EFI_HANDLE *secRegionHandle
	)
{
	EFI_STATUS res;
	res = PlatformGetAuthDataByType(data, len, secRegionHandle, gBioIndexAuthOnRemovable);
	if (EFI_ERROR(res)) {
		if (gBioIndexAuthOnRemovable) {
			gBioIndexAuthOnRemovable = FALSE;
			gBioIndexAuth = 0;
			res = PlatformGetAuthDataByType(data, len, secRegionHandle, FALSE);
		}
	}
	return res;
}

