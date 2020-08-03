/** @file
Block R/W interceptor

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include "DcsInt.h"
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/DevicePathLib.h>
#include <Library/BaseMemoryLib.h>

#include <Library/CommonLib.h>
#include <Library/GraphLib.h>
#include <Library/PasswordLib.h>
#include <Library/BaseLib.h>
#include <Library/DcsCfgLib.h>
#include <Library/DcsTpmLib.h>
#include <Library/PasswordLib.h>

#include "common/Tcdefs.h"
#include "common/Crypto.h"
#include "common/Volumes.h"
#include "common/Crc.h"
#include "crypto/cpu.h"
#include "BootCommon.h"
#include "DcsConfig.h"
#include "DcsVeraCrypt.h"
#include <Guid/EventGroup.h>

// #define TRC_HANDLE_PATH(msg,h)                     \
//                   OUT_PRINT(msg);                  \
//                   EfiPrintDevicePath(h);           \
//                   OUT_PRINT(L"\n")
#define TRC_HANDLE_PATH(msg,h)

EFI_DEVICE_PATH*  gDcsBoot;
UINTN             gDcsBootSize;

DCSINT_BLOCK_IO*  DcsIntBlockIoFirst = NULL; //< List of block I/O head

EFI_DRIVER_BINDING_PROTOCOL g_DcsIntDriverBinding = {
	DcsIntBindingSupported,
	DcsIntBindingStart,
	DcsIntBindingStop,
	DCSINT_DRIVER_VERSION,
	NULL,
	NULL
};

#pragma pack(1)
typedef struct _BOOT_PARAMS {
	CHAR8                  Offset[TC_BOOT_LOADER_ARGS_OFFSET];
	BootArguments          BootArgs;
	BOOT_CRYPTO_HEADER     BootCryptoInfo;
	uint16                 pad1;
	SECREGION_BOOT_PARAMS  SecRegion;
} BOOT_PARAMS, *PBOOT_PARAMS;
#pragma pack()

UINT32                  gHeaderSaltCrc32 = 0;
PBOOT_PARAMS            bootParams = NULL;
// #define EFI_BOOTARGS_REGIONS_TEST ,0x9000000, 0xA000000
#define EFI_BOOTARGS_REGIONS_TEST
UINTN BootArgsRegions[] = { EFI_BOOTARGS_REGIONS_HIGH, EFI_BOOTARGS_REGIONS_LOW EFI_BOOTARGS_REGIONS_TEST };

CHAR8      Header[512];
UINT32     BootDriveSignature;
EFI_GUID   BootDriveSignatureGpt;

EFI_HANDLE              SecRegionHandle = NULL;
UINT64                  SecRegionSector = 0;
UINT8*                  SecRegionData = NULL;
UINTN                   SecRegionSize = 0;
UINTN                   SecRegionOffset = 0;
PCRYPTO_INFO            SecRegionCryptInfo = NULL;

VOID
CleanSensitiveData(BOOLEAN bClearBootParams)
{
	if (SecRegionCryptInfo != NULL) {
		MEM_BURN(SecRegionCryptInfo, sizeof(*SecRegionCryptInfo));
	}

	if (gRnd != NULL) {
		MEM_BURN(gRnd, sizeof(*gRnd));
	}

	if (SecRegionData != NULL) {
		MEM_BURN(SecRegionData, SecRegionSize);
	}
	
	if (bootParams != NULL && bClearBootParams) {
		MEM_BURN(bootParams, sizeof(*bootParams));
	}

	if (gAutoPassword != NULL) {
		MEM_BURN(gAutoPassword, MAX_PASSWORD);
	}
}

void HaltPrint(const CHAR16* Msg)
{
	CleanSensitiveData(TRUE);
	Print(L"%s - system Halted\n", Msg);
	EfiCpuHalt();
}
//////////////////////////////////////////////////////////////////////////
// Boot params memory
//////////////////////////////////////////////////////////////////////////

EFI_STATUS
GetBootParamsMemory() {
	EFI_STATUS              status = 0;
	UINTN                   index;
	if (bootParams != NULL) return EFI_SUCCESS;
	for (index = 0; index < sizeof(BootArgsRegions) / sizeof(BootArgsRegions[1]); ++index) {
		status = PrepareMemory(BootArgsRegions[index], sizeof(*bootParams), &bootParams);
		if (!EFI_ERROR(status)) {
			return status;
		}
	}
	return status;
}

EFI_STATUS
SetSecRegionParamsMemory() {
	EFI_STATUS              status = 0;
	UINTN                   index;
	UINT8*                  secRegion = NULL;
	UINT32                  crc;
	if (bootParams == NULL) return EFI_NOT_READY;

	bootParams->SecRegion.Ptr = 0;
	bootParams->SecRegion.Size = 0;
	if (DeList != NULL) {
		for (index = 0; index < sizeof(BootArgsRegions) / sizeof(BootArgsRegions[1]); ++index) {
			status = PrepareMemory(BootArgsRegions[index], DeList->DataSize, &secRegion);
			if (!EFI_ERROR(status)) {
//				OUT_PRINT(L"bootParams %08x SecRegion %08x\n", (UINTN)bootParams, (UINTN)secRegion);
				CopyMem(secRegion, SecRegionData + SecRegionOffset, DeList->DataSize);
				bootParams->SecRegion.Ptr = (UINT64)secRegion;
				bootParams->SecRegion.Size = DeList->DataSize;
				break;
			}
		}
	}
	status = gBS->CalculateCrc32(&bootParams->SecRegion, sizeof(SECREGION_BOOT_PARAMS) - 4, &crc);
	bootParams->SecRegion.Crc = crc;
	return status;
}

EFI_STATUS
PrepareBootParams(
	IN UINT32         bootDriveSignature,
	IN PCRYPTO_INFO   cryptoInfo)
{
	BootArguments           *bootArgs;
	EFI_STATUS              status;
	if (bootParams == NULL) status = EFI_UNSUPPORTED;
	else {
		bootArgs = &bootParams->BootArgs;
		TC_SET_BOOT_ARGUMENTS_SIGNATURE(bootArgs->Signature);
		bootArgs->BootLoaderVersion = VERSION_NUM;
		bootArgs->CryptoInfoOffset = (uint16)(FIELD_OFFSET(BOOT_PARAMS, BootCryptoInfo));
		bootArgs->CryptoInfoLength = (uint16)(sizeof(BOOT_CRYPTO_HEADER) + 2 + sizeof(SECREGION_BOOT_PARAMS));
		bootArgs->HeaderSaltCrc32 = gHeaderSaltCrc32;
		CopyMem(&bootArgs->BootPassword, &gAuthPassword, sizeof(gAuthPassword));
		bootArgs->HiddenSystemPartitionStart = 0;
		bootArgs->DecoySystemPartitionStart = 0;
		bootArgs->BootDriveSignature = bootDriveSignature;
		bootArgs->Flags = (uint32)(gAuthPim << 16);
		bootArgs->BootArgumentsCrc32 = GetCrc32((byte *)bootArgs, (int)((byte *)&bootArgs->BootArgumentsCrc32 - (byte *)bootArgs));
		bootParams->BootCryptoInfo.ea = (uint16)cryptoInfo->ea;
		bootParams->BootCryptoInfo.mode = (uint16)cryptoInfo->mode;
		bootParams->BootCryptoInfo.pkcs5 = (uint16)cryptoInfo->pkcs5;
		SetSecRegionParamsMemory();
		status = EFI_SUCCESS;
	}

	// Clean auth data
	MEM_BURN(&gAuthPassword, sizeof(gAuthPassword));
	MEM_BURN(&gAuthPim, sizeof(gAuthPim));

	return status;
}

void GetIntersection(uint64 start1, uint32 length1, uint64 start2, uint64 end2, uint64 *intersectStart, uint32 *intersectLength)
{
	uint64 end1 = start1 + length1 - 1;
	uint64 intersectEnd = (end1 <= end2) ? end1 : end2;

	*intersectStart = (start1 >= start2) ? start1 : start2;
	*intersectLength = (uint32)((*intersectStart > intersectEnd) ? 0 : intersectEnd + 1 - *intersectStart);

	if (*intersectLength == 0)
		*intersectStart = start1;
}

VOID UpdateDataBuffer(
	IN OUT UINT8* buf,
	IN UINT32    bufSize,
	IN UINT64    sector
	) {
	UINT64       intersectStart;
	UINT32       intersectLength;
	UINTN        i;
	if (DeList == NULL) return;
	for (i = 0; i < DeList->Count; ++i) {
		if (DeList->DE[i].Type == DE_Sectors) {
			GetIntersection(
				sector << 9, bufSize,
				DeList->DE[i].Sectors.Start, DeList->DE[i].Sectors.Start + DeList->DE[i].Sectors.Length - 1,
				&intersectStart, &intersectLength
				);
			if (intersectLength != 0) {
//				OUT_PRINT(L"S %d : %lld, %d\n", i, intersectStart, intersectLength);
//				OUT_PRINT(L"S");
				CopyMem(
					buf + (intersectStart - (sector << 9)),
					SecRegionData + SecRegionOffset + DeList->DE[i].Sectors.Offset + (intersectStart - (sector << 9)),
					intersectLength
					);
			}
		}
	}

}

//////////////////////////////////////////////////////////////////////////
// List of block I/O
//////////////////////////////////////////////////////////////////////////
DCSINT_BLOCK_IO*
GetBlockIoByHandle(
	IN EFI_HANDLE handle)
{
	DCSINT_BLOCK_IO         *DcsIntBlockIo = DcsIntBlockIoFirst;
	while (DcsIntBlockIo != NULL) {
		if (DcsIntBlockIo->Controller == handle) {
			return DcsIntBlockIo;
		}
		DcsIntBlockIo = DcsIntBlockIo->Next;
	}
	return NULL;
}

DCSINT_BLOCK_IO*
GetBlockIoByProtocol(
	IN EFI_BLOCK_IO_PROTOCOL* protocol)
{
	DCSINT_BLOCK_IO         *DcsIntBlockIo = DcsIntBlockIoFirst;
	while (DcsIntBlockIo != NULL) {
		if (DcsIntBlockIo->BlockIo == protocol) {
			return DcsIntBlockIo;
		}
		DcsIntBlockIo = DcsIntBlockIo->Next;
	}
	return NULL;
}

//////////////////////////////////////////////////////////////////////////
// Read/Write
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
IntBlockIO_Write(
	IN EFI_BLOCK_IO_PROTOCOL *This,
	IN UINT32                MediaId,
	IN EFI_LBA               Lba,
	IN UINTN                 BufferSize,
	OUT VOID                 *Buffer
	)
{
	DCSINT_BLOCK_IO      *DcsIntBlockIo = NULL;
	EFI_STATUS        Status = EFI_SUCCESS;
	EFI_LBA              startSector;
	DcsIntBlockIo = GetBlockIoByProtocol(This);

	if (DcsIntBlockIo) {
		startSector = Lba;
		startSector += gAuthBoot ? 0 : DcsIntBlockIo->CryptInfo->EncryptedAreaStart.Value >> 9;
		//Print(L"This[0x%x] mid %x Write: lba=%lld, size=%d %r\n", This, MediaId, Lba, BufferSize, Status);
		if ((startSector >= DcsIntBlockIo->CryptInfo->EncryptedAreaStart.Value >> 9) &&
			(startSector < ((DcsIntBlockIo->CryptInfo->EncryptedAreaStart.Value + DcsIntBlockIo->CryptInfo->EncryptedAreaLength.Value) >> 9))) {
			VOID*	writeCrypted;
			writeCrypted = MEM_ALLOC(BufferSize);
			if (writeCrypted == NULL) {
				Status = EFI_BAD_BUFFER_SIZE;
				return Status;
			}
			CopyMem(writeCrypted, Buffer, BufferSize);
			//      Print(L"*");
			UpdateDataBuffer(writeCrypted, (UINT32)BufferSize, startSector);
			EncryptDataUnits(writeCrypted, (UINT64_STRUCT*)&startSector, (UINT32)(BufferSize >> 9), DcsIntBlockIo->CryptInfo);
			Status = DcsIntBlockIo->LowWrite(This, MediaId, startSector, BufferSize, writeCrypted);
			MEM_FREE(writeCrypted);
		}
		else {
			Status = DcsIntBlockIo->LowWrite(This, MediaId, startSector, BufferSize, Buffer);
		}
	}
	else {
		Status = EFI_BAD_BUFFER_SIZE;
	}
	return Status;
}

EFI_STATUS
IntBlockIO_Read(
	IN EFI_BLOCK_IO_PROTOCOL *This,
	IN UINT32                MediaId,
	IN EFI_LBA               Lba,
	IN UINTN                 BufferSize,
	OUT VOID                 *Buffer
	)
{
	DCSINT_BLOCK_IO      *DcsIntBlockIo = NULL;
	EFI_STATUS           Status = EFI_SUCCESS;
	EFI_LBA              startSector;

	DcsIntBlockIo = GetBlockIoByProtocol(This);
	if (DcsIntBlockIo) {
		startSector = Lba;
		startSector += gAuthBoot ? 0 : DcsIntBlockIo->CryptInfo->EncryptedAreaStart.Value >> 9;
		Status = DcsIntBlockIo->LowRead(This, MediaId, startSector, BufferSize, Buffer);
		//Print(L"This[0x%x] mid %x ReadBlock: lba=%lld, size=%d %r\n", This, MediaId, Lba, BufferSize, Status);
		if ((startSector >= DcsIntBlockIo->CryptInfo->EncryptedAreaStart.Value >> 9) &&
			(startSector < ((DcsIntBlockIo->CryptInfo->EncryptedAreaStart.Value + DcsIntBlockIo->CryptInfo->EncryptedAreaLength.Value) >> 9))) {
			//         Print(L".");
			DecryptDataUnits(Buffer, (UINT64_STRUCT*)&startSector, (UINT32)(BufferSize >> 9), DcsIntBlockIo->CryptInfo);
		}
		UpdateDataBuffer(Buffer, (UINT32)BufferSize, startSector);
	}
	else {
		Status = EFI_BAD_BUFFER_SIZE;
	}
	return Status;
}

//////////////////////////////////////////////////////////////////////////
// Block IO hook
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
IntBlockIo_Hook(
	IN EFI_DRIVER_BINDING_PROTOCOL   *This,
	IN EFI_HANDLE                    DeviceHandle
	)
{
	EFI_BLOCK_IO_PROTOCOL   *BlockIo;
	DCSINT_BLOCK_IO         *DcsIntBlockIo = 0;
	EFI_STATUS              Status;
//	EFI_TPL                 Tpl;

	// Already hook?
	DcsIntBlockIo = GetBlockIoByHandle(DeviceHandle);
	if (DcsIntBlockIo != NULL) {
		return EFI_SUCCESS;
	}

	Status = gBS->OpenProtocol(
		DeviceHandle,
		&gEfiBlockIoProtocolGuid,
		(VOID**)&BlockIo,
		This->DriverBindingHandle,
		DeviceHandle,
		EFI_OPEN_PROTOCOL_GET_PROTOCOL
		);

	if (!EFI_ERROR(Status)) {
		// Check is this protocol already hooked
		DcsIntBlockIo = (DCSINT_BLOCK_IO *)MEM_ALLOC(sizeof(DCSINT_BLOCK_IO));
		if (DcsIntBlockIo == NULL) {
			return EFI_OUT_OF_RESOURCES;
		}

		// construct new DcsIntBlockIo
		DcsIntBlockIo->Sign = DCSINT_BLOCK_IO_SIGN;
		DcsIntBlockIo->Controller = DeviceHandle;
		DcsIntBlockIo->BlockIo = BlockIo;
		DcsIntBlockIo->IsReinstalled = 0;
// Block
//		Tpl = gBS->RaiseTPL(TPL_NOTIFY);
		// Install new routines
		DcsIntBlockIo->CryptInfo = SecRegionCryptInfo;
		DcsIntBlockIo->LowRead = BlockIo->ReadBlocks;
		DcsIntBlockIo->LowWrite = BlockIo->WriteBlocks;
		BlockIo->ReadBlocks = IntBlockIO_Read;
		BlockIo->WriteBlocks = IntBlockIO_Write;

		// close protocol before reinstall
		gBS->CloseProtocol(
			DeviceHandle,
			&gEfiBlockIoProtocolGuid,
			This->DriverBindingHandle,
			DeviceHandle
			);

		// add to global list
		if (DcsIntBlockIoFirst == NULL) {
			DcsIntBlockIoFirst = DcsIntBlockIo;
			DcsIntBlockIoFirst->Next = NULL;
		}
		else {
			DcsIntBlockIo->Next = DcsIntBlockIoFirst;
			DcsIntBlockIoFirst = DcsIntBlockIo;
		}

		// reinstall BlockIo protocol
		Status = gBS->ReinstallProtocolInterface(
			DeviceHandle,
			&gEfiBlockIoProtocolGuid,
			BlockIo,
			BlockIo
			);

//		gBS->RestoreTPL(Tpl);
		DcsIntBlockIo->IsReinstalled = 1;

		Status = EFI_SUCCESS;
	}
	return Status;
}

//////////////////////////////////////////////////////////////////////////
// DriverBinding routines
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
DcsIntBindingStart(
	IN EFI_DRIVER_BINDING_PROTOCOL  *This,
	IN EFI_HANDLE                   Controller,
	IN EFI_DEVICE_PATH_PROTOCOL     *RemainingDevicePath
	)
{
	EFI_STATUS     Status;

	TRC_HANDLE_PATH(L"t: ", Controller);

	// hook blockIo
	Status = IntBlockIo_Hook(This, Controller);
	if (EFI_ERROR(Status)) {
		HaltPrint(L"Failed");
	}
	return Status;
}

EFI_STATUS
DcsIntBindingSupported(
	IN EFI_DRIVER_BINDING_PROTOCOL  *This,
	IN EFI_HANDLE                   Controller,
	IN EFI_DEVICE_PATH_PROTOCOL     *RemainingDevicePath
	)
{
	EFI_DEVICE_PATH             *DevicePath;
	DevicePath = DevicePathFromHandle(Controller);
	if ((DevicePath != NULL) && CompareMem(DevicePath, gDcsBoot, gDcsBootSize) == 0) {
		DCSINT_BLOCK_IO*  DcsIntBlockIo = NULL;
		// Is installed?
		DcsIntBlockIo = GetBlockIoByHandle(Controller);
		if (DcsIntBlockIo != NULL) {
			return EFI_UNSUPPORTED;
		}
		return EFI_SUCCESS;
	}
	return EFI_UNSUPPORTED;
}

EFI_STATUS
DcsIntBindingStop(
	IN  EFI_DRIVER_BINDING_PROTOCOL  *This,
	IN  EFI_HANDLE                   Controller,
	IN  UINTN                        NumberOfChildren,
	IN  EFI_HANDLE                   *ChildHandleBuffer
	)
{
	TRC_HANDLE_PATH(L"p: ", Controller);
	return EFI_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////
// Security regions
//////////////////////////////////////////////////////////////////////////
EFI_STATUS 
SecRegionLoadDefault(EFI_HANDLE partHandle)
{
	EFI_STATUS              res = EFI_SUCCESS;
	HARDDRIVE_DEVICE_PATH   dpVolme;
	EFI_BLOCK_IO_PROTOCOL   *bio = NULL;
	EFI_PARTITION_TABLE_HEADER* gptHdr;
	res = EfiGetPartDetails(partHandle, &dpVolme, &SecRegionHandle);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Part details: %r\n,", res);
		return res;
	}

	// get BlockIo protocol
	bio = EfiGetBlockIO(SecRegionHandle);
	if (bio == NULL) {
		ERR_PRINT(L"Block I/O not supported\n");
		return EFI_NOT_FOUND;
	}

    if (bio->Media != NULL) {
        if (bio->Media->BlockSize != 512) {
            ERR_PRINT(L"Block size is %d. (not supported)\n", bio->Media->BlockSize);
            return EFI_INVALID_PARAMETER;
        }
    }

	SecRegionData = MEM_ALLOC(512);
	if (SecRegionData == NULL) {
		ERR_PRINT(L"No memory\n");
		return EFI_BUFFER_TOO_SMALL;
	}
	SecRegionSize = 512;

	res = bio->ReadBlocks(bio, bio->Media->MediaId, 0, 512, SecRegionData);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Read: %r\n", res);
		goto error;
	}

	BootDriveSignature = *(uint32 *)(SecRegionData + 0x1b8);

	res = bio->ReadBlocks(bio, bio->Media->MediaId, 1, 512, SecRegionData);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Read: %r\n", res);
		goto error;
	}

	gptHdr = (EFI_PARTITION_TABLE_HEADER*)SecRegionData;
	CopyMem(&BootDriveSignatureGpt, &gptHdr->DiskGUID, sizeof(BootDriveSignatureGpt));

	res = bio->ReadBlocks(bio, bio->Media->MediaId, TC_BOOT_VOLUME_HEADER_SECTOR, 512, SecRegionData);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Read: %r\n", res);
		goto error;
	}

	return EFI_SUCCESS;
error:
	MEM_FREE(SecRegionData);
	SecRegionData = NULL;
	SecRegionSize = 0;
	return res;
}

EFI_STATUS 
SecRegionChangePwd() {
	EFI_STATUS              Status;
	EFI_BLOCK_IO_PROTOCOL*  bio = NULL;
	PCRYPTO_INFO            cryptoInfo, ci;
	Password                newPassword;
	Password                confirmPassword;
	INT32                   vcres;

	Status = RndPreapare();
	if (EFI_ERROR(Status)) {
		ERR_PRINT(L"Rnd: %r\n", Status);
		return Status;
	}

	do {
		ZeroMem(&newPassword, sizeof(newPassword));
		ZeroMem(&confirmPassword, sizeof(newPassword));
		VCAskPwd(AskPwdNew, &newPassword);
		if (gAuthPwdCode == AskPwdRetCancel) {
			return EFI_DCS_USER_CANCELED;
		}
		if (gAuthPwdCode == AskPwdRetTimeout) {
			return EFI_TIMEOUT;
		}
		VCAskPwd(AskPwdConfirm, &confirmPassword);
		if (gAuthPwdCode == AskPwdRetCancel) {
			MEM_BURN(&newPassword, sizeof(newPassword));
			return EFI_DCS_USER_CANCELED;
		}
		if (gAuthPwdCode == AskPwdRetTimeout) {
			MEM_BURN(&newPassword, sizeof(newPassword));
			return EFI_TIMEOUT;
		}
		if (newPassword.Length == confirmPassword.Length) {
			if (CompareMem(newPassword.Text, confirmPassword.Text, confirmPassword.Length) == 0) {
				break;
			}
		}
		ERR_PRINT(L"Password mismatch");
	} while (TRUE);

	OUT_PRINT(L"Generate...\n\r");
	cryptoInfo = SecRegionCryptInfo;
	vcres = CreateVolumeHeaderInMemory(
		gAuthBoot, Header,
		cryptoInfo->ea,
		cryptoInfo->mode,
		&newPassword,
		cryptoInfo->pkcs5,
		gAuthPim,
		cryptoInfo->master_keydata,
		&ci,
		cryptoInfo->VolumeSize.Value,
		0, //(volumeType == TC_VOLUME_TYPE_HIDDEN) ? cryptoInfo->hiddenVolumeSize : 0,
		cryptoInfo->EncryptedAreaStart.Value,
		cryptoInfo->EncryptedAreaLength.Value,
		gAuthTc ? 0 : cryptoInfo->RequiredProgramVersion,
		cryptoInfo->HeaderFlags,
		cryptoInfo->SectorSize,
		FALSE);

	if (vcres != 0) {
		ERR_PRINT(L"header create error(%x)\n", vcres);
		Status = EFI_INVALID_PARAMETER;
		goto ret;
	}

	// get BlockIo protocol
	bio = EfiGetBlockIO(SecRegionHandle);
	if (bio == NULL) {
		ERR_PRINT(L"Block io not supported\n,");
		Status = EFI_NOT_FOUND;
		goto ret;
	}

	Status = bio->WriteBlocks(bio, bio->Media->MediaId, SecRegionSector, 512, Header);
	if (EFI_ERROR(Status)) {
		ERR_PRINT(L"Write: %r\n", Status);
		goto ret;
	}
	CopyMem(&gAuthPassword, &newPassword, sizeof(gAuthPassword));
	CopyMem(SecRegionData + SecRegionOffset, Header, 512);

	ERR_PRINT(L"Update (%r)\n", Status);
	if (!EFI_ERROR(Status)) {
		EFI_INPUT_KEY key;
		key = KeyWait(L"Boot OS in %2d ('r' to reset)   \r", 5, 0, 0);
		if (key.UnicodeChar == 'r') {
			MEM_BURN(&newPassword, sizeof(newPassword));
			MEM_BURN(&confirmPassword, sizeof(confirmPassword));
			CleanSensitiveData(TRUE);
			gST->RuntimeServices->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);
		}
	}

ret:
	MEM_BURN(&newPassword, sizeof(newPassword));
	MEM_BURN(&confirmPassword, sizeof(confirmPassword));
	return Status;
}

EFI_STATUS
SelectDcsBootBySignature() 
{
	EFI_STATUS             res = EFI_NOT_FOUND;
	EFI_BLOCK_IO_PROTOCOL* bio = NULL;
	EFI_PARTITION_TABLE_HEADER* gptHdr;
	UINTN                  i;
	for (i = 0; i < gBIOCount; ++i) {
		if(EfiIsPartition(gBIOHandles[i])) continue;
		bio = EfiGetBlockIO(gBIOHandles[i]);
		if(bio == NULL) continue;
		res = bio->ReadBlocks(bio, bio->Media->MediaId, 0, 512, Header);
		if(EFI_ERROR(res)) continue;
		if((*(UINT32*)(Header+0x1b8)) != BootDriveSignature) continue;
		res = bio->ReadBlocks(bio, bio->Media->MediaId, 1, 512, Header);
		if (EFI_ERROR(res)) continue;
		gptHdr = (EFI_PARTITION_TABLE_HEADER*)Header;
		if (CompareMem(&BootDriveSignatureGpt, &gptHdr->DiskGUID, sizeof(BootDriveSignatureGpt)) != 0) continue;
		gDcsBoot = DevicePathFromHandle(gBIOHandles[i]);
		gDcsBootSize = GetDevicePathSize(gDcsBoot);
		return EFI_SUCCESS;
	}
	return EFI_NOT_FOUND;
}

EFI_STATUS
SecRegionTryDecrypt() 
{
	int          vcres = 1;
	EFI_STATUS   res = EFI_SUCCESS;
	int          retry = gAuthRetry;
	PlatformGetID(SecRegionHandle, &gPlatformKeyFile, &gPlatformKeyFileSize);

	do {
		SecRegionOffset = 0;
		VCAuthAsk();
		if (gAuthPwdCode == AskPwdRetCancel) {
			return EFI_DCS_USER_CANCELED;
		}
		if (gAuthPwdCode == AskPwdRetTimeout) {
			return EFI_TIMEOUT;
		}
		OUT_PRINT(L"%a", gAuthStartMsg);
		do {
			// EFI tables?
			if (TablesVerify(SecRegionSize - SecRegionOffset, SecRegionData + SecRegionOffset)) {
				EFI_TABLE_HEADER *mhdr = (EFI_TABLE_HEADER *)(SecRegionData + SecRegionOffset);
				UINTN tblZones = (mhdr->HeaderSize + 1024 * 128 - 1) / (1024 * 128);
				SecRegionOffset += tblZones * 1024 * 128;
				vcres = 1;
				continue;
			}
			// Try authorize zone
			CopyMem(Header, SecRegionData + SecRegionOffset, 512);
			vcres = ReadVolumeHeader(gAuthBoot, Header, &gAuthPassword, gAuthHash, gAuthPim, gAuthTc, &SecRegionCryptInfo, NULL);
		   SecRegionOffset += (vcres != 0) ? 1024 * 128 : 0;
		} while (SecRegionOffset < SecRegionSize && vcres != 0);
		if (vcres == 0) {
			OUT_PRINT(L"Success\n");
			OUT_PRINT(L"Start %d %lld len %lld\n", SecRegionOffset / (1024*128), SecRegionCryptInfo->EncryptedAreaStart.Value, SecRegionCryptInfo->EncryptedAreaLength.Value);
			break;
		}	else {
			ERR_PRINT(L"%a", gAuthErrorMsg);
			// clear previous failed authentication information
			MEM_BURN(&gAuthPassword, sizeof(gAuthPassword));
			if (gAuthPimRqt)
				MEM_BURN(&gAuthPim, sizeof(gAuthPim));
		}
		retry--;
	} while (vcres != 0 && retry > 0);
	if (vcres != 0) {
		return EFI_CRC_ERROR;
	}

	SecRegionSector = 62 + SecRegionOffset / 512;
	DeList = NULL;
	if (SecRegionSize > 512) {
		UINT64 startUnit = 0;
		DecryptDataUnits(SecRegionData + SecRegionOffset + 512, (UINT64_STRUCT*)&startUnit,(UINT32)255, SecRegionCryptInfo);
		if (CompareMem(SecRegionData + SecRegionOffset + 512, &gDcsDiskEntryListHeaderID, sizeof(gDcsDiskEntryListHeaderID)) != 0) {
			ERR_PRINT(L"Wrong DCS list header");
			return EFI_CRC_ERROR;
		}
		DeList = (DCS_DISK_ENTRY_LIST *)(SecRegionData + SecRegionOffset + 512);
		CopyMem(&BootDriveSignature, &DeList->DE[DE_IDX_DISKID].DiskId.MbrID, sizeof(BootDriveSignature));
		CopyMem(&BootDriveSignatureGpt, &DeList->DE[DE_IDX_DISKID].DiskId.GptID, sizeof(BootDriveSignatureGpt));

		if (DeList->DE[DE_IDX_EXEC].Type == DE_ExecParams) {
			DCS_DEP_EXEC *execParams = NULL;
			execParams = (DCS_DEP_EXEC *)(SecRegionData + SecRegionOffset + DeList->DE[DE_IDX_EXEC].Offset);
			EfiSetVar(L"DcsExecPartGuid", NULL, &execParams->ExecPartGuid, sizeof(EFI_GUID), EFI_VARIABLE_BOOTSERVICE_ACCESS);
			EfiSetVar(L"DcsExecCmd", NULL, &execParams->ExecCmd, (StrLen((CHAR16*)&execParams->ExecCmd) + 1) * 2, EFI_VARIABLE_BOOTSERVICE_ACCESS);
		}

		if (DeList->DE[DE_IDX_PWDCACHE].Type == DE_PwdCache) {
			DCS_DEP_PWD_CACHE *pwdCache = NULL;
			UINT64  sector = 0;
			pwdCache = (DCS_DEP_PWD_CACHE *)(SecRegionData + SecRegionOffset + DeList->DE[DE_IDX_PWDCACHE].Offset);
			EncryptDataUnits((UINT8*)pwdCache, (UINT64_STRUCT*)&sector, 1, SecRegionCryptInfo);
		}

		if (DeList->DE[DE_IDX_RND].Type == DE_Rnd) {
			UINT8 temp[4];
			UINT64  sector = 0;
			DCS_RND_SAVED* rndNewSaved;
			DCS_RND_SAVED* rndSaved = (DCS_RND_SAVED*)(SecRegionData + SecRegionOffset + DeList->DE[DE_IDX_RND].Offset);
			if (DeList->DE[DE_IDX_RND].Length == sizeof(DCS_RND_SAVED)) {
				if (!EFI_ERROR(res = RndLoad(rndSaved, &gRnd)) &&
					!EFI_ERROR(res = RndGetBytes(temp, sizeof(temp))) &&
					!EFI_ERROR(res = RndSave(gRnd, &rndNewSaved))
				) {
					EFI_BLOCK_IO_PROTOCOL   *bio = NULL;
					sector = (DeList->DE[DE_IDX_RND].Offset >> 9) - 1;
					OUT_PRINT(L"Last login %H%t%N\n", &rndSaved->SavedAt);

					EncryptDataUnits((UINT8*)rndNewSaved, (UINT64_STRUCT*)&sector, 1, SecRegionCryptInfo);
					sector = SecRegionSector + (DeList->DE[DE_IDX_RND].Offset >> 9);

					// get BlockIo protocol
					bio = EfiGetBlockIO(SecRegionHandle);
					if (bio == NULL) {
						ERR_PRINT(L"Block io not supported\n,");
					}
					
					res = bio->WriteBlocks(bio, bio->Media->MediaId, sector, 512, rndNewSaved);
					if (EFI_ERROR(res)) {
						ERR_PRINT(L"Write: %r\n", res);
					}
				}
			}
		}
	}

	// Select boot device
	res = SelectDcsBootBySignature();
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Decrypt device not found\n");
		return res;
	}

	// Change password if requested
	if (gAuthPwdCode == AskPwdRetChange && gRnd != NULL) {
		res = RndPreapare();
		if (!EFI_ERROR(res)) {
			res = SecRegionChangePwd();
			if (EFI_ERROR(res)) {
				return res;
			}
		}	else {
			ERR_PRINT(L"Random: %r\n", res);
		}
	}
	gHeaderSaltCrc32 = GetCrc32(SecRegionData + SecRegionOffset, PKCS5_SALT_SIZE);	
	return EFI_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////
// Exit action
//////////////////////////////////////////////////////////////////////////
enum OnExitTypes{
	OnExitAuthFaild = 1,
	OnExitAuthNotFound,
	OnExitAuthTimeout,
	OnExitAuthCancelled,
	OnExitSuccess
};

BOOLEAN 
AsciiCharNCmp(
	IN CHAR8 ch1,
	IN CHAR8 ch2
	)
{
	return (ch1 | 0x20) == (ch2 | 0x20);
}

CHAR8* 
AsciiStrNStr(
	IN CHAR8* str,
	IN CHAR8* pattern) 
{
	CHAR8* pos1 = str;
	CHAR8* pos2;
	CHAR8* posp;
	while (*pos1 != 0) {
		posp = pattern;
		pos2 = pos1;
		while (*posp != 0 && *pos2 != 0 && AsciiCharNCmp(*pos2,*posp)) {
			++posp;
			++pos2;
		}
		if (*pos2 == 0 && *posp) return NULL;
		if (*posp == 0) return pos1;
		++pos1;
	}
	return NULL;
}

BOOLEAN
OnExitGetParam(
	IN CHAR8 *action,
	IN CHAR8 *name,
	OUT CHAR8  **value,
	OUT CHAR16 **valueU
	) 
{
	CHAR8* pos;
	UINTN  len = 0;
	UINTN  i = 0;
	pos = AsciiStrNStr(action, name);
	if (pos == NULL) return FALSE;
	pos += AsciiStrLen(name);
	if(*pos != '(') return FALSE;
	pos++;
	while (pos[len] != 0 && pos[len] != ')') len++;
	if (pos[len] == 0) return FALSE;
	if (value != NULL) *value = MEM_ALLOC(len + 1);
	if (valueU != NULL) *valueU = MEM_ALLOC((len + 1) * 2);
	for (i = 0; i < len; ++i) {
		if (value != NULL) (*value)[i] = pos[i];
		if (valueU != NULL) (*valueU)[i] = pos[i];
	}
	return TRUE;
}

EFI_STATUS
OnExit(
	IN CHAR8 *action,
	IN UINTN  type,
	IN EFI_STATUS retValue)
{
	CHAR8* guidStr = NULL;
	CHAR8* exitStatusStr = NULL;
	CHAR8* messageStr = NULL;
	CHAR8* delayStr = NULL;
	EFI_GUID *guid = NULL;
	CHAR16  *fileStr  = NULL;
	
	if (EFI_ERROR(retValue))
	{
		CleanSensitiveData(TRUE);
	}
	
	if (action == NULL) return retValue;

	if (OnExitGetParam(action, "guid", &guidStr, NULL)) {
		EFI_GUID tmp;
		if (DcsAsciiStrToGuid(&tmp, guidStr)) {
			guid = MEM_ALLOC(sizeof(EFI_GUID));
			CopyMem(guid, &tmp, sizeof(EFI_GUID));
		}
	}

	if (OnExitGetParam(action, "status", &exitStatusStr, NULL)) {
		retValue = AsciiStrDecimalToUintn(exitStatusStr);
	}

	if (!OnExitGetParam(action, "file", NULL, &fileStr)) {
		fileStr = NULL;
	}


	if (OnExitGetParam(action, "printinfo", NULL, NULL)) {
		OUT_PRINT(L"type %d\naction %a\n", type, action);
		if (guid != NULL) OUT_PRINT(L"guid %g\n", guid);
		if (fileStr != NULL) OUT_PRINT(L"file %s\n", fileStr);
		if (exitStatusStr != NULL) OUT_PRINT(L"status %d, %r\n", retValue, retValue);
	}

	if (OnExitGetParam(action, "message", &messageStr, NULL)) {
		OUT_PRINT(L"%a", messageStr);
	}

	if (OnExitGetParam(action, "delay", &delayStr, NULL)) {
		UINTN delay;
		EFI_INPUT_KEY key;
		delay = AsciiStrDecimalToUintn(delayStr);
		OUT_PRINT(L"\n");
		key = KeyWait(L"\r%d  ", delay, 0, 0);
		if (key.UnicodeChar != 0) GetKey();
	}

	if (AsciiStrNStr(action, "halt") == action) {
		retValue = EFI_DCS_HALT_REQUESTED;
	}

	else if (AsciiStrNStr(action, "shutdown") == action) {
		retValue = EFI_DCS_SHUTDOWN_REQUESTED;
	}
	
	else if (AsciiStrNStr(action, "reboot") == action) {
		retValue = EFI_DCS_REBOOT_REQUESTED;
	}

	else if (AsciiStrNStr(action, "exec") == action) {
		if (guid != NULL) {
			EFI_STATUS res;
			EFI_HANDLE h;
			res = EfiFindPartByGUID(guid, &h);
			if (EFI_ERROR(res)) {
				ERR_PRINT(L"\nCan't find start partition\n");
				CleanSensitiveData(TRUE);
				retValue = EFI_DCS_HALT_REQUESTED;
				goto exit;
			}
			// Try to exec
			if (fileStr != NULL) {				
				res = EfiExec(h, fileStr);
				if (EFI_ERROR(res)) {
					ERR_PRINT(L"\nStart %s - %r\n", fileStr, res);
					CleanSensitiveData(TRUE);
					retValue = EFI_DCS_HALT_REQUESTED;
					goto exit;
				}
			}
			else {
				ERR_PRINT(L"\nNo EFI execution path specified. Halting!\n");
				CleanSensitiveData(TRUE);
				retValue = EFI_DCS_HALT_REQUESTED;
				goto exit;
			}
		}		

		if (fileStr != NULL) {
			EfiSetVar(L"DcsExecCmd", NULL, fileStr, (StrLen(fileStr) + 1) * 2, EFI_VARIABLE_BOOTSERVICE_ACCESS);
		}
		goto exit;
	}

	else if (AsciiStrNStr(action, "postexec") == action) {
		if (guid != NULL) {
			EfiSetVar(L"DcsExecPartGuid", NULL, &guid, sizeof(EFI_GUID), EFI_VARIABLE_BOOTSERVICE_ACCESS);
		}
		if (fileStr != NULL) {
			EfiSetVar(L"DcsExecCmd", NULL, fileStr, (StrLen(fileStr) + 1) * 2, EFI_VARIABLE_BOOTSERVICE_ACCESS);
		}

		retValue = EFI_DCS_POSTEXEC_REQUESTED;
		goto exit;
	}

	else if (AsciiStrStr(action, "exit") == action) {
		goto exit;
	}

exit:
	MEM_FREE(guidStr);
	MEM_FREE(exitStatusStr);
	MEM_FREE(messageStr);
	MEM_FREE(delayStr);
	MEM_FREE(guid);
	MEM_FREE(fileStr);
	return retValue;
}

//////////////////////////////////////////////////////////////////////////
// Exit boot loader event
//////////////////////////////////////////////////////////////////////////
EFI_EVENT             mVirtualAddrChangeEvent;
VOID
EFIAPI
VirtualNotifyEvent(
	IN EFI_EVENT        Event,
	IN VOID             *Context
	)
{
	// Clean all sensible info and keys before transfer to OS
	CleanSensitiveData(FALSE);
}

//////////////////////////////////////////////////////////////////////////
// Open tables
//////////////////////////////////////////////////////////////////////////
UINT8* gOpenTables = NULL;

BOOLEAN
SecRegionTablesFind(UINT8* secRegion, UINTN secRegionSize, VOID** tables) {
	UINTN pos = 0;
	while (pos < SecRegionSize) {
		if (TablesVerify(secRegionSize - pos, secRegion + pos)) {
			*tables = secRegion + pos;
			return TRUE;
		}
		pos += 128 * 1024;
	}
	return FALSE;
}

#define DCSPROP_HEADER_SIGN SIGNATURE_64('D','C','S','P','R','O','P','_')
#define PICTPWD_HEADER_SIGN SIGNATURE_64('P','I','C','T','P','W','D','_')

VOID
VCAuthLoadConfigUpdated(UINT8* secRegion, UINTN secRegionSize) {
	if (SecRegionTablesFind(secRegion, secRegionSize, &gOpenTables)) {
		if (TablesGetData(gOpenTables, DCSPROP_HEADER_SIGN, &gConfigBufferUpdated, &gConfigBufferUpdatedSize)) {
			// Reload config parameters
			MEM_FREE(gAuthPasswordMsg);
			gAuthPasswordMsg = NULL;
			VCAuthLoadConfig();
		}
		TablesGetData(gOpenTables, PICTPWD_HEADER_SIGN, &gPictPwdBmp, &gPictPwdBmpSize);
	}
}

VOID
Pause(
	IN UINTN      seconds
	)
{
	if (seconds) {
		EFI_INPUT_KEY key;
		key = KeyWait(L"%2d   \r", seconds, 0, 0);
		if (key.UnicodeChar != 0) {
			GetKey();
		}
	}
}

VOID
PauseHandleInfo(
	IN EFI_HANDLE hndle,
	IN UINTN      seconds)
{
	if (seconds) {
		EfiPrintDevicePath(hndle);
		Pause(seconds);
		OUT_PRINT(L"\n");
	}
}

//////////////////////////////////////////////////////////////////////////
// Driver Entry Point
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
UefiMain(
	EFI_HANDLE ImageHandle,
	EFI_SYSTEM_TABLE *SystemTable)
{
	EFI_STATUS res;

	InitBio();
	InitFS();

	// Remove BootNext to restore boot order
	BootMenuItemRemove(L"BootNext");

	// Load auth parameters
	VCAuthLoadConfig();
	if (gAuthSecRegionSearch) {
		res = PlatformGetAuthData(&SecRegionData, &SecRegionSize, &SecRegionHandle);
		if (!EFI_ERROR(res)) {
			VCAuthLoadConfigUpdated(SecRegionData, SecRegionSize);
			PauseHandleInfo(SecRegionHandle, gSecRegionInfoDelay);
		}
	} else if (gRUD != 0) {
		// RUD defined
		UINTN			i;
		BOOLEAN		devFound = FALSE;
		InitUsb();
		for (i = 0; i < gUSBCount; ++i) {
			CHAR8*		id = NULL;
			res = UsbGetId(gUSBHandles[i], &id);
			if (!EFI_ERROR(res) && id != NULL) {
				INT32		rud;
				rud = GetCrc32((unsigned char*)id, (int)AsciiStrLen(id));
				MEM_FREE(id);
				if (rud == gRUD) {
					devFound = TRUE;
					PauseHandleInfo(SecRegionHandle, gSecRegionInfoDelay);
					break;
				}
			}
		}
		if (!devFound) return OnExit(gOnExitNotFound, OnExitAuthNotFound, EFI_NOT_FOUND);
   }

	// Force authorization
	if (SecRegionData == NULL && gDcsBootForce != 0) {
		res = EFI_NOT_FOUND;
		if (gPartitionGuidOS != NULL) {
			// Try to find by OS partition GUID
			UINTN i;
			for (i = 0; i < gBIOCount; ++i) {
				EFI_GUID guid;
				res = EfiGetPartGUID(gBIOHandles[i], &guid);
				if (EFI_ERROR(res)) continue;
				if (memcmp(gPartitionGuidOS, &guid, sizeof(guid)) == 0) {
					res = SecRegionLoadDefault(gBIOHandles[i]);
					break;
				}
			}
		}	else {
			res = SecRegionLoadDefault(gFileRootHandle);
		}
		if (EFI_ERROR(res)) {
			return OnExit(gOnExitNotFound, OnExitAuthNotFound, res);
		}
		// force password type and message to simulate "press ESC to continue"
		MEM_FREE(gAuthPasswordMsg);
		gAuthPasswordType = gForcePasswordType;
		gAuthPasswordMsg = gForcePasswordMsg;
		gPasswordProgress = gForcePasswordProgress;
	}

	// ask any way? (by DcsBoot flag)
	if (SecRegionData == NULL) {
		if (gDcsBootForce != 0) {
			res = SecRegionLoadDefault(gFileRootHandle);
			if (EFI_ERROR(res)) {
				return OnExit(gOnExitNotFound, OnExitAuthNotFound, res);
			}
		}	else {
			return OnExit(gOnExitNotFound, OnExitAuthNotFound, EFI_NOT_FOUND);
		}
	}

	res = GetBootParamsMemory();
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"No boot args memory: %r\n\r", res);
		KeyWait(L"%02d\r", 10, 0, 0);
		return res;
	}

	RndInit(gRndDefault, NULL, 0, &gRnd);

	res = GetTpm(); // Try to get TPM
	if (!EFI_ERROR(res)) {
		if (gConfigBuffer != NULL) {
			gTpm->Measure(gTpm, DCS_TPM_PCR_LOCK, gConfigBufferSize, gConfigBuffer); // Measure configuration
		}
		if (gTpm->IsConfigured(gTpm) && !gTpm->IsOpen(gTpm) && gTPMLockedInfoDelay) {
			ERR_PRINT(L"TPM is configured but locked. Probably boot chain is modified!\n");
			Pause(gTPMLockedInfoDelay);
		}
	}

	DetectX86Features();
	res = SecRegionTryDecrypt();
	if (gTpm != NULL) {
		gTpm->Lock(gTpm);
	}
	// Reset Console buffer
	gST->ConIn->Reset(gST->ConIn, FALSE);

	if (EFI_ERROR(res)) {
		// clear buffers with potential authentication data
		MEM_BURN(&gAuthPassword, sizeof(gAuthPassword));
		MEM_BURN(&gAuthPim, sizeof(gAuthPim));

		if (res == EFI_TIMEOUT)
			return OnExit(gOnExitTimeout, OnExitAuthTimeout, res);
		else if (res == EFI_DCS_USER_CANCELED)
			return OnExit(gOnExitCancelled, OnExitAuthCancelled, res);
		else
			return OnExit(gOnExitFailed, OnExitAuthFaild, res);
	}

	res = PrepareBootParams(BootDriveSignature, SecRegionCryptInfo);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Can not set params for OS: %r", res);
		return OnExit(gOnExitFailed, OnExitAuthFaild, res);
	}

	// Install decrypt
	res = EfiLibInstallDriverBindingComponentName2(
		ImageHandle,
		SystemTable,
		&g_DcsIntDriverBinding,
		ImageHandle,
		&gDcsIntComponentName,
		&gDcsIntComponentName2);

	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Bind %r\n", res);
		return OnExit(gOnExitFailed, OnExitAuthFaild, res);
	}

	res = gBS->CreateEventEx(
		EVT_NOTIFY_SIGNAL,
		TPL_NOTIFY,
		VirtualNotifyEvent,
		NULL,
		&gEfiEventVirtualAddressChangeGuid,
		&mVirtualAddrChangeEvent
		);

	return OnExit(gOnExitSuccess, OnExitSuccess, res);
}
