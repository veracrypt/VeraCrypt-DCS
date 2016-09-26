/** @file
GPT actions

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Library/UefiBootServicesTableLib.h>
#include <Library/DevicePathLib.h>
#include <Library/BaseMemoryLib.h>
#include <Uefi/UefiGpt.h>
#include <Guid/Gpt.h>

#include <Library/CommonLib.h>
#include <Library/DcsCfgLib.h>

#include <common/Tcdefs.h>
#include <BootCommon.h>

EFI_GUID gEfiPartTypeMsReservedPartGuid = EFI_PART_TYPE_MS_RESERVED_PART_GUID;
EFI_GUID gEfiPartTypeBasicDataPartGuid = EFI_PART_TYPE_BASIC_DATA_PART_GUID;
EFI_GUID gEfiPartTypeMsRecoveryPartGuid = EFI_PART_TYPE_MS_RECOVERY_PART_GUID;

UINT64  gDcsDiskEntryListHeaderID = DCS_DISK_ENTRY_LIST_HEADER_SIGN;
UINT64  gDcsDiskEntryPwdCacheID = DCS_DEP_PWD_CACHE_SIGN;

DCS_DISK_ENTRY_LIST         *DeList = NULL;

UINT8                       *CryptoHeader = NULL;

EFI_PARTITION_TABLE_HEADER  *GptMainHdr = NULL;
EFI_PARTITION_ENTRY         *GptMainEntrys = NULL;
EFI_PARTITION_TABLE_HEADER  *GptAltHdr = NULL;
EFI_PARTITION_ENTRY         *GptAltEntrys = NULL;

UINT32                      DiskIdMbr = 0;
EFI_GUID                    DiskIdGpt = EFI_PART_TYPE_UNUSED_GUID;
DCS_DISK_ENTRY_DISKID       DeDiskId;

DCS_DEP_EXEC         *DeExecParams = NULL;

DCS_DEP_PWD_CACHE    *DePwdCache = NULL;

DCS_RND_SAVED        *DeRndSaved;

EFI_BLOCK_IO_PROTOCOL*      BlockIo = NULL;
CONST CHAR16*               DcsDiskEntrysFileName = L"DcsDiskEntrys";

EFI_PARTITION_ENTRY DcsHidePart;

UINTN   BootPartIdx;
UINTN   MirrorPartIdx;

//////////////////////////////////////////////////////////////////////////
// Partitions
//////////////////////////////////////////////////////////////////////////


/**
Checks the CRC32 value in the table header.

@param  MaxSize   Max Size limit
@param  Size      The size of the table
@param  Hdr       Table to check

@return TRUE    CRC Valid
@return FALSE   CRC Invalid

**/
BOOLEAN
GptHeaderCheckCrcAltSize(
	IN UINTN                 MaxSize,
	IN UINTN                 Size,
	IN OUT EFI_TABLE_HEADER  *Hdr
	)
{
	UINT32      Crc;
	UINT32      OrgCrc;
	EFI_STATUS  Status;

	Crc = 0;

	if (Size == 0) {
		//
		// If header size is 0 CRC will pass so return FALSE here
		//
		return FALSE;
	}

	if ((MaxSize != 0) && (Size > MaxSize)) {
		return FALSE;
	}
	//
	// clear old crc from header
	//
	OrgCrc = Hdr->CRC32;
	Hdr->CRC32 = 0;

	Status = gBS->CalculateCrc32((UINT8 *)Hdr, Size, &Crc);
	if (EFI_ERROR(Status)) {
		return FALSE;
	}
	//
	// set results
	//
	Hdr->CRC32 = OrgCrc;

	return (BOOLEAN)(OrgCrc == Crc);
}

/**
Checks the CRC32 value in the table header.

@param  MaxSize   Max Size limit
@param  Hdr       Table to check

@return TRUE      CRC Valid
@return FALSE     CRC Invalid

**/
BOOLEAN
GptHeaderCheckCrc(
	IN UINTN                 MaxSize,
	IN OUT EFI_TABLE_HEADER  *Hdr
	)
{
	return GptHeaderCheckCrcAltSize(MaxSize, Hdr->HeaderSize, Hdr);
}

EFI_STATUS
GptCheckEntryArray(
	IN  EFI_PARTITION_TABLE_HEADER  *PartHeader,
	IN  EFI_PARTITION_ENTRY         *Entrys
	)
{
	EFI_STATUS  Status;
	UINT32      Crc;
	UINTN       Size;

	Size = (UINTN) PartHeader->NumberOfPartitionEntries * (UINTN) PartHeader->SizeOfPartitionEntry;
	Status = gBS->CalculateCrc32(Entrys, Size, &Crc);
	if (EFI_ERROR(Status)) {
		return EFI_CRC_ERROR;
	}
	Status = (PartHeader->PartitionEntryArrayCRC32 == Crc) ? EFI_SUCCESS : EFI_CRC_ERROR;
	return Status;
}

EFI_STATUS
GptUpdateCRC(
	IN  EFI_PARTITION_TABLE_HEADER  *PartHeader,
	IN  EFI_PARTITION_ENTRY         *Entrys
	)
{
	EFI_STATUS  Status;
	UINT32      Crc;
	UINTN       Size;

	Size = (UINTN) PartHeader->NumberOfPartitionEntries * (UINTN) PartHeader->SizeOfPartitionEntry;
	Status = gBS->CalculateCrc32(Entrys, Size, &Crc);
	if (EFI_ERROR(Status)) {
		return Status;
	}
	PartHeader->PartitionEntryArrayCRC32 = Crc;
	PartHeader->Header.CRC32 = 0;

	Status = gBS->CalculateCrc32((UINT8 *)PartHeader, PartHeader->Header.HeaderSize, &Crc);
	if (EFI_ERROR(Status)) {
		return Status;
	}
	PartHeader->Header.CRC32 = Crc;
	return Status;
}

/**
Read GPT
Check if the CRC field in the Partition table header is valid
for Partition entry array.

@param[in]  DiskIo      Disk Io Protocol.
@param[in]  PartHeader  Partition table header structure

@retval EFI_SUCCESS     the CRC is valid
**/
EFI_STATUS
GptReadEntryArray(
	IN  EFI_PARTITION_TABLE_HEADER  *PartHeader,
	OUT EFI_PARTITION_ENTRY         **Entrys
	)
{
	EFI_STATUS  Status;
	UINT8       *Ptr;

	//
	// Read the EFI Partition Entries
	//
	Ptr = MEM_ALLOC(PartHeader->NumberOfPartitionEntries * PartHeader->SizeOfPartitionEntry);
	if (Ptr == NULL) {
		return EFI_BUFFER_TOO_SMALL;
	}

	Status = BlockIo->ReadBlocks(
		BlockIo,
		BlockIo->Media->MediaId,
		PartHeader->PartitionEntryLBA,
		PartHeader->NumberOfPartitionEntries * PartHeader->SizeOfPartitionEntry,
		Ptr
		);
	if (EFI_ERROR(Status)) {
		MEM_FREE(Ptr);
		return Status;
	}

	*Entrys = (EFI_PARTITION_ENTRY*)Ptr;
	return GptCheckEntryArray(PartHeader, *Entrys);
}

EFI_STATUS
GptReadHeader(
	IN  EFI_LBA                     HeaderLba,
	OUT EFI_PARTITION_TABLE_HEADER  **PartHeader
	)
{
	EFI_STATUS                  res = EFI_SUCCESS;
	UINT32                      BlockSize;
	EFI_PARTITION_TABLE_HEADER  *PartHdr;
	UINT32                      MediaId;

	BlockSize = BlockIo->Media->BlockSize;
	MediaId = BlockIo->Media->MediaId;
	PartHdr = MEM_ALLOC(BlockSize);

	res = BlockIo->ReadBlocks(BlockIo, MediaId, HeaderLba, BlockSize, PartHdr);
	if (EFI_ERROR(res)) {
		MEM_FREE(PartHdr);
		return res;
	}

	// Check header
	if ((PartHdr->Header.Signature != EFI_PTAB_HEADER_ID) ||
		!GptHeaderCheckCrc(BlockSize, &PartHdr->Header) ||
		PartHdr->MyLBA != HeaderLba ||
		(PartHdr->SizeOfPartitionEntry < sizeof(EFI_PARTITION_ENTRY))
		) {
		MEM_FREE(PartHdr);
		return EFI_CRC_ERROR;
	}
	*PartHeader = PartHdr;
	return EFI_SUCCESS;
}

VOID
GptPrint(
	IN  EFI_PARTITION_TABLE_HEADER  *PartHdr,
	IN  EFI_PARTITION_ENTRY         *Entrys
	)
{
	EFI_PARTITION_ENTRY         *Entry;
	UINTN                       index;
	if (PartHdr == NULL) {
		ERR_PRINT(L"No GPT is loaded\n");
		return;
	}
	Entry = Entrys;
	for (index = 0; index < PartHdr->NumberOfPartitionEntries; ++index, ++Entry) {
		if (CompareGuid(&Entry->PartitionTypeGUID, &gEfiPartTypeUnusedGuid)) {
			continue;
		}
		OUT_PRINT(L"%H%02d%N I:%g T:%g [%lld, %lld] %s\n",
			index,
			&Entry->UniquePartitionGUID,
			&Entry->PartitionTypeGUID,
			Entry->StartingLBA,
			Entry->EndingLBA,
			&Entry->PartitionName
			);
	}
}

EFI_STATUS
GptLoadFromDisk(
	IN UINTN  diskIdx
	) 
{
	EFI_STATUS                  res = EFI_SUCCESS;
	UINTN                       i;
	InitBio();

	BlockIo = EfiGetBlockIO(gBIOHandles[diskIdx]);
	if (BlockIo == NULL) {
		ERR_PRINT(L"Can't open device\n");
		return EFI_NOT_FOUND;
	}

	res = GptReadHeader(1, &GptMainHdr);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Can't read main GPT header: %r\n", res);
		goto error;
	}

	res = GptReadHeader(GptMainHdr->AlternateLBA, &GptAltHdr);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Can't read alt GPT header: %r\n", res);
		goto error;
	}

	res = GptReadEntryArray(GptMainHdr, &GptMainEntrys);
	// Read GPT
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Main GPT error: %r\n", res);
		goto error;
	}

	res = GptReadEntryArray(GptAltHdr, &GptAltEntrys);
	// Read GPT
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Alt GPT error: %r\n", res);
		goto error;
	}

	CryptoHeader = MEM_ALLOC(512);
	if (CryptoHeader == NULL) {
		ERR_PRINT(L"Can't alloc CryptoHeader\n");
		res = EFI_BUFFER_TOO_SMALL;
		goto error;
	}

	// Load disk IDs
	res = BlockIo->ReadBlocks(BlockIo, BlockIo->Media->MediaId, 0, 512, CryptoHeader);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Can't MBR \n");
		goto error;
	}

	SetMem(&DeDiskId, sizeof(DeDiskId), 0);
	DeDiskId.Type = DE_DISKID;
	CopyMem(&DeDiskId.MbrID, &CryptoHeader[0x1b8], sizeof(DiskIdMbr));
	CopyMem(&DeDiskId.GptID, &GptMainHdr->DiskGUID, sizeof(DiskIdGpt));

	// Load crypto header
	res = BlockIo->ReadBlocks(BlockIo, BlockIo->Media->MediaId, 62, 512, CryptoHeader);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Can't read CryptoHeader\n");
		goto error;
	}

	for (i = 0; i < GptMainHdr->NumberOfPartitionEntries; ++i) {
		EFI_PARTITION_ENTRY *part;
		part = &GptMainEntrys[i];
		if (CompareMem(&gEfiPartTypeSystemPartGuid, &part->PartitionTypeGUID, sizeof(EFI_GUID)) == 0) {
			CHAR16*   defExec = L"\\EFI\\Microsoft\\Boot\\Bootmgfw.efi";
			DeExecParams = MEM_ALLOC(sizeof(*DeExecParams));
			ZeroMem(DeExecParams, sizeof(*DeExecParams));
			CopyMem(&DeExecParams->ExecPartGuid, &part->UniquePartitionGUID, sizeof(EFI_GUID));
			CopyMem(&DeExecParams->ExecCmd, defExec, (StrLen(defExec) + 1 ) * 2);
			break;
		}
	}
	return res;

error:
	MEM_FREE(GptMainHdr);
	MEM_FREE(GptMainEntrys);
	MEM_FREE(GptAltHdr);
	MEM_FREE(GptAltEntrys);
	MEM_FREE(CryptoHeader);
	return res;
}

VOID
DeListPrint() {
	OUT_PRINT(L"Diskid %08x, %g\n", DeDiskId.MbrID, &DeDiskId.GptID);
	if (DeExecParams != NULL) {
		OUT_PRINT(L"Exec %g, %s\n", &DeExecParams->ExecPartGuid, &DeExecParams->ExecCmd);
	}
	if (DePwdCache != NULL) {
		OUT_PRINT(L"PwdCache %d\n", DePwdCache->Count);
	}
	if (DeRndSaved != NULL) {
		OUT_PRINT(L"Rnd %d\n", DeRndSaved->Type);
	}
	GptPrint(GptMainHdr, GptMainEntrys);
}

#define DeList_UPDATE_BEGIN(Data, DEType, Index, Len)    \
   if (Data != NULL) {                                 \
       DeData[Index] = Data;                           \
       DeList->DE[Index].Type = DEType;                  \
       DeList->DE[Index].Offset = Offset;              \
       DeList->DE[Index].Length = Len;                 \
       Offset += ((Len + 511) >> 9) << 9;

#define DeList_UPDATE_END    \
   }

VOID
DeListSaveToFile() {
	EFI_STATUS                  res = EFI_SUCCESS;
	UINT32                      Offset;
	VOID*                       DeData[DE_IDX_TOTAL];
	UINT8*                      pad512buf = NULL;

	ZeroMem(DeData, sizeof(DeData));

	res = EFI_BUFFER_TOO_SMALL;
	DeList = MEM_ALLOC(sizeof(*DeList));
	if (DeList == NULL) {
		ERR_PRINT(L"Can't alloc DeList\n");
		goto error;
	}

	pad512buf = MEM_ALLOC(512);
	if (pad512buf == NULL) {
		ERR_PRINT(L"No memory\n");
		goto error;
	}

	DeList->Signature = DCS_DISK_ENTRY_LIST_HEADER_SIGN;
	DeList->HeaderSize = sizeof(*DeList);
	DeList->Count = DE_IDX_TOTAL;
	Offset = 0;

	DeList_UPDATE_BEGIN(CryptoHeader, DE_Sectors, DE_IDX_CRYPTOHEADER, 512)
		DeList->DE[DE_IDX_CRYPTOHEADER].Sectors.Start = 62 * 512;
	DeList_UPDATE_END

	DeList_UPDATE_BEGIN(DeList, DE_List, DE_IDX_LIST, 512)
	DeList_UPDATE_END

	CopyMem(&DeList->DE[DE_IDX_DISKID], &DeDiskId, sizeof(DeDiskId));

	DeList_UPDATE_BEGIN(GptMainHdr, DE_Sectors, DE_IDX_MAINGPTHDR, 512)
		DeList->DE[DE_IDX_MAINGPTHDR].Sectors.Start = GptMainHdr->MyLBA * 512;
	DeList_UPDATE_END

	DeList_UPDATE_BEGIN(GptMainEntrys, DE_Sectors, DE_IDX_MAINGPTENTRYS, GptMainHdr->NumberOfPartitionEntries * GptMainHdr->SizeOfPartitionEntry)
		DeList->DE[DE_IDX_MAINGPTENTRYS].Sectors.Start = GptMainHdr->PartitionEntryLBA * 512;
	DeList_UPDATE_END

	DeList_UPDATE_BEGIN(GptAltHdr, DE_Sectors, DE_IDX_ALTGPTHDR, 512)
		DeList->DE[DE_IDX_ALTGPTHDR].Sectors.Start = GptAltHdr->MyLBA * 512;
	DeList_UPDATE_END

	DeList_UPDATE_BEGIN(GptAltEntrys, DE_Sectors, DE_IDX_ALTGPTENTRYS, GptAltHdr->NumberOfPartitionEntries * GptAltHdr->SizeOfPartitionEntry)
		DeList->DE[DE_IDX_ALTGPTENTRYS].Sectors.Start = GptAltHdr->PartitionEntryLBA * 512;
	DeList_UPDATE_END

	DeList_UPDATE_BEGIN(DeExecParams, DE_ExecParams, DE_IDX_EXEC, sizeof(*DeExecParams))
	DeList_UPDATE_END

	DeList_UPDATE_BEGIN(DePwdCache, DE_PwdCache, DE_IDX_PWDCACHE, sizeof(*DePwdCache))
	DeList_UPDATE_END

	DeList_UPDATE_BEGIN(DeRndSaved, DE_Rnd, DE_IDX_RND, sizeof(*DeRndSaved))
	DeList_UPDATE_END

	DeList->DataSize = Offset;
	res = gBS->CalculateCrc32(DeList, 512, &DeList->CRC32);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"CRC: %r\n", res);
		goto error;
	}
	{
		EFI_FILE*  file;
		UINTN     i;

		FileDelete(NULL, (CHAR16*)DcsDiskEntrysFileName);
		res = FileOpen(NULL, (CHAR16*)DcsDiskEntrysFileName, &file, EFI_FILE_MODE_READ | EFI_FILE_MODE_CREATE | EFI_FILE_MODE_WRITE, 0);
		if (EFI_ERROR(res)) {
			ERR_PRINT(L"File: %r\n", res);
			goto error;
		}
		for (i = 0; i < DeList->Count; ++i) {
			if (DeData[i] != 0 && DeList->DE[i].Type != DE_DISKID) {
				UINTN len;
				UINTN pad;
				len = (UINTN)DeList->DE[i].Length;
				pad = (((len + 511) >> 9) << 9) - len;
				res = FileWrite(file, DeData[i], &len, NULL);
				if (EFI_ERROR(res)) {
					ERR_PRINT(L"Write: %r\n", res);
					goto error;
				}
				if (pad > 0) {
					res = FileWrite(file, pad512buf, &pad, NULL);
					if (EFI_ERROR(res)) {
						ERR_PRINT(L"Write: %r\n", res);
						goto error;
					}
				}
			}
		}
		FileClose(file);
	}

error:
	MEM_FREE(DeList);
	MEM_FREE(pad512buf);
}

EFI_STATUS
DeListZero() {
	if (DePwdCache != NULL) {
		DePwdCache = AskConfirm("Remove passwords cache?", 1) ? NULL : DePwdCache;
	}
	if (DeExecParams != NULL) {
		DeExecParams = AskConfirm("Remove exec?", 1) ? NULL : DeExecParams;
	}
	if (DeRndSaved != NULL) {
		DeRndSaved = AskConfirm("Remove rnd?", 1) ? NULL : DeRndSaved;
	}
	if (GptMainHdr != NULL) {
		if (AskConfirm("Remove GPT?", 1)) {
			GptMainHdr = NULL;
			GptMainEntrys = NULL;
			GptAltHdr = NULL;
			GptAltEntrys = NULL;
		}
	}
	return EFI_SUCCESS;
}

EFI_STATUS
DeListParseSaved(
	IN UINT8 *DeBuffer
	)
{
	EFI_STATUS                  res = EFI_SUCCESS;
	CryptoHeader = DeBuffer;
	DeList = (DCS_DISK_ENTRY_LIST*)(DeBuffer + 512);
	CopyMem(&DeDiskId, &DeList->DE[DE_IDX_DISKID], sizeof(DeDiskId));

	if (DeList->DE[DE_IDX_EXEC].Type == DE_ExecParams) {
		DeExecParams = (DCS_DEP_EXEC *)(DeBuffer + DeList->DE[DE_IDX_EXEC].Offset);
	}

	if (DeList->DE[DE_IDX_RND].Type == DE_Rnd) {
		DeRndSaved = (DCS_RND_SAVED *)(DeBuffer + DeList->DE[DE_IDX_RND].Offset);
		if ((UINTN)DeList->DE[DE_IDX_RND].Length != sizeof(*DeRndSaved)) {
			return EFI_CRC_ERROR;
		}
	}

	if (DeList->DE[DE_IDX_PWDCACHE].Type == DE_PwdCache) {
		UINT32 crc = 0;
		UINT32 crcSaved = 0;
		DePwdCache = (DCS_DEP_PWD_CACHE*)(DeBuffer + DeList->DE[DE_IDX_PWDCACHE].Offset);
		if (DePwdCache->Sign != gDcsDiskEntryPwdCacheID) {
			return EFI_CRC_ERROR;
		}
		crcSaved = DePwdCache->CRC;
		DePwdCache->CRC = 0;
		res = gBS->CalculateCrc32(DePwdCache, sizeof(*DePwdCache), &crc);
		if (crc != crcSaved) {
			ERR_PRINT(L"Pwd cache crc\n");
			return EFI_CRC_ERROR;
		}
		DePwdCache->CRC = crcSaved;
	}

	if (DeList->DE[DE_IDX_MAINGPTHDR].Type == DE_Sectors) {
		GptMainHdr = (EFI_PARTITION_TABLE_HEADER*)(DeBuffer + DeList->DE[DE_IDX_MAINGPTHDR].Sectors.Offset);
		if ((GptMainHdr->Header.Signature != EFI_PTAB_HEADER_ID) ||
			!GptHeaderCheckCrc(512, &GptMainHdr->Header) ||
			(DeList->DE[DE_IDX_MAINGPTHDR].Sectors.Start >> 9) != GptMainHdr->MyLBA ||
			(GptMainHdr->SizeOfPartitionEntry < sizeof(EFI_PARTITION_ENTRY))) {
			res = EFI_CRC_ERROR;
			ERR_PRINT(L"Main GPT header: %r\n", res);
			return res;
		}
	}

	if (DeList->DE[DE_IDX_MAINGPTENTRYS].Type == DE_Sectors) {
		GptMainEntrys = (EFI_PARTITION_ENTRY*)(DeBuffer + DeList->DE[DE_IDX_MAINGPTENTRYS].Sectors.Offset);
		res = GptCheckEntryArray(GptMainHdr, GptMainEntrys);
		if (EFI_ERROR(res)) {
			ERR_PRINT(L"Main GPT: %r\n", res);
			return res;
		}
	}

	if (DeList->DE[DE_IDX_ALTGPTHDR].Type == DE_Sectors) {
		GptAltHdr = (EFI_PARTITION_TABLE_HEADER*)(DeBuffer + DeList->DE[DE_IDX_ALTGPTHDR].Sectors.Offset);
		if ((GptAltHdr->Header.Signature != EFI_PTAB_HEADER_ID) ||
			!GptHeaderCheckCrc(512, &GptAltHdr->Header) ||
			(DeList->DE[DE_IDX_ALTGPTHDR].Sectors.Start >> 9) != GptAltHdr->MyLBA ||
			(GptAltHdr->SizeOfPartitionEntry < sizeof(EFI_PARTITION_ENTRY))) {
			res = EFI_CRC_ERROR;
			ERR_PRINT(L"Alt GPT header: %r\n", res);
			return res;
		}
	}

	if (DeList->DE[DE_IDX_ALTGPTENTRYS].Type == DE_Sectors) {
		GptAltEntrys = (EFI_PARTITION_ENTRY*)(DeBuffer + DeList->DE[DE_IDX_ALTGPTENTRYS].Sectors.Offset);
		res = GptCheckEntryArray(GptAltHdr, GptAltEntrys);
		if (EFI_ERROR(res)) {
			ERR_PRINT(L"Alt GPT: %r\n", res);
			return res;
		}
	}

	if (GptMainEntrys != NULL && GptAltEntrys != NULL && GptMainHdr != NULL) {
		if (CompareMem(GptMainEntrys, GptAltEntrys, GptMainHdr->NumberOfPartitionEntries * GptMainHdr->SizeOfPartitionEntry) != 0) {
			ERR_PRINT(L"Alt GPT != Main GPT\n", );
			return EFI_CRC_ERROR;
		}
	}
	return EFI_SUCCESS;
}

EFI_STATUS
DeListLoadFromFile()
{
	EFI_STATUS                  res = EFI_SUCCESS;
	UINTN                       len;
	UINT8                       *DeBuffer;

	InitFS();
	res = FileLoad(NULL, (CHAR16*)DcsDiskEntrysFileName, &DeBuffer, &len);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Load: %r\n", res);
		return res;
	}
	return DeListParseSaved(DeBuffer);
}

EFI_STATUS
DeListApplySectorsToDisk(
	IN UINTN   diskIdx
	) 
{
	EFI_STATUS                  res = EFI_SUCCESS;
	UINTN                       i;
	UINT8                       *Mbr;

	InitBio();
	InitFS();
	BlockIo = EfiGetBlockIO(gBIOHandles[diskIdx]);
	if (BlockIo == NULL) {
		ERR_PRINT(L"Can't open device\n");
		return EFI_NOT_FOUND;
	}

	// Compare MBR disk ID
	Mbr = MEM_ALLOC(512);
	if (Mbr == NULL) {
		ERR_PRINT(L"Can't load MBR\n");
		return EFI_BUFFER_TOO_SMALL;
	}

	res = BlockIo->ReadBlocks(BlockIo, BlockIo->Media->MediaId, 0, 512, Mbr);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Read MBR: %r\n", res);
		MEM_FREE(Mbr);
		return res;
	}

	if (CompareMem(Mbr + 0x1b8, &DeDiskId.MbrID, sizeof(UINT32)) != 0) {
		ERR_PRINT(L"Disk MBR ID %08x != %08x \n", *((UINT32*)(Mbr + 0x1b8)), DeDiskId.MbrID);
		MEM_FREE(Mbr);
		return res;
	}
	MEM_FREE(Mbr);

	// Save sectors
	for (i = 0; i < DeList->Count; ++i) {
		if (DeList->DE[i].Type == DE_Sectors) {
			OUT_PRINT(L"%d Write: %lld, %lld\n", i, DeList->DE[i].Sectors.Start, DeList->DE[i].Sectors.Length);
			res = BlockIo->WriteBlocks(BlockIo, BlockIo->Media->MediaId,
				DeList->DE[i].Sectors.Start >> 9,
				(UINTN)DeList->DE[i].Sectors.Length,
				CryptoHeader + DeList->DE[i].Sectors.Offset);
		}
		if (EFI_ERROR(res)) {
			ERR_PRINT(L"Write: %r\n", res);
			return res;
		}
	}
	return EFI_SUCCESS;
}


EFI_STATUS
GptSyncMainAlt() {
	EFI_STATUS                  res = EFI_SUCCESS;
	// Duplicate parts array
	CopyMem(GptAltEntrys, GptMainEntrys, GptMainHdr->NumberOfPartitionEntries * GptMainHdr->SizeOfPartitionEntry);

	res = GptUpdateCRC(GptMainHdr, GptMainEntrys);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Main CRC: %r\n", res);
		return res;
	}
	GptUpdateCRC(GptAltHdr, GptAltEntrys);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Alt CRC: %r\n", res);
		return res;
	}
	return res;
}

VOID
GptSqueze() {
	UINTN i = 0;
	UINTN emptyIdx = 0;
	UINTN count;
	count = GptMainHdr->NumberOfPartitionEntries;
	while (i < count) {
		if (CompareGuid(&GptMainEntrys[i].PartitionTypeGUID, &gEfiPartTypeUnusedGuid)) {
			SetMem(&GptMainEntrys[i], sizeof(*GptMainEntrys), 0);
			++i;
			continue;
		}
		else {
			if (emptyIdx != i) {
				CopyMem(&GptMainEntrys[emptyIdx], &GptMainEntrys[i], sizeof(*GptMainEntrys) * (count - i));
				SetMem(&GptMainEntrys[i], sizeof(*GptMainEntrys), 0);
			}
			++emptyIdx;
			i = emptyIdx;
		}
	}
}

VOID
GptSort() {
	UINTN i = 0;
	UINTN j = 0;
	UINTN n = 0;
	UINTN count;
	EFI_PARTITION_ENTRY         tmp;
	BOOLEAN swapped = TRUE;
	count = GptMainHdr->NumberOfPartitionEntries;

	while (n < count) {
		if (CompareGuid(&GptMainEntrys[n].PartitionTypeGUID, &gEfiPartTypeUnusedGuid)) {
			break;
		}
		++n;
	}

	while (swapped) {
		swapped = FALSE;
		j++;
		for (i = 0; i < n - j; ++i) {
			if (GptMainEntrys[i].StartingLBA > GptMainEntrys[i + 1].StartingLBA) {
				CopyMem(&tmp, &GptMainEntrys[i], sizeof(tmp));
				CopyMem(&GptMainEntrys[i], &GptMainEntrys[i + 1], sizeof(tmp));
				CopyMem(&GptMainEntrys[i + 1], &tmp, sizeof(tmp));
				swapped = TRUE;
			}
		}
	}
}

// Checks if two regions overlap (borders are parts of regions)
BOOLEAN
IsRegionOverlap(UINT64 start1, UINT64 end1, UINT64 start2, UINT64 end2) {
	return (start1 < start2) ? (end1 >= start2) : (start1 <= end2);
}

VOID
GptHideParts() {
	UINTN count;
	UINTN n;
	BOOLEAN set = FALSE;
	count = GptMainHdr->NumberOfPartitionEntries;

	for (n = 0; n < count; ++n) {
		if (CompareGuid(&GptMainEntrys[n].PartitionTypeGUID, &gEfiPartTypeUnusedGuid)) {
			continue;
		}
		if (IsRegionOverlap(
			GptMainEntrys[n].StartingLBA, GptMainEntrys[n].EndingLBA,
			DcsHidePart.StartingLBA, DcsHidePart.EndingLBA)) {
			if (set) {
				SetMem(&GptMainEntrys[n], sizeof(*GptMainEntrys), 0);
			}
			else {
				set = TRUE;
				CopyMem(&GptMainEntrys[n], &DcsHidePart, sizeof(*GptMainEntrys));
			}
		}
	}
	GptSqueze();
	GptSort();
	GptSyncMainAlt();
}

BOOLEAN
GptAskGUID(
	IN     char* prompt,
	IN OUT EFI_GUID* guid)
{
	CHAR8      buf[128];
	UINTN      len = 0;
	EFI_GUID   result;
	BOOLEAN    ok = TRUE;
	OUT_PRINT(L"[%g] %a", guid, prompt);

	// (msr, data, oem, efi, del or guid)
	GetLine(&len, NULL, buf, sizeof(buf), 1);
	if (AsciiStrCmp(buf, "msr") == 0) {
		CopyMem(guid, &gEfiPartTypeMsReservedPartGuid, sizeof(EFI_GUID));
	}
	else if (AsciiStrCmp(buf, "data") == 0) {
		CopyMem(guid, &gEfiPartTypeBasicDataPartGuid, sizeof(EFI_GUID));
	}
	else if (AsciiStrCmp(buf, "wre") == 0) {
		CopyMem(guid, &gEfiPartTypeMsRecoveryPartGuid, sizeof(EFI_GUID));
	}
	else if (AsciiStrCmp(buf, "efi") == 0) {
		CopyMem(guid, &gEfiPartTypeSystemPartGuid, sizeof(EFI_GUID));
	}
	else if (AsciiStrCmp(buf, "del") == 0) {
		CopyMem(guid, &gEfiPartTypeUnusedGuid, sizeof(EFI_GUID));
	}
	else if (len == 0) {
		ok = TRUE;
	}
	else {
		ok = AsciiStrToGuid(&result, buf);
		if (ok) {
			CopyMem(guid, &result, sizeof(result));
		}
	}
	return ok;
}

EFI_STATUS
DeListExecEdit() 
{
	UINTN     len;
	UINTN     i;
	CHAR16    execCmd[FIELD_SIZEOF(DCS_DEP_EXEC, ExecCmd)];
	if (DeExecParams == NULL) {
		DeExecParams = MEM_ALLOC(sizeof(*DeExecParams));
	}
	OUT_PRINT(L"Exec %g, %s\n", &DeExecParams->ExecPartGuid, &DeExecParams->ExecCmd);
	if (GptMainHdr != NULL) {
		for (i = 0; i < GptMainHdr->NumberOfPartitionEntries; ++i) {
			EFI_PARTITION_ENTRY *part;
			part = &GptMainEntrys[i];
			if (CompareMem(&gEfiPartTypeSystemPartGuid, &part->PartitionTypeGUID, sizeof(EFI_GUID)) == 0) {
				if (CompareMem(&DeExecParams->ExecPartGuid, &part->UniquePartitionGUID, sizeof(EFI_GUID)) != 0) {
					OUT_PRINT(L"EFI partition missmatched, updated");
					CopyMem(&DeExecParams->ExecPartGuid, &part->UniquePartitionGUID, sizeof(EFI_GUID));
				}
				break;
			}
		}
	}
	while (!GptAskGUID("\n\r:",(EFI_GUID*) &DeExecParams->ExecPartGuid));
	OUT_PRINT(L"[%s]\n\r:", &DeExecParams->ExecCmd);
	GetLine(&len, execCmd, NULL, sizeof(execCmd) / 2 - 1, 1);
	if (len != 0) {
		CopyMem(&DeExecParams->ExecCmd, execCmd, sizeof(execCmd));
	}
	return EFI_SUCCESS;
}

EFI_STATUS
DeListPwdCacheEdit()
{
	UINTN     count;
	UINTN     len;
	UINTN     i;
	UINT32    crc = 0;
	Password  pwd;
	UINTN     pim;
	EFI_STATUS res;
	if (DePwdCache == NULL) {
		DePwdCache = MEM_ALLOC(sizeof(*DePwdCache));
		DePwdCache->Sign = DCS_DEP_PWD_CACHE_SIGN;
	}
	OUT_PRINT(L"PwdCache\n");
	do {
		count = (uint32)AskUINTN("Count[0-4]:", DePwdCache->Count);
	} while (count > 4);
	DePwdCache->Count = (uint32)count;
	for (i = 0; i < 4; ++i) {
		ZeroMem(&pwd, sizeof(pwd));
		pim = 0;
		if (i < DePwdCache->Count) {
			OUT_PRINT(L"%H%d%N [%a] [%d]\n:", i, DePwdCache->Pwd[i].Text, DePwdCache->Pim[i]);
			GetLine(&len, NULL, pwd.Text, MAX_PASSWORD, 1);
			if (len != 0) {
				pwd.Length = (uint32)len;
				pim = (uint32)AskUINTN("Pim:", DePwdCache->Pim[i]);
			}
		}
		DePwdCache->Pim[i] = (uint32)pim;
		CopyMem(&DePwdCache->Pwd[i], &pwd, sizeof(pwd));
	}
	ZeroMem(&DePwdCache->pad, sizeof(DePwdCache->pad));
	DePwdCache->CRC = 0;
	res =gBS->CalculateCrc32(DePwdCache, 512, &crc);
	DePwdCache->CRC = crc;
	burn (&pwd, sizeof(pwd));
	burn (&pim, sizeof(pim));
	return res;
}

EFI_STATUS
DeListRndSave()
{
	EFI_STATUS res;
	if (gRnd == NULL) {
		DeRndSaved = NULL;
		return EFI_SUCCESS;
	}
	res = RndSave(gRnd,&DeRndSaved);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Random: %r\n", res);
		return res;
	}
	OUT_PRINT(L"Rnd selected:%d\n", DeRndSaved->Type);
	return res;
}

EFI_STATUS
DeListRndLoad()
{
	EFI_STATUS res = EFI_NOT_FOUND;
	if (DeRndSaved != NULL) {
		res = RndLoad(DeRndSaved,&gRnd);
		if (EFI_ERROR(res)) {
			ERR_PRINT(L"Random: %r\n", res);
			return res;
		}
		OUT_PRINT(L"Rnd selected:%d\n", gRnd->Type);
	}
	return res;
}
