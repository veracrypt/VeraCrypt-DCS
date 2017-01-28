/** @file
GPT low level actions

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

	Size = (UINTN)PartHeader->NumberOfPartitionEntries * (UINTN)PartHeader->SizeOfPartitionEntry;
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

	Size = (UINTN)PartHeader->NumberOfPartitionEntries * (UINTN)PartHeader->SizeOfPartitionEntry;
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

@param[in]  BlockIo     Disk Io Protocol.
@param[in]  PartHeader  Partition table header structure

@retval EFI_SUCCESS     the CRC is valid
**/
EFI_STATUS
GptReadEntryArray(
	IN  EFI_BLOCK_IO_PROTOCOL*      BlockIo,
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
	IN  EFI_BLOCK_IO_PROTOCOL*      BlockIo,
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
