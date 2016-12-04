/** @file
Dcs TPM library

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI 

This program and the accompanying materials are licensed and made available 
under the terms and conditions of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#ifndef __DCSTPMLIB_H__
#define __DCSTPMLIB_H__

#include <Uefi.h>

EFI_STATUS
InitTpm12();

EFI_STATUS
Tpm12PcrRead(
	IN UINT32   PcrIndex,
	OUT void    *PcrValue
	);

EFI_STATUS
Tpm12DumpPcrs(
	IN UINT32 sPcr,
	IN UINT32 ePcr);

EFI_STATUS
Tpm12GetNvList(
	OUT UINT32    *respSize,
	OUT UINT32    *resp
	);

EFI_STATUS
Tpm12NvDetails(
	IN  UINT32    index,
	OUT UINT32    *attr,
	OUT UINT32    *dataSz,
	OUT UINT32    *pcrR,
	OUT UINT32    *pcrW
	);

EFI_STATUS
Tpm12GetRandom(
	IN OUT UINT32     *DataSize,
	OUT    UINT8      *Data
	);

//////////////////////////////////////////////////////////////////////////
// DCS TPM protocol
//////////////////////////////////////////////////////////////////////////
/*
Lock         - Try lock TPM secret
Apply        - Apply secret to password
Configure    - Create TPM secret and configure PCRs
IsConfigured - TPM secret is set?
IsOpen       - Can apply secret?
*/
typedef struct _DCS_TPM_PROTOCOL DCS_TPM_PROTOCOL;

extern DCS_TPM_PROTOCOL* gTpm;

typedef EFI_STATUS(*DCS_TPM_LOCK)(
	IN  DCS_TPM_PROTOCOL   *tpm
	);

typedef EFI_STATUS(*DCS_TPM_APPLY)(
	IN  DCS_TPM_PROTOCOL   *tpm,
	OUT VOID*              pwd
	);

typedef EFI_STATUS(*DCS_TPM_CONFIGURE)(
	IN  DCS_TPM_PROTOCOL  *tpm
	);

typedef BOOLEAN(*DCS_TPM_IS_OPEN)(
	IN  DCS_TPM_PROTOCOL   *tpm
	);

typedef BOOLEAN(*DCS_TPM_IS_CONFIGURED)(
	IN  DCS_TPM_PROTOCOL  *tpm
	);

typedef struct _DCS_TPM_PROTOCOL {
	DCS_TPM_LOCK           Lock;
	DCS_TPM_APPLY          Apply;
	DCS_TPM_CONFIGURE      Configure;
	DCS_TPM_IS_OPEN        IsOpen;
	DCS_TPM_IS_CONFIGURED  IsConfigured;
} DCS_TPM_PROTOCOL;

EFI_STATUS
GetTpm();

EFI_STATUS
TpmMeasure(
	IN VOID* data,
	IN UINTN dataSz
	);

#endif