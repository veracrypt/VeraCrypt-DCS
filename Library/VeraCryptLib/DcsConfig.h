/** @file
Interface for DCS services

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the Apache License, Version 2.0.

The full text of the license may be found at
https://opensource.org/licenses/Apache-2.0
**/

#ifndef __DCSCONFIG_H__
#define __DCSCONFIG_H__

#include <Uefi.h>

//////////////////////////////////////////////////////////////////////////
// Config
//////////////////////////////////////////////////////////////////////////
extern char    *gConfigBuffer;
extern UINTN    gConfigBufferSize;
extern char *gConfigBufferUpdated;
extern UINTN	gConfigBufferUpdatedSize;

#define DCS_RESCUE_BOOT_VAR           L"DcsRescueBoot"
#define DCS_RESCUE_EXEC_PART_GUID_VAR L"DcsRescueExecPartGuid"
#define DCS_RESCUE_HEADER_BACKUP      L"\\EFI\\VeraCrypt\\svh_bak"

BOOLEAN ConfigRead(char *configKey, char *configValue, int maxValueSize);
int ConfigReadInt(char *configKey, int defaultValue);
char *ConfigReadString(char *configKey, char *defaultValue, char *str, int maxLen);
#endif
