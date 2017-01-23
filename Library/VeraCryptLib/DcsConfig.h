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

BOOLEAN ConfigRead(char *configKey, char *configValue, int maxValueSize);
int ConfigReadInt(char *configKey, int defaultValue);
char *ConfigReadString(char *configKey, char *defaultValue, char *str, int maxLen); 
#endif
