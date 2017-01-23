/** @file
Interface for DCS

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the Apache License, Version 2.0.

The full text of the license may be found at
https://opensource.org/licenses/Apache-2.0
**/

#include <Uefi.h>
#include <DcsConfig.h>

#include <Library/CommonLib.h>
#include "common/Xml.h"

//////////////////////////////////////////////////////////////////////////
// Config
//////////////////////////////////////////////////////////////////////////
char *gConfigBuffer = NULL;
UINTN	gConfigBufferSize = 0;

BOOLEAN
ConfigRead(char *configKey, char *configValue, int maxValueSize)
{
	char *xml;

	if (gConfigBuffer == NULL) {
		if (FileLoad(NULL, L"\\EFI\\VeraCrypt\\DcsProp", &gConfigBuffer, &gConfigBufferSize) != EFI_SUCCESS) {
			return FALSE;
		}
	}

	xml = gConfigBuffer;
	if (xml != NULL)
	{
		xml = XmlFindElementByAttributeValue(xml, "config", "key", configKey);
		if (xml != NULL)
		{
			XmlGetNodeText(xml, configValue, maxValueSize);
			return TRUE;
		}
	}

	return FALSE;
}

int ConfigReadInt(char *configKey, int defaultValue)
{
	char s[32];
	if (ConfigRead(configKey, s, sizeof(s))) {
		if (*s == '-') {
			return (-1) * (int)AsciiStrDecimalToUintn(&s[1]);
		}
		return (int)AsciiStrDecimalToUintn(s);
	}
	else
		return defaultValue;
}


char *ConfigReadString(char *configKey, char *defaultValue, char *str, int maxLen)
{
	if (!ConfigRead(configKey, str, maxLen)) {
		AsciiStrCpyS(str, maxLen, defaultValue);
	}
	return str;
}
