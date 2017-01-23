/** @file
  This is DCS platform information application

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI 

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Uefi.h>
#include <Library/CommonLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DevicePathLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PrintLib.h>
#include <Guid/GlobalVariable.h>
#include <Library/PasswordLib.h>
#include <Library/GraphLib.h>

#ifdef _M_X64
#define ARCH_NAME L"x64"
#else
#define ARCH_NAME L"IA32"
#endif
CHAR8 Temp[1024];
CHAR8 StrBuffer[1024];
UINTN gXmlTabs = 0;

UINTN
XmlOutTab() {
	UINTN len;
	UINTN i = gXmlTabs;
	CHAR8*   pos = (CHAR8*)StrBuffer;
	INTN     remains = sizeof(StrBuffer) - 1;
	while (i > 0 && remains > 0) {
		*pos = ' ';
		remains--;
		i--;
		pos++;
	}
	len = sizeof(StrBuffer) - remains - 1;
	return len;
}

UINTN
XmlTag(
	IN EFI_FILE            *infoFileTxt,
	IN CONST CHAR8         *tag,
	IN BOOLEAN             closeTag,
	IN CONST CHAR8         *value,
	...
	) {
	VA_LIST  args;
	UINTN    len = XmlOutTab();
	CHAR8*   pos = (CHAR8*)StrBuffer + len;
	CHAR8*   attrFormat = NULL;
	INTN     remains = sizeof(StrBuffer) - 1 - len;
	if (infoFileTxt == NULL) return 0;
	VA_START(args, value);
	len = AsciiSPrint(pos, remains, "<%a", tag);
	remains -= len;
	pos += len;
	if ((attrFormat = VA_ARG(args, CHAR8 *)) != NULL) {
		len = AsciiVSPrint(pos, remains, attrFormat, args);
		remains -= len;
		pos += len;
	}
	VA_END(args);
	if (closeTag) {
		if (value == NULL) {
			len = AsciiSPrint(pos, remains, "/>\n");
			remains -= len;
			pos += len;
		}
		else {
			len = AsciiSPrint(pos, remains, ">%a</%a>\n", value, tag);
			remains -= len;
			pos += len;
		}
	}	else {
		if (value == NULL) {
			len = AsciiSPrint(pos, remains, ">");
			remains -= len;
			pos += len;
		}
		else {
			len = AsciiSPrint(pos, remains, ">%a", value, tag);
			remains -= len;
			pos += len;
		}
	}
	len = sizeof(StrBuffer) - remains - 1;
	infoFileTxt->Write(infoFileTxt, &len, StrBuffer);
	return len;
}

UINTN
XmlStartTag(
	IN EFI_FILE            *infoFileTxt,
	IN CONST CHAR8         *tag) 
{
	UINTN    len = XmlOutTab();
	CHAR8*   pos = (CHAR8*)StrBuffer + len;
	INTN     remains = sizeof(StrBuffer) - 1 - len;
	gXmlTabs += remains > 0 ? 1 : 0;
	len = AsciiSPrint(pos, remains, "<%a>\n", tag);
	remains -= len;
	pos += len;
	len = sizeof(StrBuffer) - remains - 1;
	infoFileTxt->Write(infoFileTxt, &len, StrBuffer);

	return len;
}

UINTN
XmlEndTag(
	IN EFI_FILE            *infoFileTxt,
	IN CONST CHAR8         *tag
	)
{
	UINTN    len;
	CHAR8*   pos;
	INTN     remains;
	gXmlTabs -= gXmlTabs > 0 ? 1 : 0;
	len = XmlOutTab();
	pos = (CHAR8*)StrBuffer + len;
	remains = sizeof(StrBuffer) - 1 - len;

	if (infoFileTxt == NULL) return 0;
	len = AsciiSPrint(pos, remains, "</%a>\n", tag);
	remains -= len;
	pos += len;
	len = sizeof(StrBuffer) - remains - 1;
	infoFileTxt->Write(infoFileTxt, &len, StrBuffer);
	return len;
}


UINTN
XmlEndTagPrint(
	IN EFI_FILE            *infoFileTxt,
	IN CONST CHAR8         *tag,
	IN CONST CHAR8         *formatValue,
	...
	)
{
	VA_LIST  args;
	UINTN    len = 0;
	CHAR8*   pos = (CHAR8*)StrBuffer + len;
	INTN     remains = sizeof(StrBuffer) - 1 - len;
	if (infoFileTxt == NULL) return 0;
	VA_START(args, formatValue);
	if (formatValue != NULL) {
		len = AsciiVSPrint(pos, remains, formatValue, args);
		remains -= len;
		pos += len;
	}
	VA_END(args);
	len = AsciiSPrint(pos, remains, "</%a>\n", tag);
	remains -= len;
	pos += len;
	len = sizeof(StrBuffer) - remains -1;
	infoFileTxt->Write(infoFileTxt, &len, StrBuffer);
	return len;
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
DcsInfoMain(
   IN EFI_HANDLE        ImageHandle,
   IN EFI_SYSTEM_TABLE  *SystemTable
   )
{
   EFI_STATUS          res;
//	EFI_INPUT_KEY       key;
	EFI_FILE            *info;
	UINTN               i;
	UINTN               j;
	InitBio();
   res = InitFS();
   if (EFI_ERROR(res)) {
      ERR_PRINT(L"InitFS %r\n", res);
		return res;
   }
	res = FileOpen(NULL, L"EFI\\VeraCrypt\\PlatformInfo", &info, EFI_FILE_MODE_READ | EFI_FILE_MODE_CREATE | EFI_FILE_MODE_WRITE, 0);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"PlatformInfo create %r\n", res);
		return res;
	}
	FileAsciiPrint(info, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
	XmlStartTag(info, "PlatformInfo");

	XmlStartTag(info, "EFI");
	XmlTag(info, "Version", FALSE, NULL, NULL);
	XmlEndTagPrint(info, "Version", "%d.%d", gST->Hdr.Revision >> 16, gST->Hdr.Revision & 0xFFFF);
	XmlTag(info, "Vendor", FALSE, NULL, NULL);
	XmlEndTagPrint(info, "Vendor", "%s", gST->FirmwareVendor);
	XmlTag(info, "Revision", FALSE, NULL, NULL);
	XmlEndTagPrint(info, "Revision", "0x0%x", gST->FirmwareRevision);
	XmlEndTag(info, "EFI");

	res = SMBIOSGetSerials();
	if (!EFI_ERROR(res)) {
//		XmlTag(info, "System",FALSE, NULL, NULL);
		XmlStartTag(info, "System");
		XmlTag(info, "Manufacture", TRUE, gSmbSystemManufacture, NULL);
		XmlTag(info, "Model", TRUE, gSmbSystemModel, NULL);
		XmlTag(info, "Version", TRUE, gSmbSystemVersion, NULL);
		XmlEndTag(info, "System");
		XmlStartTag(info, "BIOS");
		XmlTag(info, "Vendor", TRUE, gSmbBiosVendor, NULL);
		XmlTag(info, "Version", TRUE, gSmbBiosVersion, NULL);
		XmlTag(info, "Date", TRUE, gSmbBiosDate, NULL);
		XmlEndTag(info, "BIOS");
	}
	// Devices info
	InitTcg();
	XmlTag(info, "TPM12", TRUE, NULL, " count=\"%d\"", gTcgCount, NULL);
	XmlTag(info, "TPM20", TRUE, NULL, " count=\"%d\"", gTcg2Count, NULL);
	XmlTag(info, "BlockDevices", TRUE, NULL, " count=\"%d\"", gBIOCount, NULL);
	InitUsb();
	XmlTag(info, "UsbDevices", TRUE, NULL, " count=\"%d\"", gUSBCount, NULL);
	InitTouch();
	XmlTag(info, "TouchDevices", FALSE, NULL, " count=\"%d\"", gTouchCount, NULL);
	FileAsciiPrint(info, "\n");
	gXmlTabs++;
	for (i = 0; i < gTouchCount; ++i) {
		EFI_ABSOLUTE_POINTER_PROTOCOL *aio;
		res = TouchGetIO(gTouchHandles[i], &aio);
		if (!EFI_ERROR(res)) {
			XmlTag(info, "TouchDevice", TRUE, NULL, 
				" index=\"%d\" minx=\"%d\" miny=\"%d\" minz=\"%d\" maxx=\"%d\" maxy=\"%d\" maxz=\"%d\" attr=\"0x0%x\"", i, 
				aio->Mode->AbsoluteMinX, aio->Mode->AbsoluteMinY, aio->Mode->AbsoluteMinZ, 
				aio->Mode->AbsoluteMaxX, aio->Mode->AbsoluteMaxY, aio->Mode->AbsoluteMaxZ, 
				aio->Mode->Attributes, NULL);
		}
	}
	XmlEndTag(info, "TouchDevices");
	InitGraph();
	XmlTag(info, "GraphDevices", FALSE, NULL, " count=\"%d\"", gGraphCount, NULL);
	FileAsciiPrint(info, "\n");
	gXmlTabs++;
	for (i = 0; i < gGraphCount; ++i) {
		EFI_GRAPHICS_OUTPUT_PROTOCOL *gio;
		res = GraphGetIO(gGraphHandles[i], &gio);
		if (!EFI_ERROR(res)) {
			XmlTag(info, "GraphDevice", FALSE, NULL,
				" index=\"%d\" modes=\"%d\" H=\"%d\" V=\"%d\"", i,
				gio->Mode->MaxMode, gio->Mode->Info->HorizontalResolution, gio->Mode->Info->VerticalResolution,
				NULL);
			FileAsciiPrint(info, "\n");
			gXmlTabs++;
			for (j = 0; j < gio->Mode->MaxMode; ++j) {
				EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *mode;
				UINTN sz = sizeof(mode);
				res = gio->QueryMode(gio, (UINT32)j, &sz, &mode);
				if (!EFI_ERROR(res)) {
					XmlTag(info, "GraphMode", TRUE, NULL,
						" index=\"%d\" H=\"%d\" V=\"%d\"", j,
						mode->HorizontalResolution, mode->VerticalResolution,
						NULL);
				}
			}
			XmlEndTag(info, "GraphDevice");
		}
	}
	XmlEndTag(info, "GraphDevices");
	InitBluetooth();
	XmlTag(info, "BluetoothIo", TRUE, NULL, " count=\"%d\"", gBluetoothIoCount, NULL);
	XmlTag(info, "BluetoothConfig", TRUE, NULL, " count=\"%d\"", gBluetoothConfigCount, NULL);
	XmlTag(info, "BluetoothHC", TRUE, NULL, " count=\"%d\"", gBluetoothHcCount, NULL);
	XmlEndTag(info, "PlatformInfo");
	FileClose(info);
	return EFI_SUCCESS;
}
