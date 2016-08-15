/** @file
EFI USB helpers

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI 

This program and the accompanying materials are licensed and made available
under the terms and conditions of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Library/CommonLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DevicePathLib.h>
#include <Library/PrintLib.h>
#include <Protocol/UsbIo.h>

EFI_HANDLE* gUSBHandles = NULL;
UINTN       gUSBCount = 0;

EFI_STATUS
InitUsb() {
	EFI_STATUS res;
	res = EfiGetHandles(ByProtocol, &gEfiUsbIoProtocolGuid, 0, &gUSBHandles, &gUSBCount);
	return res;
}

EFI_STATUS
UsbGetIO(
	IN    EFI_HANDLE					Handle,
	OUT   EFI_USB_IO_PROTOCOL**	UsbIo
	) {
	if (!UsbIo) {
		return EFI_INVALID_PARAMETER;
	}
	return gBS->HandleProtocol(Handle, &gEfiUsbIoProtocolGuid, (VOID**)UsbIo);
}

EFI_STATUS
UsbGetIOwithDescriptor(
	IN    EFI_HANDLE					Handle,
	OUT   EFI_USB_IO_PROTOCOL**	UsbIo,
	OUT   EFI_USB_DEVICE_DESCRIPTOR* UsbDescriptor
	) {
	EFI_STATUS                    res;
	if (!UsbIo || !UsbDescriptor) {
		return EFI_INVALID_PARAMETER;
	}
	res = UsbGetIO(Handle, UsbIo);
	if (EFI_ERROR(res)) {
		return res;
	}
	return (*UsbIo)->UsbGetDeviceDescriptor(*UsbIo, UsbDescriptor);
}

EFI_STATUS
UsbGetId(
	IN    EFI_HANDLE		Handle,
	OUT   CHAR8**			id
	)
{
	EFI_STATUS                    res;
	EFI_USB_IO_PROTOCOL           *usbIO = NULL;
	EFI_USB_DEVICE_DESCRIPTOR     usbDescriptor;
	CHAR16*                       serial = NULL;
	CHAR8*                        buff;
	UINTN                         len;
	res = UsbGetIOwithDescriptor(Handle, &usbIO, &usbDescriptor);
	if (EFI_ERROR(res)) {
		return res;
	}
//	Print(L" %02x ", (UINTN)usbDescriptor.StrSerialNumber);
	res = usbIO->UsbGetStringDescriptor(usbIO, 0x409, usbDescriptor.StrSerialNumber, &serial);
	if (!EFI_ERROR(res)) {
		len = 11 + StrLen(serial);
		buff = (CHAR8*)MEM_ALLOC(len);
		AsciiSPrint(buff, len, "%04x_%04x_%s", usbDescriptor.IdVendor, usbDescriptor.IdProduct, serial);
	}	else {
//		Print(L" %04x %r ", res, res);
		len = 10;
		buff = (CHAR8*)MEM_ALLOC(len);
		AsciiSPrint(buff, len, "%04x_%04x", usbDescriptor.IdVendor, usbDescriptor.IdProduct);
	}
	*id = buff;
	return EFI_SUCCESS;
}
