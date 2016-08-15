/** @file
Ask password from console

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Uefi.h>
#include "Library/CommonLib.h"
#include "Library/PasswordLib.h"
#include <Library/UefiBootServicesTableLib.h>

VOID
AskConsolePwdInt(
	OUT UINT32   *length,
	OUT CHAR8    *asciiLine,
	OUT INT32    *retCode,
	IN  UINTN    line_max,
	IN  UINT8    show
	)
{
	EFI_INPUT_KEY key;
	UINT32 count = 0;
	UINTN i;

	gST->ConOut->EnableCursor(gST->ConOut, TRUE);

	do {
		key = GetKey();
		// Remove dirty chars 0.1s
		FlushInputDelay(100000);
		
		if (key.ScanCode == SCAN_ESC) {
			*retCode = AskPwdRetCancel;
			break;
		}

		if (key.ScanCode == SCAN_F2) {
			*retCode = AskPwdRetChange;
			break;
		}

		if (key.ScanCode == SCAN_F5) {
			show = show ? 0 : 1;
			if (show) {
				for (i = 0; i < count; i++) {
					OUT_PRINT(L"\b");
				}
				OUT_PRINT(L"%a", asciiLine);
			}
			else {
				for (i = 0; i < count; i++) {
					OUT_PRINT(L"\b");
				}
				for (i = 0; i < count; i++) {
					OUT_PRINT(L"*");
				}
			}
		}

		if (key.ScanCode == SCAN_F7) {
			gPlatformLocked = gPlatformLocked ? 0 : 1;
			ConsoleShowTip(gPlatformLocked ? L" Platform locked!" : L" Platform unlocked!", 10000000);
		}

		if (key.ScanCode == SCAN_F8) {
			gTPMLocked = gTPMLocked ? 0 : 1;
			ConsoleShowTip(gTPMLocked ? L" TPM locked!" : L" TPM unlocked!", 10000000);
		}


		if (key.UnicodeChar == CHAR_CARRIAGE_RETURN) {
			*retCode = AskPwdRetLogin;
			break;
		}

		if ((count >= line_max &&
			key.UnicodeChar != CHAR_BACKSPACE) ||
			key.UnicodeChar == CHAR_NULL ||
			key.UnicodeChar == CHAR_TAB ||
			key.UnicodeChar == CHAR_LINEFEED ||
			key.UnicodeChar == CHAR_CARRIAGE_RETURN) {
			continue;
		}

		if (count == 0 && key.UnicodeChar == CHAR_BACKSPACE) {
			continue;
		}
		else if (key.UnicodeChar == CHAR_BACKSPACE) {
			OUT_PRINT(L"\b \b");
			if (asciiLine != NULL) asciiLine[--count] = '\0';
			continue;
		}

		// check size of line
		if (count < line_max - 1) {
			if (show) {
				OUT_PRINT(L"%c", key.UnicodeChar);
			}
			else {
				OUT_PRINT(L"*");
			}
			// save char
			if (asciiLine != NULL) {
				asciiLine[count++] = (CHAR8)key.UnicodeChar;
				asciiLine[count] = 0;
			}
		}
	} while (key.UnicodeChar != CHAR_CARRIAGE_RETURN);

	if (length != NULL) *length = count;
	// Set end of line
	if (asciiLine != NULL) {
		asciiLine[count] = '\0';
		for (i = 0; i < count; i++) {
			OUT_PRINT(L"\b \b");
		}
		OUT_PRINT(L"*");
	}
	OUT_PRINT(L"\n");
}
