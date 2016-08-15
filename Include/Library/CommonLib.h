/** @file
EFI common library (helpers)

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI 

This program and the accompanying materials are licensed and made available
under the terms and conditions of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#ifndef __COMMONLIB_H__
#define __COMMONLIB_H__

#include <Uefi.h>
#include <Protocol/BlockIo.h>
#include <Library/UefiLib.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/UsbIo.h>
#include <Protocol/AbsolutePointer.h>
#include <Guid/FileInfo.h>

#define FIELD_SIZEOF(t, f) (sizeof(((t*)0)->f))
#define FIELD_OFFSET(t, f) ((UINTN)(&((t*)0)->f))

//////////////////////////////////////////////////////////////////////////
// Memory procedures wrappers
//////////////////////////////////////////////////////////////////////////

#define MEM_ALLOC MemAlloc
#define MEM_FREE MemFree
#define MEM_REALLOC MemRealloc

VOID*
MemAlloc(
   IN UINTN size
   );

VOID
MemFree(
   IN VOID* ptr
   );

VOID*
MemRealloc(
	IN UINTN  OldSize,
	IN UINTN  NewSize,
	IN VOID   *OldBuffer  OPTIONAL
	);

EFI_STATUS
PrepareMemory(
   IN UINTN    address,
   IN UINTN    len,
   OUT VOID**  mem
   );

//////////////////////////////////////////////////////////////////////////
// handles
//////////////////////////////////////////////////////////////////////////

EFI_STATUS
EfiGetHandles(
   IN  EFI_LOCATE_SEARCH_TYPE   SearchType,
   IN  EFI_GUID                 *Protocol, OPTIONAL
   IN  VOID                     *SearchKey, OPTIONAL
   OUT EFI_HANDLE               **Buffer,
   OUT UINTN                    *Count
   );

EFI_STATUS
EfiGetStartDevice(
   OUT EFI_HANDLE* handle
   );
//////////////////////////////////////////////////////////////////////////
// Print handle info
//////////////////////////////////////////////////////////////////////////

VOID EfiPrintDevicePath(
   IN EFI_HANDLE handle
   );

VOID
EfiPrintProtocols(
   IN EFI_HANDLE handle
   );

//////////////////////////////////////////////////////////////////////////
// Block I/O
//////////////////////////////////////////////////////////////////////////

EFI_BLOCK_IO_PROTOCOL*
EfiGetBlockIO(
   IN EFI_HANDLE handle
   );

extern EFI_HANDLE* gBIOHandles;
extern UINTN       gBIOCount;

EFI_STATUS
InitBio();

BOOLEAN
EfiIsPartition(
	IN    EFI_HANDLE              h
	);

EFI_STATUS
EfiGetPartDetails(
	IN    EFI_HANDLE              h,
	OUT   HARDDRIVE_DEVICE_PATH*  dpVolme,
	OUT   EFI_HANDLE*             hDisk
	);

EFI_STATUS
EfiGetPartGUID(
	IN    EFI_HANDLE              h,
	OUT   EFI_GUID*               guid
	);

EFI_STATUS
EfiFindPartByGUID(
	IN   EFI_GUID*               guid,
	OUT  EFI_HANDLE*             h
	);

//////////////////////////////////////////////////////////////////////////
// USB
//////////////////////////////////////////////////////////////////////////
extern EFI_HANDLE* gUSBHandles;
extern UINTN       gUSBCount;

EFI_STATUS
InitUsb();

EFI_STATUS
UsbGetIO(
	IN    EFI_HANDLE					Handle,
	OUT   EFI_USB_IO_PROTOCOL**	UsbIo
	);

EFI_STATUS
UsbGetIOwithDescriptor(
	IN    EFI_HANDLE					Handle,
	OUT   EFI_USB_IO_PROTOCOL**	UsbIo,
	OUT   EFI_USB_DEVICE_DESCRIPTOR* UsbDescriptor
	);

EFI_STATUS
UsbGetId(
	IN    EFI_HANDLE		Handle,
	OUT   CHAR8**			id
	);

//////////////////////////////////////////////////////////////////////////
// Touch
//////////////////////////////////////////////////////////////////////////

extern EFI_HANDLE* gTouchHandles;
extern UINTN       gTouchCount;
extern int         gTouchSimulate;
extern EFI_ABSOLUTE_POINTER_PROTOCOL*	gTouchPointer;
extern UINT32      gTouchSimulateStep;

EFI_STATUS
InitTouch();

EFI_STATUS
TouchGetIO(
	IN    EFI_HANDLE								Handle,
	OUT   EFI_ABSOLUTE_POINTER_PROTOCOL**	io
	);


//////////////////////////////////////////////////////////////////////////
// Console I/O
//////////////////////////////////////////////////////////////////////////

#define OUT_PRINT(format, ...) AttrPrintEx(-1,-1, format, ##__VA_ARGS__)
#define ERR_PRINT(format, ...) AttrPrintEx(-1,-1, L"%E" format L"%N" , ##__VA_ARGS__)

EFI_STATUS
ConsoleGetOutput(
	IN EFI_HANDLE handle,
	OUT   EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL**	io
	);

VOID 
FlushInput();

VOID
FlushInputDelay(
	IN UINTN delay
	);

EFI_INPUT_KEY
KeyWait(
   CHAR16* Prompt,
   UINTN mDelay,
   UINT16 scanCode,
   UINT16 unicodeChar);

EFI_INPUT_KEY
GetKey(void);

VOID
ConsoleShowTip(
	IN CHAR16* tip,
	IN UINTN   delay);

VOID
GetLine(
   UINTN    *length,
   CHAR16   *line,
   CHAR8    *asciiLine,
   UINTN    line_max,
   UINT8    show);

int
AskAsciiString(
   CHAR8* prompt,
   CHAR8* str,
   UINTN max_len,
   UINT8 visible);

int
AskInt(
   CHAR8* prompt,
   UINT8 visible);


UINT8
AskConfirm(
   CHAR8* prompt,
   UINT8 visible);

UINT64
AskUINT64(
	IN char* prompt,
	IN UINT64 def);

UINT64
AskHexUINT64(
	IN char* prompt,
	IN UINT64 def);

UINTN
AskUINTN(
	IN char* prompt,
	IN UINTN def);

BOOLEAN
AsciiHexToDigit(
	OUT UINT8  *b, 
	IN  CHAR8  *str
	);

BOOLEAN
AsciiHexToByte(
	OUT UINT8  *b,
	IN  CHAR8  *str
	);

BOOLEAN
AsciiStrToGuid(
	OUT EFI_GUID  *guid, 
	IN  CHAR8     *str
	);


//////////////////////////////////////////////////////////////////////////
// Attribute print
//////////////////////////////////////////////////////////////////////////

extern BOOLEAN	gShellReady;

VOID
SetShellAPI(
	IN VOID* shellProtocol,
	IN VOID* shellParametersProtocol
	);

/**
Print at a specific location on the screen.

This function will move the cursor to a given screen location and print the specified string.

If -1 is specified for either the Row or Col the current screen location for BOTH
will be used.

If either Row or Col is out of range for the current console, then ASSERT.
If Format is NULL, then ASSERT.

In addition to the standard %-based flags as supported by UefiLib Print() this supports
the following additional flags:
%N       -   Set output attribute to normal
%H       -   Set output attribute to highlight
%E       -   Set output attribute to error
%B       -   Set output attribute to blue color
%V       -   Set output attribute to green color

Note: The background color is controlled by the shell command cls.

@param[in] Col        the column to print at
@param[in] Row        the row to print at
@param[in] Format     the format string
@param[in] ...        The variable argument list.

@return EFI_SUCCESS           The printing was successful.
@return EFI_DEVICE_ERROR      The console device reported an error.
**/
EFI_STATUS
EFIAPI
AttrPrintEx(
	IN INT32                Col OPTIONAL,
	IN INT32                Row OPTIONAL,
	IN CONST CHAR16         *Format,
	...
	);

//////////////////////////////////////////////////////////////////////////
// Console control
//////////////////////////////////////////////////////////////////////////

extern EFI_HANDLE* gConsoleControlHandles;
extern UINTN       gConsoleControlCount;

EFI_STATUS
InitConsoleControl();

//////////////////////////////////////////////////////////////////////////
// Beep
//////////////////////////////////////////////////////////////////////////
extern EFI_HANDLE*                gSpeakerHandles;
extern UINTN                      gSpeakerCount;
extern EFI_GUID                   gSpeakerGuid;

extern int gBeepEnabled;
extern BOOLEAN	gBeepControlEnabled;
extern int gBeepDevice;
extern int gBeepNumberDefault;
extern int gBeepDurationDefault;
extern int gBeepIntervalDefault;
extern int gBeepToneDefault;


EFI_STATUS
InitSpeaker();

EFI_STATUS
SpeakerBeep(
	IN UINT16  Tone,
	IN UINTN   NumberOfBeeps,
	IN UINTN   Duration,
	IN UINTN   Interval
	);

EFI_STATUS
SpeakerSelect(
	IN UINTN index
	);

//////////////////////////////////////////////////////////////////////////
// Efi variables
//////////////////////////////////////////////////////////////////////////

#define DCS_BOOT_STR L"DcsBoot"

extern EFI_GUID gEfiDcsVariableGuid;

EFI_STATUS
EfiGetVar(
   IN  CONST CHAR16*    varName,
   IN  EFI_GUID*        varGuid,
   OUT VOID**           varValue,
   OUT UINTN*           varSize,
   OUT UINT32*          varAttr
   );

EFI_STATUS
EfiSetVar(
   IN  CONST CHAR16*    varName,
   IN  EFI_GUID*        varGuid,
   IN  VOID*            varValue,
   IN  UINTN            varSize,
   IN  UINT32           varAttr
   );

EFI_STATUS
BootOrderInsert(
	IN CHAR16 *OrderVarName,
	IN UINTN index,
	UINT16   value);

EFI_STATUS
BootOrderRemove(
	IN CHAR16 *OrderVarName,
	UINT16   value
	);

EFI_STATUS
BootMenuItemCreate(
	IN CHAR16     *VarName,
	IN CHAR16     *Desc,
	IN EFI_HANDLE volumeHandle,
	IN CHAR16     *Path,
	IN BOOLEAN    Reduced
	);

EFI_STATUS
BootMenuItemRemove(
	IN CHAR16     *VarName
	);



//////////////////////////////////////////////////////////////////////////
// File
//////////////////////////////////////////////////////////////////////////


extern EFI_FILE*      gFileRoot;
extern EFI_HANDLE     gFileRootHandle;

extern EFI_HANDLE* gFSHandles;
extern UINTN       gFSCount;

EFI_STATUS
InitFS();

EFI_STATUS
FileOpenRoot(
   IN    EFI_HANDLE rootHandle,
   OUT   EFI_FILE** rootFile);

EFI_STATUS
FileOpen(
   IN    EFI_FILE*   root,
   IN    CHAR16*     name,
   OUT   EFI_FILE**  file,
   IN    UINT64      mode,
   IN    UINT64      attributes
   );

EFI_STATUS
FileClose(
   IN EFI_FILE* f);

EFI_STATUS
FileDelete(
   IN    EFI_FILE*   root,
   IN    CHAR16*     name
   );

EFI_STATUS
FileRead(
   IN       EFI_FILE*   f,
   OUT      VOID*       data,
   IN OUT   UINTN*      bytes,
   IN OUT   UINT64*     position);

EFI_STATUS
FileWrite(
   IN       EFI_FILE*   f,
   IN       VOID*       data,
   IN OUT   UINTN*      bytes,
   IN OUT   UINT64*     position);

EFI_STATUS
FileGetInfo(
   IN    EFI_FILE*         f,
   OUT   EFI_FILE_INFO**   info,
   OUT   UINTN*            size
   );

EFI_STATUS
FileGetSize(
   IN    EFI_FILE*   f,
   OUT   UINTN*     size
   );

EFI_STATUS
FileLoad(
   IN    EFI_FILE*   root,
   IN    CHAR16*     name,
   OUT   VOID**      data,
   OUT   UINTN*      size
   );

EFI_STATUS
FileSave(
   IN    EFI_FILE*   root,
   IN    CHAR16*     name,
   IN    VOID*       data,
   IN    UINTN      size
   );

EFI_STATUS
FileExist(
	IN    EFI_FILE*   root,
	IN    CHAR16*     name
	);

EFI_STATUS
FileRename(
	IN    EFI_FILE*   root,
	IN    CHAR16*     src,
	IN    CHAR16*     dst
	);

EFI_STATUS
FileCopy(
	IN    EFI_FILE*   srcroot,
	IN    CHAR16*     src,
	IN    EFI_FILE*   dstroot,
	IN    CHAR16*     dst,
	IN    UINTN       bufSz
	);

//////////////////////////////////////////////////////////////////////////
// Exec
//////////////////////////////////////////////////////////////////////////

EFI_STATUS
EfiExec(
   IN    EFI_HANDLE  deviceHandle,
   IN    CHAR16*     path
   );

EFI_STATUS
ConnectAllEfi(
   VOID
   );

VOID
EfiCpuHalt();

#endif