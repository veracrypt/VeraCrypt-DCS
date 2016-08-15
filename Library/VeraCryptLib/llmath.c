#include <uefi.h>
void __cdecl atexit() {}

int __cdecl _purecall() { return 0; }

#if defined(_M_IX86)
//////////////////////////////////////////////////////////////////////////
// _allmul
//////////////////////////////////////////////////////////////////////////
__declspec(naked) void __cdecl _allmul(void)
{
   _asm {
      mov  ebx, [esp + 4]              ; ebx <- M1[0..31]
      mov  edx, [esp + 12]             ; edx <- M2[0..31]
      mov  ecx, ebx
      mov  eax, edx
      imul ebx, [esp + 16]             ; ebx <- M1[0..31] * M2[32..63]
      imul edx, [esp + 8]              ; edx <- M1[32..63] * M2[0..31]
      add  ebx, edx                    ; carries are abandoned
      mul  ecx                         ; edx:eax <- M1[0..31] * M2[0..31]
      add  edx, ebx                    ; carries are abandoned
      ret 16
   }
}

//////////////////////////////////////////////////////////////////////////
// _aullmul
//////////////////////////////////////////////////////////////////////////
__declspec(naked) void __cdecl _aullmul()
{
   _asm {
      mov  ebx, [esp + 4]              ; ebx <- M1[0..31]
      mov  edx, [esp + 12]             ; edx <- M2[0..31]
      mov  ecx, ebx
      mov  eax, edx
      imul ebx, [esp + 16]             ; ebx <- M1[0..31] * M2[32..63]
      imul edx, [esp + 8]              ; edx <- M1[32..63] * M2[0..31]
      add  ebx, edx                    ; carries are abandoned
      mul  ecx                         ; edx:eax <- M1[0..31] * M2[0..31]
      add  edx, ebx                    ; carries are abandoned
      ret 16
   }
}

//////////////////////////////////////////////////////////////////////////
// _alldiv
//////////////////////////////////////////////////////////////////////////
__declspec(naked) void __cdecl _alldiv()
{
   _asm {
      ; Check sign of res
      mov     ebx, [esp + 8]    ; dividend msdw
      mov     ecx, [esp + 16]   ; divisor msdw
      xor     ebx, ecx
      shr     ebx, 31
      jz      _PosRes           ; if Result is positive
      push    1                 ; if is negative
      jmp _Preparing
      _PosRes:
      push    0

      ; Preparing operands
      ; Dividend
      _Preparing:
      mov     ecx, [esp + 12]
      shr     ecx, 31
      jz      _ChkDvsr                        ; Divident is positive
      mov     eax, [esp + 12]                 ; is negative
      mov     ecx, [esp + 8]
      xor     eax, 0xFFFFFFFF
      xor     ecx, 0xFFFFFFFF
      add     ecx, 1
      jnc     _DvntOK
      adc     eax, 0
      _DvntOK:
      mov     [esp + 12], eax
      mov     [esp + 8], ecx

      ; Divisor
      _ChkDvsr:
      mov     ecx, [esp + 20]
      shr     ecx, 31
      jz      _Divide                         ; Divisor is positive
      mov     eax, [esp + 20]                 ; is negative
      mov     ecx, [esp + 16]
      xor     eax, 0xFFFFFFFF
      xor     ecx, 0xFFFFFFFF
      add     ecx, 1
      jnc     _DvsrOK
      adc     eax, 0
      _DvsrOK:
      mov     [esp + 20], eax
      mov     [esp + 16], ecx
      
      _Divide:
      mov     ecx, [esp + 20]             ; ecx <- divisor[32..63]
      test    ecx, ecx
      jnz     __DivRemU64x64              ; call __DivRemU64x64 if Divisor > 2^32
      mov     ecx, [esp + 16]             ; ecx <- divisor
      mov     eax, [esp + 12]             ; eax <- dividend[32..63]
      xor     edx, edx
      div     ecx                         ; eax <- quotient[32..63], edx <- remainder
      push    eax
      mov     eax, [esp + 12]             ; eax <- dividend[0..31]
      div     ecx                         ; eax <- quotient[0..31]
      pop     edx                         ; edx <- quotient[32..63] - edx:eax
      jmp     _GetSign

      __DivRemU64x64:
      mov     edx, dword ptr [esp + 12]
      mov     eax, dword ptr [esp + 8]    ; edx:eax <- dividend
      mov     edi, edx
      mov     esi, eax                    ; edi:esi <- dividend
      mov     ebx, dword ptr [esp + 16]   ; ecx:ebx <- divisor
      _B:
      shr     edx, 1
      rcr     eax, 1
      shrd    ebx, ecx, 1
      shr     ecx, 1
      jnz     _B
      div     ebx
      mov     ebx, eax                    ; ebx <- quotient
      mov     ecx, [esp + 20]             ; ecx <- high dword of divisor
      mul     dword ptr [esp + 16]        ; edx:eax <- quotient * divisor[0..31]
      imul    ecx, ebx                    ; ecx <- quotient * divisor[32..63]
      add     edx, ecx                    ; edx <- (quotient * divisor)[32..63]
      ;mov     ecx, dword ptr [esp + 32]   ; ecx <- addr for Remainder
      jc      _TooLarge                   ; product > 2^64
      cmp     edi, edx                    ; compare high 32 bits
      ja      _Correct
      jb      _TooLarge                   ; product > dividend
      cmp     esi, eax
      jae     _Correct                    ; product <= dividend
      _TooLarge:
      dec     ebx                         ; adjust quotient by -1
      jecxz   _Return                     ; return if Remainder == NULL
      sub     eax, dword ptr [esp + 16]
      sbb     edx, dword ptr [esp + 20]   ; edx:eax <- (quotient - 1) * divisor
      _Correct:
      jecxz   _Return
      sub     esi, eax
      sbb     edi, edx                    ; edi:esi <- remainder
      ;mov     [ecx], esi
      ;mov     [ecx + 4], edi
      _Return:
      mov     eax, ebx                    ; eax <- quotient
      xor     edx, edx                    ; quotient is 32 bits long

      ; Get sign of result
      _GetSign:
      pop     ecx                         ; Sign of res
      jecxz   _Rtrn                       ; Result is positive
      xor     eax, 0xFFFFFFFF
      xor     edx, 0xFFFFFFFF
      add     eax, 1                      ; edx:eax
      jnc     _Rtrn
      adc     edx, 0

      _Rtrn:
      ret     16
   }
}

//////////////////////////////////////////////////////////////////////////
// _aulldiv
//////////////////////////////////////////////////////////////////////////
__declspec(naked) void __cdecl _aulldiv()
{
   _asm {
      mov     ecx, [esp + 16]             ; ecx <- divisor[32..63]
      test    ecx, ecx
      jnz     __DivRemU64x64              ; call __DivRemU64x64 if Divisor > 2^32
      mov     ecx, [esp + 12]             ; ecx <- divisor
      mov     eax, [esp + 8]              ; eax <- dividend[32..63]
      xor     edx, edx
      div     ecx                         ; eax <- quotient[32..63], edx <- remainder
      push    eax
      mov     eax, [esp + 8]              ; eax <- dividend[0..31]
      div     ecx                         ; eax <- quotient[0..31]
      pop     edx                         ; edx <- quotient[32..63]
      ret     16

      __DivRemU64x64:
      mov     edx, dword ptr [esp + 8]
      mov     eax, dword ptr [esp + 4]    ; edx:eax <- dividend
      mov     edi, edx
      mov     esi, eax                    ; edi:esi <- dividend
      mov     ebx, dword ptr [esp + 12]   ; ecx:ebx <- divisor
      _B:
      shr     edx, 1
      rcr     eax, 1
      shrd    ebx, ecx, 1
      shr     ecx, 1
      jnz     _B
      div     ebx
      mov     ebx, eax                    ; ebx <- quotient
      mov     ecx, [esp + 16]             ; ecx <- high dword of divisor
      mul     dword ptr [esp + 12]        ; edx:eax <- quotient * divisor[0..31]
      imul    ecx, ebx                    ; ecx <- quotient * divisor[32..63]
      add     edx, ecx                    ; edx <- (quotient * divisor)[32..63]
      ;mov     ecx, dword ptr [esp + 32]   ; ecx <- addr for Remainder
      jc      _TooLarge                   ; product > 2^64
      cmp     edi, edx                    ; compare high 32 bits
      ja      _Correct
      jb      _TooLarge                   ; product > dividend
      cmp     esi, eax
      jae     _Correct                    ; product <= dividend
      _TooLarge:
      dec     ebx                         ; adjust quotient by -1
      jecxz   _Return                     ; return if Remainder == NULL
      sub     eax, dword ptr [esp + 12]
      sbb     edx, dword ptr [esp + 16]   ; edx:eax <- (quotient - 1) * divisor
      _Correct:
      jecxz   _Return
      sub     esi, eax
      sbb     edi, edx                    ; edi:esi <- remainder
      ;mov     [ecx], esi
      ;mov     [ecx + 4], edi
      _Return:
      mov     eax, ebx                    ; eax <- quotient
      xor     edx, edx                    ; quotient is 32 bits long

      ret     16
   }
}

//////////////////////////////////////////////////////////////////////////
// Shifts
//////////////////////////////////////////////////////////////////////////
__declspec(naked) void __cdecl _aullshr() {
   _asm {
    ;
    ; Checking: Only handle 64bit shifting or more
    ;
    cmp     cl, 64
    jae     _Exit

    ;
    ; Handle shifting between 0 and 31 bits
    ;
    cmp     cl, 32
    jae     More32
    shrd    eax, edx, cl
    shr     edx, cl
    ret

    ;
    ; Handle shifting of 32-63 bits
    ;
More32:
    mov     eax, edx
    xor     edx, edx
    and     cl, 31
    shr     eax, cl
    ret

    ;
    ; Invalid number (less then 32bits), return 0
    ;
_Exit:
    xor     eax, eax
    xor     edx, edx
    ret
  }
}

__declspec(naked) void __cdecl _allshl() {
     _asm {
    ;
    ; Handle shifting of 64 or more bits (return 0)
    ;
    cmp     cl, 64
    jae     short ReturnZero

    ;
    ; Handle shifting of between 0 and 31 bits
    ;
    cmp     cl, 32
    jae     short More32
    shld    edx, eax, cl
    shl     eax, cl
    ret

    ;
    ; Handle shifting of between 32 and 63 bits
    ;
More32:
    mov     edx, eax
    xor     eax, eax
    and     cl, 31
    shl     edx, cl
    ret

ReturnZero:
    xor     eax,eax
    xor     edx,edx
    ret
  }
}

UINT64
EFIAPI
DivU64x64Remainder(
IN      UINT64                    Dividend,
IN      UINT64                    Divisor,
OUT     UINT64                    *Remainder  OPTIONAL
);
/*
 * Divides a 64-bit unsigned value by another 64-bit unsigned value and returns
 * the 64-bit unsigned remainder.
 */
__declspec(naked) void __cdecl _aullrem(void)
{
  //
  // Wrapper Implementation over EDKII DivU64x64Remainder() routine
  //    UINT64
  //    EFIAPI
  //    DivU64x64Remainder (
  //      IN      UINT64     Dividend,
  //      IN      UINT64     Divisor,
  //      OUT     UINT64     *Remainder  OPTIONAL
  //      )
  //
  _asm {
    ; Original local stack when calling _aullrem
    ;               -----------------
    ;               |               |
    ;               |---------------|
    ;               |               |
    ;               |--  Divisor  --|
    ;               |               |
    ;               |---------------|
    ;               |               |
    ;               |--  Dividend --|
    ;               |               |
    ;               |---------------|
    ;               |  ReturnAddr** |
    ;       ESP---->|---------------|
    ;

    ;
    ; Set up the local stack for Reminder pointer
    ;
    sub  esp, 8
    push esp

    ;
    ; Set up the local stack for Divisor parameter
    ;
    mov  eax, [esp + 28]
    push eax
    mov  eax, [esp + 28]
    push eax

    ;
    ; Set up the local stack for Dividend parameter
    ;
    mov  eax, [esp + 28]
    push eax
    mov  eax, [esp + 28]
    push eax

    ;
    ; Call native DivU64x64Remainder of BaseLib
    ;
    call DivU64x64Remainder

    ;
    ; Put the Reminder in EDX:EAX as return value
    ;
    mov  eax, [esp + 20]
    mov  edx, [esp + 24]

    ;
    ; Adjust stack
    ;
    add  esp, 28

    ret  16
  }
}

#endif
