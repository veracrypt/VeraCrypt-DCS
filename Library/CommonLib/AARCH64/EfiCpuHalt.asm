;------------------------------------------------------------------------------
; VOID
; EFIAPI
; EfiCpuHalt (
;   VOID
;   );
;------------------------------------------------------------------------------
    AREA    |.text|, CODE, READONLY

    EXPORT  EfiCpuHalt

EfiCpuHalt PROC
    msr     daifset, #0xf

loop
    wfi
    b       loop

    ret

    ENDP

    END
