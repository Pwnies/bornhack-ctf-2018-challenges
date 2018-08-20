[BITS 32]

start:
    inc edi
    cmp DWORD [edi], `flag`
    jne start
