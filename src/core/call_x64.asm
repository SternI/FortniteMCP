option casemap:none

.code

; uint64_t FmcpInvokeX64(void* fn,
;                        const uint64_t* ints, uint32_t intMask,
;                        const uint64_t* xmm, uint32_t xmmMask,
;                        const uint64_t* stackArgs, uint32_t stackCount,
;                        uint64_t* xmmOut)
FmcpInvokeX64 PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 120h
    .allocstack 120h
    .endprolog

    mov qword ptr [rbp-08h], rcx
    mov qword ptr [rbp-10h], rdx
    mov dword ptr [rbp-18h], r8d
    mov qword ptr [rbp-20h], r9

    mov eax, dword ptr [rbp+30h]
    mov dword ptr [rbp-28h], eax
    mov rax, qword ptr [rbp+38h]
    mov qword ptr [rbp-30h], rax
    mov eax, dword ptr [rbp+40h]
    mov dword ptr [rbp-38h], eax
    mov rax, qword ptr [rbp+48h]
    mov qword ptr [rbp-40h], rax

    mov r10, qword ptr [rbp-30h]
    mov ecx, dword ptr [rbp-38h]
    xor eax, eax
    test ecx, ecx
    jz copy_done
copy_loop:
    mov r11, qword ptr [r10 + rax*8]
    mov qword ptr [rsp + 20h + rax*8], r11
    inc eax
    cmp eax, ecx
    jb copy_loop
copy_done:

    xor ecx, ecx
    xor edx, edx
    xor r8d, r8d
    xor r9d, r9d

    mov r11, qword ptr [rbp-10h]
    mov r10d, dword ptr [rbp-18h]

    test r10d, 1
    jz int2
    mov rcx, qword ptr [r11]
int2:
    test r10d, 2
    jz int3
    mov rdx, qword ptr [r11+8]
int3:
    test r10d, 4
    jz int4
    mov r8, qword ptr [r11+16]
int4:
    test r10d, 8
    jz int_done
    mov r9, qword ptr [r11+24]
int_done:

    xorps xmm0, xmm0
    xorps xmm1, xmm1
    xorps xmm2, xmm2
    xorps xmm3, xmm3

    mov r11, qword ptr [rbp-20h]
    mov r10d, dword ptr [rbp-28h]

    test r10d, 1
    jz load_xmm1_done
    movq xmm0, qword ptr [r11]
load_xmm1_done:
    test r10d, 2
    jz load_xmm2_done
    movq xmm1, qword ptr [r11+8]
load_xmm2_done:
    test r10d, 4
    jz load_xmm3_done
    movq xmm2, qword ptr [r11+16]
load_xmm3_done:
    test r10d, 8
    jz load_xmm_done
    movq xmm3, qword ptr [r11+24]
load_xmm_done:

    xor eax, eax
    test r10d, 1
    jz var2
    inc eax
var2:
    test r10d, 2
    jz var3
    inc eax
var3:
    test r10d, 4
    jz var4
    inc eax
var4:
    test r10d, 8
    jz var_done
    inc eax
var_done:

    mov r11, qword ptr [rbp-08h]
    call r11

    mov r10, qword ptr [rbp-40h]
    test r10, r10
    jz no_xmm_out
    movq qword ptr [r10], xmm0
no_xmm_out:
    leave
    ret
FmcpInvokeX64 ENDP

end
