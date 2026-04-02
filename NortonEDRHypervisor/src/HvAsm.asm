; HvAsm.asm — x64 assembly stubs for Intel VT-x hypervisor
; All routines follow the Microsoft x64 calling convention.
; Callable from C++ via the extern "C" declarations in HvDefs.h.

EXTERN HvHandleVmExit:PROC

.CODE

; ---------------------------------------------------------------------------
; NTSTATUS HvVmxOn(PHYSICAL_ADDRESS* physAddr)
; RCX = pointer to 64-bit physical address of the VMXON region.
; Returns STATUS_SUCCESS or STATUS_UNSUCCESSFUL.
; ---------------------------------------------------------------------------
HvVmxOn PROC
    vmxon QWORD PTR [rcx]
    jc    vmxon_fail        ; CF=1: VMX instruction error (invalid operand)
    jz    vmxon_fail        ; ZF=1: VM-entry failure (valid but failed)
    xor   eax, eax          ; STATUS_SUCCESS
    ret
vmxon_fail:
    mov   eax, 0C0000001h   ; STATUS_UNSUCCESSFUL
    ret
HvVmxOn ENDP


; ---------------------------------------------------------------------------
; VOID HvVmxOff()
; Leaves VMX operation on the current logical processor.
; ---------------------------------------------------------------------------
HvVmxOff PROC
    vmxoff
    ret
HvVmxOff ENDP


; ---------------------------------------------------------------------------
; NTSTATUS HvVmClear(PHYSICAL_ADDRESS* physAddr)
; RCX = pointer to the 64-bit physical address of the VMCS to clear.
; ---------------------------------------------------------------------------
HvVmClear PROC
    vmclear QWORD PTR [rcx]
    jc    vmclear_fail
    jz    vmclear_fail
    xor   eax, eax
    ret
vmclear_fail:
    mov   eax, 0C0000001h
    ret
HvVmClear ENDP


; ---------------------------------------------------------------------------
; NTSTATUS HvVmPtrLd(PHYSICAL_ADDRESS* physAddr)
; RCX = pointer to the 64-bit physical address of the VMCS to make current.
; ---------------------------------------------------------------------------
HvVmPtrLd PROC
    vmptrld QWORD PTR [rcx]
    jc    vmptrld_fail
    jz    vmptrld_fail
    xor   eax, eax
    ret
vmptrld_fail:
    mov   eax, 0C0000001h
    ret
HvVmPtrLd ENDP


; ---------------------------------------------------------------------------
; ULONG_PTR HvVmRead(ULONG_PTR encoding)
; RCX = VMCS field encoding. Returns field value in RAX.
; ---------------------------------------------------------------------------
HvVmRead PROC
    vmread rax, rcx         ; RAX = VMCS[RCX]
    ret
HvVmRead ENDP


; ---------------------------------------------------------------------------
; VOID HvVmWrite(ULONG_PTR encoding, ULONG_PTR value)
; RCX = VMCS field encoding, RDX = value to write.
; ---------------------------------------------------------------------------
HvVmWrite PROC
    vmwrite rcx, rdx        ; VMCS[RCX] = RDX
    ret
HvVmWrite ENDP


; ---------------------------------------------------------------------------
; VOID HvInvEpt(ULONG type, PVOID descriptor)
; RCX = invalidation type (1=single-context, 2=all-contexts)
; RDX = pointer to 128-bit INVEPT descriptor {EPTP[63:0], reserved[63:0]}
; ---------------------------------------------------------------------------
HvInvEpt PROC
    invept rcx, OWORD PTR [rdx]
    ret
HvInvEpt ENDP


; ---------------------------------------------------------------------------
; ULONG_PTR HvVmCall(ULONG_PTR code, ULONG_PTR arg1, ULONG_PTR arg2)
; Issues a VMCALL hypercall from guest to the hypervisor.
; RCX=code, RDX=arg1, R8=arg2. Return value in RAX.
; ---------------------------------------------------------------------------
HvVmCall PROC
    vmcall
    ret
HvVmCall ENDP


; ---------------------------------------------------------------------------
; BOOLEAN HvLaunchVm(PVCPU vcpu)
; RCX = pointer to VCPU struct.
;
; This routine sets GUEST_RSP/RIP in the VMCS to capture the current
; execution context, then executes VMLAUNCH.
;
;   • On VMLAUNCH failure  → returns FALSE (0); caller handles error.
;   • On VMLAUNCH success  → the CPU enters VMX non-root (guest mode) and
;     begins executing the guest from guest_continuation below.  Every
;     subsequent VM exit will be dispatched to HvVmExitStub (HOST_RIP),
;     handled in C, and returned via VMRESUME — the guest resumes from
;     wherever the exit occurred, NOT back here.
;
; The guest_continuation label is visited exactly once per processor:
; immediately after a successful VMLAUNCH, the first VMRESUME returns the
; guest to that label, which restores callee-saved registers and returns
; TRUE to the original caller (HvInitOnProcessor in HvEntry.cpp).
; ---------------------------------------------------------------------------
HvLaunchVm PROC
    ; Save callee-saved registers onto the (guest) stack.
    ; These will be restored in guest_continuation.
    push    rbp
    push    rdi
    push    rsi
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15

    ; Write GUEST_RSP = current RSP (stack now holds the 8 saved registers).
    mov     rdx, rsp
    mov     rcx, 681Ch          ; VMCS_GUEST_RSP encoding
    vmwrite rcx, rdx

    ; Write GUEST_RIP = address of guest_continuation below.
    lea     rdx, guest_continuation
    mov     rcx, 681Eh          ; VMCS_GUEST_RIP encoding
    vmwrite rcx, rdx

    ; Execute VMLAUNCH.  If it succeeds the CPU transitions to guest mode
    ; and HOST_RIP (HvVmExitStub) becomes the next exit entry point.
    vmlaunch

    ; ---- VMLAUNCH failed — we reach here only on error ----
    ; CF=1: VM-instruction error (bad VMCS pointer / field); ZF=1: valid error.
    ; Restore callee-saved registers and return FALSE.
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rsi
    pop     rdi
    pop     rbp
    xor     eax, eax            ; return FALSE
    ret

    ; ---- Guest continuation — reached after VMLAUNCH + first VMRESUME ----
    ; Execution arrives here inside VMX non-root mode (guest).
    ; RSP = the value saved above; the 8 callee-saved registers are on top.
guest_continuation:
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rsi
    pop     rdi
    pop     rbp
    mov     eax, 1              ; return TRUE — virtualization active
    ret
HvLaunchVm ENDP


; ---------------------------------------------------------------------------
; HvVmExitStub — HOST_RIP entry point for every VM exit.
;
; Calling convention: none — control arrives here via hardware VM exit,
; not via a CALL instruction.  RSP = HOST_RSP configured in the VMCS
; (the dedicated per-vCPU host stack), fully restored by the hardware.
;
; Stack layout at entry:   RSP → (fresh host stack, no frame yet)
;
; Procedure:
;   1. Push all guest GPRs (saved in GUEST_REGISTERS order from HvDefs.h).
;   2. Pass a pointer to that save area as arg1 to HvHandleVmExit (C++).
;   3. After the C handler returns, restore registers and VMRESUME.
;
; Stack math (HOST_RSP is 16-byte aligned):
;   15 pushes × 8 bytes = 120 bytes.   120 mod 16 = 8.
;   Before CALL, RSP mod 16 must be 8 (CALL adds 8-byte ret-addr → 16-aligned).
;   Shadow space = 32 bytes (0x20); 120 + 0x20 = 152; 152 mod 16 = 8.
;   Add 8 bytes alignment pad → 160 bytes; CALL then adds 8 → RSP 16-aligned. ✓
; ---------------------------------------------------------------------------
HvVmExitStub PROC
    ; Push guest GPRs — ORDER must match GUEST_REGISTERS struct in HvDefs.h.
    push    rax         ; +0
    push    rcx         ; +8
    push    rdx         ; +16
    push    rbx         ; +24
    push    rbp         ; +32
    push    rsi         ; +40
    push    rdi         ; +48
    push    r8          ; +56
    push    r9          ; +64
    push    r10         ; +72
    push    r11         ; +80
    push    r12         ; +88
    push    r13         ; +96
    push    r14         ; +104
    push    r15         ; +112    (RSP now = HOST_RSP_orig - 120)

    ; Arg1 (RCX) = pointer to the GUEST_REGISTERS structure on the stack.
    mov     rcx, rsp

    ; Allocate shadow space (32 bytes) + 8 bytes alignment pad = 40 bytes.
    ; After this sub, RSP mod 16 == 8; CALL makes it == 0.
    sub     rsp, 28h

    call    HvHandleVmExit      ; HvHandleVmExit(PGUEST_REGISTERS regs)

    add     rsp, 28h

    ; Restore guest GPRs (reverse of push order).
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rdi
    pop     rsi
    pop     rbp
    pop     rbx
    pop     rdx
    pop     rcx
    pop     rax

    ; Return to guest.
    vmresume

    ; VMRESUME should never fail in steady state.
    ; If it does, halt the processor to prevent undefined behaviour.
    cli
    hlt
HvVmExitStub ENDP


; ---------------------------------------------------------------------------
; VOID HvSgdt(PVOID desc)
; Stores the current GDTR into the 10-byte PSEUDO_DESCRIPTOR at [RCX].
; ---------------------------------------------------------------------------
HvSgdt PROC
    sgdt [rcx]
    ret
HvSgdt ENDP


; ---------------------------------------------------------------------------
; VOID HvSidt(PVOID desc)
; Stores the current IDTR into the 10-byte PSEUDO_DESCRIPTOR at [RCX].
; ---------------------------------------------------------------------------
HvSidt PROC
    sidt [rcx]
    ret
HvSidt ENDP


; ---------------------------------------------------------------------------
; Segment selector reads — return value in AX (zero-extended to RAX).
; ---------------------------------------------------------------------------
HvReadCs PROC
    mov ax, cs
    ret
HvReadCs ENDP

HvReadSs PROC
    mov ax, ss
    ret
HvReadSs ENDP

HvReadDs PROC
    mov ax, ds
    ret
HvReadDs ENDP

HvReadEs PROC
    mov ax, es
    ret
HvReadEs ENDP

HvReadFs PROC
    mov ax, fs
    ret
HvReadFs ENDP

HvReadGs PROC
    mov ax, gs
    ret
HvReadGs ENDP

HvReadTr PROC
    str ax
    ret
HvReadTr ENDP

HvReadLdtr PROC
    sldt ax
    ret
HvReadLdtr ENDP

END
