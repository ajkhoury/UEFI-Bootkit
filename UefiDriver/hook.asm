; ++
;
; Copyright (c) dude719.  All rights reserved.
;
; Module:
;
;	hooks.asm
;
; Summary:
;
;    This module implements a hook for OslArchTransferToKernel in winload.efi
;
; Environment:
;
;    UEFI firmware
;
; --

;*********************************************************************
; Public symbols
; Saved OslArchTransferToKernel location and bytes from before the patch
public OslArchTransferToKernelBackup
public OslArchTransferToKernelPatchLocation

;*********************************************************************
; .data section
.DATA

ALIGN 16

; Original OslArchTransferToKernel address
extern oOslArchTransferToKernel:dq
; Saved OslArchTransferToKernel bytes from before the patch
OslArchTransferToKernelBackup db 5 dup(0)
OslArchTransferToKernelPatchLocation dq 0

; UEFI System Table for printing to console
extern gST:dq

extern UtilWaitForKey:proc
extern Print:proc

; Test string for PrintString
TestString dw "A","S","M"," ","T","E","S","T", 000Dh, 000Ah, 0000h



;*********************************************************************
; .text section
.CODE

;*********************************************************************
; EFI_STATUS 
; PrintString( 
;	IN CHAR16* Str 
; );				
;*********************************************************************
PrintString PROC
	sub rsp, 30h
	mov rdx, rcx ; Str
	mov rax, gST
	mov r8, [rax + 40h]
	mov rcx, r8
	call qword ptr [r8 + 8h]
	add rsp, 30h
	ret
PrintString ENDP

PrintStringTest PROC
	lea rcx, TestString
	call PrintString
	ret
PrintStringTest ENDP


;	; Search image base
;	and rdx, 0FFFFFFFFFFFFF000h
;get_imagebase:
;	cmp word ptr [rdx], 05A4Dh
;	je get_imagesize
;	sub rdx, 01000h
;	jmp get_imagebase
;
;	; Search for NX flag pattern in image
;get_imagesize:
;	mov ecx, dword ptr[rdx+03Ch]			; get e_lfanew from DOS headers
;	mov ebx, dword ptr[rdx+rcx+050h]		; get sizeOfImage from OptionialHeader in PE

;
; Our OslArchTransferToKernelHook hook
;
; VOID __fastcall OslArchTransferToKernel(VOID *KernelParams, VOID *KiSystemStartup)
;
OslArchTransferToKernelHook PROC
	; Save registers to do our kernel patching
	push r15
	push r14
	push r13
	push r12
	push r11
	push r10
	push r9
	push r8
	push rbp
	push rdi
	push rsi
	push rdx ; rdx is a pointer to KiSystemStartup
	push rcx ; rcx is a pointer to kernel loading paramters
	push rbx
	push rax
	pushfq
	mov rbp, rsp
	and rsp, 0FFFFFFFFFFFFFFF0h ; align stack to 16 bytes

	; Before we do anything lets restore the original function bytes
restore_bytes:
	lea rsi, OslArchTransferToKernelBackup
	mov rdi, OslArchTransferToKernelPatchLocation
	mov rcx, 5 ; our patch size was 5 bytes
	rep movsb byte ptr [rdi], byte ptr [rsi] ; restore bytes

	mov rsp, rbp
	popfq
	pop rax
	pop rbx
	pop rcx
	pop rdx
	pop rsi
	pop rdi
	pop rbp
	pop r8
	pop r9
	pop r10
	pop r11
	pop r12
	pop r13
	pop r14
	pop r15

	; jump to original
	jmp qword ptr [oOslArchTransferToKernel]

OslArchTransferToKernelHook ENDP

END