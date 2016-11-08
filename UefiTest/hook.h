#pragma once

//
// Implemented in hook.asm
//
EFI_STATUS PrintString( IN CHAR16* Str );
EFI_STATUS PrintTestString( VOID );

//
// ImgArchEfiStartBootApplication hook
//
typedef EFI_STATUS( EFIAPI *tImgArchEfiStartBootApplication )(VOID* Parameters, VOID* ImageBase, UINT32 ImageSize, UINT8 BootOption, UINT64* SomeReturnValue);
static UINT8 sigImgArchEfiStartBootApplicationCall[] = { 0xE8, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x8B, 0xCE, 0x8B, 0xD8, 0xE8, 0xCC, 0xCC, 0xCC, 0xCC, 0x41 };
VOID* ImgArchEfiStartBootApplicationPatchLocation = NULL;
UINT8 ImgArchEfiStartBootApplicationBackup[5] = { 0 };
tImgArchEfiStartBootApplication oImgArchEfiStartBootApplication = NULL;

//
// OslArchTransferToKernel hook
//
typedef VOID( EFIAPI *tOslArchTransferToKernel )(VOID *KernelParams, VOID *KiSystemStartup);
static UINT8 sigOslArchTransferToKernel[] = { 0xE8, 0xCC, 0xCC, 0xCC, 0xCC, 0xEB, 0xFE }; //48 8B 45 A8 33 FF
extern VOID* OslArchTransferToKernelPatchLocation;
extern UINT8 OslArchTransferToKernelBackup[5];
tOslArchTransferToKernel oOslArchTransferToKernel = NULL;
extern VOID* OslArchTransferToKernelHook;

//
// Winload calls
//
UINT8 sigEfiStallCall[] = { 0xE8, 0xCC, 0xCC, 0xCC, 0xCC, 0x0F, 0x31, 0x48, 0xC1, 0xE2, 0x20, 0x48, 0x8B };
typedef INT64( EFIAPI *tEfiStall )(UINT64 MicroSeconds);
tEfiStall EfiStall = NULL;

UINT8 sigEfiConOutOutputString[] = { 0xE8, 0xCC, 0xCC, 0xCC, 0xCC, 0x85, 0xC0, 0x78, 0x05, 0x83, 0xC3, 0xFF };
typedef INT64( EFIAPI *tEfiConOutOutputString )(VOID* ConOut, CHAR16* String);
tEfiConOutOutputString EfiConOutOutputString = NULL;


// 
// Kernel patches
//

// Skip setting the NoExecute bit
// KiInitializeNxSupportDiscard
// 74 ? B9 80 00 00 C0 0F 32
// INIT:0000000140756968                          loc_140756968:					; CODE XREF: KiInitializeNxSupportDiscard+8Dj
// INIT:0000000140756968															; KiInitializeNxSupportDiscard+97j
// INIT:0000000140756968 E8 63 DB C4 FF                call    KiIsNXSupported
// INIT:000000014075696D 84 C0                         test    al, al
// INIT:000000014075696F 74 27                         jz      short loc_140756998 <------------ PATCH HERE TO FORCE JUMP
// INIT:0000000140756971 B9 80 00 00 C0                mov     ecx, 0C0000080h
// INIT:0000000140756976 0F 32                         rdmsr
// INIT:0000000140756978 48 C1 E2 20                   shl     rdx, 20h
// INIT:000000014075697C 48 0B C2                      or      rax, rdx
// INIT:000000014075697F 48 0F BA E8 0B                bts     rax, 0Bh
// INIT:0000000140756984 48 8B D0                      mov     rdx, rax
// INIT:0000000140756987 48 C1 EA 20                   shr     rdx, 20h
// INIT:000000014075698B 0F 30                         wrmsr
// INIT:000000014075698D B0 01                         mov     al, 1
// INIT:000000014075698F A2 80 02 00 00 80 F7 FF FF    mov     ds:0FFFFF78000000280h, al
UINT8 sigNxSetBit[] = { 0x74, 0x27, 0xB9, 0x80, 0x00, 0x00, 0xC0, 0x0F, 0x32 };
UINTN sigNxSetBitSize = sizeof( sigNxSetBit );

// Skip initializing patchguard
// KeInitAmd64SpecificState
// 75 2D 0F B6 15
// INIT:000000014074BA6C                     KeInitAmd64SpecificState proc near      ; CODE XREF: PipInitializeCoreDriversAndElam+24p
// INIT:000000014074BA6C
// INIT:000000014074BA6C                          arg_0           = dword ptr  8
// INIT:000000014074BA6C
// INIT:000000014074BA6C 48 83 EC 28              sub     rsp, 28h
// INIT:000000014074BA70 83 3D 8D E1 BA FF 00     cmp     cs:InitSafeBootMode, 0
// INIT:000000014074BA77 75 2D                    jnz     short loc_14074BAA6 <---------------------- PATCH HERE TO FORCE JUMP
// INIT:000000014074BA79 0F B6 15 42 90 BA FF     movzx   edx, byte ptr cs:KdDebuggerNotPresent
// INIT:000000014074BA80 0F B6 05 61 83 B7 FF     movzx   eax, cs:KdPitchDebugger
// INIT:000000014074BA87 0B D0                    or      edx, eax
// INIT:000000014074BA89 8B CA                    mov     ecx, edx
// INIT:000000014074BA8B F7 D9                    neg     ecx
// INIT:000000014074BA8D 45 1B C0                 sbb     r8d, r8d
// INIT:000000014074BA90 41 83 E0 EE              and     r8d, 0FFFFFFEEh
// INIT:000000014074BA94 41 83 C0 11              add     r8d, 11h
// INIT:000000014074BA98 D1 CA                    ror     edx, 1
// INIT:000000014074BA9A 8B C2                    mov     eax, edx
// INIT:000000014074BA9C 99                       cdq
// INIT:000000014074BA9D 41 F7 F8                 idiv    r8d
// INIT:000000014074BAA0 89 44 24 30              mov     [rsp+28h+arg_0], eax
// INIT:000000014074BAA4 EB 00                    jmp     short $+2
// INIT:000000014074BAA6                     ; ---------------------------------------------------------------------------
// INIT:000000014074BAA6                     loc_14074BAA6:                          ; CODE XREF: KeInitAmd64SpecificState+Bj
// INIT:000000014074BAA6                                                             ; KeInitAmd64SpecificState+38j
// INIT:000000014074BAA6 48 83 C4 28              add     rsp, 28h
// INIT:000000014074BAAA C3                       retn
// INIT:000000014074BAAA                     KeInitAmd64SpecificState endp
UINT8 sigInitPatchGuard[] = { 0x75, 0x2D, 0x0F, 0xB6, 0x15 };
UINTN sigInitPatchGuardSize = sizeof( sigInitPatchGuard );

