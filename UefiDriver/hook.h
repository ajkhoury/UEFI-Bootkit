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

typedef VOID( EFIAPI *tOslArchTransferToKernel )(VOID *KernelParams, VOID *KiSystemStartup);
static UINT8 sigOslArchTransferToKernel[] = { 0xE8, 0xCC, 0xCC, 0xCC, 0xCC, 0xEB, 0xFE }; //48 8B 45 A8 33 FF
extern VOID* OslArchTransferToKernelPatchLocation;
extern UINT8 OslArchTransferToKernelBackup[5];
tOslArchTransferToKernel oOslArchTransferToKernel = NULL;
extern VOID* OslArchTransferToKernelHook;