//
// Basic UEFI Libraries
//
#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>

//
// Boot and Runtime Services
//
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/DevicePathLib.h>

//
// Protocols
//
#include <Protocol/SimpleFileSystem.h>

//
// Custom Driver Protocol
//
#include "../UefiDriver/drvproto.h"
EFI_GUID gEfiSampleDriverProtocolGuid = EFI_RUNTIME_DRIVER_PROTOCOL_GUID;

//
// My includes
//
#include "imageldr.h"

//
// Globals
//

// We run on any UEFI Specification
extern CONST UINT32 _gUefiDriverRevision = 0;
// Our name
CHAR8 *gEfiCallerBaseName = "UefiApplication";
// Windows Boot Manager x64 image path
static CHAR16 *gRuntimeDriverImagePath = L"\\EFI\\Boot\\rtdriver.efi";

// 
// Try to find a file by browsing each device
// 
EFI_STATUS LocateFile( IN CHAR16* ImagePath, OUT EFI_DEVICE_PATH** DevicePath )
{
	EFI_FILE_IO_INTERFACE *ioDevice;
	EFI_FILE_HANDLE handleRoots, bootFile;
	EFI_HANDLE* handleArray;
	UINTN nbHandles, i;
	EFI_STATUS efistatus;

	*DevicePath = (EFI_DEVICE_PATH *)NULL;
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

		efistatus = handleRoots->Open( handleRoots, &bootFile, ImagePath, EFI_FILE_MODE_READ, EFI_FILE_READ_ONLY );
		if (!EFI_ERROR( efistatus ))
		{
			handleRoots->Close( bootFile );
			*DevicePath = FileDevicePath( handleArray[i], ImagePath );
			Print( L"\r\nFound file at \'%s\'\r\n", ConvertDevicePathToText( *DevicePath, TRUE, TRUE ) );
			break;
		}
	}

	return efistatus;
}

EFI_STATUS EFIAPI UefiMain( IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE* SystemTable )
{
	EFI_STATUS efiStatus;
	EFI_DEVICE_PATH* RuntimeDriverDevicePath = NULL;
	EFI_HANDLE RuntimeDriverHandle = NULL;

	//
	// Clear screen and make pretty
	//
	gST->ConOut->ClearScreen( gST->ConOut );
	gST->ConOut->SetAttribute( gST->ConOut, EFI_GREEN | EFI_BACKGROUND_LIGHTGRAY );

	//
	// Locate the runtime driver
	//
	efiStatus = LocateFile( gRuntimeDriverImagePath, &RuntimeDriverDevicePath );
	if (EFI_ERROR( efiStatus ))
		goto Exit;

	//
	// Load Runtime Driver into memory
	//
	efiStatus = ImageLoad( ImageHandle, RuntimeDriverDevicePath, &RuntimeDriverHandle );
	if (EFI_ERROR( efiStatus ))
		goto Exit;

	//
	// Transfer executon to the Runtime Driver
	//
	efiStatus = ImageStart( RuntimeDriverHandle );
	if (EFI_ERROR( efiStatus ))
		goto Exit;

Exit:
	if (efiStatus != EFI_SUCCESS)
	{
		ErrorPrint( L"%EUEFI Runtime Driver Loader failed with status: %H%lx%N\r\n", efiStatus );
	}

	return efiStatus;
}



EFI_STATUS EFIAPI UefiUnload( IN EFI_HANDLE ImageHandle )
{
	//
	// This code should be compiled out and never called
	//
	ASSERT( FALSE );
}
