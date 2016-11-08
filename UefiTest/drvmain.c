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
CHAR8 *gEfiCallerBaseName = "UefiTestDriver";

// Title
static CHAR16 *gTitle = L"-= UefiTest =-\r\n";


// 
// Main entry point
// 
EFI_STATUS EFIAPI UefiMain( IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE *SystemTable )
{
	EFI_STATUS efiStatus;
	//EFI_LOADED_IMAGE* Image = NULL;

	//
	// Install required driver binding components
	//
	efiStatus = EfiLibInstallDriverBindingComponentName2( ImageHandle, SystemTable, &gDriverBindingProtocol, ImageHandle, &gComponentNameProtocol, &gComponentName2Protocol );
	if (EFI_ERROR( efiStatus ))
		goto Exit;

	// Clear screen
	gST->ConOut->ClearScreen( gST->ConOut );
	Print( L"TEST!!!\r\n" );
	UtilWaitForKey( );

	Print( gTitle );
	Print( L"\r\nRuntime Driver handle is %lx and System Table is at %p\r\n", ImageHandle, SystemTable );

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