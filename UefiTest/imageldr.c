#include "imageldr.h"

#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/LoadedImage.h>

EFI_STATUS ImageLoad( IN EFI_HANDLE ParentHandle, IN EFI_DEVICE_PATH* DevicePath, OUT EFI_HANDLE* ImageHandle )
{
	EFI_STATUS status = EFI_NOT_FOUND;
	// Load image in memory 
	status = gBS->LoadImage( TRUE, ParentHandle, DevicePath, NULL, 0, ImageHandle );
	if (status != EFI_SUCCESS)
	{
		Print( L"[!] LoadImage error = %X\r\n", status );
	}

	return status;
}

EFI_STATUS ImageStart( IN EFI_HANDLE ImageHandle )
{
	return gBS->StartImage( ImageHandle, (UINTN *)NULL, (CHAR16 **)NULL );
}
