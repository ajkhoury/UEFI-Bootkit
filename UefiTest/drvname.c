#include "drv.h"

//
// EFI Component Name Protocol
//
EFI_COMPONENT_NAME_PROTOCOL gComponentNameProtocol =
{
    TestComponentNameGetDriverName,
    TestComponentNameGetControllerName,
    "eng"
};

//
// EFI Component Name 2 Protocol
//
EFI_COMPONENT_NAME2_PROTOCOL gComponentName2Protocol =
{
    (EFI_COMPONENT_NAME2_GET_DRIVER_NAME)TestComponentNameGetDriverName,
    (EFI_COMPONENT_NAME2_GET_CONTROLLER_NAME)TestComponentNameGetControllerName,
    "en"
};

//
// Internationalized names for the driver
//
EFI_UNICODE_STRING_TABLE gDriverNameTable[] =
{
    {
        "eng;en",
        L"Test Driver"
    },
    {NULL, NULL}
};

//
// Internationalized names for the device
//
EFI_UNICODE_STRING_TABLE gDeviceNameTable[] =
{
    {
        "eng;en",
        L"Test Device"
    },
    {NULL, NULL}
};

EFI_STATUS
EFIAPI
TestComponentNameGetDriverName (
    IN EFI_COMPONENT_NAME_PROTOCOL *This,
    IN CHAR8 *Language,
    OUT CHAR16 **DriverName
    )
{
    //
    // Find a matching string in the driver name string table
    //
    return LookupUnicodeString2(Language,
                                This->SupportedLanguages,
                                gDriverNameTable,
                                DriverName,
                                This == &gComponentNameProtocol);
}

EFI_STATUS
EFIAPI
TestComponentNameGetControllerName (
    IN EFI_COMPONENT_NAME_PROTOCOL *This,
    IN EFI_HANDLE ControllerHandle,
    IN EFI_HANDLE ChildHandle OPTIONAL,
    IN CHAR8 *Language,
    OUT CHAR16 **ControllerName
    )
{
    EFI_STATUS efiStatus;

    //
    // We don't currently support names for our child devices
    //
    if (ChildHandle != NULL)
    {
       efiStatus =  EFI_UNSUPPORTED;
       goto Exit;
    }

    //
    // Make sure that this is a device we support
    //
    efiStatus = EfiTestManagedDevice(ControllerHandle,
                                     gDriverBindingProtocol.DriverBindingHandle,
                                     &gEfiPciIoProtocolGuid);
    if (EFI_ERROR(efiStatus))
    {
        goto Exit;
    }

    //
    // Find a matching string in the device name string table
    //
    efiStatus = LookupUnicodeString2(Language,
                                     This->SupportedLanguages,
                                     gDeviceNameTable,
                                     ControllerName,
                                     This == &gComponentNameProtocol);

Exit:
    //
    // Return back to DXE
    //
    return efiStatus;
}
