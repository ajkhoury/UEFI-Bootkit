#pragma once

#include <Protocol/DevicePath.h>

EFI_STATUS ImageLoad( IN EFI_HANDLE ParentHandle, IN EFI_DEVICE_PATH* DevicePath, OUT EFI_HANDLE* ImageHandle );

EFI_STATUS ImageStart( IN EFI_HANDLE ImageHandle );