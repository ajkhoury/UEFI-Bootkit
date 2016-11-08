# UEFI-Bootkit

A small bootkit designed to use as little ASM as possible. Make sure to compile the driver as an EFI Runtime driver (EFI_RUNTIME_DRIVER) or else the bootkit will be freed once winload.efi calls ExitBootService!

Thanks to [pyro666](https://github.com/Pyro666)
