# UEFI-Bootkit

A small bootkit designed to use zero assembly. Make sure to compile the driver as an EFI Runtime driver (EFI_RUNTIME_DRIVER) or else the bootkit will be freed once winload.efi calls ExitBootServices!

Thanks to [dreamboot](https://github.com/quarkslab/dreamboot), and [VisualUEFI](https://github.com/ionescu007/VisualUefi)


## License
Copyright (C) 2016-2019 Aidan Khoury (ajkhoury), Quarkslab

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
