#!/usr/bin/env python3
# Framework for mounting and patching macOS root volume
# Copyright (C) 2020-2021, Dhinak G, Mykola Grymalyuk
# Based on OpenCore Legacy Patcher's SysPatch.py
# https://github.com/dortania/OpenCore-Legacy-Patcher/blob/85559d4d9e3dbd6a485f7dc2f5630187ac9d5f5a/Resources/SysPatch.py

import os
import plistlib
import subprocess
from pathlib import Path


class PatchSysVolume:
    def __init__(self):
        self.mount_location = "/System/Volumes/Update/mnt1"
        self.mount_extensions = f"{self.mount_location}/System/Library/Extensions"
        self.root_patch_sip_big_sur = [
            # Variables required to root patch in Big Sur and Monterey
            "CSR_ALLOW_UNTRUSTED_KEXTS",
            "CSR_ALLOW_UNRESTRICTED_FS",
            "CSR_ALLOW_UNAPPROVED_KEXTS",
            "CSR_ALLOW_EXECUTABLE_POLICY_OVERRIDE",
            "CSR_ALLOW_UNAUTHENTICATED_ROOT",
        ]
        self.csr_values = {
            "CSR_ALLOW_UNTRUSTED_KEXTS": False,  # 0x1   - Allows Unsigned Kexts           - Introduced in El Capitan  # noqa: E241
            "CSR_ALLOW_UNRESTRICTED_FS": False,  # 0x2   - File System Access              - Introduced in El Capitan  # noqa: E241
            "CSR_ALLOW_TASK_FOR_PID": False,  # 0x4   - Unrestricted Debugging          - Introduced in El Capitan  # noqa: E241
            "CSR_ALLOW_KERNEL_DEBUGGER": False,  # 0x8   - Allow Kernel Debugger           - Introduced in El Capitan  # noqa: E241
            "CSR_ALLOW_APPLE_INTERNAL": False,  # 0x10  - Set AppleInternal Features      - Introduced in El Capitan  # noqa: E241
            "CSR_ALLOW_UNRESTRICTED_DTRACE": False,  # 0x20  - Unrestricted DTrace usage       - Introduced in El Capitan  # noqa: E241
            "CSR_ALLOW_UNRESTRICTED_NVRAM": False,  # 0x40  - Unrestricted NVRAM write        - Introduced in El Capitan  # noqa: E241
            "CSR_ALLOW_DEVICE_CONFIGURATION": False,  # 0x80  - Allow Device Configuration(?)   - Introduced in El Capitan  # noqa: E241
            "CSR_ALLOW_ANY_RECOVERY_OS": False,  # 0x100 - Disable BaseSystem Verification - Introduced in Sierra      # noqa: E241
            "CSR_ALLOW_UNAPPROVED_KEXTS": False,  # 0x200 - Allow Unapproved Kexts          - Introduced in High Sierra # noqa: E241
            "CSR_ALLOW_EXECUTABLE_POLICY_OVERRIDE": False,  # 0x400 - Override Executable Policy      - Introduced in Mojave      # noqa: E241
            "CSR_ALLOW_UNAUTHENTICATED_ROOT": False,  # 0x800 - Allow Root Volume Mounting      - Introduced in Big Sur     # noqa: E241
        }
        self.sbm_values = [
            "j137",
            "j680",
            "j132",
            "j174",
            "j140k",
            "j780",
            "j213",
            "j140a",
            "j152f",
            "j160",
            "j230k",
            "j214k",
            "j223",
            "j215",
            "j185",
            "j185f",
        ]

        self.start_patch()

    def elevated(self, *args, **kwargs) -> subprocess.CompletedProcess:
        if os.getuid() == 0:
            return subprocess.run(*args, **kwargs)
        else:
            return subprocess.run(["sudo"] + [args[0][0]] + args[0][1:], **kwargs)

    def get_disk_path(self):
        root_partition_info = plistlib.loads(subprocess.run("diskutil info -plist /".split(), stdout=subprocess.PIPE).stdout.decode().strip().encode())
        root_mount_path = root_partition_info["DeviceIdentifier"]
        root_mount_path = root_mount_path[:-2] if root_mount_path.count("s") > 1 else root_mount_path
        return root_mount_path

    def csr_decode(self, csr_active_config):
        if csr_active_config is None:
            csr_active_config = b"\x00\x00\x00\x00"
        sip_int = int.from_bytes(csr_active_config, byteorder="little")
        i = 0
        for current_sip_bit in self.csr_values:
            if sip_int & (1 << i):
                self.csr_values[current_sip_bit] = True
            i = i + 1

        # Can be adjusted to whatever OS needs patching
        sip_needs_change = all(self.csr_values[i] for i in self.root_patch_sip_big_sur)
        if sip_needs_change is True:
            return False
        else:
            return True

    def patching_status(self):
        # Detection for Root Patching
        sip_enabled = True  # System Integrity Protection
        sbm_enabled = True  # Secure Boot Status (SecureBootModel)
        fv_enabled = True  # FileVault

        if self.get_nvram("HardwareModel", "94B73556-2197-4702-82A8-3E1337DAFBFB", decode=False) not in self.sbm_values:
            sbm_enabled = False

        if self.get_nvram("csr-active-config", decode=False) and self.csr_decode(self.get_nvram("csr-active-config", decode=False)) is False:
            sip_enabled = False

        fv_status: str = subprocess.run("fdesetup status".split(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout.decode()
        if fv_status.startswith("FileVault is Off"):
            fv_enabled = False

        return sip_enabled, sbm_enabled, fv_enabled


    def cls():
        os.system("cls" if os.name == "nt" else "clear")


    def get_nvram(self, variable: str, uuid: str = None, *, decode: bool = False):
        if uuid is not None:
            uuid += ":"
        else:
            uuid = ""
        result = subprocess.run(f"nvram -x {uuid}{variable}".split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.strip()
        try:
            value = plistlib.loads(result)[f"{uuid}{variable}"]
        except plistlib.InvalidFileException:
            return None
        if decode:
            value = value.strip(b"\0").decode()
        return value

    def find_mount_root_vol(self, patch):
        self.root_mount_path = self.get_disk_path()
        if self.root_mount_path.startswith("disk"):
            print(f"- Found Root Volume at: {self.root_mount_path}")
            if Path(self.mount_extensions).exists():
                print("- Root Volume is already mounted")
                if patch is True:
                    self.patch_root_vol()
                    return True
                else:
                    self.unpatch_root_vol()
                    return True
            else:
                print("- Mounting APFS Snapshot as writable")
                self.elevated(["mount", "-o", "nobrowse", "-t", "apfs", f"/dev/{self.root_mount_path}", self.mount_location], stdout=subprocess.PIPE).stdout.decode().strip().encode()
                if Path(self.mount_extensions).exists():
                    print("- Successfully mounted the Root Volume")
                    if patch is True:
                        self.patch_root_vol()
                        return True
                    else:
                        self.unpatch_root_vol()
                        return True
                else:
                    print("- Failed to mount the Root Volume")
                    print("- Recommend rebooting the machine and trying to patch again")
                    input("- Press [ENTER] to exit: ")
        else:
            print("- Could not find root volume")
            input("- Press [ENTER] to exit: ")

    def unpatch_root_vol(self):
        print("- Reverting to last signed APFS snapshot")
        self.elevated(["bless", "--mount", self.mount_location, "--bootefi", "--last-sealed-snapshot"], stdout=subprocess.PIPE).stdout.decode().strip().encode()

    def rebuild_snapshot(self):
        input("Press [ENTER] to continue with cache rebuild: ")
        print("- Rebuilding Kernel Cache (This may take some time)")
        result = self.elevated(["kmutil", "install", "--volume-root", self.mount_location, "--update-all"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        if result.returncode != 0:
            self.success_status = False
            print("- Unable to build new kernel cache")
            print("\nReason for Patch Failure:")
            print(result.stdout.decode())
            print("")
            print("\nPlease reboot the machine to avoid potential issues rerunning the patcher")
            input("Press [ENTER] to continue")
        else:
            self.success_status = True
            print("- Successfully built new kernel cache")
            input("Press [ENTER] to continue with snapshotting")
            print("- Creating new APFS snapshot")
            self.elevated(["bless", "--folder", f"{self.mount_location}/System/Library/CoreServices", "--bootefi", "--create-snapshot"], stdout=subprocess.PIPE).stdout.decode().strip().encode()
            self.unmount_drive()
            print("- Patching complete")
            print("\nPlease reboot the machine for patches to take effect")
            input("Press [ENTER] to continue")

    def unmount_drive(self):
        print("- Unmounting Root Volume (Don't worry if this fails)")
        self.elevated(["diskutil", "unmount", self.root_mount_path], stdout=subprocess.PIPE).stdout.decode().strip().encode()


    def patch_root_vol(self):
        input("Once done editing root volume, press enter to rebuild snapshot")
        self.rebuild_snapshot()

    def verify_patch_allowed(self):
        self.sip_enabled, self.sbm_enabled, self.fv_enabled = self.patching_status()
        if self.sip_enabled is True:
            print("\nCannot patch! Please disable System Integrity Protection (SIP).")
            print("Disable SIP in Patcher Settings and Rebuild OpenCore\n")
            print("Ensure the following bits are set for csr-active-config:")
            print("\n".join(self.root_patch_sip_big_sur))
            print("For Hackintoshes, please set csr-active-config to '030A0000' (0xA03)")
            print("For non-OpenCore Macs, please run 'csrutil disable' and \n'csrutil authenticated-root disable' in RecoveryOS")

        if self.sbm_enabled is True:
            print("\nCannot patch! Please disable Apple Secure Boot.")
            print("Disable SecureBootModel in Patcher Settings and Rebuild OpenCore")
            print("For Hackintoshes, set SecureBootModel to Disabled")

        if self.fv_enabled is True:
            print("\nCannot patch! Please disable FileVault.")
            print("Go to System Preferences -> Security and disable FileVault")

        if self.sip_enabled is True or self.sbm_enabled is True or self.fv_enabled is True:
            return False
        else:
            return True

    # Entry Function
    def start_patch(self):
        print("- Starting Patch Process")
        if self.verify_patch_allowed() is True:
            print("- Found Root Volume can be mounted, continuing")
            self.find_mount_root_vol(True)

    def start_unpatch(self):
        print("- Starting Unpatch Process")
        if self.verify_patch_allowed() is True:
            print("- Found Root Volume can be mounted, continuing")
            self.find_mount_root_vol(False)
            input("\nPress [ENTER] to return to the main menu")

PatchSysVolume()
