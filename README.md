# Type-1 hypervisor on consumer AMD (Rust)

Bare-metal hypervisor in Rust for AMD SVM. Loads from a UEFI boot entry before Windows, virtualizes all active logical processors, and uses identity-mapped nested page tables with APIC MMIO trapping for AP startup. Built on tandasat/barevisor; most of the interesting code in this repo is mine. The SmmLock discovery alone ate two weeks of debugging against an undocumented AMD interaction that only manifests on consumer Ryzen boards.

## What I added

- **SmmLock workaround.** Consumer Ryzen boards set SmmLock (HWCR bit 0), which silently neuters the VMCB's SMI intercept. AMD's manual does not document this interaction. I spent two weeks isolating the crash before finding it. The fix is to defer hypervisor activation until after UEFI's SMM-heavy DXE phase finishes.
- **ExitBootServices survival.** Normal EFI apps get their memory reclaimed when the OS calls ExitBootServices. I use a two-binary deployment: an EFI APPLICATION shim loads an EFI RUNTIME_DRIVER, whose pages survive reclamation. PE relocation table gets zeroed so SetVirtualAddressMap cannot corrupt host addresses.
- **Multi-core SVM.** Seven bug fixes for Windows SMP boot: HLT/MWAIT intercepts, I/O port passthrough, NMI re-injection, PAUSE filter, INIT/SIPI emulation, TR busy-bit fix for Zen+ steppings.
- **NPT page splitting.** 2MB NPT entries split into 4KB pages for APIC MMIO write interception during AP startup.
- **CPUID intercept handling.** Per-leaf CPUID interception: advertises hypervisor presence via CPUID leaf 0x40000000 and sets ECX[31] on leaf 1.

## Architecture

Three-crate workspace:

| Crate | What it does |
|-|-|
| `src/hvcore` | `no_std` core. SVM setup, VMCB state, nested page tables, VMEXIT handling. |
| `src/uefi` | Boot shim and runtime driver that load before Windows and stay resident across ExitBootServices. |
| `src/windows` | Windows kernel driver that loads and activates the hypervisor via DriverEntry. |

hvcore links into both the UEFI and Windows targets.

## Building

UEFI build and deployment flow: `src/uefi/README.md`. Windows driver build: `src/windows/README.md`. You need eWDK for the Windows side, which means building on Windows.

## Acknowledgement

This project is based on tandasat/barevisor (MIT). memN0ps' Rust hypervisor projects were also a major reference.
