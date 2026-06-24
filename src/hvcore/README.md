# hvcore

## What

hvcore is a thin hypervisor that virtualizes the running system in-place using AMD SVM. It snapshots the current register state when loaded (as uefi_hv.efi), starts a VM from that snapshot, and the system keeps running as a guest without knowing anything changed. One VM, one set of hardware, no isolation boundary.

## How

On entry, a VM gets created from the current processor state with full access to hardware and physical memory via identity-mapped nested page tables. Only specific operations are intercepted: CPUID, MSR access, HLT/MWAIT, INIT/SIPI, and certain I/O ports. Everything else passes through directly.

APIC MMIO pages get split from 2MB to 4KB granularity so the hypervisor can trap inter-processor interrupt writes during AP startup emulation. All other memory stays at 2MB page granularity. Because there is only one VM and no isolation boundary to enforce, code stays small and performance overhead stays low compared to full hypervisors that manage multiple isolated guests.
