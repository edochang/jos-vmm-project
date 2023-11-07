
#include <vmm/vmx.h>
#include <inc/error.h>
#include <vmm/vmexits.h>
#include <vmm/ept.h>
#include <inc/x86.h>
#include <inc/assert.h>
#include <kern/pmap.h>
#include <kern/console.h>
#include <kern/kclock.h>
#include <kern/multiboot.h>
#include <inc/string.h>
#include <inc/stdio.h>
#include <kern/syscall.h>
#include <kern/env.h>
#include <kern/cpu.h>

static int vmdisk_number = 0;	//this number assign to the vm
int 
vmx_get_vmdisk_number() {
	return vmdisk_number;
}

void
vmx_incr_vmdisk_number() {
	vmdisk_number++;
}
bool
find_msr_in_region(uint32_t msr_idx, uintptr_t *area, int area_sz, struct vmx_msr_entry **msr_entry) {
	struct vmx_msr_entry *entry = (struct vmx_msr_entry *)area;
	int i;
	for(i=0; i<area_sz; ++i) {
		if(entry->msr_index == msr_idx) {
			*msr_entry = entry;
			return true;
		}
	}
	return false;
}

bool
handle_interrupt_window(struct Trapframe *tf, struct VmxGuestInfo *ginfo, uint32_t host_vector) {
	uint64_t rflags;
	uint32_t procbased_ctls_or;

	procbased_ctls_or = vmcs_read32( VMCS_32BIT_CONTROL_PROCESSOR_BASED_VMEXEC_CONTROLS );

        //disable the interrupt window exiting
        procbased_ctls_or &= ~(VMCS_PROC_BASED_VMEXEC_CTL_INTRWINEXIT); 

        vmcs_write32( VMCS_32BIT_CONTROL_PROCESSOR_BASED_VMEXEC_CONTROLS, 
		      procbased_ctls_or);
        //write back the host_vector, which can insert a virtual interrupt
	vmcs_write32( VMCS_32BIT_CONTROL_VMENTRY_INTERRUPTION_INFO , host_vector);
	return true;
}
bool
handle_interrupts(struct Trapframe *tf, struct VmxGuestInfo *ginfo, uint32_t host_vector) {
	uint64_t rflags;
	uint32_t procbased_ctls_or;
	rflags = vmcs_read64(VMCS_GUEST_RFLAGS);

	if ( !(rflags & (0x1 << 9)) ) {	//we have to wait the interrupt window open
		//get the interrupt info

		procbased_ctls_or = vmcs_read32( VMCS_32BIT_CONTROL_PROCESSOR_BASED_VMEXEC_CONTROLS);

		//disable the interrupt window exiting
		procbased_ctls_or |= VMCS_PROC_BASED_VMEXEC_CTL_INTRWINEXIT; 

		vmcs_write32( VMCS_32BIT_CONTROL_PROCESSOR_BASED_VMEXEC_CONTROLS, 
			      procbased_ctls_or);
	}
	else {	//revector the host vector to the guest vector

		vmcs_write32( VMCS_32BIT_CONTROL_VMENTRY_INTERRUPTION_INFO , host_vector);
	}
	return true;
}

bool
handle_rdmsr(struct Trapframe *tf, struct VmxGuestInfo *ginfo) {
	uint64_t msr = tf->tf_regs.reg_rcx;
	if(msr == EFER_MSR) {
		// TODO: setup msr_bitmap to ignore EFER_MSR
		uint64_t val;
		struct vmx_msr_entry *entry;
		bool r = find_msr_in_region(msr, ginfo->msr_guest_area, ginfo->msr_count, &entry);
		assert(r);
		val = entry->msr_value;

		tf->tf_regs.reg_rdx = val << 32;
		tf->tf_regs.reg_rax = val & 0xFFFFFFFF;

		tf->tf_rip += vmcs_read32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH);
		return true;
	}

	return false;
}

bool 
handle_wrmsr(struct Trapframe *tf, struct VmxGuestInfo *ginfo) {
	uint64_t msr = tf->tf_regs.reg_rcx;
	if(msr == EFER_MSR) {

		uint64_t cur_val, new_val;
		struct vmx_msr_entry *entry;
		bool r = 
			find_msr_in_region(msr, ginfo->msr_guest_area, ginfo->msr_count, &entry);
		assert(r);
		cur_val = entry->msr_value;

		new_val = (tf->tf_regs.reg_rdx << 32)|tf->tf_regs.reg_rax;
		if(BIT(cur_val, EFER_LME) == 0 && BIT(new_val, EFER_LME) == 1) {
			// Long mode enable.
			uint32_t entry_ctls = vmcs_read32( VMCS_32BIT_CONTROL_VMENTRY_CONTROLS );
			//entry_ctls |= VMCS_VMENTRY_x64_GUEST;
			vmcs_write32( VMCS_32BIT_CONTROL_VMENTRY_CONTROLS, 
				      entry_ctls );

		}

		entry->msr_value = new_val;
		tf->tf_rip += vmcs_read32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH);
		return true;
	}

	return false;
}

bool
handle_eptviolation(uint64_t *eptrt, struct VmxGuestInfo *ginfo) {
	uint64_t gpa = vmcs_read64(VMCS_64BIT_GUEST_PHYSICAL_ADDR);
	int r;
	if(gpa < 0xA0000 || (gpa >= 0x100000 && gpa < ginfo->phys_sz)) 
	{
		// Allocate a new page to the guest.
		struct PageInfo *p = page_alloc(0);
		if(!p) {
			cprintf("vmm: handle_eptviolation: Failed to allocate a page for guest---out of memory.\n");
			return false;
		}
		p->pp_ref += 1;
		r = ept_map_hva2gpa(eptrt, 
				    page2kva(p), (void *)ROUNDDOWN(gpa, PGSIZE), __EPTE_FULL, 0);
		assert(r >= 0);
		/* cprintf("EPT violation for gpa:%x mapped KVA:%x\n", gpa, page2kva(p)); */
		return true;
	} else if (gpa >= CGA_BUF && gpa < CGA_BUF + PGSIZE) {
		// FIXME: This give direct access to VGA MMIO region.
		r = ept_map_hva2gpa(eptrt, 
				    (void *)(KERNBASE + CGA_BUF), (void *)CGA_BUF, __EPTE_FULL, 0);
		assert(r >= 0);
		return true;
	}
	cprintf("vmm: handle_eptviolation: Case 2, gpa %x\n", gpa);
	return false;
}

bool
handle_ioinstr(struct Trapframe *tf, struct VmxGuestInfo *ginfo) {
	static int port_iortc;

	uint64_t qualification = vmcs_read64(VMCS_VMEXIT_QUALIFICATION);
	int port_number = (qualification >> 16) & 0xFFFF;
	bool is_in = BIT(qualification, 3);
	bool handled = false;

	// handle reading physical memory from the CMOS.
	if(port_number == IO_RTC) {
		if(!is_in) {
			port_iortc = tf->tf_regs.reg_rax;
			handled = true;
		}
	} else if (port_number == IO_RTC + 1) {
		if(is_in) {
			if(port_iortc == NVRAM_BASELO) {
				tf->tf_regs.reg_rax = 640 & 0xFF;
				handled = true;
			} else if (port_iortc == NVRAM_BASEHI) {
				tf->tf_regs.reg_rax = (640 >> 8) & 0xFF;
				handled = true;
			} else if (port_iortc == NVRAM_EXTLO) {
				tf->tf_regs.reg_rax = ((ginfo->phys_sz / 1024) - 1024) & 0xFF;
				handled = true;
			} else if (port_iortc == NVRAM_EXTHI) {
				tf->tf_regs.reg_rax = (((ginfo->phys_sz / 1024) - 1024) >> 8) & 0xFF;
				handled = true;
			}
		}

	} 
	if(handled) {
		tf->tf_rip += vmcs_read32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH);
		return true;
	} else {
		cprintf("%x %x\n", qualification, port_iortc);
		return false;
	}
}

// Emulate a cpuid instruction.
// It is sufficient to issue the cpuid instruction here and collect the return value.
// You can store the output of the instruction in Trapframe tf,
//  but you should hide the presence of vmx from the guest if processor features are requested.
// 
// Return true if the exit is handled properly, false if the VM should be terminated.
//
// Finally, you need to increment the program counter in the trap frame.
// 
// Hint: The TA's solution does not hard-code the length of the cpuid instruction.
bool
handle_cpuid(struct Trapframe *tf, struct VmxGuestInfo *ginfo)
{
	/* Your code here  */
	//panic("handle_cpuid is not impemented\n");
	uint32_t initial_eax = (uint32_t)tf->tf_regs.reg_rax;
	uint32_t eax, ebx, ecx, edx;
	cpuid( initial_eax, &eax, &ebx, &ecx, &edx );
	// If requesting basic CPUID Information with the initial trapframe EAX = 01H, override the vmx bit to be 0.
	// Clear the vmx bit.
	if (initial_eax == 1) {
		ecx = ecx & ~(1 << 5);  // binary mask: 11111111111111111111111111011111
	}
	tf->tf_regs.reg_rax = (uint64_t)eax;
	tf->tf_regs.reg_rbx = (uint64_t)ebx;
	tf->tf_regs.reg_rcx = (uint64_t)ecx;
	tf->tf_regs.reg_rdx = (uint64_t)edx;
    
	tf->tf_rip += vmcs_read32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH);

	return true;
}

// Handle vmcall traps from the guest.
// We currently support 3 traps: read the virtual e820 map, 
//   and use host-level IPC (send andrecv).
//
// Return true if the exit is handled properly, false if the VM should be terminated.
//
// Finally, you need to increment the program counter in the trap frame.
// 
// Hint: The TA's solution does not hard-code the length of the cpuid instruction.//

bool
handle_vmcall(struct Trapframe *tf, struct VmxGuestInfo *gInfo, uint64_t *eptrt)
{
	bool handled = false;
	multiboot_info_t mbinfo;
	int perm, r;
	void *gpa_pg, *hva_pg;
	envid_t to_env;
	uint32_t val;
	// phys address of the multiboot map in the guest.
	uint64_t multiboot_map_addr = 0x6000;

	/* Group 7 Local Variables */
	
	// Defines the number of memory map segments
	int memory_map_segments = 3;
	// Holds the memory map information for the low, I/O hole, and high memory segments.
	// Note: In multiboot_read(), it reads an mmap_list array, could use an array / list instead.
	memory_map_t lo_mem_segment, ioh_mem_segment, hi_mem_segment;
	
	//int32_t mem_segment_size = 0x14;  // 20 bytes minimum (Typical e820 segment size)
	
	// sizeof(memory_map_t); 24 bytes
	size_t mem_segment_size = sizeof(memory_map_t);
	uint64_t mmap_addr = multiboot_map_addr + sizeof(multiboot_info_t);
	void *hva_pg_addr_lo, *hva_pg_addr_ioh, *hva_pg_addr_hi;

	switch(tf->tf_regs.reg_rax) {
	case VMX_VMCALL_MBMAP:
		/* Hint: */
		// Craft a multiboot (e820) memory map for the guest.
		//
		// Create three  memory mapping segments: 640k of low mem, the I/O hole (unusable), and 
		//   high memory (phys_size - 1024k).
		//
		// Once the map is ready, find the kernel virtual address of the guest page (if present),
		//   or allocate one and map it at the multiboot_map_addr (0x6000).
		// Copy the mbinfo and memory_map_t (segment descriptions) into the guest page, and return
		//   a pointer to this region in rbx (as a guest physical address).
		/* Your code here */
		// If the guest doesn't have enough memory allocated to it, then the VMX_VMCALL_MBMAP will not be handled.
		if (gInfo->phys_sz < EXTPHYSMEM) {
			cprintf("VMX_VMCALL_MBMAP: phys_sz is smaller than 1024k.\n");
			break;
		}

		//cprintf("Debug: Define low memory segment \n");  // debug
		// Define Low Memory Segment
		lo_mem_segment.size = mem_segment_size;
		lo_mem_segment.base_addr_low = 0x0;
		lo_mem_segment.base_addr_high = 0x0;
		lo_mem_segment.length_low = IOPHYSMEM;
		lo_mem_segment.length_high = 0x0;
		lo_mem_segment.type = MB_TYPE_USABLE;

		//cprintf("Debug: Define I/O hole memory segment \n");  // debug
		// Define I/O Hole (Reserved) Memory Segment
		ioh_mem_segment.size = mem_segment_size;
		ioh_mem_segment.base_addr_low = IOPHYSMEM;
		ioh_mem_segment.base_addr_high = 0x0;
		ioh_mem_segment.length_low = EXTPHYSMEM - IOPHYSMEM;
		ioh_mem_segment.length_high = 0x0;
		ioh_mem_segment.type = MB_TYPE_RESERVED;

		//cprintf("Debug: Define high memory segment \n");  // debug
		// Define High Memory Segment
		hi_mem_segment.size = mem_segment_size;
		hi_mem_segment.base_addr_low = EXTPHYSMEM;
		hi_mem_segment.base_addr_high = 0x0;
		hi_mem_segment.length_low = (uint32_t)(((gInfo->phys_sz - EXTPHYSMEM) << 32) >> 32);
		hi_mem_segment.length_high = (uint32_t)((gInfo->phys_sz - EXTPHYSMEM) >> 32);
		hi_mem_segment.type = MB_TYPE_USABLE;

		//cprintf("Debug: Find hva_pg if it exists \n");
		ept_gpa2hva(eptrt, (void*) multiboot_map_addr, &hva_pg);
		// Took inspirations from handle_eptviolation()
		if(!hva_pg) {
			//cprintf("Debug: hva_pg doesn't exist, so allocate it \n");  // debug
			// Allocate a new page to the guest.
			struct PageInfo *p = page_alloc(ALLOC_ZERO);
			if(!p) {
				cprintf("vmm: handle_vmcall:VMX_VMCALL_MBMAP: Failed to allocate a page for guest---out of memory.\n");
				return false;
			}
			p->pp_ref += 1;
			hva_pg = page2kva(p);
			r = ept_map_hva2gpa(eptrt, hva_pg, (void *)ROUNDDOWN(multiboot_map_addr, PGSIZE), __EPTE_FULL, 0);
			assert(r >= 0);
		}

		//cprintf("Debug: Set mbinfo \n");  // debug

		// Copy the mbinfo and memory_map_t (segment descriptions) into the guest page
		/* If bit 6 in the ‘flags’ word is set, then the ‘mmap_*’ fields are valid, and indicate the address and length of a buffer containing a memory map of the machine provided by the BIOS. ‘mmap_addr’ is the address, and ‘mmap_length’ is the total size of the buffer.
		*/
		mbinfo.flags = MB_FLAG_MMAP; // base10: 64, binary: 1000000
		mbinfo.mmap_length = mem_segment_size * memory_map_segments;
		mbinfo.mmap_addr = mmap_addr;  // memory map will be stored right after mbinfo.

		//cprintf("Debug: sizeof(mbinfo): %d \n", sizeof(mbinfo)); // debug
		//cprintf("Debug: sizeof(multiboot_info_t): %d \n", sizeof(multiboot_info_t)); // debug

		//cprintf("Debug: memcpy mbinfo \n");  // debug
		memcpy((void *)hva_pg, (void *)&mbinfo, sizeof(multiboot_info_t));

		hva_pg_addr_lo = hva_pg + sizeof(multiboot_info_t);
		hva_pg_addr_ioh = hva_pg_addr_lo + sizeof(memory_map_t);
		hva_pg_addr_hi = hva_pg_addr_ioh + sizeof(memory_map_t);

		//cprintf("Debug: memcpy lo_mem_segment:: hva_pg_addr_lo: %x, lo_mem_segment: %x, mem_segment_size: %d \n", hva_pg_addr_lo, (void*)&lo_mem_segment, mem_segment_size);  // debug
		memcpy(hva_pg_addr_lo, (void *)&lo_mem_segment, mem_segment_size);
		//cprintf("Debug: memcpy ioh_mem_segment:: hva_pg_addr_ioh: %x, ioh_mem_segment: %x, mem_segment_size: %d \n", hva_pg_addr_ioh, (void*)&ioh_mem_segment, mem_segment_size);  // debug
		memcpy(hva_pg_addr_ioh, (void *)&ioh_mem_segment, mem_segment_size);
		//cprintf("Debug: memcpy hi_mem_segment:: hva_pg_addr_hi: %x, hi_mem_segment: %x, mem_segment_size: %d \n", hva_pg_addr_hi, (void*)&hi_mem_segment, mem_segment_size);  // debug
		memcpy(hva_pg_addr_hi, (void *)&hi_mem_segment, mem_segment_size);
		
		// a pointer to this region in rbx (as a guest physical address).
		tf->tf_regs.reg_rbx = multiboot_map_addr;
		handled = true;
		cprintf("Debug: completed VMX_VMCALL_MBMAP \n");
		break;
	case VMX_VMCALL_IPCSEND:
		/* Hint: */
		// Issue the sys_ipc_send call to the host.
		// 
		// If the requested environment is the HOST FS, this call should
		//  do this translation.
		//
		// The input should be a guest physical address; you will need to convert
		//  this to a host virtual address for the IPC to work properly.
		//  Then you should call sys_ipc_try_send()
		/* Your code here */
		break;

	case VMX_VMCALL_IPCRECV:
		// Issue the sys_ipc_recv call for the guest.
		// NB: because recv can call schedule, clobbering the VMCS, 
		// you should go ahead and increment rip before this call.
		/* Your code here */
		break;
	case VMX_VMCALL_LAPICEOI:
		lapic_eoi();
		handled = true;
		break;
	case VMX_VMCALL_BACKTOHOST:
		cprintf("Now back to the host, VM halt in the background, run vmmanager to resume the VM.\n");
		curenv->env_status = ENV_NOT_RUNNABLE;	//mark the guest not runable
		ENV_CREATE(user_sh, ENV_TYPE_USER);	//create a new host shell
		handled = true;
		break;	
	case VMX_VMCALL_GETDISKIMGNUM:	//alloc a number to guest
		tf->tf_regs.reg_rax = vmdisk_number;
		handled = true;
		break;		
         
	}
	if(handled) {
		/* Advance the program counter by the length of the vmcall instruction. 
		 * 
		 * Hint: The solution does not hard-code the length of the vmcall instruction.
		 */
		/* Your code here */
		tf->tf_rip += vmcs_read32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH);
	}
	return handled;
}


