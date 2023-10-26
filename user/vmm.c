#include <inc/lib.h>
#include <inc/vmx.h>
#include <inc/elf.h>
#include <inc/ept.h>
#include <inc/stdio.h>

#define GUEST_KERN "/vmm/kernel"
#define GUEST_BOOT "/vmm/boot"

#define JOS_ENTRY 0x7000

// Map a region of file fd into the guest at guest physical address gpa.
// The file region to map should start at fileoffset and be length filesz.
// The region to map in the guest should be memsz.  The region can span multiple pages.
//
// Return 0 on success, <0 on failure.
//
// Hint: Call sys_ept_map() for mapping page. 
static int
map_in_guest( envid_t guest, uintptr_t gpa, size_t memsz, 
	      int fd, size_t filesz, off_t fileoffset ) {
	/* Your code here */
	/*
	map_in_guest() breaks down each segment in number of pages, and calls sys_ept_map() for each page. You cannot pass in the page directly, but rather will have to use a TEMP variable. This is defined as a macro in memlayout.h

	Note: Reading and loading is part of map_in_guest function.
	In map in guest you take 
		- FD, readn(), allocate a page, then get to the right location of the descriptor to read this data.
		- Then set the mapping and do it for every size of the FD.  
		- Get the right file-offset.  
		- Do page size read.
		- Set the mappings
		- continue on until you finish doing it for all the memsizes.  
	Don't do all the reads in copy_guest_kern.  There are library calls that will help you create a page of memory in the guest environment to find and use.  Don't use malloc because it'll be on host.  Want to be more specific to where you allocate memory.

	Args:
		guest (envid_t):  The guest environment id
		gpa (uintptr_t):  A guest physical address in 64 bit
		memsz (size_t):  Memory size of the region to map in guest.  Can span multple pages.
		fd (int):  Region of file to be mapped into the guest
		filesz (size_t):  file size length used on the file offset
		fileoffset (off_t):  The starting offset for mapping a file region
	Returns:
		(int):  Result of the operation using codes as defined in the comments above this function
	*/
	int perm = __EPTE_FULL;
	int result;
	int i;

	// Adjust gpa to align with PGSIZE.
	if ((i = PGOFF(gpa))) {
		gpa -= i;
		memsz += i;
		filesz += i;
		fileoffset -= i;
	}
	
	// walk through the provided region page by page and copy in the file contents
	// the the physical memory region of the guest
	for (i = 0; i < memsz; i += PGSIZE) {
		// allocate a temporary page
		if ((result = sys_page_alloc(0, UTEMP, PTE_P|PTE_U|PTE_W)) < 0) {
			sys_page_unmap(0, UTEMP);
			return result;
		}
		// seek to the location to write the file contents at
		if ((result = seek(fd, fileoffset + i)) < 0) {
			sys_page_unmap(0, UTEMP);
			return result;
		}
		// read file contents into the mapped page
		if ((result = readn(fd, UTEMP, MIN(PGSIZE, filesz-i))) < 0) {
			sys_page_unmap(0, UTEMP);
			return result;
		}
		// map the page in the EPT
		if ((result = sys_ept_map(0, UTEMP, guest, (void*) (gpa + i), perm)) < 0) {
			sys_page_unmap(0, UTEMP);
			return result;
		}
		sys_page_unmap(0, UTEMP);
	}

	return 0;
} 

// Read the ELF headers of kernel file specified by fname,
// mapping all valid segments into guest physical memory as appropriate.
//
// Return 0 on success, <0 on error
//
// Hint: compare with ELF parsing in env.c, and use map_in_guest for each segment.
static int
copy_guest_kern_gpa( envid_t guest, char* fname ) {
	/* Your code here */
	/*
	copy_guest_kern_gpa() reads the ELF header from the kernel executable into the struct Elf. The kernel ELF contains multiple segments which must be copied from the host to the guest. This function is similar to the one observed in the prelab but has to call something other than memcpy() to map the memory because we are in the virtual guest.
	
	Args:
		guest (envid_t):  The guest environment id
		fname (char*):  fname specifies the ELF files to be read and added to Guest physical memory
	Returns:
		(int):  Result of the operation using codes as defined in the comments above this function

	copy_guest_kern does the following:
		// - How can i parse the elf header
		// - how can i traverse all the segments 
		// - how i can call map_in_guest for each of these segments
	*/

	// Local Variables
	int result, fd;
	struct Elf *elf;
	struct Proghdr *ph, *eph;
	int buflen = 512;
	unsigned char elf_buf[buflen];  // large enough to fit the whole Elf struct

	//cprintf("map_segment %x+%x\n", va, memsz);

	// open the specified file
	// Read the ELF files from disk from our project directory ./vmm/guest
	if ((fd = open(fname, O_RDONLY)) < 0) {
		cprintf("error opening %s: %e\n", fname, fd);
		return fd;
	}

	// read in the header of file fname
	if (readn(fd, elf_buf, sizeof(elf_buf)) != sizeof(elf_buf)) {
		close(fd);
		cprintf("Failed to read in ELF header\n");
		return -E_NOT_EXEC;
	}

	// Read elf header
	// point the elf struct at the elf buf
	elf = (struct Elf*) elf_buf;

	// check the ELF header's magic value to check that we are working with a valid ELF binary
	if (elf->e_magic != ELF_MAGIC) {
		close(fd);
		cprintf("elf magic %08x want %08x\n", elf->e_magic, ELF_MAGIC);
		return -E_NOT_EXEC;
	}

	//cprintf("[VMM] DEBUG: copy_guest_kern_gpa: Setup program segments for Guest Kernel\n");  // debug

	// Set up program segments as defined in ELF header.
	// point the program header struct at the location indicated by the elf header
	ph = (struct Proghdr*) (elf_buf + elf->e_phoff);

	// for every entry in the program header table, map the corresponding entry of the file 
	// into the guest's physical address space
	eph = ph + elf->e_phnum;
	for(;ph < eph; ph++) {
		if ((result = map_in_guest(guest, (uintptr_t) ph->p_pa, ph->p_memsz, fd, ph->p_filesz, ph->p_offset)) < 0) {
			cprintf("Error mapping EPT page in guest %e\n", result);
			close(fd);
			return result;
		}
	}
	/* STAB segments are optional.
	cprintf("[VMM] DEBUG: copy_guest_kern_gpa: Setup STAB segments for Guest Kernel\n");  // debug

	uintptr_t debug_address = USTABDATA;
	struct Secthdr *sh = (struct Secthdr *)(((uint8_t *)elf + elf->e_shoff));
	struct Secthdr *shstr_tab = sh + elf->e_shstrndx;
	struct Secthdr* esh = sh + elf->e_shnum;
	for(;sh < esh; sh++) {
		char* name = (char*)((uint8_t*)elf + shstr_tab->sh_offset) + sh->sh_name;
		if(!strcmp(name, ".debug_info") || !strcmp(name, ".debug_abbrev")
			|| !strcmp(name, ".debug_line") || !strcmp(name, ".eh_frame")
			|| !strcmp(name, ".debug_str")) {
			if ((result = map_in_guest(guest, (uintptr_t) USTABDATA, sh->sh_addr, fd, sh->sh_size, sh->sh_offset)) < 0)
				return -E_FAULT;
			debug_address += sh->sh_size;
		}
	}
	*/
	
	//cprintf("[VMM] DEBUG: copy_guest_kern_gpa: Completed segment processing\n");  // debug

	close(fd);

	return 0;
	// return -E_NO_SYS;
}

void
umain(int argc, char **argv) {
	int ret;
	envid_t guest;
	char filename_buffer[50];	//buffer to save the path 
	int vmdisk_number;
	int r;
	if ((ret = sys_env_mkguest( GUEST_MEM_SZ, JOS_ENTRY )) < 0) {
		cprintf("Error creating a guest OS env: %e\n", ret );
		exit();
	}
	guest = ret;

	//cprintf("[VMM] DEBUG: copy_guest_kern_gpa()\n");  // debug
	// Copy the guest kernel code into guest phys mem.
	if((ret = copy_guest_kern_gpa(guest, GUEST_KERN)) < 0) {
		cprintf("Error copying page into the guest - %d\n.", ret);
		exit();
	}

	//cprintf("[VMM] DEBUG: Open bootloader()\n");  // debug
	// Now copy the bootloader.
	int fd;
	if ((fd = open( GUEST_BOOT, O_RDONLY)) < 0 ) {
		cprintf("open %s for read: %e\n", GUEST_BOOT, fd );
		exit();
	}

	//cprintf("[VMM] DEBUG: map_in_guest() the bootloader\n");  // debug
	// sizeof(bootloader) < 512.
	if ((ret = map_in_guest(guest, JOS_ENTRY, 512, fd, 512, 0)) < 0) {
		cprintf("Error mapping bootloader into the guest - %d\n.", ret);
		exit();
	}
#ifndef VMM_GUEST	
	sys_vmx_incr_vmdisk_number();	//increase the vmdisk number
	//create a new guest disk image
	
	vmdisk_number = sys_vmx_get_vmdisk_number();
	snprintf(filename_buffer, 50, "/vmm/fs%d.img", vmdisk_number);
	
	cprintf("Creating a new virtual HDD at /vmm/fs%d.img\n", vmdisk_number);
        r = copy("vmm/clean-fs.img", filename_buffer);
        
        if (r < 0) {
        	cprintf("Create new virtual HDD failed: %e\n", r);
        	exit();
        }
        
        cprintf("Create VHD finished\n");
#endif
	// Mark the guest as runnable.
	sys_env_set_status(guest, ENV_RUNNABLE);
	wait(guest);
}


