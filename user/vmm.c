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

	// Call sys_ept_map() for mapping page.
	return 0;
	// return -E_NO_SYS;
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
	*/
	// From user/vmm.c calls this function and passes GUEST_KERN as fname
	// #define GUEST_KERN "/vmm/kernel", so we are reading from disk in our project directory
	// Local Variables
	int result, fd;
	struct Elf *elf;
	struct Proghdr *ph, *eph;
	unsigned char elf_buf[512];

	// Read the ELF files from disk from our project directory ./vmm/guest
	if ((result = open(fname, O_RDONLY)) < 0)
		return result;
	fd = result;

	// Read elf header
	elf = (struct Elf*) elf_buf;
	if (readn(fd, elf_buf, sizeof(elf_buf)) != sizeof(elf_buf)
            || elf->e_magic != ELF_MAGIC) {
		close(fd);
		cprintf("elf magic %08x want %08x\n", elf->e_magic, ELF_MAGIC);
		return -E_NOT_EXEC;
	}

	// Set up program segments as defined in ELF header.
	//lcr3(PADDR((uint64_t)e->env_pml4e)); // TODO: Is this needed?
	ph = (struct Proghdr*) (elf_buf + elf->e_phoff);
	eph = ph + elf->e_phnum;
	for(;ph < eph; ph++) {
		if (ph->p_type == ELF_PROG_LOAD) {
			// TODO: Do we need to do a region_alloc()?  We have no access to Env in user program.
			//region_alloc(e, (void *)ph->p_va, ph->p_memsz);
			// TODO: Replace memcpy, with map_in_guest
			//memcpy((void *)ph->p_va, (void *)((uint8_t *)elf + ph->p_offset), ph->p_filesz);
			//map_in_guest( envid_t guest, uintptr_t gpa, size_t memsz, int fd, size_t filesz, off_t fileoffset )
			/*if ((result = map_in_guest(guest, gpa, ph->p_memsz, fd, filesize, fileoffset) < 0)
				return -E_FAULT;
			*/
			if (ph->p_filesz < ph->p_memsz) {
				memset((void *)(ph->p_va + ph->p_filesz), 0, ph->p_memsz-ph->p_filesz);
			}
		}
	}
	// TODO: Do we need to do a region_alloc()?  We have no access to Env in user program.
	//region_alloc(e, (void*) (USTACKTOP - PGSIZE), PGSIZE);
	// TODO: Env / e is not accessable in user program.
	//e->env_tf.tf_rip    = elf->e_entry;
	//e->env_tf.tf_rsp    = USTACKTOP; //keeping stack 8 byte aligned

	uintptr_t debug_address = USTABDATA;
	struct Secthdr *sh = (struct Secthdr *)(((uint8_t *)elf + elf->e_shoff));
	struct Secthdr *shstr_tab = sh + elf->e_shstrndx;
	struct Secthdr* esh = sh + elf->e_shnum;
	for(;sh < esh; sh++) {
		char* name = (char*)((uint8_t*)elf + shstr_tab->sh_offset) + sh->sh_name;
		if(!strcmp(name, ".debug_info") || !strcmp(name, ".debug_abbrev")
			|| !strcmp(name, ".debug_line") || !strcmp(name, ".eh_frame")
			|| !strcmp(name, ".debug_str")) {
			// TODO: Do we need to do a region_alloc()?  We have no access to Env in user program.
			//region_alloc(e ,(void*)debug_address, sh->sh_size);
			// TODO: Replace memcpy, with map_in_guest
			//memcpy((void *)debug_address, (void *)((uint8_t *)elf + sh->sh_offset),
			//		sh->sh_size);
			debug_address += sh->sh_size;
		}
	}
	lcr3(boot_cr3);

	// TODO: Is this needed?
	// Give environment a stack
	// e->elf = binary;  

	close(fd);
	fd = -1;

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

	// Copy the guest kernel code into guest phys mem.
	if((ret = copy_guest_kern_gpa(guest, GUEST_KERN)) < 0) {
		cprintf("Error copying page into the guest - %d\n.", ret);
		exit();
	}

	// Now copy the bootloader.
	int fd;
	if ((fd = open( GUEST_BOOT, O_RDONLY)) < 0 ) {
		cprintf("open %s for read: %e\n", GUEST_BOOT, fd );
		exit();
	}

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


