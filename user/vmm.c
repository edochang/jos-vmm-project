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
	struct Env *env_guest;

	// use readn()

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


