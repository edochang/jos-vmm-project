#line 2 "../vmm/ept.c"

#include <vmm/ept.h>
#include <inc/x86.h>
#include <inc/error.h>
#include <inc/memlayout.h>
#include <kern/pmap.h>
#include <inc/string.h>

// Return the physical address of an ept entry
static inline uintptr_t epte_addr(epte_t epte)
{
	return (epte & EPTE_ADDR);
}

// Return the host kernel virtual address of an ept entry
static inline uintptr_t epte_page_vaddr(epte_t epte)
{
	return (uintptr_t) KADDR(epte_addr(epte));
}

// Return the flags from an ept entry
static inline epte_t epte_flags(epte_t epte)
{
	return (epte & EPTE_FLAGS);
}

// Return true if an ept entry's mapping is present
static inline int epte_present(epte_t epte)
{
	return (epte & __EPTE_FULL) > 0;
}

// Find the final ept entry for a given guest physical address,
// creating any missing intermediate extended page tables if create is non-zero.
//
// If epte_out is non-NULL, store the found epte_t* at this address.
//
// Return 0 on success.
//
// Error values:
//    -E_INVAL if eptrt is NULL
//    -E_NO_ENT if create == 0 and the intermediate page table entries are missing.
//    -E_NO_MEM if allocation of intermediate page table entries fails
//
// Hint: Set the permissions of intermediate ept entries to __EPTE_FULL.
//       The hardware ANDs the permissions at each level, so removing a permission
//       bit at the last level entry is sufficient (and the bookkeeping is much simpler).
static int ept_lookup_gpa(epte_t* eptrt, void *gpa,
			  int create, epte_t **epte_out) {
    /* Your code here */
	/*
	ept_lookup_gpa() does the walk on the page table hierarchy at the guest and returns the page table entry corresponding to a gpa. It calculates the next index using the address and iterates until it reaches the page table entry at level 0 which points to the actual page.

	Args:
		eptrt (epte_t*): A pointer to ept root represented as an extended page table entry type
		gpa (void*): A guest physical address in 64 bit
		create (int): Create any missing intermedate extended page tables if create is != 0
		epte_out (epte_t): A pointer to a pointer that points to the final ept entry outputing the host physical address
	Returns:
		result (int): 0 on success otherwise use an error value as defined in the comment above that is < 0
	*/
	// Local Variables
	int i;

	// -E_INVAL if eptrt is NULL
	if (eptrt == NULL)
		return -E_INVAL;

	// Walk the 4-Level Page Table Hierarchy with a linear address
	epte_t *dir = eptrt;
	for (i = EPT_LEVELS - 1; i >= 0; --i ) {
        int idx = ADDR_TO_IDX(gpa, i);  // 3 - EPML4; 2 - EPDPT; 1- EPD; 0 - EPT
		if (!epte_present(dir[idx]) && create) {
			// If EPDPTE, EPDE, or EPTE is missing, create page
			struct PageInfo *page = NULL;
			if ((page = page_alloc(ALLOC_ZERO))) {
				page->pp_ref += 1;
				// Set the type to EPTE_TYPE_WB and set __EPTE_IPAT flag.
				// Set the permissions of intermediate ept entries to __EPTE_FULL.
				dir[idx] = page2pa(page)|__EPTE_TYPE(6)|__EPTE_IPAT|__EPTE_FULL;
			} else {
				// -E_NO_MEM if allocation of intermediate page table entries fails
				return -E_NO_MEM;
			}
		}

		if (!epte_present(dir[idx]) && create == 0)
			// -E_NO_ENT if create == 0 and the intermediate page table entries are missing.
			return -E_NO_ENT;

		if (i == 0) {
			*epte_out = (epte_t *) epte_page_vaddr(dir[idx]);
		} else {
			dir = (epte_t *) epte_page_vaddr(dir[idx]);
		}
	}
    return 0;
}

void ept_gpa2hva(epte_t* eptrt, void *gpa, void **hva) {
    epte_t* pte;
    int ret = ept_lookup_gpa(eptrt, gpa, 0, &pte);
    if(ret < 0) {
        *hva = NULL;
    } else {
        if(!epte_present(*pte)) {
           *hva = NULL;
        } else {
           *hva = KADDR(epte_addr(*pte));
        }
    }
}

static void free_ept_level(epte_t* eptrt, int level) {
    epte_t* dir = eptrt;
    int i;

    for(i=0; i<NPTENTRIES; ++i) {
        if(level != 0) {
            if(epte_present(dir[i])) {
                physaddr_t pa = epte_addr(dir[i]);
                free_ept_level((epte_t*) KADDR(pa), level-1);
                // free the table.
                page_decref(pa2page(pa));
            }
        } else {
            // Last level, free the guest physical page.
            if(epte_present(dir[i])) {
                physaddr_t pa = epte_addr(dir[i]);
                page_decref(pa2page(pa));
            }
        }
    }
    return;
}

// Free the EPT table entries and the EPT tables.
// NOTE: Does not deallocate EPT PML4 page.
void free_guest_mem(epte_t* eptrt) {
    free_ept_level(eptrt, EPT_LEVELS - 1);
    tlbflush();
}

// Add Page pp to a guest's EPT at guest physical address gpa
//  with permission perm.  eptrt is the EPT root.
//
// This function should increment the reference count of pp on a
//   successful insert.  If you overwrite a mapping, your code should
//   decrement the reference count of the old mapping.
//
// Return 0 on success, <0 on failure.
//
int ept_page_insert(epte_t* eptrt, struct PageInfo* pp, void* gpa, int perm) {

    /* Your code here */
    return 0;
}

// Map host virtual address hva to guest physical address gpa,
// with permissions perm.  eptrt is a pointer to the extended
// page table root.
//
// Return 0 on success.
//
// If the mapping already exists and overwrite is set to 0,
//  return -E_INVAL.
//
// Hint: use ept_lookup_gpa to create the intermediate
//       ept levels, and return the final epte_t pointer.
//       You should set the type to EPTE_TYPE_WB and set __EPTE_IPAT flag.
int ept_map_hva2gpa(epte_t* eptrt, void* hva, void* gpa, int perm,
        int overwrite) {
    /* Your code here */
	/*
	ept_map_hva2gpa() does a walk on the page table levels at the guest (given the gpa) using ept_lookup_gpa() and then gets a page table entry at level 0 corresponding to the gpa. This function then inserts the physical address corresponding to the hva, in the page table entry returned by ept_lookup_gpa().

	Args:
		eptrt (epte_t*):  A pointer to ept root represented as an extended page table entry type
		hva (void*):  A host virtual address in 64 bit
		gpa (void*):  A guest physical address in 64 bit
		perm (int):  Defines the permission
		overwrite (int):  Overwrite the mapping to an existing EPTE with the corresponding hva.
	Returns:
		(int): 0 on success otherwise use an error value as defined in the comment above that is < 0
	*/
	// Temporary variables to store the results calling other helper functions.
	int result;
	// Local variables
	int idx = ADDR_TO_IDX(gpa, 0);
	epte_t *epte_out;
	physaddr_t hpa;

	// Lookup the gpa
	if ((result = ept_lookup_gpa(eptrt, gpa, 1, &epte_out) < 0))
		return result;

	if (epte_present(*epte_out)) {
		if (overwrite == 0) {
			return -E_INVAL;
		} else {
			// If the mapping already exists, then overwrite it and decrement the old page reference count
			//pa2page(epte_addr(*epte_out))->pp_ref -= 1;
			page_decref(pa2page(epte_addr(*epte_out)));  // Inspiration from free_ept_level()
			hpa = PADDR(hva); 
			// Increment the reference count since 2 page table entries reference to it.
			pa2page(hpa)->pp_ref += 1;
			// Based on the test_ept_map(), the perm sets the PTE-4KB Page
			epte_out[idx] = hpa|__EPTE_TYPE(6)|__EPTE_IPAT|perm;
		}
	} else {
		// Map hva's physical page to gpa at the lowest page table entry, set EPT permissions
		hpa = PADDR(hva); 
		// Increment the reference count since 2 page table entries reference to it.
		pa2page(hpa)->pp_ref += 1;
		// Based on the test_ept_map(), the perm sets the PTE-4KB Page
		epte_out[idx] = hpa|__EPTE_TYPE(6)|__EPTE_IPAT|perm;
	}
		
    return 0;
}

int ept_alloc_static(epte_t *eptrt, struct VmxGuestInfo *ginfo) {
    physaddr_t i;

    for(i=0x0; i < 0xA0000; i+=PGSIZE) {
        struct PageInfo *p = page_alloc(0);
        p->pp_ref += 1;
        int r = ept_map_hva2gpa(eptrt, page2kva(p), (void *)i, __EPTE_FULL, 0);
    }

    for(i=0x100000; i < ginfo->phys_sz; i+=PGSIZE) {
        struct PageInfo *p = page_alloc(0);
        p->pp_ref += 1;
        int r = ept_map_hva2gpa(eptrt, page2kva(p), (void *)i, __EPTE_FULL, 0);
    }
    return 0;
}

#ifdef TEST_EPT_MAP
#include <kern/env.h>
#include <kern/syscall.h>
int _export_sys_ept_map(envid_t srcenvid, void *srcva,
	    envid_t guest, void* guest_pa, int perm);

int test_ept_map(void)
{
	struct Env *srcenv, *dstenv;
	struct PageInfo *pp;
	epte_t *epte;
	int r;
	int pp_ref;
	int i;
	epte_t* dir;
	/* Initialize source env */
	if ((r = env_alloc(&srcenv, 0)) < 0)
		panic("Failed to allocate env (%d)\n", r);
	if (!(pp = page_alloc(ALLOC_ZERO)))
		panic("Failed to allocate page (%d)\n", r);
	if ((r = page_insert(srcenv->env_pml4e, pp, UTEMP, 0)) < 0)
		panic("Failed to insert page (%d)\n", r);
	curenv = srcenv;

	/* Check if sys_ept_map correctly verify the target env */
	if ((r = env_alloc(&dstenv, srcenv->env_id)) < 0)
		panic("Failed to allocate env (%d)\n", r);
	if ((r = _export_sys_ept_map(srcenv->env_id, UTEMP, dstenv->env_id, UTEMP, __EPTE_READ)) < 0)
		cprintf("EPT map to non-guest env failed as expected (%d).\n", r);  // pass
	else
		panic("sys_ept_map success on non-guest env.\n");

	/*env_destroy(dstenv);*/

	if ((r = env_guest_alloc(&dstenv, srcenv->env_id)) < 0)
		panic("Failed to allocate guest env (%d)\n", r);
	dstenv->env_vmxinfo.phys_sz = (uint64_t)UTEMP + PGSIZE;

	/* Check if sys_ept_map can verify srcva correctly */
	if ((r = _export_sys_ept_map(srcenv->env_id, (void *)UTOP, dstenv->env_id, UTEMP, __EPTE_READ)) < 0)
		cprintf("EPT map from above UTOP area failed as expected (%d).\n", r);  // pass
	else
		panic("sys_ept_map from above UTOP area success\n");
	if ((r = _export_sys_ept_map(srcenv->env_id, UTEMP+1, dstenv->env_id, UTEMP, __EPTE_READ)) < 0)
		cprintf("EPT map from unaligned srcva failed as expected (%d).\n", r);  // pass
	else
		panic("sys_ept_map from unaligned srcva success\n");

	/* Check if sys_ept_map can verify guest_pa correctly */
	if ((r = _export_sys_ept_map(srcenv->env_id, UTEMP, dstenv->env_id, UTEMP + PGSIZE, __EPTE_READ)) < 0)
		cprintf("EPT map to out-of-boundary area failed as expected (%d).\n", r);  // pass
	else
		panic("sys_ept_map success on out-of-boundary area\n");
	if ((r = _export_sys_ept_map(srcenv->env_id, UTEMP, dstenv->env_id, UTEMP-1, __EPTE_READ)) < 0)
		cprintf("EPT map to unaligned guest_pa failed as expected (%d).\n", r);  // pass
	else
		panic("sys_ept_map success on unaligned guest_pa\n");

	/* Check if the sys_ept_map can verify the permission correctly */
	if ((r = _export_sys_ept_map(srcenv->env_id, UTEMP, dstenv->env_id, UTEMP, 0)) < 0)
		cprintf("EPT map with empty perm parameter failed as expected (%d).\n", r);  // pass
	else
		panic("sys_ept_map success on empty perm\n");
	if ((r = _export_sys_ept_map(srcenv->env_id, UTEMP, dstenv->env_id, UTEMP, __EPTE_WRITE)) < 0)
		cprintf("EPT map with write perm parameter failed as expected (%d).\n", r);  // pass
	else
		panic("sys_ept_map success on write perm\n");

	pp_ref = pp->pp_ref;
	/* Check if the sys_ept_map can succeed on correct setup */
	if ((r = _export_sys_ept_map(srcenv->env_id, UTEMP, dstenv->env_id, UTEMP, __EPTE_READ)) < 0)
		panic("Failed to do sys_ept_map (%d)\n", r);
	else
		cprintf("sys_ept_map finished normally.\n");  // pass
	if (pp->pp_ref != pp_ref + 1)
		panic("Failed on checking pp_ref\n");
	else
		cprintf("pp_ref incremented correctly\n");  // pass

	/* Check if the sys_ept_map can handle remapping correctly */
	pp_ref = pp->pp_ref;
	if ((r = _export_sys_ept_map(srcenv->env_id, UTEMP, dstenv->env_id, UTEMP, __EPTE_READ)) < 0)
		cprintf("sys_ept_map finished normally.\n");  // pass
	else
		panic("sys_ept_map success on remapping the same page\n");
	/* Check if the sys_ept_map reset the pp_ref after failed on remapping the same page */
	if (pp->pp_ref == pp_ref)
		cprintf("sys_ept_map handled pp_ref correctly.\n");  // pass
	else
		panic("sys_ept_map failed to handle pp_ref.\n");

	/* Check if ept_lookup_gpa can handle empty eptrt correctly */
	if ((r = ept_lookup_gpa(NULL, UTEMP, 0, &epte)) < 0)
		cprintf("EPT lookup with a null eptrt failed as expected\n");  // pass
	else
		panic ("ept_lookup_gpa success on null eptrt\n");


	/* Check if the mapping is valid */
	if ((r = ept_lookup_gpa(dstenv->env_pml4e, UTEMP, 0, &epte)) < 0)
		panic("Failed on ept_lookup_gpa (%d)\n", r);
	if (page2pa(pp) != (epte_addr(*epte)))
		panic("EPT mapping address mismatching (%x vs %x).\n",
				page2pa(pp), epte_addr(*epte));
	else
		cprintf("EPT mapping address looks good: %x vs %x.\n",
				page2pa(pp), epte_addr(*epte));  // pass

	/* Check if the map_hva2gpa handle the overwrite correctly */
	if ((r = ept_map_hva2gpa(dstenv->env_pml4e, page2kva(pp), UTEMP, __EPTE_READ, 0)) < 0)
		cprintf("map_hva2gpa handle not overwriting correctly\n");  // pass
	else
		panic("map_hva2gpa success on overwriting with non-overwrite parameter\n");

	/* Check if the map_hva2gpa can map a page */
	if ((r = ept_map_hva2gpa(dstenv->env_pml4e, page2kva(pp), UTEMP, __EPTE_READ, 1)) < 0)
		panic ("Failed on mapping a page from kva to gpa\n");
	else
		cprintf("map_hva2gpa success on mapping a page\n");  // pass

	/* Check if the map_hva2gpa set permission correctly */
	if ((r = ept_lookup_gpa(dstenv->env_pml4e, UTEMP, 0, &epte)) < 0)
		panic("Failed on ept_lookup_gpa (%d)\n", r);
	if (((uint64_t)*epte & (~EPTE_ADDR)) == (__EPTE_READ | __EPTE_TYPE( EPTE_TYPE_WB ) | __EPTE_IPAT))
		cprintf("map_hva2gpa success on perm check\n");  // pass
	else
		panic("map_hva2gpa didn't set permission correctly\n");
	/* Go through the extended page table to check if the immediate mappings are correct */
	dir = dstenv->env_pml4e;
	for ( i = EPT_LEVELS - 1; i > 0; --i ) {
        	int idx = ADDR_TO_IDX(UTEMP, i);
        	if (!epte_present(dir[idx])) {
        		panic("Failed to find page table item at the immediate level %d.", i);
        	}
			if (!(dir[idx] & __EPTE_FULL)) {
				panic("Permission check failed at immediate level %d.", i);
			}
			dir = (epte_t *) epte_page_vaddr(dir[idx]);
        }
	cprintf("EPT immediate mapping check passed\n");  // pass


	/* stop running after test, as this is just a test run. */
	panic("Cheers! sys_ept_map seems to work correctly.\n");

	return 0;
}
#endif

