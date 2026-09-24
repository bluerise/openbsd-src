/*	$OpenBSD: arm64_vm.c,v 1.14 2026/09/19 17:21:52 dv Exp $	*/
/*
 * Copyright (c) 2024 Dave Voutila <dv@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>

#include <machine/armreg.h>
#include <machine/vmmvar.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>

#include "atomicio.h"
#include "lapic.h"
#include "mmio.h"
#include "pci.h"
#include "virtio.h"
#include "vmd.h"
#include "vmm.h"

extern struct vmd_vm	*current_vm;
extern int		 con_fd;

SLIST_HEAD(mmio_dev_head, mmio_dev) mmio_devs;

static int vcpu_exit_data_abort(struct vm_run_params *);

/*
 * create_memory_map
 *
 * Sets up the guest physical memory ranges that the ARM64 VM can access.
 */
void
create_memory_map(struct vmd_vm *vm)
{
	struct vmop_create_params *vmc = &vm->vm_params;
	size_t mem_bytes, low_ram, high_ram;

	mem_bytes = vmc->vmc_memranges[0].vmr_size;
	vmc->vmc_nmemranges = 0;
	if (mem_bytes == 0 || mem_bytes > VMM_MAX_VM_MEM_SIZE)
		return;

	/*
	 * Region 0: 0x00000000 - 0x3fffffff: 1GB MMIO device space
	 * (GICv3, UART, platform peripherals).
	 */
	vmc->vmc_memranges[0].vmr_gpa = 0x0;
	vmc->vmc_memranges[0].vmr_size = 0x40000000ULL;
	vmc->vmc_memranges[0].vmr_type = VM_MEM_MMIO;

	/*
	 * Region 1: RAM from 1GB (0x40000000) up to PCI MMIO base (0xF0000000).
	 */
	if (mem_bytes > PCI_MMIO_BAR_BASE - 0x40000000ULL) {
		low_ram = PCI_MMIO_BAR_BASE - 0x40000000ULL;
		high_ram = mem_bytes - low_ram;
	} else {
		low_ram = mem_bytes;
		high_ram = 0;
	}

	vmc->vmc_memranges[1].vmr_gpa = 0x40000000ULL;
	vmc->vmc_memranges[1].vmr_size = low_ram;
	vmc->vmc_memranges[1].vmr_type = VM_MEM_RAM;

	/*
	 * Region 2: PCI MMIO window.
	 */
	vmc->vmc_memranges[2].vmr_gpa = PCI_MMIO_BAR_BASE;
	vmc->vmc_memranges[2].vmr_size = PCI_MMIO_BAR_END -
	    PCI_MMIO_BAR_BASE + 1;
	vmc->vmc_memranges[2].vmr_type = VM_MEM_MMIO;

	/*
	 * Region 3: Any RAM remainder mapped above 4GB.
	 */
	if (high_ram > 0) {
		vmc->vmc_memranges[3].vmr_gpa = GB(4);
		vmc->vmc_memranges[3].vmr_size = high_ram;
		vmc->vmc_memranges[3].vmr_type = VM_MEM_RAM;
		vmc->vmc_nmemranges = 4;
	} else {
		vmc->vmc_nmemranges = 3;
	}
}

/*
 * load_firmware
 *
 * Loads the raw kernel / firmware image into guest RAM.
 */
int
load_firmware(struct vmd_vm *vm, struct vcpu_reg_state *vrs)
{
	char buf[PAGE_SIZE];
	paddr_t load_addr;
	gzFile fp;
	int len;

	memset(vrs, 0, sizeof(*vrs));
	vrs->vrs_spsr = PSR_M_EL1h | PSR_F | PSR_I | PSR_A | PSR_D;

	/* Guest RAM starts at 0x40000000 */
	load_addr = 0x40000000ULL;
	vrs->vrs_pc = load_addr;

	if (vm->vm_kernel == -1)
		return (0);

	if ((fp = gzdopen(vm->vm_kernel, "r")) == NULL) {
		log_warn("%s: failed to open kernel image", __func__);
		return (-1);
	}

	while ((len = gzread(fp, buf, sizeof(buf))) > 0) {
		if (write_mem(load_addr, buf, (size_t)len) != 0) {
			log_warnx("%s: failed to write kernel at 0x%llx",
			    __func__, (unsigned long long)load_addr);
			gzclose(fp);
			return (-1);
		}
		load_addr += (size_t)len;
	}

	gzclose(fp);
	return (0);
}

/*
 * init_emulated_hw
 *
 * Initialize MMIO subsystem, PCI bus, and VirtIO devices.
 */
int
init_emulated_hw(struct vmd_vm *vm, int child_cdrom,
    int child_disks[][VM_MAX_BASE_PER_DISK], int *child_taps)
{
	mmio_init();

	pci_init();
	if (mmio_dev_add(PCI_MMIO_BAR_BASE, PCI_MMIO_BAR_END,
	    pci_handle_mmio) != 0)
		fatalx("%s: cannot register PCI MMIO window", __func__);

	/* Initialize virtio devices */
	if (virtio_init(current_vm, child_cdrom, child_disks, child_taps))
		return (1);

	return (0);
}

void
pause_vm_md(struct vmd_vm *vm)
{
	virtio_stop(vm);
}

void
unpause_vm_md(struct vmd_vm *vm)
{
	virtio_start(vm);
}

/*
 * find_gpa_range
 *
 * Find the base memory range that provides contiguous memory for the given
 * starting gpa and spanning len bytes.
 */
struct vm_mem_range *
find_gpa_range(struct vmop_create_params *vmc, paddr_t gpa, size_t len)
{
	size_t i, n, rest;
	paddr_t prev_end_gpa;
	struct vm_mem_range *vmr, *end_vmr;

	/* Find the first vm_mem_range that contains gpa */
	for (i = 0; i < vmc->vmc_nmemranges; i++) {
		vmr = &vmc->vmc_memranges[i];
		if (gpa >= vmr->vmr_gpa &&
		    gpa - vmr->vmr_gpa < vmr->vmr_size)
			break;
	}

	/* No range found. */
	if (i == vmc->vmc_nmemranges)
		return (NULL);

	/* Reject MMIO ranges or those with bogus host VAs. */
	if (vmr->vmr_type == VM_MEM_MMIO || vmr->vmr_va == 0)
		return (NULL);

	/* Does the requested span fit in the found range? */
	n = vmr->vmr_size - (gpa - vmr->vmr_gpa);
	if (len <= n)
		return (vmr);
	rest = len - n;

	/*
	 * vmr covers the range [gpa, gpa + len) partially. Make sure
	 * that the following vm_mem_ranges are contiguous without
	 * any gap and that they cover the rest of the span.
	 */
	prev_end_gpa = vmr->vmr_gpa + vmr->vmr_size;
	for (i++; i < vmc->vmc_nmemranges; i++) {
		end_vmr = &vmc->vmc_memranges[i];
		if (end_vmr->vmr_gpa != prev_end_gpa ||
		    end_vmr->vmr_type == VM_MEM_MMIO ||
		    end_vmr->vmr_va == 0)
			return (NULL);

		if (rest <= end_vmr->vmr_size)
			return (vmr);

		rest -= end_vmr->vmr_size;
		prev_end_gpa = end_vmr->vmr_gpa + end_vmr->vmr_size;
	}

	return (NULL);
}

/*
 * write_mem
 *
 * Copies data from 'buf' into the guest VM's memory at paddr 'dst'.
 */
int
write_mem(paddr_t dst, const void *buf, size_t len)
{
	const char *from = buf;
	char *to;
	size_t n, off;
	struct vm_mem_range *vmr;

	vmr = find_gpa_range(&current_vm->vm_params, dst, len);
	if (vmr == NULL) {
		errno = EINVAL;
		log_warn("%s: failed - invalid memory range dst = 0x%lx, "
		    "len = 0x%zx", __func__, dst, len);
		return (EINVAL);
	}

	off = dst - vmr->vmr_gpa;
	while (len != 0) {
		n = vmr->vmr_size - off;
		if (len < n)
			n = len;

		to = (char *)vmr->vmr_va + off;
		if (buf == NULL)
			memset(to, 0, n);
		else {
			memcpy(to, from, n);
			from += n;
		}
		len -= n;
		off = 0;
		vmr++;
	}

	return (0);
}

/*
 * read_mem
 *
 * Reads memory at guest paddr 'src' into 'buf'.
 */
int
read_mem(paddr_t src, void *buf, size_t len)
{
	char *from, *to = buf;
	size_t n, off;
	struct vm_mem_range *vmr;

	vmr = find_gpa_range(&current_vm->vm_params, src, len);
	if (vmr == NULL) {
		errno = EINVAL;
		log_warn("%s: failed - invalid memory range src = 0x%lx, "
		    "len = 0x%zx", __func__, src, len);
		return (EINVAL);
	}

	off = src - vmr->vmr_gpa;
	while (len != 0) {
		n = vmr->vmr_size - off;
		if (len < n)
			n = len;

		from = (char *)vmr->vmr_va + off;
		memcpy(to, from, n);

		to += n;
		len -= n;
		off = 0;
		vmr++;
	}

	return (0);
}

/*
 * hvaddr_mem
 *
 * Translate a guest physical address to a host virtual address.
 */
void *
hvaddr_mem(paddr_t gpa, size_t len)
{
	struct vm_mem_range *vmr;
	size_t off;

	vmr = find_gpa_range(&current_vm->vm_params, gpa, len);
	if (vmr == NULL) {
		log_warnx("%s: failed - invalid gpa: 0x%lx\n", __func__, gpa);
		errno = EFAULT;
		return (NULL);
	}

	off = gpa - vmr->vmr_gpa;
	if (len > (vmr->vmr_size - off)) {
		log_warnx("%s: length 0x%lx exceeds region size 0x%lx",
		    __func__, len, vmr->vmr_size);
		errno = EINVAL;
		return (NULL);
	}

	return ((void *)((vaddr_t)vmr->vmr_va + off));
}

void
mmio_init(void)
{
	SLIST_INIT(&mmio_devs);
}

int
mmio_dev_add(paddr_t start, paddr_t end, mmio_dev_fn_t fn)
{
	struct mmio_dev *dev;

	dev = malloc(sizeof(*dev));
	if (!dev)
		return (ENOMEM);

	dev->start = start;
	dev->end = end;
	dev->fn = fn;

	SLIST_INSERT_HEAD(&mmio_devs, dev, dev_next);
	log_debug("%s: added mmio handler for range [0x%lx - 0x%lx]",
	    __func__, start, end);

	return (0);
}

mmio_dev_fn_t
mmio_find_dev(paddr_t addr)
{
	struct mmio_dev *dev;

	SLIST_FOREACH(dev, &mmio_devs, dev_next) {
		if (addr >= dev->start && addr <= dev->end)
			return (dev->fn);
	}

	return (NULL);
}

int
intr_pending(int vcpu_id)
{
	return (0);
}

void
intr_toggle_el(struct vmd_vm *vm, int irq, int val)
{
}

int
intr_ack(int vcpu_id)
{
	return (0xffff);
}

void
vcpu_assert_vector(int fd, uint32_t vcpu_id, uint8_t vector)
{
	if (vcpu_intr(fd, vcpu_id, 1))
		log_debug("%s: can't assert vector", __func__);
	vcpu_unhalt(vcpu_id);
	vcpu_signal_run(vcpu_id);
}

void
vcpu_assert_irq(int fd, uint32_t vcpu_id, int vector)
{
	if (vcpu_intr(fd, vcpu_id, 1))
		log_debug("%s: can't assert INTR", __func__);
	vcpu_unhalt(vcpu_id);
	vcpu_signal_run(vcpu_id);
}

void
vcpu_deassert_irq(int fd, uint32_t vcpu_id, int vector)
{
}

static int
vcpu_exit_data_abort(struct vm_run_params *vrp)
{
	struct vm_exit *ve = vrp->vrp_exit;
	struct vm_exit_data_abort *vda = &ve->vda;
	mmio_dev_fn_t fn;
	uint64_t data = 0;
	int dir, ret;
	uint8_t reg, size;

	if (!vda->vda_isv) {
		log_warnx("%s: data abort without valid syndrome (gpa=0x%llx)",
		    __func__, (unsigned long long)vda->vda_gpa);
		return (1);
	}

	fn = mmio_find_dev(vda->vda_gpa);
	if (fn == NULL) {
		log_warnx("%s: no mmio device for gpa 0x%llx",
		    __func__, (unsigned long long)vda->vda_gpa);
		return (1);
	}

	size = 1 << vda->vda_sas;
	dir = vda->vda_wnr ? MMIO_DIR_WRITE : MMIO_DIR_READ;
	reg = vda->vda_reg;

	if (dir == MMIO_DIR_WRITE) {
		if (reg < VCPU_REGS_NGPRS)
			data = ve->vrs.vrs_gprs[reg];
		else
			data = 0;
	}

	ret = fn(vrp->vrp_vcpu_id, dir, vda->vda_gpa, size, &data);
	if (ret != 0)
		return (ret);

	if (dir == MMIO_DIR_READ) {
		if (reg < VCPU_REGS_NGPRS) {
			if (size == 1)
				ve->vrs.vrs_gprs[reg] = (uint8_t)data;
			else if (size == 2)
				ve->vrs.vrs_gprs[reg] = (uint16_t)data;
			else if (size == 4)
				ve->vrs.vrs_gprs[reg] = (uint32_t)data;
			else
				ve->vrs.vrs_gprs[reg] = data;
		}
	}

	ve->vrs.vrs_pc += 4;
	return (0);
}

int
vcpu_exit(struct vm_run_params *vrp)
{
	int ret;

	switch (vrp->vrp_exit_reason) {
	case VM_EXIT_ARM64_WFI:
		vcpu_halt(vrp->vrp_vcpu_id, 1);
		break;
	case VM_EXIT_ARM64_DATA_ABORT:
		ret = vcpu_exit_data_abort(vrp);
		if (ret)
			return (ret);
		break;
	case VM_EXIT_ARM64_HVC:
	case VM_EXIT_ARM64_SMC:
		/* Unhandled hypercalls return -1 in X0 */
		vrp->vrp_exit->vrs.vrs_gprs[0] = (uint64_t)-1;
		break;
	case VM_EXIT_NONE:
		break;
	default:
		log_warnx("%s: unknown exit reason 0x%x", __func__,
		    vrp->vrp_exit_reason);
		return (1);
	}

	return (0);
}

uint8_t
vcpu_exit_pci(struct vm_run_params *vrp)
{
	return (0xff);
}

int
sev_init(struct vmd_vm *vm)
{
	return (0);
}

int
sev_shutdown(struct vmd_vm *vm)
{
	return (0);
}

int
sev_activate(struct vmd_vm *vm, int vcpu_id)
{
	return (0);
}

int
sev_encrypt_memory(struct vmd_vm *vm)
{
	return (0);
}

int
sev_encrypt_state(struct vmd_vm *vm, int vcpu_id)
{
	return (0);
}

int
sev_launch_finalize(struct vmd_vm *vm)
{
	return (0);
}

void
psp_setup(void)
{
}

uint64_t
lapic_targets(uint8_t dest, int dest_mode)
{
	return (0);
}

int
lapic_lowest_priority(uint64_t targets, uint32_t arb_id)
{
	return (-1);
}
