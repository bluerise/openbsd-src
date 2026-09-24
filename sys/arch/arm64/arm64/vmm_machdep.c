/*	$OpenBSD$	*/
/*
 * Copyright (c) 2026 OpenBSD
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
#include <sys/systm.h>
#include <sys/device.h>
#include <sys/file.h>
#include <sys/pool.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/ioctl.h>
#include <sys/rwlock.h>

#include <uvm/uvm_extern.h>

#include <machine/armreg.h>
#include <machine/cpufunc.h>
#include <machine/cpu.h>
#include <machine/hypervisor.h>
#include <machine/vmmvar.h>
#include <dev/vmm/vmm.h>

int arm64_vhe_enter_guest(struct vcpu *);

static inline int
vmm_has_vhe(void)
{
	uint64_t mmfr1;
	uint64_t el;

	el = READ_SPECIALREG(CurrentEL) & CURRENTEL_EL_MASK;
	if (el != CURRENTEL_EL_EL2)
		return (0);

	mmfr1 = READ_SPECIALREG(id_aa64mmfr1_el1);
	if (ID_AA64MMFR1_VH(mmfr1) < ID_AA64MMFR1_VH_IMPL)
		return (0);

	return (1);
}

int
vmm_probe_machdep(struct device *parent, void *match, void *aux)
{
	uint64_t pfr0;

	pfr0 = READ_SPECIALREG(id_aa64pfr0_el1);
	if (ID_AA64PFR0_EL2(pfr0) == ID_AA64PFR0_EL2_NONE)
		return (0);

	/* Currently we require ARMv8.1-A VHE support */
	if (!vmm_has_vhe())
		return (0);

	return (1);
}

void
vmm_attach_machdep(struct device *parent, struct device *self, void *aux)
{
	struct vmm_softc *sc = (struct vmm_softc *)self;
	uint64_t pfr0, vtr;

	sc->sc_md.has_vhe = vmm_has_vhe();
	sc->mode = VMM_MODE_ARM64;

	pfr0 = READ_SPECIALREG(id_aa64pfr0_el1);
	if (ID_AA64PFR0_GIC(pfr0) != ID_AA64PFR0_GIC_CPUIF_NONE) {
		sc->sc_md.has_gicv3 = 1;
		vtr = READ_SPECIALREG(ich_vtr_el2);
		sc->sc_md.nr_lrs = ((vtr & ICH_VTR_LIST_MASK) >>
		    ICH_VTR_LIST_SHIFT) + 1;
		if (sc->sc_md.nr_lrs > VMM_ARM64_MAX_LRS)
			sc->sc_md.nr_lrs = VMM_ARM64_MAX_LRS;
	}

	printf(": ARM64 (VHE%s)", sc->sc_md.has_gicv3 ? ", GICv3" : "");
}

void
vmm_activate_machdep(struct device *self, int act)
{
}

int
vmm_start(void)
{
	return (0);
}

int
vmm_stop(void)
{
	return (0);
}

int
vm_impl_init(struct vm *vm, struct proc *p)
{
	pmap_convert(vm->vm_pmap, PMAP_TYPE_STAGE2);
	return (0);
}

void
vm_impl_deinit(struct vm *vm)
{
}

int
vcpu_init(struct vcpu *vcpu, struct vm_create_params *vcp)
{
	uint64_t mmfr0, vtcr;

	vcpu->vc_virt_mode = vmm_softc->mode;
	vcpu->vc_state = VCPU_STATE_STOPPED;
	vcpu->vc_vpid = vcpu->vc_parent->vm_id;
	vcpu->vc_last_pcpu = NULL;
	rw_init(&vcpu->vc_lock, "vcpu");

	/* Initial HCR_EL2 configuration for 64-bit guest execution */
	vcpu->vc_hcr_el2 = HCR_RW | HCR_VM | HCR_AMO | HCR_IMO | HCR_FMO |
	    HCR_TWI;

	/* Setup VTCR_EL2 and VTTBR_EL2 for Stage 2 translation */
	mmfr0 = READ_SPECIALREG(id_aa64mmfr0_el1);
	vtcr = VTCR_RES1 | VTCR_TG0_4K | VTCR_SH0_INNER |
	    VTCR_ORGN0_WBWA | VTCR_IRGN0_WBWA;
	vtcr |= (ID_AA64MMFR0_PA_RANGE(mmfr0) & 0x7) << VTCR_PS_SHIFT;
	if (vcpu->vc_parent->vm_pmap->have_4_level_pt)
		vtcr |= VTCR_SL0_L0 | VTCR_T0SZ(64 - 48);
	else
		vtcr |= VTCR_SL0_L1 | VTCR_T0SZ(64 - 39);
	vcpu->vc_vtcr_el2 = vtcr;

	vcpu->vc_vttbr_el2 = VTTBR_VMID(vcpu->vc_vpid) |
	    (vcpu->vc_parent->vm_pmap->pm_pt0pa & VTTBR_BADDR_MASK);

	/* Initialize Virtual Timer */
	vcpu->vc_cntvoff_el2 = 0;
	vcpu->vc_cntv_ctl_el0 = 0;
	vcpu->vc_cntv_cval_el0 = 0;

	/* Initialize GICv3 virtual CPU interface */
	if (vmm_softc->sc_md.has_gicv3) {
		vcpu->vc_gic.vg_hcr = ICH_HCR_EN;
		vcpu->vc_gic.vg_vmcr = ICH_VMCR_VENG1 |
		    (0xffULL << ICH_VMCR_VPMR_SHIFT);
		vcpu->vc_gic.vg_nr_lrs = vmm_softc->sc_md.nr_lrs;
	}

	return (0);
}

void
vcpu_deinit(struct vcpu *vcpu)
{
}

int
vcpu_reset_regs(struct vcpu *vcpu, struct vcpu_reg_state *vrs)
{
	int i;

	if (vrs != NULL) {
		for (i = 0; i < VCPU_REGS_NGPRS; i++)
			vcpu->vc_regs.vrs_gprs[i] = vrs->vrs_gprs[i];
		vcpu->vc_regs.vrs_pc = vrs->vrs_pc;
		vcpu->vc_regs.vrs_sp = vrs->vrs_sp;
		vcpu->vc_regs.vrs_spsr = vrs->vrs_spsr;
	} else {
		memset(&vcpu->vc_regs, 0, sizeof(vcpu->vc_regs));
		vcpu->vc_regs.vrs_spsr = PSR_M_EL1h | PSR_F | PSR_I | PSR_A | PSR_D;
	}

	memset(&vcpu->vc_exit, 0, sizeof(vcpu->vc_exit));
	vcpu->vc_inject.vie_type = VCPU_INJECT_NONE;
	vcpu->vc_intr = 0;
	atomic_swap_uint(&vcpu->vc_intr_latch, 0);
	vcpu->vc_irqready = 0;

	/* Reset virtual timer and GIC state */
	vcpu->vc_cntv_ctl_el0 = 0;
	vcpu->vc_cntv_cval_el0 = 0;
	if (vmm_softc->sc_md.has_gicv3) {
		memset(vcpu->vc_gic.vg_lr, 0, sizeof(vcpu->vc_gic.vg_lr));
		memset(vcpu->vc_gic.vg_ap0r, 0, sizeof(vcpu->vc_gic.vg_ap0r));
		memset(vcpu->vc_gic.vg_ap1r, 0, sizeof(vcpu->vc_gic.vg_ap1r));
		vcpu->vc_gic.vg_vmcr = ICH_VMCR_VENG1 |
		    (0xffULL << ICH_VMCR_VPMR_SHIFT);
	}

	return (0);
}

int
vm_rwregs(struct vm *vm, struct vm_rwregs_params *vrwp, int dir)
{
	struct vcpu *vcpu;
	struct vcpu_reg_state *vrs;
	int i, ret = 0;

	vcpu = vm_find_vcpu(vm, vrwp->vrwp_vcpu_id);
	if (vcpu == NULL)
		return (ENOENT);

	vrs = &vrwp->vrwp_regs;
	rw_enter_write(&vcpu->vc_lock);
	if (dir == 0) {
		if (vrwp->vrwp_mask & VM_RWREGS_GPRS) {
			for (i = 0; i < VCPU_REGS_NGPRS; i++)
				vrs->vrs_gprs[i] = vcpu->vc_regs.vrs_gprs[i];
		}
		if (vrwp->vrwp_mask & VM_RWREGS_PC)
			vrs->vrs_pc = vcpu->vc_regs.vrs_pc;
		if (vrwp->vrwp_mask & VM_RWREGS_SP)
			vrs->vrs_sp = vcpu->vc_regs.vrs_sp;
		if (vrwp->vrwp_mask & VM_RWREGS_SPSR)
			vrs->vrs_spsr = vcpu->vc_regs.vrs_spsr;
	} else {
		if (vrwp->vrwp_mask & VM_RWREGS_GPRS) {
			for (i = 0; i < VCPU_REGS_NGPRS; i++)
				vcpu->vc_regs.vrs_gprs[i] = vrs->vrs_gprs[i];
		}
		if (vrwp->vrwp_mask & VM_RWREGS_PC)
			vcpu->vc_regs.vrs_pc = vrs->vrs_pc;
		if (vrwp->vrwp_mask & VM_RWREGS_SP)
			vcpu->vc_regs.vrs_sp = vrs->vrs_sp;
		if (vrwp->vrwp_mask & VM_RWREGS_SPSR)
			vcpu->vc_regs.vrs_spsr = vrs->vrs_spsr;
	}
	rw_exit_write(&vcpu->vc_lock);

	return (ret);
}

int
vm_rwvmparams(struct vm *vm, struct vm_rwvmparams_params *vpp, int dir)
{
	struct vcpu *vcpu;

	vcpu = vm_find_vcpu(vm, vpp->vpp_vcpu_id);
	if (vcpu == NULL)
		return (ENOENT);

	return (0);
}

int
vm_intr_pending(struct vm *vm, struct vm_intr_params *vip)
{
	struct vcpu *vcpu;
#ifdef MULTIPROCESSOR
	struct cpu_info *ci;
#endif

	vcpu = vm_find_vcpu(vm, vip->vip_vcpu_id);
	if (vcpu == NULL)
		return (ENOENT);

	if (vip->vip_intr)
		atomic_setbits_int(&vcpu->vc_intr_latch, 1);

#ifdef MULTIPROCESSOR
	ci = READ_ONCE(vcpu->vc_curcpu);
	if (ci != NULL)
		vmm_nudge_cpu(ci);
#endif

	return (0);
}

static void
vmm_save_guest_sysregs(struct vcpu *vcpu)
{
	vcpu->vc_sp_el0 = READ_SPECIALREG(sp_el0);
	vcpu->vc_sp_el1 = READ_SPECIALREG(sp_el1);
	vcpu->vc_elr_el1 = READ_SPECIALREG(elr_el1);
	vcpu->vc_spsr_el1 = READ_SPECIALREG(spsr_el1);
	vcpu->vc_sctlr_el1 = READ_SPECIALREG(sctlr_el1);
	vcpu->vc_cpacr_el1 = READ_SPECIALREG(cpacr_el1);
	vcpu->vc_ttbr0_el1 = READ_SPECIALREG(ttbr0_el1);
	vcpu->vc_ttbr1_el1 = READ_SPECIALREG(ttbr1_el1);
	vcpu->vc_tcr_el1 = READ_SPECIALREG(tcr_el1);
	vcpu->vc_esr_el1 = READ_SPECIALREG(esr_el1);
	vcpu->vc_far_el1 = READ_SPECIALREG(far_el1);
	vcpu->vc_mair_el1 = READ_SPECIALREG(mair_el1);
	vcpu->vc_vbar_el1 = READ_SPECIALREG(vbar_el1);
	vcpu->vc_contextidr_el1 = READ_SPECIALREG(contextidr_el1);
	vcpu->vc_tpidr_el0 = READ_SPECIALREG(tpidr_el0);
	vcpu->vc_tpidr_el1 = READ_SPECIALREG(tpidr_el1);
	vcpu->vc_tpidrro_el0 = READ_SPECIALREG(tpidrro_el0);
}

static void
vmm_restore_guest_sysregs(struct vcpu *vcpu)
{
	WRITE_SPECIALREG(sp_el0, vcpu->vc_sp_el0);
	WRITE_SPECIALREG(sp_el1, vcpu->vc_sp_el1);
	WRITE_SPECIALREG(elr_el1, vcpu->vc_elr_el1);
	WRITE_SPECIALREG(spsr_el1, vcpu->vc_spsr_el1);
	WRITE_SPECIALREG(sctlr_el1, vcpu->vc_sctlr_el1);
	WRITE_SPECIALREG(cpacr_el1, vcpu->vc_cpacr_el1);
	WRITE_SPECIALREG(ttbr0_el1, vcpu->vc_ttbr0_el1);
	WRITE_SPECIALREG(ttbr1_el1, vcpu->vc_ttbr1_el1);
	WRITE_SPECIALREG(tcr_el1, vcpu->vc_tcr_el1);
	WRITE_SPECIALREG(esr_el1, vcpu->vc_esr_el1);
	WRITE_SPECIALREG(far_el1, vcpu->vc_far_el1);
	WRITE_SPECIALREG(mair_el1, vcpu->vc_mair_el1);
	WRITE_SPECIALREG(vbar_el1, vcpu->vc_vbar_el1);
	WRITE_SPECIALREG(contextidr_el1, vcpu->vc_contextidr_el1);
	WRITE_SPECIALREG(tpidr_el0, vcpu->vc_tpidr_el0);
	WRITE_SPECIALREG(tpidr_el1, vcpu->vc_tpidr_el1);
	WRITE_SPECIALREG(tpidrro_el0, vcpu->vc_tpidrro_el0);
	__asm volatile("isb" ::: "memory");
}

static void
vmm_restore_guest_timer(struct vcpu *vcpu)
{
	WRITE_SPECIALREG(cntvoff_el2, vcpu->vc_cntvoff_el2);
	WRITE_SPECIALREG(cntv_cval_el0, vcpu->vc_cntv_cval_el0);
	WRITE_SPECIALREG(cntv_ctl_el0, vcpu->vc_cntv_ctl_el0);
	__asm volatile("isb" ::: "memory");
}

static void
vmm_save_guest_timer(struct vcpu *vcpu)
{
	vcpu->vc_cntv_ctl_el0 = READ_SPECIALREG(cntv_ctl_el0);
	vcpu->vc_cntv_cval_el0 = READ_SPECIALREG(cntv_cval_el0);

	/* Disable virtual timer in host context and clear offset */
	WRITE_SPECIALREG(cntv_ctl_el0, 0);
	WRITE_SPECIALREG(cntvoff_el2, 0);
	__asm volatile("isb" ::: "memory");
}

static void
vmm_restore_guest_gic(struct vcpu *vcpu)
{
	int i, nr_lrs;

	if (!vmm_softc->sc_md.has_gicv3)
		return;

	nr_lrs = vcpu->vc_gic.vg_nr_lrs;
	WRITE_SPECIALREG(ich_vmcr_el2, vcpu->vc_gic.vg_vmcr);
	WRITE_SPECIALREG(ich_hcr_el2, vcpu->vc_gic.vg_hcr);

	WRITE_SPECIALREG(ich_ap0r0_el2, vcpu->vc_gic.vg_ap0r[0]);
	WRITE_SPECIALREG(ich_ap1r0_el2, vcpu->vc_gic.vg_ap1r[0]);

	for (i = 0; i < nr_lrs; i++) {
		switch (i) {
		case 0:  WRITE_SPECIALREG(ich_lr0_el2, vcpu->vc_gic.vg_lr[0]); break;
		case 1:  WRITE_SPECIALREG(ich_lr1_el2, vcpu->vc_gic.vg_lr[1]); break;
		case 2:  WRITE_SPECIALREG(ich_lr2_el2, vcpu->vc_gic.vg_lr[2]); break;
		case 3:  WRITE_SPECIALREG(ich_lr3_el2, vcpu->vc_gic.vg_lr[3]); break;
		case 4:  WRITE_SPECIALREG(ich_lr4_el2, vcpu->vc_gic.vg_lr[4]); break;
		case 5:  WRITE_SPECIALREG(ich_lr5_el2, vcpu->vc_gic.vg_lr[5]); break;
		case 6:  WRITE_SPECIALREG(ich_lr6_el2, vcpu->vc_gic.vg_lr[6]); break;
		case 7:  WRITE_SPECIALREG(ich_lr7_el2, vcpu->vc_gic.vg_lr[7]); break;
		case 8:  WRITE_SPECIALREG(ich_lr8_el2, vcpu->vc_gic.vg_lr[8]); break;
		case 9:  WRITE_SPECIALREG(ich_lr9_el2, vcpu->vc_gic.vg_lr[9]); break;
		case 10: WRITE_SPECIALREG(ich_lr10_el2, vcpu->vc_gic.vg_lr[10]); break;
		case 11: WRITE_SPECIALREG(ich_lr11_el2, vcpu->vc_gic.vg_lr[11]); break;
		case 12: WRITE_SPECIALREG(ich_lr12_el2, vcpu->vc_gic.vg_lr[12]); break;
		case 13: WRITE_SPECIALREG(ich_lr13_el2, vcpu->vc_gic.vg_lr[13]); break;
		case 14: WRITE_SPECIALREG(ich_lr14_el2, vcpu->vc_gic.vg_lr[14]); break;
		case 15: WRITE_SPECIALREG(ich_lr15_el2, vcpu->vc_gic.vg_lr[15]); break;
		}
	}
	__asm volatile("isb" ::: "memory");
}

static void
vmm_save_guest_gic(struct vcpu *vcpu)
{
	int i, nr_lrs;

	if (!vmm_softc->sc_md.has_gicv3)
		return;

	nr_lrs = vcpu->vc_gic.vg_nr_lrs;
	vcpu->vc_gic.vg_hcr = READ_SPECIALREG(ich_hcr_el2);
	vcpu->vc_gic.vg_vmcr = READ_SPECIALREG(ich_vmcr_el2);
	vcpu->vc_gic.vg_misr = READ_SPECIALREG(ich_misr_el2);
	vcpu->vc_gic.vg_eisr = READ_SPECIALREG(ich_eisr_el2);
	vcpu->vc_gic.vg_elrsr = READ_SPECIALREG(ich_elrsr_el2);

	vcpu->vc_gic.vg_ap0r[0] = READ_SPECIALREG(ich_ap0r0_el2);
	vcpu->vc_gic.vg_ap1r[0] = READ_SPECIALREG(ich_ap1r0_el2);

	for (i = 0; i < nr_lrs; i++) {
		switch (i) {
		case 0:  vcpu->vc_gic.vg_lr[0] = READ_SPECIALREG(ich_lr0_el2); break;
		case 1:  vcpu->vc_gic.vg_lr[1] = READ_SPECIALREG(ich_lr1_el2); break;
		case 2:  vcpu->vc_gic.vg_lr[2] = READ_SPECIALREG(ich_lr2_el2); break;
		case 3:  vcpu->vc_gic.vg_lr[3] = READ_SPECIALREG(ich_lr3_el2); break;
		case 4:  vcpu->vc_gic.vg_lr[4] = READ_SPECIALREG(ich_lr4_el2); break;
		case 5:  vcpu->vc_gic.vg_lr[5] = READ_SPECIALREG(ich_lr5_el2); break;
		case 6:  vcpu->vc_gic.vg_lr[6] = READ_SPECIALREG(ich_lr6_el2); break;
		case 7:  vcpu->vc_gic.vg_lr[7] = READ_SPECIALREG(ich_lr7_el2); break;
		case 8:  vcpu->vc_gic.vg_lr[8] = READ_SPECIALREG(ich_lr8_el2); break;
		case 9:  vcpu->vc_gic.vg_lr[9] = READ_SPECIALREG(ich_lr9_el2); break;
		case 10: vcpu->vc_gic.vg_lr[10] = READ_SPECIALREG(ich_lr10_el2); break;
		case 11: vcpu->vc_gic.vg_lr[11] = READ_SPECIALREG(ich_lr11_el2); break;
		case 12: vcpu->vc_gic.vg_lr[12] = READ_SPECIALREG(ich_lr12_el2); break;
		case 13: vcpu->vc_gic.vg_lr[13] = READ_SPECIALREG(ich_lr13_el2); break;
		case 14: vcpu->vc_gic.vg_lr[14] = READ_SPECIALREG(ich_lr14_el2); break;
		case 15: vcpu->vc_gic.vg_lr[15] = READ_SPECIALREG(ich_lr15_el2); break;
		}
	}

	WRITE_SPECIALREG(ich_hcr_el2, 0);
	__asm volatile("isb" ::: "memory");
}

static void
vmm_inject_intr(struct vcpu *vcpu)
{
	uint64_t lr;
	uint32_t vector;
	int i, nr_lrs;

	if (vcpu->vc_inject.vie_type != VCPU_INJECT_INTR &&
	    atomic_load_int(&vcpu->vc_intr_latch) == 0)
		return;

	vector = (vcpu->vc_inject.vie_type == VCPU_INJECT_INTR) ?
	    vcpu->vc_inject.vie_vector : 0;

	if (vmm_softc->sc_md.has_gicv3) {
		nr_lrs = vcpu->vc_gic.vg_nr_lrs;

		for (i = 0; i < nr_lrs; i++) {
			lr = vcpu->vc_gic.vg_lr[i];
			if ((lr & ICH_LR_STATE_MASK) != ICH_LR_STATE_INVALID &&
			    (lr & ICH_LR_VINTID_MASK) == vector) {
				vcpu->vc_inject.vie_type = VCPU_INJECT_NONE;
				atomic_swap_uint(&vcpu->vc_intr_latch, 0);
				return;
			}
		}

		for (i = 0; i < nr_lrs; i++) {
			if ((vcpu->vc_gic.vg_lr[i] & ICH_LR_STATE_MASK) ==
			    ICH_LR_STATE_INVALID) {
				vcpu->vc_gic.vg_lr[i] = (uint64_t)vector |
				    ICH_LR_GROUP | ICH_LR_STATE_PENDING |
				    ((uint64_t)0xa0 << ICH_LR_PRIORITY_SHIFT);
				vcpu->vc_inject.vie_type = VCPU_INJECT_NONE;
				atomic_swap_uint(&vcpu->vc_intr_latch, 0);
				return;
			}
		}
	}

	/* Fallback: assert Virtual IRQ via HCR_VI */
	vcpu->vc_hcr_el2 |= HCR_VI;
	vcpu->vc_inject.vie_type = VCPU_INJECT_NONE;
	atomic_swap_uint(&vcpu->vc_intr_latch, 0);
}

int
vmm_get_guest_memtype(struct vm *vm, paddr_t gpa)
{
	struct vm_mem_range *vmr;
	int i;

	for (i = 0; i < vm->vm_nmemranges; i++) {
		vmr = &vm->vm_memranges[i];
		if (gpa < vmr->vmr_gpa)
			break;

		if (gpa < vmr->vmr_gpa + vmr->vmr_size) {
			if (vmr->vmr_type == VM_MEM_MMIO)
				return (VMM_MEM_TYPE_MMIO);
			return (VMM_MEM_TYPE_REGULAR);
		}
	}

	return (VMM_MEM_TYPE_UNKNOWN);
}

vaddr_t
vmm_translate_gpa(struct vm *vm, paddr_t gpa)
{
	struct vm_mem_range *vmr;
	vaddr_t hva = 0;
	int i;

	for (i = 0; i < vm->vm_nmemranges; i++) {
		vmr = &vm->vm_memranges[i];
		if (gpa >= vmr->vmr_gpa && gpa < vmr->vmr_gpa + vmr->vmr_size) {
			hva = vmr->vmr_va + (gpa - vmr->vmr_gpa);
			break;
		}
	}

	return (hva);
}

static enum vmm_action
vmm_fault_page(struct vcpu *vcpu, paddr_t gpa)
{
	struct proc *p = curproc;
	paddr_t hpa, pa = trunc_page(gpa);
	vaddr_t hva;
	int ret;

	hva = vmm_translate_gpa(vcpu->vc_parent, pa);
	if (hva == 0) {
		printf("%s: unable to translate gpa 0x%llx\n", __func__,
		    (uint64_t)pa);
		return (VMM_ACTION_TERMINATE);
	}

	/* If we don't already have a backing page... */
	if (!pmap_extract(p->p_vmspace->vm_map.pmap, hva, &hpa)) {
		/* ...fault a RW page into the process address space... */
		ret = uvm_fault_wire(&p->p_vmspace->vm_map, hva,
		    hva + PAGE_SIZE, PROT_READ | PROT_WRITE);
		if (ret) {
			printf("%s: uvm_fault failed %d hva=0x%llx\n", __func__,
			    ret, (uint64_t)hva);
			return (VMM_ACTION_TERMINATE);
		}

		/* ...and then get the mapping. */
		if (!pmap_extract(p->p_vmspace->vm_map.pmap, hva, &hpa)) {
			printf("%s: failed to extract hpa for hva 0x%llx\n",
			    __func__, (uint64_t)hva);
			return (VMM_ACTION_TERMINATE);
		}
	}

	/* Insert a RWX mapping into the guest's stage 2 pmap. */
	ret = pmap_enter(vcpu->vc_parent->vm_pmap, pa, hpa,
	    PROT_READ | PROT_WRITE | PROT_EXEC,
	    PROT_READ | PROT_WRITE | PROT_EXEC | PMAP_WIRED);
	if (ret) {
		printf("%s: pmap_enter failed pa=0x%llx, hpa=0x%llx\n",
		    __func__, (uint64_t)pa, (uint64_t)hpa);
		return (VMM_ACTION_TERMINATE);
	}

	return (VMM_ACTION_RETRY);
}

static enum vmm_action
vmm_vhe_handle_exit(struct vcpu *vcpu, struct vm_run_params *vrp)
{
	uint64_t gpa;
	uint32_t ec, esr = vcpu->vc_esr_el2;
	int memtype;

	if (vcpu->vc_exit_type == VCPU_EXIT_TYPE_IRQ ||
	    vcpu->vc_exit_type == VCPU_EXIT_TYPE_FIQ)
		return (VMM_ACTION_RETRY);

	if (vcpu->vc_exit_type == VCPU_EXIT_TYPE_SERROR) {
		vrp->vrp_exit_reason = VM_EXIT_ARM64_UNKNOWN;
		return (VMM_ACTION_TERMINATE);
	}

	ec = ESR_ELx_EXCEPTION(esr);
	switch (ec) {
	case EXCP_UNKNOWN:
		vrp->vrp_exit_reason = VM_EXIT_ARM64_UNKNOWN;
		break;
	case EXCP_WFI_WFE:
		vcpu->vc_regs.vrs_pc += 4;
		vrp->vrp_exit_reason = VM_EXIT_ARM64_WFI;
		break;
	case EXCP_FP_SIMD:
	case EXCP_TRAP_FP:
		vrp->vrp_exit_reason = VM_EXIT_ARM64_FP_TRAP;
		break;
	case EXCP_HVC:
		vcpu->vc_regs.vrs_pc += 4;
		vrp->vrp_exit_reason = VM_EXIT_ARM64_HVC;
		break;
	case EXCP_SMC:
		vcpu->vc_regs.vrs_pc += 4;
		vrp->vrp_exit_reason = VM_EXIT_ARM64_SMC;
		break;
	case EXCP_MSR:
		vrp->vrp_exit_reason = VM_EXIT_ARM64_SYSREG;
		break;
	case EXCP_INSN_ABORT_L:
		gpa = ((vcpu->vc_hpfar_el2 & 0x00000ffffffffff0ULL) << 8) |
		    (vcpu->vc_far_el2 & PAGE_MASK);
		memtype = vmm_get_guest_memtype(vcpu->vc_parent, gpa);
		if (memtype == VMM_MEM_TYPE_REGULAR)
			return (vmm_fault_page(vcpu, gpa));

		vrp->vrp_exit_reason = VM_EXIT_ARM64_INSN_ABORT;
		return (VMM_ACTION_TERMINATE);
	case EXCP_DATA_ABORT_L:
		gpa = ((vcpu->vc_hpfar_el2 & 0x00000ffffffffff0ULL) << 8) |
		    (vcpu->vc_far_el2 & PAGE_MASK);
		memtype = vmm_get_guest_memtype(vcpu->vc_parent, gpa);
		switch (memtype) {
		case VMM_MEM_TYPE_REGULAR:
			return (vmm_fault_page(vcpu, gpa));
		case VMM_MEM_TYPE_MMIO:
			vrp->vrp_exit_reason = VM_EXIT_ARM64_DATA_ABORT;
			vrp->vrp_exit->vda.vda_esr = esr;
			vrp->vrp_exit->vda.vda_far = vcpu->vc_far_el2;
			vrp->vrp_exit->vda.vda_gpa = gpa;
			if (esr & ISS_DATA_ISV) {
				vrp->vrp_exit->vda.vda_isv = 1;
				vrp->vrp_exit->vda.vda_sas =
				    (esr & ISS_DATA_SAS_MASK) >> 22;
				vrp->vrp_exit->vda.vda_wnr =
				    (esr & ISS_DATA_WnR) ? 1 : 0;
				vrp->vrp_exit->vda.vda_reg =
				    (esr & ISS_DATA_SRT_MASK) >> 16;
			} else {
				vrp->vrp_exit->vda.vda_isv = 0;
			}
			return (VMM_ACTION_ASSIST);
		default:
			printf("%s: unknown memory type %d for GPA 0x%llx\n",
			    __func__, memtype, (uint64_t)gpa);
			return (VMM_ACTION_TERMINATE);
		}
		break;
	default:
		vrp->vrp_exit_reason = VM_EXIT_ARM64_UNKNOWN;
		break;
	}

	return (VMM_ACTION_ASSIST);
}

int
vm_run(struct vm *vm, struct vm_run_params *vrp)
{
	struct vcpu *vcpu;
	enum vmm_action action;
	uint64_t host_cnthctl, host_hcr;
	u_int next, old;
	int ret = 0;

	vcpu = vm_find_vcpu(vm, vrp->vrp_vcpu_id);
	if (vcpu == NULL) {
		ret = ENOENT;
		goto out;
	}

	rw_enter_write(&vcpu->vc_lock);

	ret = copyin(vrp->vrp_exit, &vcpu->vc_exit, sizeof(struct vm_exit));
	if (ret)
		goto out_unlock;

	old = VCPU_STATE_STOPPED;
	next = VCPU_STATE_RUNNING;
	if (atomic_cas_uint(&vcpu->vc_state, old, next) != old) {
		ret = EBUSY;
		goto out_unlock;
	}

	/* Update register state from copyin */
	vcpu->vc_regs = vcpu->vc_exit.vrs;

	vcpu->vc_inject.vie_type = vrp->vrp_inject.vie_type;
	vcpu->vc_inject.vie_vector = vrp->vrp_inject.vie_vector;
	vcpu->vc_inject.vie_errorcode = vrp->vrp_inject.vie_errorcode;

	WRITE_ONCE(vcpu->vc_curcpu, curcpu());

	/* Save host HCR_EL2 and CNTHCTL_EL2 */
	host_hcr = READ_SPECIALREG(hcr_el2);
	host_cnthctl = READ_SPECIALREG(cnthctl_el2);

	/* Set up guest Stage-2 translation base */
	WRITE_SPECIALREG(vtcr_el2, vcpu->vc_vtcr_el2);
	WRITE_SPECIALREG(vttbr_el2, vcpu->vc_vttbr_el2);

	/* Allow guest access to counters and virtual timer */
	WRITE_SPECIALREG(cnthctl_el2, host_cnthctl | CNTHCTL_EL1PCEN |
	    CNTHCTL_EL1PCTEN | CNTHCTL_EL1PTEN | CNTHCTL_EL0VTEN |
	    CNTHCTL_EL0PTEN);

	/* Inject pending interrupt if requested */
	vmm_inject_intr(vcpu);

	/* Set guest HCR_EL2 */
	WRITE_SPECIALREG(hcr_el2, vcpu->vc_hcr_el2);
	__asm volatile("isb" ::: "memory");

	/* Restore guest system registers */
	vmm_restore_guest_sysregs(vcpu);

	/* Restore guest virtual timer */
	vmm_restore_guest_timer(vcpu);

	/* Restore guest GICv3 virtual CPU interface */
	vmm_restore_guest_gic(vcpu);

	for (;;) {
		if (vcpu_must_yield(vcpu)) {
			vrp->vrp_exit_reason = VM_EXIT_NONE;
			action = VMM_ACTION_ASSIST;
			break;
		}

		/* Enter guest EL1 */
		arm64_vhe_enter_guest(vcpu);

		/* Classify exit */
		action = vmm_vhe_handle_exit(vcpu, vrp);
		if (action == VMM_ACTION_RETRY) {
			vmm_inject_intr(vcpu);
			WRITE_SPECIALREG(hcr_el2, vcpu->vc_hcr_el2);
			continue;
		}

		break;
	}

	/* Save guest GICv3 virtual CPU interface */
	vmm_save_guest_gic(vcpu);

	/* Save guest virtual timer */
	vmm_save_guest_timer(vcpu);

	/* Restore host HCR_EL2 and CNTHCTL_EL2 */
	WRITE_SPECIALREG(hcr_el2, host_hcr);
	WRITE_SPECIALREG(cnthctl_el2, host_cnthctl);
	__asm volatile("isb" ::: "memory");

	/* Clear temporary HCR_VI if set */
	vcpu->vc_hcr_el2 &= ~HCR_VI;

	/* Save guest system registers */
	vmm_save_guest_sysregs(vcpu);

	WRITE_ONCE(vcpu->vc_curcpu, NULL);

	/* Copy out updated register state */
	vcpu->vc_exit.vrs = vcpu->vc_regs;

	if (action == VMM_ACTION_TERMINATE) {
		vrp->vrp_exit_reason = VM_EXIT_TERMINATED;
		atomic_store_int(&vcpu->vc_state, VCPU_STATE_TERMINATED);
	} else {
		atomic_store_int(&vcpu->vc_state, VCPU_STATE_STOPPED);
	}

	if (copyout(&vcpu->vc_exit, vrp->vrp_exit, sizeof(struct vm_exit)))
		ret = EFAULT;

out_unlock:
	rw_exit_write(&vcpu->vc_lock);
out:
	return (ret);
}
