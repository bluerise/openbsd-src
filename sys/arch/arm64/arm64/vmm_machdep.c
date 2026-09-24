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

	sc->sc_md.has_vhe = vmm_has_vhe();
	sc->mode = VMM_MODE_ARM64;
	printf(": ARM64 (VHE)");
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
	return (0);
}

void
vm_impl_deinit(struct vm *vm)
{
}

int
vcpu_init(struct vcpu *vcpu, struct vm_create_params *vcp)
{
	vcpu->vc_virt_mode = vmm_softc->mode;
	vcpu->vc_state = VCPU_STATE_STOPPED;
	vcpu->vc_vpid = 0;
	vcpu->vc_last_pcpu = NULL;
	rw_init(&vcpu->vc_lock, "vcpu");

	/* Initial HCR_EL2 configuration for 64-bit guest execution */
	vcpu->vc_hcr_el2 = HCR_RW | HCR_VM | HCR_AMO | HCR_IMO | HCR_FMO;

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

static enum vmm_action
vmm_vhe_handle_exit(struct vcpu *vcpu, struct vm_run_params *vrp)
{
	uint32_t ec;
	uint32_t esr = vcpu->vc_esr_el2;

	ec = ESR_ELx_EXCEPTION(esr);
	switch (ec) {
	case EXCP_UNKNOWN:
		vrp->vrp_exit_reason = VM_EXIT_ARM64_UNKNOWN;
		break;
	case EXCP_FP_SIMD:
	case EXCP_TRAP_FP:
		vrp->vrp_exit_reason = VM_EXIT_ARM64_FP_TRAP;
		break;
	case EXCP_HVC:
		vrp->vrp_exit_reason = VM_EXIT_ARM64_HVC;
		break;
	case EXCP_SMC:
		vrp->vrp_exit_reason = VM_EXIT_ARM64_SMC;
		break;
	case EXCP_MSR:
		vrp->vrp_exit_reason = VM_EXIT_ARM64_SYSREG;
		break;
	case EXCP_INSN_ABORT_L:
		vrp->vrp_exit_reason = VM_EXIT_ARM64_INSN_ABORT;
		break;
	case EXCP_DATA_ABORT_L:
		vrp->vrp_exit_reason = VM_EXIT_ARM64_DATA_ABORT;
		vrp->vrp_exit->vda.vda_esr = esr;
		vrp->vrp_exit->vda.vda_far = vcpu->vc_far_el2;
		vrp->vrp_exit->vda.vda_gpa = vcpu->vc_hpfar_el2 << 8;
		if (esr & ISS_DATA_ISV) {
			vrp->vrp_exit->vda.vda_isv = 1;
			vrp->vrp_exit->vda.vda_sas = (esr & ISS_DATA_SAS_MASK) >> 22;
			vrp->vrp_exit->vda.vda_wnr = (esr & ISS_DATA_WnR) ? 1 : 0;
			vrp->vrp_exit->vda.vda_reg = (esr & ISS_DATA_SRT_MASK) >> 16;
		} else {
			vrp->vrp_exit->vda.vda_isv = 0;
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
	uint64_t host_hcr;
	int ret = 0;
	u_int next, old;

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

	/* Save host HCR_EL2 (HCR_E2H | HCR_TGE) */
	host_hcr = READ_SPECIALREG(hcr_el2);

	/* Set up guest Stage-2 translation base and guest HCR_EL2 */
	WRITE_SPECIALREG(vttbr_el2, vcpu->vc_vttbr_el2);
	WRITE_SPECIALREG(hcr_el2, vcpu->vc_hcr_el2);
	__asm volatile("isb" ::: "memory");

	/* Restore guest system registers */
	vmm_restore_guest_sysregs(vcpu);

	/* Enter guest EL1 */
	arm64_vhe_enter_guest(vcpu);

	/* Restore host HCR_EL2 */
	WRITE_SPECIALREG(hcr_el2, host_hcr);
	__asm volatile("isb" ::: "memory");

	/* Save guest system registers */
	vmm_save_guest_sysregs(vcpu);

	WRITE_ONCE(vcpu->vc_curcpu, NULL);

	/* Classify exit */
	vmm_vhe_handle_exit(vcpu, vrp);

	/* Copy out updated register state */
	vcpu->vc_exit.vrs = vcpu->vc_regs;

	atomic_store_int(&vcpu->vc_state, VCPU_STATE_STOPPED);

	if (copyout(&vcpu->vc_exit, vrp->vrp_exit, sizeof(struct vm_exit)))
		ret = EFAULT;

out_unlock:
	rw_exit_write(&vcpu->vc_lock);
out:
	return (ret);
}
