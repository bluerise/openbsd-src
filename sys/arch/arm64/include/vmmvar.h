/*	$OpenBSD: vmmvar.h,v 1.4 2026/09/19 17:21:52 dv Exp $	*/
/*
 * Copyright (c) 2014 Mike Larkin <mlarkin@openbsd.org>
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

/*
 * CPU capabilities for VMM operation
 */
#ifndef _MACHINE_VMMVAR_H_
#define _MACHINE_VMMVAR_H_

#define VMM_HV_SIGNATURE 	"OpenBSDVMM58"

/* Exit Reasons */
#define VM_EXIT_ARM64_UNKNOWN			0
#define VM_EXIT_ARM64_WFI			1
#define VM_EXIT_ARM64_HVC			2
#define VM_EXIT_ARM64_SMC			3
#define VM_EXIT_ARM64_SYSREG			4
#define VM_EXIT_ARM64_INSN_ABORT		5
#define VM_EXIT_ARM64_DATA_ABORT		6
#define VM_EXIT_ARM64_FP_TRAP			7
#define VM_EXIT_TERMINATED			0xFFFE
#define VM_EXIT_NONE				0xFFFF

struct vmm_softc_md {
	/* Capabilities */
	uint32_t		nr_cpus;	/* [I] */
	int			has_vhe;	/* [I] */
};

/*
 * struct vcpu_inject_event	: describes an exception or interrupt to inject.
 */
struct vcpu_inject_event {
	uint8_t		vie_vector;	/* Exception or interrupt vector. */
	uint32_t	vie_errorcode;	/* Optional error code. */
	uint8_t		vie_type;
#define VCPU_INJECT_NONE	0
#define VCPU_INJECT_INTR	1	/* External hardware interrupt. */
#define VCPU_INJECT_EX		2	/* HW or SW Exception */
#define VCPU_INJECT_NMI		3	/* Non-maskable Interrupt */
};

#define VCPU_REGS_NGPRS		31

struct vcpu_reg_state {
	uint64_t			vrs_gprs[VCPU_REGS_NGPRS];
	uint64_t			vrs_pc;
	uint64_t			vrs_sp;
	uint64_t			vrs_spsr;
};

/*
 * struct vm_exit_data_abort: describes a stage 2 data abort (MMIO, page fault)
 */
struct vm_exit_data_abort {
	uint64_t	vda_gpa;		/* Faulting GPA */
	uint64_t	vda_far;		/* Faulting VA */
	uint32_t	vda_esr;		/* ESR_EL2 register */
	uint8_t		vda_isv;		/* Instruction syndrome valid */
	uint8_t		vda_sas;		/* Access size: 0=1B, 1=2B, 2=4B, 3=8B */
	uint8_t		vda_wnr;		/* Write (1) or Read (0) */
	uint8_t		vda_reg;		/* Target register Rt */
};

/*
 * struct vm_exit
 *
 * Contains VM exit information communicated to vmd(8). This information is
 * gathered by vmm(4) from the CPU on each exit that requires help from vmd.
 */
struct vm_exit {
	union {
		struct vm_exit_data_abort	vda;
	};
	struct vcpu_reg_state			vrs;
};

struct vm_intr_params {
	/* Input parameters to VMM_IOC_INTR */
	uint32_t		vip_vcpu_id;
	uint16_t		vip_intr;
};

#define VM_RWREGS_GPRS	0x1	/* read/write GPRs */
#define VM_RWREGS_SPSR	0x2	/* read/write SPSR */
#define VM_RWREGS_PC	0x4	/* read/write PC */
#define VM_RWREGS_SP	0x8	/* read/write SP */
#define VM_RWREGS_ALL	(VM_RWREGS_GPRS | VM_RWREGS_SPSR | VM_RWREGS_PC | VM_RWREGS_SP)

struct vm_rwregs_params {
	/*
	 * Input/output parameters to VMM_IOC_READREGS /
	 * VMM_IOC_WRITEREGS
	 */
	uint32_t		vrwp_vcpu_id;
	uint64_t		vrwp_mask;
	struct vcpu_reg_state	vrwp_regs;
};

enum {
	VEI_DIR_OUT,
	VEI_DIR_IN
};

enum {
	VMM_MODE_UNKNOWN,
	VMM_MODE_ARM64
};

enum {
	VMM_MEM_TYPE_REGULAR,
	VMM_MEM_TYPE_MMIO,
	VMM_MEM_TYPE_UNKNOWN
};

/* IOCTL definitions */
#define VMM_IOC_INTR _IOW('V', 6, struct vm_intr_params) /* Intr pending */

#ifdef _KERNEL

#include <sys/rwlock.h>
#include <sys/queue.h>
#include <machine/reg.h>

struct cpu_info;
struct device;
struct proc;
struct vm;
struct vm_create_params;
struct vm_run_params;
struct vm_rwregs_params;
struct vm_rwvmparams_params;
struct vm_intr_params;

/*
 * Virtual CPU representation for ARM64
 */
struct vcpu {
	struct vm		*vc_parent;	/* [I] */
	uint32_t		 vc_id;		/* [I] */
	uint16_t		 vc_vpid;	/* [I] VMID */
	u_int			 vc_state;	/* [a] */
	SLIST_ENTRY(vcpu)	 vc_vcpu_link;	/* [V] */
	uint8_t			 vc_virt_mode;	/* [I] */

	struct rwlock		 vc_lock;

	struct cpu_info		*vc_curcpu;	/* [a] */
	struct cpu_info		*vc_last_pcpu;	/* [v] */
	struct vm_exit		 vc_exit;	/* [v] */

	uint16_t		 vc_intr;	/* [v] */
	u_int			 vc_intr_latch;	/* [a] */
	uint8_t			 vc_irqready;	/* [v] */
	struct vcpu_inject_event vc_inject;	/* [v] */

	/* Architecture register state */
	struct vcpu_reg_state	 vc_regs;
	uint64_t		 vc_pc;
	uint64_t		 vc_sp_el0;
	uint64_t		 vc_sp_el1;
	uint64_t		 vc_elr_el1;
	uint64_t		 vc_spsr_el1;

	/* System registers */
	uint64_t		 vc_sctlr_el1;
	uint64_t		 vc_actlr_el1;
	uint64_t		 vc_cpacr_el1;
	uint64_t		 vc_ttbr0_el1;
	uint64_t		 vc_ttbr1_el1;
	uint64_t		 vc_tcr_el1;
	uint64_t		 vc_esr_el1;
	uint64_t		 vc_far_el1;
	uint64_t		 vc_mair_el1;
	uint64_t		 vc_amair_el1;
	uint64_t		 vc_vbar_el1;
	uint64_t		 vc_contextidr_el1;
	uint64_t		 vc_tpidr_el0;
	uint64_t		 vc_tpidr_el1;
	uint64_t		 vc_tpidrro_el0;
	uint64_t		 vc_par_el1;
	uint64_t		 vc_mdscr_el1;

	/* Virtual timer state */
	uint64_t		 vc_cntv_cval_el0;
	uint32_t		 vc_cntv_ctl_el0;
	uint64_t		 vc_cntvoff_el2;

	/* Hypervisor / Stage 2 control */
	uint64_t		 vc_vttbr_el2;
	uint64_t		 vc_vtcr_el2;
	uint64_t		 vc_hcr_el2;

	/* Floating point state */
	struct fpreg		 vc_fp;
	int			 vc_fpuinited;

	/* Exit decoding */
	uint64_t		 vc_hpfar_el2;
	uint64_t		 vc_far_el2;
	uint32_t		 vc_esr_el2;
};

SLIST_HEAD(vcpu_head, vcpu);

int	vmm_probe_machdep(struct device *, void *, void *);
void	vmm_attach_machdep(struct device *, struct device *, void *);
void	vmm_activate_machdep(struct device *, int);
int	vmm_start(void);
int	vmm_stop(void);
int	vm_impl_init(struct vm *, struct proc *);
void	vm_impl_deinit(struct vm *);
int	vcpu_init(struct vcpu *, struct vm_create_params *);
void	vcpu_deinit(struct vcpu *);
int	vm_rwregs(struct vm *, struct vm_rwregs_params *, int);
int	vcpu_reset_regs(struct vcpu *, struct vcpu_reg_state *);
int	vmm_get_guest_memtype(struct vm *, paddr_t);
vaddr_t	vmm_translate_gpa(struct vm *, paddr_t);

#ifdef MULTIPROCESSOR
void	arm_send_ipi(struct cpu_info *, int);
#define vmm_nudge_cpu(ci) arm_send_ipi((ci), ARM_IPI_NOP)
#endif

#endif /* _KERNEL */

#endif /* ! _MACHINE_VMMVAR_H_ */
