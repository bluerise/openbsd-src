/*	$NetBSD: nvmm_x86_vmx.c,v 1.82 2021/03/26 15:59:53 reinoud Exp $	*/

/*
 * Copyright (c) 2018-2020 Maxime Villard, m00nbsd.net
 * All rights reserved.
 *
 * This code is part of the NVMM hypervisor.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
//__KERNEL_RCSID(0, "$NetBSD: nvmm_x86_vmx.c,v 1.82 2021/03/26 15:59:53 reinoud Exp $");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
//#include <sys/cpu.h>
//#include <sys/xcall.h>
#include <sys/mman.h>
#include <sys/proc.h>
//#include <sys/bitops.h>

#include <uvm/uvm_extern.h>
#include <uvm/uvm_page.h>

//#include <x86/cputypes.h>
#include <machine/specialreg.h>
#include <machine/fpu.h>
//#include <x86/dbregs.h>
//#include <x86/cpu_counter.h>

#include <machine/cpuvar.h>

#include <dev/nvmm/nvmm.h>
#include <dev/nvmm/nvmm_internal.h>
#include <dev/nvmm/x86/nvmm_x86.h>

#if 1
#define __read_mostly
#define __cacheline_aligned

/* __BIT(n): nth bit, where __BIT(0) == 0x1. */
#define __BIT(__n)	\
    (((uintmax_t)(__n) >= NBBY * sizeof(uintmax_t)) ? 0 : \
    ((uintmax_t)1 << (uintmax_t)((__n) & (NBBY * sizeof(uintmax_t) - 1))))

/* Macros for min/max. */
#define __MIN(a,b)	((/*CONSTCOND*/(a)<=(b))?(a):(b))
#define __MAX(a,b)	((/*CONSTCOND*/(a)>(b))?(a):(b))

/* __BITS(m, n): bits m through n, m < n. */
#define __BITS(__m, __n)	\
	((__BIT(__MAX((__m), (__n)) + 1) - 1) ^ (__BIT(__MIN((__m), (__n))) - 1))

/* find least significant bit that is set */
#define __LOWEST_SET_BIT(__mask) ((((__mask) - 1) & (__mask)) ^ (__mask))

#define __SHIFTOUT(__x, __mask) (((__x) & (__mask)) / __LOWEST_SET_BIT(__mask))
#define __SHIFTIN(__x, __mask) ((__x) * __LOWEST_SET_BIT(__mask))
#define __SHIFTOUT_MASK(__mask) __SHIFTOUT((__mask), (__mask))

#define ilog2(x) ((sizeof(x) <= 4) ? (fls(x) - 1) : (flsl(x) - 1))
#endif

int _vmx_vmxon(paddr_t *pa);
int _vmx_vmxoff(void);
int vmx_vmlaunch(uint64_t *gprs);
int vmx_vmresume(uint64_t *gprs);

#define vmx_vmxon(a) \
	if (__predict_false(_vmx_vmxon(a) != 0)) { \
		panic("%s: VMXON failed", __func__); \
	}
#define vmx_vmxoff() \
	if (__predict_false(_vmx_vmxoff() != 0)) { \
		panic("%s: VMXOFF failed", __func__); \
	}

struct ept_desc {
	uint64_t eptp;
	uint64_t mbz;
} __packed;

struct vpid_desc {
	uint64_t vpid;
	uint64_t addr;
} __packed;

static inline void
vmx_invept(uint64_t op, struct ept_desc *desc)
{
	asm volatile (
		"invept		%[desc],%[op];"
		"jz		vmx_insn_failvalid;"
		"jc		vmx_insn_failinvalid;"
		:
		: [desc] "m" (*desc), [op] "r" (op)
		: "memory", "cc"
	);
}

static inline void
vmx_invvpid(uint64_t op, struct vpid_desc *desc)
{
	asm volatile (
		"invvpid	%[desc],%[op];"
		"jz		vmx_insn_failvalid;"
		"jc		vmx_insn_failinvalid;"
		:
		: [desc] "m" (*desc), [op] "r" (op)
		: "memory", "cc"
	);
}

static inline uint64_t
vmx_vmread(uint64_t field)
{
	uint64_t value;

	asm volatile (
		"vmread		%[field],%[value];"
		"jz		vmx_insn_failvalid;"
		"jc		vmx_insn_failinvalid;"
		: [value] "=r" (value)
		: [field] "r" (field)
		: "cc"
	);

	return value;
}

static inline void
vmx_vmwrite(uint64_t field, uint64_t value)
{
	asm volatile (
		"vmwrite	%[value],%[field];"
		"jz		vmx_insn_failvalid;"
		"jc		vmx_insn_failinvalid;"
		:
		: [field] "r" (field), [value] "r" (value)
		: "cc"
	);
}

#ifdef DIAGNOSTIC
static inline paddr_t
vmx_vmptrst(void)
{
	paddr_t pa;

	asm volatile (
		"vmptrst	%[pa];"
		:
		: [pa] "m" (*(paddr_t *)&pa)
		: "memory"
	);

	return pa;
}
#endif

static inline void
vmx_vmptrld(paddr_t *pa)
{
	asm volatile (
		"vmptrld	%[pa];"
		"jz		vmx_insn_failvalid;"
		"jc		vmx_insn_failinvalid;"
		:
		: [pa] "m" (*pa)
		: "memory", "cc"
	);
}

static inline void
vmx_vmclear(paddr_t *pa)
{
	asm volatile (
		"vmclear	%[pa];"
		"jz		vmx_insn_failvalid;"
		"jc		vmx_insn_failinvalid;"
		:
		: [pa] "m" (*pa)
		: "memory", "cc"
	);
}

static inline void
vmx_cli(void)
{
	asm volatile ("cli" ::: "memory");
}

static inline void
vmx_sti(void)
{
	asm volatile ("sti" ::: "memory");
}

/* VMX basic exit reasons. */
#define VMCS_EXITCODE_EXC_NMI			0
#define VMCS_EXITCODE_EXT_INT			1
#define VMCS_EXITCODE_SHUTDOWN			2
#define VMCS_EXITCODE_INIT			3
#define VMCS_EXITCODE_SIPI			4
#define VMCS_EXITCODE_SMI			5
#define VMCS_EXITCODE_OTHER_SMI			6
#define VMCS_EXITCODE_INT_WINDOW		7
#define VMCS_EXITCODE_NMI_WINDOW		8
#define VMCS_EXITCODE_TASK_SWITCH		9
#define VMCS_EXITCODE_CPUID			10
#define VMCS_EXITCODE_GETSEC			11
#define VMCS_EXITCODE_HLT			12
#define VMCS_EXITCODE_INVD			13
#define VMCS_EXITCODE_INVLPG			14
#define VMCS_EXITCODE_RDPMC			15
#define VMCS_EXITCODE_RDTSC			16
#define VMCS_EXITCODE_RSM			17
#define VMCS_EXITCODE_VMCALL			18
#define VMCS_EXITCODE_VMCLEAR			19
#define VMCS_EXITCODE_VMLAUNCH			20
#define VMCS_EXITCODE_VMPTRLD			21
#define VMCS_EXITCODE_VMPTRST			22
#define VMCS_EXITCODE_VMREAD			23
#define VMCS_EXITCODE_VMRESUME			24
#define VMCS_EXITCODE_VMWRITE			25
#define VMCS_EXITCODE_VMXOFF			26
#define VMCS_EXITCODE_VMXON			27
#define VMCS_EXITCODE_CR			28
#define VMCS_EXITCODE_DR			29
#define VMCS_EXITCODE_IO			30
#define VMCS_EXITCODE_RDMSR			31
#define VMCS_EXITCODE_WRMSR			32
#define VMCS_EXITCODE_FAIL_GUEST_INVALID	33
#define VMCS_EXITCODE_FAIL_MSR_INVALID		34
#define VMCS_EXITCODE_MWAIT			36
#define VMCS_EXITCODE_TRAP_FLAG			37
#define VMCS_EXITCODE_MONITOR			39
#define VMCS_EXITCODE_PAUSE			40
#define VMCS_EXITCODE_FAIL_MACHINE_CHECK	41
#define VMCS_EXITCODE_TPR_BELOW			43
#define VMCS_EXITCODE_APIC_ACCESS		44
#define VMCS_EXITCODE_VEOI			45
#define VMCS_EXITCODE_GDTR_IDTR			46
#define VMCS_EXITCODE_LDTR_TR			47
#define VMCS_EXITCODE_EPT_VIOLATION		48
#define VMCS_EXITCODE_EPT_MISCONFIG		49
#define VMCS_EXITCODE_INVEPT			50
#define VMCS_EXITCODE_RDTSCP			51
#define VMCS_EXITCODE_PREEMPT_TIMEOUT		52
#define VMCS_EXITCODE_INVVPID			53
#define VMCS_EXITCODE_WBINVD			54
#define VMCS_EXITCODE_XSETBV			55
#define VMCS_EXITCODE_APIC_WRITE		56
#define VMCS_EXITCODE_RDRAND			57
#define VMCS_EXITCODE_INVPCID			58
#define VMCS_EXITCODE_VMFUNC			59
#define VMCS_EXITCODE_ENCLS			60
#define VMCS_EXITCODE_RDSEED			61
#define VMCS_EXITCODE_PAGE_LOG_FULL		62
#define VMCS_EXITCODE_XSAVES			63
#define VMCS_EXITCODE_XRSTORS			64
#define VMCS_EXITCODE_SPP			66
#define VMCS_EXITCODE_UMWAIT			67
#define VMCS_EXITCODE_TPAUSE			68

/* -------------------------------------------------------------------------- */

static void vmx_vcpu_state_provide(struct nvmm_cpu *, uint64_t);
static void vmx_vcpu_state_commit(struct nvmm_cpu *);

#define VMX_MSRLIST_STAR		0
#define VMX_MSRLIST_LSTAR		1
#define VMX_MSRLIST_CSTAR		2
#define VMX_MSRLIST_SFMASK		3
#define VMX_MSRLIST_KERNELGSBASE	4
#define VMX_MSRLIST_EXIT_NMSR		5
#define VMX_MSRLIST_L1DFLUSH		5

/* On entry, we may do +1 to include L1DFLUSH. */
static size_t vmx_msrlist_entry_nmsr __read_mostly = VMX_MSRLIST_EXIT_NMSR;

struct vmxon {
	uint32_t ident;
#define VMXON_IDENT_REVISION	__BITS(30,0)

	uint8_t data[PAGE_SIZE - 4];
} __packed;

CTASSERT(sizeof(struct vmxon) == PAGE_SIZE);

struct vmxoncpu {
	vaddr_t va;
	paddr_t pa;
};

static struct vmxoncpu vmxoncpu[MAXCPUS];

struct vmcs {
	uint32_t ident;
#define VMCS_IDENT_REVISION	__BITS(30,0)
#define VMCS_IDENT_SHADOW	__BIT(31)

	uint32_t abort;
	uint8_t data[PAGE_SIZE - 8];
} __packed;

CTASSERT(sizeof(struct vmcs) == PAGE_SIZE);

struct msr_entry {
	uint32_t msr;
	uint32_t rsvd;
	uint64_t val;
} __packed;

#define VPID_MAX	0xFFFF

/* Make sure we never run out of VPIDs. */
CTASSERT(VPID_MAX-1 >= NVMM_MAX_MACHINES * NVMM_MAX_VCPUS);

static uint64_t vmx_tlb_flush_op __read_mostly;
static uint64_t vmx_ept_flush_op __read_mostly;
static uint64_t vmx_eptp_type __read_mostly;

static uint64_t vmx_pinbased_ctls __read_mostly;
static uint64_t vmx_procbased_ctls __read_mostly;
static uint64_t vmx_procbased_ctls2 __read_mostly;
static uint64_t vmx_entry_ctls __read_mostly;
static uint64_t vmx_exit_ctls __read_mostly;

static uint64_t vmx_cr0_fixed0 __read_mostly;
static uint64_t vmx_cr0_fixed1 __read_mostly;
static uint64_t vmx_cr4_fixed0 __read_mostly;
static uint64_t vmx_cr4_fixed1 __read_mostly;

extern bool pmap_ept_has_ad;

#define VMX_PINBASED_CTLS_ONE	\
	(IA32_VMX_EXTERNAL_INT_EXITING| \
	 IA32_VMX_NMI_EXITING| \
	 IA32_VMX_VIRTUAL_NMIS)

#define VMX_PINBASED_CTLS_ZERO	0

#define VMX_PROCBASED_CTLS_ONE	\
	(IA32_VMX_USE_TSC_OFFSETTING| \
	 IA32_VMX_HLT_EXITING| \
	 IA32_VMX_MWAIT_EXITING| \
	 IA32_VMX_RDPMC_EXITING| \
	 IA32_VMX_CR8_LOAD_EXITING| \
	 IA32_VMX_CR8_STORE_EXITING| \
	 IA32_VMX_UNCONDITIONAL_IO_EXITING| /* no I/O bitmap */ \
	 IA32_VMX_USE_MSR_BITMAPS| \
	 IA32_VMX_MONITOR_EXITING| \
	 IA32_VMX_ACTIVATE_SECONDARY_CONTROLS)

#define VMX_PROCBASED_CTLS_ZERO	\
	(IA32_VMX_CR3_LOAD_EXITING| \
	 IA32_VMX_CR3_STORE_EXITING)

#define VMX_PROCBASED_CTLS2_ONE	\
	(IA32_VMX_ENABLE_EPT| \
	 IA32_VMX_ENABLE_VPID| \
	 IA32_VMX_UNRESTRICTED_GUEST)

#define VMX_PROCBASED_CTLS2_ZERO	0

#define VMX_ENTRY_CTLS_ONE	\
	(IA32_VMX_LOAD_DEBUG_CONTROLS| \
	 IA32_VMX_LOAD_IA32_EFER_ON_ENTRY| \
	 IA32_VMX_LOAD_IA32_PAT_ON_ENTRY)

#define VMX_ENTRY_CTLS_ZERO	\
	(IA32_VMX_ENTRY_TO_SMM| \
	 IA32_VMX_DEACTIVATE_DUAL_MONITOR_TREATMENT)

#define VMX_EXIT_CTLS_ONE	\
	(IA32_VMX_SAVE_DEBUG_CONTROLS| \
	 IA32_VMX_HOST_SPACE_ADDRESS_SIZE| \
	 IA32_VMX_SAVE_IA32_PAT_ON_EXIT| \
	 IA32_VMX_LOAD_IA32_PAT_ON_EXIT| \
	 IA32_VMX_SAVE_IA32_EFER_ON_EXIT| \
	 IA32_VMX_LOAD_IA32_EFER_ON_EXIT)

#define VMX_EXIT_CTLS_ZERO	0

static uint8_t *vmx_asidmap __read_mostly;
static uint32_t vmx_maxasid __read_mostly;
static struct mutex vmx_asidlock __cacheline_aligned;

#define VMX_XCR0_MASK_DEFAULT	(XCR0_X87|XCR0_SSE)
static uint64_t vmx_xcr0_mask __read_mostly;

#define VMX_NCPUIDS	32

#define VMCS_NPAGES	1
#define VMCS_SIZE	(VMCS_NPAGES * PAGE_SIZE)

#define MSRBM_NPAGES	1
#define MSRBM_SIZE	(MSRBM_NPAGES * PAGE_SIZE)

#define CR0_STATIC_MASK \
	(CR0_ET | CR0_NW | CR0_CD)

#define CR4_VALID \
	(CR4_VME |			\
	 CR4_PVI |			\
	 CR4_TSD |			\
	 CR4_DE |			\
	 CR4_PSE |			\
	 CR4_PAE |			\
	 CR4_MCE |			\
	 CR4_PGE |			\
	 CR4_PCE |			\
	 CR4_OSFXSR |			\
	 CR4_OSXMMEXCPT |		\
	 CR4_UMIP |			\
	 /* CR4_LA57 excluded */	\
	 /* CR4_VMXE excluded */	\
	 /* CR4_SMXE excluded */	\
	 CR4_FSGSBASE |			\
	 CR4_PCIDE |			\
	 CR4_OSXSAVE |			\
	 CR4_SMEP |			\
	 CR4_SMAP			\
	 /* CR4_PKE excluded */		\
	 /* CR4_CET excluded */		\
	 /* CR4_PKS excluded */)
#define CR4_INVALID \
	(0xFFFFFFFFFFFFFFFFULL & ~CR4_VALID)

#define EFER_TLB_FLUSH \
	(EFER_NXE|EFER_LMA|EFER_LME)
#define CR0_TLB_FLUSH \
	(CR0_PG|CR0_WP|CR0_CD|CR0_NW)
#define CR4_TLB_FLUSH \
	(CR4_PSE|CR4_PAE|CR4_PGE|CR4_PCIDE|CR4_SMEP)

/* -------------------------------------------------------------------------- */

struct vmx_machdata {
	volatile long mach_htlb_gen;
};

static const size_t vmx_vcpu_conf_sizes[NVMM_X86_VCPU_NCONF] = {
	[NVMM_VCPU_CONF_MD(NVMM_VCPU_CONF_CPUID)] =
	    sizeof(struct nvmm_vcpu_conf_cpuid),
	[NVMM_VCPU_CONF_MD(NVMM_VCPU_CONF_TPR)] =
	    sizeof(struct nvmm_vcpu_conf_tpr)
};

struct vmx_cpudata {
	/* General */
	uint64_t asid;
	bool gtlb_want_flush;
	bool gtsc_want_update;
	uint64_t vcpu_htlb_gen;
	struct cpuset *htlb_want_flush;

	/* VMCS */
	struct vmcs *vmcs;
	paddr_t vmcs_pa;
	size_t vmcs_refcnt;
	struct cpu_info *vmcs_ci;
	bool vmcs_launched;

	/* MSR bitmap */
	uint8_t *msrbm;
	paddr_t msrbm_pa;

	/* Host state */
	uint64_t hxcr0;
	uint64_t star;
	uint64_t lstar;
	uint64_t cstar;
	uint64_t sfmask;
	uint64_t kernelgsbase;

	/* Intr state */
	bool int_window_exit;
	bool nmi_window_exit;
	bool evt_pending;

	/* Guest state */
	struct msr_entry *gmsr;
	paddr_t gmsr_pa;
	uint64_t gmsr_misc_enable;
	uint64_t gcr2;
	uint64_t gcr8;
	uint64_t gxcr0;
	uint64_t gprs[NVMM_X64_NGPR];
	uint64_t drs[NVMM_X64_NDR];
	uint64_t gtsc;
	struct savefpu gfpu __aligned(64);

	/* VCPU configuration. */
	bool cpuidpresent[VMX_NCPUIDS];
	struct nvmm_vcpu_conf_cpuid cpuid[VMX_NCPUIDS];
	struct nvmm_vcpu_conf_tpr tpr;
};

static const struct {
	uint64_t selector;
	uint64_t attrib;
	uint64_t limit;
	uint64_t base;
} vmx_guest_segs[NVMM_X64_NSEG] = {
	[NVMM_X64_SEG_ES] = {
		VMCS_GUEST_IA32_ES_SEL,
		VMCS_GUEST_IA32_ES_AR,
		VMCS_GUEST_IA32_ES_LIMIT,
		VMCS_GUEST_IA32_ES_BASE
	},
	[NVMM_X64_SEG_CS] = {
		VMCS_GUEST_IA32_CS_SEL,
		VMCS_GUEST_IA32_CS_AR,
		VMCS_GUEST_IA32_CS_LIMIT,
		VMCS_GUEST_IA32_CS_BASE
	},
	[NVMM_X64_SEG_SS] = {
		VMCS_GUEST_IA32_SS_SEL,
		VMCS_GUEST_IA32_SS_AR,
		VMCS_GUEST_IA32_SS_LIMIT,
		VMCS_GUEST_IA32_SS_BASE
	},
	[NVMM_X64_SEG_DS] = {
		VMCS_GUEST_IA32_DS_SEL,
		VMCS_GUEST_IA32_DS_AR,
		VMCS_GUEST_IA32_DS_LIMIT,
		VMCS_GUEST_IA32_DS_BASE
	},
	[NVMM_X64_SEG_FS] = {
		VMCS_GUEST_IA32_FS_SEL,
		VMCS_GUEST_IA32_FS_AR,
		VMCS_GUEST_IA32_FS_LIMIT,
		VMCS_GUEST_IA32_FS_BASE
	},
	[NVMM_X64_SEG_GS] = {
		VMCS_GUEST_IA32_GS_SEL,
		VMCS_GUEST_IA32_GS_AR,
		VMCS_GUEST_IA32_GS_LIMIT,
		VMCS_GUEST_IA32_GS_BASE
	},
	[NVMM_X64_SEG_GDT] = {
		0, /* doesn't exist */
		0, /* doesn't exist */
		VMCS_GUEST_IA32_GDTR_LIMIT,
		VMCS_GUEST_IA32_GDTR_BASE
	},
	[NVMM_X64_SEG_IDT] = {
		0, /* doesn't exist */
		0, /* doesn't exist */
		VMCS_GUEST_IA32_IDTR_LIMIT,
		VMCS_GUEST_IA32_IDTR_BASE
	},
	[NVMM_X64_SEG_LDT] = {
		VMCS_GUEST_IA32_LDTR_SEL,
		VMCS_GUEST_IA32_LDTR_AR,
		VMCS_GUEST_IA32_LDTR_LIMIT,
		VMCS_GUEST_IA32_LDTR_BASE
	},
	[NVMM_X64_SEG_TR] = {
		VMCS_GUEST_IA32_TR_SEL,
		VMCS_GUEST_IA32_TR_AR,
		VMCS_GUEST_IA32_TR_LIMIT,
		VMCS_GUEST_IA32_TR_BASE
	}
};

/* -------------------------------------------------------------------------- */

static uint64_t
vmx_get_revision(void)
{
	uint64_t msr;

	msr = rdmsr(IA32_VMX_BASIC);
	msr &= IA32_VMX_BASIC_IDENT;

	return msr;
}

static void
vmx_vmclear_ipi(void *arg1, void *arg2)
{
	paddr_t vmcs_pa = (paddr_t)arg1;
	vmx_vmclear(&vmcs_pa);
}

static void
vmx_vmclear_remote(struct cpu_info *ci, paddr_t vmcs_pa)
{
	uint64_t xc;

	/*KASSERT(kpreempt_disabled());*/

	sched_peg_curproc(curcpu());
	/*kpreempt_enable();*/

	xc = xc_unicast(XC_HIGHPRI, vmx_vmclear_ipi, (void *)vmcs_pa, NULL, ci);
	xc_wait(xc);

	/*kpreempt_disable();*/
	atomic_clearbits_int(&curproc->p_flag, P_CPUPEG);
}

static void
vmx_vmcs_enter(struct nvmm_cpu *vcpu)
{
	struct vmx_cpudata *cpudata = vcpu->cpudata;
	struct cpu_info *vmcs_ci;

	cpudata->vmcs_refcnt++;
	if (cpudata->vmcs_refcnt > 1) {
		/*KASSERT(kpreempt_disabled());*/
		KASSERT(vmx_vmptrst() == cpudata->vmcs_pa);
		return;
	}

	vmcs_ci = cpudata->vmcs_ci;
	cpudata->vmcs_ci = (void *)0x00FFFFFFFFFFFFFF; /* clobber */

	/*kpreempt_disable();*/

	if (vmcs_ci == NULL) {
		/* This VMCS is loaded for the first time. */
		vmx_vmclear(&cpudata->vmcs_pa);
		cpudata->vmcs_launched = false;
	} else if (vmcs_ci != curcpu()) {
		/* This VMCS is active on a remote CPU. */
		vmx_vmclear_remote(vmcs_ci, cpudata->vmcs_pa);
		cpudata->vmcs_launched = false;
	} else {
		/* This VMCS is active on curcpu, nothing to do. */
	}

	vmx_vmptrld(&cpudata->vmcs_pa);
}

static void
vmx_vmcs_leave(struct nvmm_cpu *vcpu)
{
	struct vmx_cpudata *cpudata = vcpu->cpudata;

	/*KASSERT(kpreempt_disabled());*/
	KASSERT(vmx_vmptrst() == cpudata->vmcs_pa);
	KASSERT(cpudata->vmcs_refcnt > 0);
	cpudata->vmcs_refcnt--;

	if (cpudata->vmcs_refcnt > 0) {
		return;
	}

	cpudata->vmcs_ci = curcpu();
	/*kpreempt_enable();*/
}

static void
vmx_vmcs_destroy(struct nvmm_cpu *vcpu)
{
	struct vmx_cpudata *cpudata = vcpu->cpudata;

	/*KASSERT(kpreempt_disabled());*/
	KASSERT(vmx_vmptrst() == cpudata->vmcs_pa);
	KASSERT(cpudata->vmcs_refcnt == 1);
	cpudata->vmcs_refcnt--;

	vmx_vmclear(&cpudata->vmcs_pa);
	/*kpreempt_enable();*/
}

/* -------------------------------------------------------------------------- */

static void
vmx_event_waitexit_enable(struct nvmm_cpu *vcpu, bool nmi)
{
	struct vmx_cpudata *cpudata = vcpu->cpudata;
	uint64_t ctls1;

	ctls1 = vmx_vmread(VMCS_PROCBASED_CTLS);

	if (nmi) {
		// XXX INT_STATE_NMI?
		ctls1 |= IA32_VMX_NMI_WINDOW_EXITING;
		cpudata->nmi_window_exit = true;
	} else {
		ctls1 |= IA32_VMX_INTERRUPT_WINDOW_EXITING;
		cpudata->int_window_exit = true;
	}

	vmx_vmwrite(VMCS_PROCBASED_CTLS, ctls1);
}

static void
vmx_event_waitexit_disable(struct nvmm_cpu *vcpu, bool nmi)
{
	struct vmx_cpudata *cpudata = vcpu->cpudata;
	uint64_t ctls1;

	ctls1 = vmx_vmread(VMCS_PROCBASED_CTLS);

	if (nmi) {
		ctls1 &= ~IA32_VMX_NMI_WINDOW_EXITING;
		cpudata->nmi_window_exit = false;
	} else {
		ctls1 &= ~IA32_VMX_INTERRUPT_WINDOW_EXITING;
		cpudata->int_window_exit = false;
	}

	vmx_vmwrite(VMCS_PROCBASED_CTLS, ctls1);
}

static inline bool
vmx_excp_has_rf(uint8_t vector)
{
	switch (vector) {
	case 1:		/* #DB */
	case 4:		/* #OF */
	case 8:		/* #DF */
	case 18:	/* #MC */
		return false;
	default:
		return true;
	}
}

static inline int
vmx_excp_has_error(uint8_t vector)
{
	switch (vector) {
	case 8:		/* #DF */
	case 10:	/* #TS */
	case 11:	/* #NP */
	case 12:	/* #SS */
	case 13:	/* #GP */
	case 14:	/* #PF */
	case 17:	/* #AC */
	case 30:	/* #SX */
		return 1;
	default:
		return 0;
	}
}

static int
vmx_vcpu_inject(struct nvmm_cpu *vcpu)
{
	struct nvmm_comm_page *comm = vcpu->comm;
	struct vmx_cpudata *cpudata = vcpu->cpudata;
	int type = 0, err = 0, ret = EINVAL;
	uint64_t rflags, info, error;
	u_int evtype;
	uint8_t vector;

	evtype = comm->event.type;
	vector = comm->event.vector;
	error = comm->event.u.excp.error;
	__insn_barrier();

	vmx_vmcs_enter(vcpu);

	switch (evtype) {
	case NVMM_VCPU_EVENT_EXCP:
		if (vector == 2 || vector >= 32)
			goto out;
		if (vector == 3 || vector == 0)
			goto out;
		if (vmx_excp_has_rf(vector)) {
			rflags = vmx_vmread(VMCS_GUEST_IA32_RFLAGS);
			vmx_vmwrite(VMCS_GUEST_IA32_RFLAGS, rflags | PSL_RF);
		}
		type = INTR_TYPE_HW_EXC;
		err = vmx_excp_has_error(vector);
		break;
	case NVMM_VCPU_EVENT_INTR:
		type = INTR_TYPE_EXT_INT;
		if (vector == 2) {
			type = INTR_TYPE_NMI;
			vmx_event_waitexit_enable(vcpu, true);
		}
		err = 0;
		break;
	default:
		goto out;
	}

	info =
	    __SHIFTIN((uint64_t)vector, INTR_INFO_VECTOR) |
	    __SHIFTIN((uint64_t)type, INTR_INFO_TYPE) |
	    __SHIFTIN((uint64_t)err, INTR_INFO_ERROR) |
	    __SHIFTIN((uint64_t)1, INTR_INFO_VALID);
	vmx_vmwrite(VMCS_ENTRY_INTERRUPTION_INFO, info);
	vmx_vmwrite(VMCS_ENTRY_EXCEPTION_ERROR_CODE, error);

	cpudata->evt_pending = true;
	ret = 0;

out:
	vmx_vmcs_leave(vcpu);
	return ret;
}

static void
vmx_inject_ud(struct nvmm_cpu *vcpu)
{
	struct nvmm_comm_page *comm = vcpu->comm;
	int ret;

	comm->event.type = NVMM_VCPU_EVENT_EXCP;
	comm->event.vector = 6;
	comm->event.u.excp.error = 0;

	ret = vmx_vcpu_inject(vcpu);
	KASSERT(ret == 0);
}

static void
vmx_inject_gp(struct nvmm_cpu *vcpu)
{
	struct nvmm_comm_page *comm = vcpu->comm;
	int ret;

	comm->event.type = NVMM_VCPU_EVENT_EXCP;
	comm->event.vector = 13;
	comm->event.u.excp.error = 0;

	ret = vmx_vcpu_inject(vcpu);
	KASSERT(ret == 0);
}

static inline int
vmx_vcpu_event_commit(struct nvmm_cpu *vcpu)
{
	if (__predict_true(!vcpu->comm->event_commit)) {
		return 0;
	}
	vcpu->comm->event_commit = false;
	return vmx_vcpu_inject(vcpu);
}

static inline void
vmx_inkernel_advance(void)
{
	uint64_t rip, inslen, intstate, rflags;

	/*
	 * Maybe we should also apply single-stepping and debug exceptions.
	 * Matters for guest-ring3, because it can execute 'cpuid' under a
	 * debugger.
	 */

	inslen = vmx_vmread(VMCS_INSTRUCTION_LENGTH);
	rip = vmx_vmread(VMCS_GUEST_IA32_RIP);
	vmx_vmwrite(VMCS_GUEST_IA32_RIP, rip + inslen);

	rflags = vmx_vmread(VMCS_GUEST_IA32_RFLAGS);
	vmx_vmwrite(VMCS_GUEST_IA32_RFLAGS, rflags & ~PSL_RF);

	intstate = vmx_vmread(VMCS_GUEST_INTERRUPTIBILITY_ST);
	vmx_vmwrite(VMCS_GUEST_INTERRUPTIBILITY_ST,
	    intstate & ~(INT_STATE_STI|INT_STATE_MOVSS));
}

static void
vmx_exit_invalid(struct nvmm_vcpu_exit *exit, uint64_t code)
{
	exit->u.inv.hwcode = code;
	exit->reason = NVMM_VCPU_EXIT_INVALID;
}

static void
vmx_exit_exc_nmi(struct nvmm_machine *mach, struct nvmm_cpu *vcpu,
    struct nvmm_vcpu_exit *exit)
{
	uint64_t qual;

	qual = vmx_vmread(VMCS_EXIT_INTERRUPTION_INFO);

	if ((qual & INTR_INFO_VALID) == 0) {
		goto error;
	}
	if (__SHIFTOUT(qual, INTR_INFO_TYPE) != INTR_TYPE_NMI) {
		goto error;
	}

	exit->reason = NVMM_VCPU_EXIT_NONE;
	return;

error:
	vmx_exit_invalid(exit, VMCS_EXITCODE_EXC_NMI);
}

#define VMX_CPUID_MAX_BASIC		0x16
#define VMX_CPUID_MAX_HYPERVISOR	0x40000000
#define VMX_CPUID_MAX_EXTENDED		0x80000008
static uint32_t vmx_cpuid_max_basic __read_mostly;
static uint32_t vmx_cpuid_max_extended __read_mostly;

static void
vmx_inkernel_exec_cpuid(struct vmx_cpudata *cpudata, uint64_t eax, uint64_t ecx)
{
	u_int descs[4];

	CPUID_LEAF(eax, ecx, descs[0], descs[1], descs[2], descs[3]);
	cpudata->gprs[NVMM_X64_GPR_RAX] = descs[0];
	cpudata->gprs[NVMM_X64_GPR_RBX] = descs[1];
	cpudata->gprs[NVMM_X64_GPR_RCX] = descs[2];
	cpudata->gprs[NVMM_X64_GPR_RDX] = descs[3];
}

static void
vmx_inkernel_handle_cpuid(struct nvmm_machine *mach, struct nvmm_cpu *vcpu,
    uint64_t eax, uint64_t ecx)
{
	struct vmx_cpudata *cpudata = vcpu->cpudata;
	unsigned int ncpus;
	uint64_t cr4;

	if (eax < 0x40000000) {
		if (__predict_false(eax > vmx_cpuid_max_basic)) {
			eax = vmx_cpuid_max_basic;
			vmx_inkernel_exec_cpuid(cpudata, eax, ecx);
		}
	} else if (eax < 0x80000000) {
		if (__predict_false(eax > VMX_CPUID_MAX_HYPERVISOR)) {
			eax = vmx_cpuid_max_basic;
			vmx_inkernel_exec_cpuid(cpudata, eax, ecx);
		}
	} else {
		if (__predict_false(eax > vmx_cpuid_max_extended)) {
			eax = vmx_cpuid_max_basic;
			vmx_inkernel_exec_cpuid(cpudata, eax, ecx);
		}
	}

	switch (eax) {
	case 0x00000000:
		cpudata->gprs[NVMM_X64_GPR_RAX] = vmx_cpuid_max_basic;
		break;
	case 0x00000001:
		cpudata->gprs[NVMM_X64_GPR_RAX] &= nvmm_cpuid_00000001.eax;

		cpudata->gprs[NVMM_X64_GPR_RBX] &= ~CPUID_LOCAL_APIC_ID;
		cpudata->gprs[NVMM_X64_GPR_RBX] |= __SHIFTIN(vcpu->cpuid,
		    CPUID_LOCAL_APIC_ID);

		cpudata->gprs[NVMM_X64_GPR_RCX] &= nvmm_cpuid_00000001.ecx;
		cpudata->gprs[NVMM_X64_GPR_RCX] |= CPUIDECX_HV;
		if (vmx_procbased_ctls2 & IA32_VMX_ENABLE_INVPCID) {
			cpudata->gprs[NVMM_X64_GPR_RCX] |= CPUIDECX_PCID;
		}

		cpudata->gprs[NVMM_X64_GPR_RDX] &= nvmm_cpuid_00000001.edx;

		/* CPUID2_OSXSAVE depends on CR4. */
		cr4 = vmx_vmread(VMCS_GUEST_IA32_CR4);
		if (!(cr4 & CR4_OSXSAVE)) {
			cpudata->gprs[NVMM_X64_GPR_RCX] &= ~CPUIDECX_OSXSAVE;
		}
		break;
	case 0x00000002:
		break;
	case 0x00000003:
		cpudata->gprs[NVMM_X64_GPR_RAX] = 0;
		cpudata->gprs[NVMM_X64_GPR_RBX] = 0;
		cpudata->gprs[NVMM_X64_GPR_RCX] = 0;
		cpudata->gprs[NVMM_X64_GPR_RDX] = 0;
		break;
	case 0x00000004: /* Deterministic Cache Parameters */
		break; /* TODO? */
	case 0x00000005: /* MONITOR/MWAIT */
	case 0x00000006: /* Thermal and Power Management */
		cpudata->gprs[NVMM_X64_GPR_RAX] = 0;
		cpudata->gprs[NVMM_X64_GPR_RBX] = 0;
		cpudata->gprs[NVMM_X64_GPR_RCX] = 0;
		cpudata->gprs[NVMM_X64_GPR_RDX] = 0;
		break;
	case 0x00000007: /* Structured Extended Feature Flags Enumeration */
		switch (ecx) {
		case 0:
			cpudata->gprs[NVMM_X64_GPR_RAX] = 0;
			cpudata->gprs[NVMM_X64_GPR_RBX] &= nvmm_cpuid_00000007.ebx;
			cpudata->gprs[NVMM_X64_GPR_RCX] &= nvmm_cpuid_00000007.ecx;
			cpudata->gprs[NVMM_X64_GPR_RDX] &= nvmm_cpuid_00000007.edx;
			if (vmx_procbased_ctls2 & IA32_VMX_ENABLE_INVPCID) {
				cpudata->gprs[NVMM_X64_GPR_RBX] |= SEFF0EBX_INVPCID;
			}
			break;
		default:
			cpudata->gprs[NVMM_X64_GPR_RAX] = 0;
			cpudata->gprs[NVMM_X64_GPR_RBX] = 0;
			cpudata->gprs[NVMM_X64_GPR_RCX] = 0;
			cpudata->gprs[NVMM_X64_GPR_RDX] = 0;
			break;
		}
		break;
	case 0x00000008: /* Empty */
	case 0x00000009: /* Direct Cache Access Information */
		cpudata->gprs[NVMM_X64_GPR_RAX] = 0;
		cpudata->gprs[NVMM_X64_GPR_RBX] = 0;
		cpudata->gprs[NVMM_X64_GPR_RCX] = 0;
		cpudata->gprs[NVMM_X64_GPR_RDX] = 0;
		break;
	case 0x0000000A: /* Architectural Performance Monitoring */
		cpudata->gprs[NVMM_X64_GPR_RAX] = 0;
		cpudata->gprs[NVMM_X64_GPR_RBX] = 0;
		cpudata->gprs[NVMM_X64_GPR_RCX] = 0;
		cpudata->gprs[NVMM_X64_GPR_RDX] = 0;
		break;
	case 0x0000000B: /* Extended Topology Enumeration */
		switch (ecx) {
		case 0: /* Threads */
			cpudata->gprs[NVMM_X64_GPR_RAX] = 0;
			cpudata->gprs[NVMM_X64_GPR_RBX] = 0;
			cpudata->gprs[NVMM_X64_GPR_RCX] =
			    __SHIFTIN(ecx, CPUID_TOP_LVLNUM) |
			    __SHIFTIN(CPUID_TOP_LVLTYPE_SMT, CPUID_TOP_LVLTYPE);
			cpudata->gprs[NVMM_X64_GPR_RDX] = vcpu->cpuid;
			break;
		case 1: /* Cores */
			ncpus = READ_ONCE(mach->ncpus);
			cpudata->gprs[NVMM_X64_GPR_RAX] = ilog2(ncpus);
			cpudata->gprs[NVMM_X64_GPR_RBX] = ncpus;
			cpudata->gprs[NVMM_X64_GPR_RCX] =
			    __SHIFTIN(ecx, CPUID_TOP_LVLNUM) |
			    __SHIFTIN(CPUID_TOP_LVLTYPE_CORE, CPUID_TOP_LVLTYPE);
			cpudata->gprs[NVMM_X64_GPR_RDX] = vcpu->cpuid;
			break;
		default:
			cpudata->gprs[NVMM_X64_GPR_RAX] = 0;
			cpudata->gprs[NVMM_X64_GPR_RBX] = 0;
			cpudata->gprs[NVMM_X64_GPR_RCX] = 0; /* LVLTYPE_INVAL */
			cpudata->gprs[NVMM_X64_GPR_RDX] = 0;
			break;
		}
		break;
	case 0x0000000C: /* Empty */
		cpudata->gprs[NVMM_X64_GPR_RAX] = 0;
		cpudata->gprs[NVMM_X64_GPR_RBX] = 0;
		cpudata->gprs[NVMM_X64_GPR_RCX] = 0;
		cpudata->gprs[NVMM_X64_GPR_RDX] = 0;
		break;
	case 0x0000000D: /* Processor Extended State Enumeration */
		if (vmx_xcr0_mask == 0) {
			break;
		}
		switch (ecx) {
		case 0:
			cpudata->gprs[NVMM_X64_GPR_RAX] = vmx_xcr0_mask & 0xFFFFFFFF;
			if (cpudata->gxcr0 & XCR0_SSE) {
				cpudata->gprs[NVMM_X64_GPR_RBX] = sizeof(struct fxsave64);
			} else {
				/* FIXME */
				panic("%s:%d", __func__, __LINE__);
//				cpudata->gprs[NVMM_X64_GPR_RBX] = sizeof(struct save87);
			}
			cpudata->gprs[NVMM_X64_GPR_RBX] += 64; /* XSAVE header */
			cpudata->gprs[NVMM_X64_GPR_RCX] = sizeof(struct fxsave64) + 64;
			cpudata->gprs[NVMM_X64_GPR_RDX] = vmx_xcr0_mask >> 32;
			break;
		case 1:
			cpudata->gprs[NVMM_X64_GPR_RAX] &=
			    (XSAVE_XSAVEOPT | XSAVE_XSAVEC |
			     XSAVE_XGETBV1);
			cpudata->gprs[NVMM_X64_GPR_RBX] = 0;
			cpudata->gprs[NVMM_X64_GPR_RCX] = 0;
			cpudata->gprs[NVMM_X64_GPR_RDX] = 0;
			break;
		default:
			cpudata->gprs[NVMM_X64_GPR_RAX] = 0;
			cpudata->gprs[NVMM_X64_GPR_RBX] = 0;
			cpudata->gprs[NVMM_X64_GPR_RCX] = 0;
			cpudata->gprs[NVMM_X64_GPR_RDX] = 0;
			break;
		}
		break;
	case 0x0000000E: /* Empty */
	case 0x0000000F: /* Intel RDT Monitoring Enumeration */
	case 0x00000010: /* Intel RDT Allocation Enumeration */
		cpudata->gprs[NVMM_X64_GPR_RAX] = 0;
		cpudata->gprs[NVMM_X64_GPR_RBX] = 0;
		cpudata->gprs[NVMM_X64_GPR_RCX] = 0;
		cpudata->gprs[NVMM_X64_GPR_RDX] = 0;
		break;
	case 0x00000011: /* Empty */
	case 0x00000012: /* Intel SGX Capability Enumeration */
	case 0x00000013: /* Empty */
	case 0x00000014: /* Intel Processor Trace Enumeration */
		cpudata->gprs[NVMM_X64_GPR_RAX] = 0;
		cpudata->gprs[NVMM_X64_GPR_RBX] = 0;
		cpudata->gprs[NVMM_X64_GPR_RCX] = 0;
		cpudata->gprs[NVMM_X64_GPR_RDX] = 0;
		break;
	case 0x00000015: /* TSC and Nominal Core Crystal Clock Information */
	case 0x00000016: /* Processor Frequency Information */
		break;

	case 0x40000000: /* Hypervisor Information */
		cpudata->gprs[NVMM_X64_GPR_RAX] = VMX_CPUID_MAX_HYPERVISOR;
		cpudata->gprs[NVMM_X64_GPR_RBX] = 0;
		cpudata->gprs[NVMM_X64_GPR_RCX] = 0;
		cpudata->gprs[NVMM_X64_GPR_RDX] = 0;
		memcpy(&cpudata->gprs[NVMM_X64_GPR_RBX], "___ ", 4);
		memcpy(&cpudata->gprs[NVMM_X64_GPR_RCX], "NVMM", 4);
		memcpy(&cpudata->gprs[NVMM_X64_GPR_RDX], " ___", 4);
		break;

	case 0x80000000:
		cpudata->gprs[NVMM_X64_GPR_RAX] = vmx_cpuid_max_extended;
		break;
	case 0x80000001:
		cpudata->gprs[NVMM_X64_GPR_RAX] &= nvmm_cpuid_80000001.eax;
		cpudata->gprs[NVMM_X64_GPR_RBX] &= nvmm_cpuid_80000001.ebx;
		cpudata->gprs[NVMM_X64_GPR_RCX] &= nvmm_cpuid_80000001.ecx;
		cpudata->gprs[NVMM_X64_GPR_RDX] &= nvmm_cpuid_80000001.edx;
		break;
	case 0x80000002: /* Processor Brand String */
	case 0x80000003: /* Processor Brand String */
	case 0x80000004: /* Processor Brand String */
	case 0x80000005: /* Reserved Zero */
	case 0x80000006: /* Cache Information */
		break;
	case 0x80000007: /* TSC Information */
		cpudata->gprs[NVMM_X64_GPR_RAX] &= nvmm_cpuid_80000007.eax;
		cpudata->gprs[NVMM_X64_GPR_RBX] &= nvmm_cpuid_80000007.ebx;
		cpudata->gprs[NVMM_X64_GPR_RCX] &= nvmm_cpuid_80000007.ecx;
		cpudata->gprs[NVMM_X64_GPR_RDX] &= nvmm_cpuid_80000007.edx;
		break;
	case 0x80000008: /* Address Sizes */
		cpudata->gprs[NVMM_X64_GPR_RAX] &= nvmm_cpuid_80000008.eax;
		cpudata->gprs[NVMM_X64_GPR_RBX] &= nvmm_cpuid_80000008.ebx;
		cpudata->gprs[NVMM_X64_GPR_RCX] &= nvmm_cpuid_80000008.ecx;
		cpudata->gprs[NVMM_X64_GPR_RDX] &= nvmm_cpuid_80000008.edx;
		break;

	default:
		break;
	}
}

static void
vmx_exit_insn(struct nvmm_vcpu_exit *exit, uint64_t reason)
{
	uint64_t inslen, rip;

	inslen = vmx_vmread(VMCS_INSTRUCTION_LENGTH);
	rip = vmx_vmread(VMCS_GUEST_IA32_RIP);
	exit->u.insn.npc = rip + inslen;
	exit->reason = reason;
}

static void
vmx_exit_cpuid(struct nvmm_machine *mach, struct nvmm_cpu *vcpu,
    struct nvmm_vcpu_exit *exit)
{
	struct vmx_cpudata *cpudata = vcpu->cpudata;
	struct nvmm_vcpu_conf_cpuid *cpuid;
	uint64_t eax, ecx;
	size_t i;

	eax = cpudata->gprs[NVMM_X64_GPR_RAX];
	ecx = cpudata->gprs[NVMM_X64_GPR_RCX];
	vmx_inkernel_exec_cpuid(cpudata, eax, ecx);
	vmx_inkernel_handle_cpuid(mach, vcpu, eax, ecx);

	for (i = 0; i < VMX_NCPUIDS; i++) {
		if (!cpudata->cpuidpresent[i]) {
			continue;
		}
		cpuid = &cpudata->cpuid[i];
		if (cpuid->leaf != eax) {
			continue;
		}

		if (cpuid->exit) {
			vmx_exit_insn(exit, NVMM_VCPU_EXIT_CPUID);
			return;
		}
		KASSERT(cpuid->mask);

		/* del */
		cpudata->gprs[NVMM_X64_GPR_RAX] &= ~cpuid->u.mask.del.eax;
		cpudata->gprs[NVMM_X64_GPR_RBX] &= ~cpuid->u.mask.del.ebx;
		cpudata->gprs[NVMM_X64_GPR_RCX] &= ~cpuid->u.mask.del.ecx;
		cpudata->gprs[NVMM_X64_GPR_RDX] &= ~cpuid->u.mask.del.edx;

		/* set */
		cpudata->gprs[NVMM_X64_GPR_RAX] |= cpuid->u.mask.set.eax;
		cpudata->gprs[NVMM_X64_GPR_RBX] |= cpuid->u.mask.set.ebx;
		cpudata->gprs[NVMM_X64_GPR_RCX] |= cpuid->u.mask.set.ecx;
		cpudata->gprs[NVMM_X64_GPR_RDX] |= cpuid->u.mask.set.edx;

		break;
	}

	vmx_inkernel_advance();
	exit->reason = NVMM_VCPU_EXIT_NONE;
}

static void
vmx_exit_hlt(struct nvmm_machine *mach, struct nvmm_cpu *vcpu,
    struct nvmm_vcpu_exit *exit)
{
	struct vmx_cpudata *cpudata = vcpu->cpudata;
	uint64_t rflags;

	if (cpudata->int_window_exit) {
		rflags = vmx_vmread(VMCS_GUEST_IA32_RFLAGS);
		if (rflags & PSL_I) {
			vmx_event_waitexit_disable(vcpu, false);
		}
	}

	vmx_inkernel_advance();
	exit->reason = NVMM_VCPU_EXIT_HALTED;
}

#define VMX_QUAL_CR_NUM		__BITS(3,0)
#define VMX_QUAL_CR_TYPE	__BITS(5,4)
#define		CR_TYPE_WRITE	0
#define		CR_TYPE_READ	1
#define		CR_TYPE_CLTS	2
#define		CR_TYPE_LMSW	3
#define VMX_QUAL_CR_LMSW_OPMEM	__BIT(6)
#define VMX_QUAL_CR_GPR		__BITS(11,8)
#define VMX_QUAL_CR_LMSW_SRC	__BIT(31,16)

static inline int
vmx_check_cr(uint64_t crval, uint64_t fixed0, uint64_t fixed1)
{
	/* Bits set to 1 in fixed0 are fixed to 1. */
	if ((crval & fixed0) != fixed0) {
		return -1;
	}
	/* Bits set to 0 in fixed1 are fixed to 0. */
	if (crval & ~fixed1) {
		return -1;
	}
	return 0;
}

static int
vmx_inkernel_handle_cr0(struct nvmm_machine *mach, struct nvmm_cpu *vcpu,
    uint64_t qual)
{
	struct vmx_cpudata *cpudata = vcpu->cpudata;
	uint64_t type, gpr, oldcr0, realcr0, fakecr0;
	uint64_t efer, ctls1;

	type = __SHIFTOUT(qual, VMX_QUAL_CR_TYPE);
	if (type != CR_TYPE_WRITE) {
		return -1;
	}

	gpr = __SHIFTOUT(qual, VMX_QUAL_CR_GPR);
	KASSERT(gpr < 16);

	if (gpr == NVMM_X64_GPR_RSP) {
		fakecr0 = vmx_vmread(VMCS_GUEST_IA32_RSP);
	} else {
		fakecr0 = cpudata->gprs[gpr];
	}

	/*
	 * fakecr0 is the value the guest believes is in %cr0. realcr0 is the
	 * actual value in %cr0.
	 *
	 * In fakecr0 we must force CR0_ET to 1.
	 *
	 * In realcr0 we must force CR0_NW and CR0_CD to 0, and CR0_ET and
	 * CR0_NE to 1.
	 */
	fakecr0 |= CR0_ET;
	realcr0 = (fakecr0 & ~CR0_STATIC_MASK) | CR0_ET | CR0_NE;

	if (vmx_check_cr(realcr0, vmx_cr0_fixed0, vmx_cr0_fixed1) == -1) {
		return -1;
	}

	/*
	 * XXX Handle 32bit PAE paging, need to set PDPTEs, fetched manually
	 * from CR3.
	 */

	if (realcr0 & CR0_PG) {
		ctls1 = vmx_vmread(VMCS_ENTRY_CTLS);
		efer = vmx_vmread(VMCS_GUEST_IA32_EFER);
		if (efer & EFER_LME) {
			ctls1 |= IA32_VMX_IA32E_MODE_GUEST;
			efer |= EFER_LMA;
		} else {
			ctls1 &= ~IA32_VMX_IA32E_MODE_GUEST;
			efer &= ~EFER_LMA;
		}
		vmx_vmwrite(VMCS_GUEST_IA32_EFER, efer);
		vmx_vmwrite(VMCS_ENTRY_CTLS, ctls1);
	}

	oldcr0 = (vmx_vmread(VMCS_CR0_READ_SHADOW) & CR0_STATIC_MASK) |
	    (vmx_vmread(VMCS_GUEST_IA32_CR0) & ~CR0_STATIC_MASK);
	if ((oldcr0 ^ fakecr0) & CR0_TLB_FLUSH) {
		cpudata->gtlb_want_flush = true;
	}

	vmx_vmwrite(VMCS_CR0_READ_SHADOW, fakecr0);
	vmx_vmwrite(VMCS_GUEST_IA32_CR0, realcr0);
	vmx_inkernel_advance();
	return 0;
}

static int
vmx_inkernel_handle_cr4(struct nvmm_machine *mach, struct nvmm_cpu *vcpu,
    uint64_t qual)
{
	struct vmx_cpudata *cpudata = vcpu->cpudata;
	uint64_t type, gpr, oldcr4, cr4;

	type = __SHIFTOUT(qual, VMX_QUAL_CR_TYPE);
	if (type != CR_TYPE_WRITE) {
		return -1;
	}

	gpr = __SHIFTOUT(qual, VMX_QUAL_CR_GPR);
	KASSERT(gpr < 16);

	if (gpr == NVMM_X64_GPR_RSP) {
		gpr = vmx_vmread(VMCS_GUEST_IA32_RSP);
	} else {
		gpr = cpudata->gprs[gpr];
	}

	if (gpr & CR4_INVALID) {
		return -1;
	}
	cr4 = gpr | CR4_VMXE;
	if (vmx_check_cr(cr4, vmx_cr4_fixed0, vmx_cr4_fixed1) == -1) {
		return -1;
	}

	oldcr4 = vmx_vmread(VMCS_GUEST_IA32_CR4);
	if ((oldcr4 ^ gpr) & CR4_TLB_FLUSH) {
		cpudata->gtlb_want_flush = true;
	}

	vmx_vmwrite(VMCS_GUEST_IA32_CR4, cr4);
	vmx_inkernel_advance();
	return 0;
}

static int
vmx_inkernel_handle_cr8(struct nvmm_machine *mach, struct nvmm_cpu *vcpu,
    uint64_t qual, struct nvmm_vcpu_exit *exit)
{
	struct vmx_cpudata *cpudata = vcpu->cpudata;
	uint64_t type, gpr;
	bool write;

	type = __SHIFTOUT(qual, VMX_QUAL_CR_TYPE);
	if (type == CR_TYPE_WRITE) {
		write = true;
	} else if (type == CR_TYPE_READ) {
		write = false;
	} else {
		return -1;
	}

	gpr = __SHIFTOUT(qual, VMX_QUAL_CR_GPR);
	KASSERT(gpr < 16);

	if (write) {
		if (gpr == NVMM_X64_GPR_RSP) {
			cpudata->gcr8 = vmx_vmread(VMCS_GUEST_IA32_RSP);
		} else {
			cpudata->gcr8 = cpudata->gprs[gpr];
		}
		if (cpudata->tpr.exit_changed) {
			exit->reason = NVMM_VCPU_EXIT_TPR_CHANGED;
		}
	} else {
		if (gpr == NVMM_X64_GPR_RSP) {
			vmx_vmwrite(VMCS_GUEST_IA32_RSP, cpudata->gcr8);
		} else {
			cpudata->gprs[gpr] = cpudata->gcr8;
		}
	}

	vmx_inkernel_advance();
	return 0;
}

static void
vmx_exit_cr(struct nvmm_machine *mach, struct nvmm_cpu *vcpu,
    struct nvmm_vcpu_exit *exit)
{
	uint64_t qual;
	int ret;

	exit->reason = NVMM_VCPU_EXIT_NONE;

	qual = vmx_vmread(VMCS_GUEST_EXIT_QUALIFICATION);

	switch (__SHIFTOUT(qual, VMX_QUAL_CR_NUM)) {
	case 0:
		ret = vmx_inkernel_handle_cr0(mach, vcpu, qual);
		break;
	case 4:
		ret = vmx_inkernel_handle_cr4(mach, vcpu, qual);
		break;
	case 8:
		ret = vmx_inkernel_handle_cr8(mach, vcpu, qual, exit);
		break;
	default:
		ret = -1;
		break;
	}

	if (ret == -1) {
		vmx_inject_gp(vcpu);
	}
}

#define VMX_QUAL_IO_SIZE	__BITS(2,0)
#define		IO_SIZE_8	0
#define		IO_SIZE_16	1
#define		IO_SIZE_32	3
#define VMX_QUAL_IO_IN		__BIT(3)
#define VMX_QUAL_IO_STR		__BIT(4)
#define VMX_QUAL_IO_REP		__BIT(5)
#define VMX_QUAL_IO_DX		__BIT(6)
#define VMX_QUAL_IO_PORT	__BITS(31,16)

#define VMX_INFO_IO_ADRSIZE	__BITS(9,7)
#define		IO_ADRSIZE_16	0
#define		IO_ADRSIZE_32	1
#define		IO_ADRSIZE_64	2
#define VMX_INFO_IO_SEG		__BITS(17,15)

static void
vmx_exit_io(struct nvmm_machine *mach, struct nvmm_cpu *vcpu,
    struct nvmm_vcpu_exit *exit)
{
	uint64_t qual, info, inslen, rip;

	qual = vmx_vmread(VMCS_GUEST_EXIT_QUALIFICATION);
	info = vmx_vmread(VMCS_EXIT_INSTRUCTION_INFO);

	exit->reason = NVMM_VCPU_EXIT_IO;

	exit->u.io.in = (qual & VMX_QUAL_IO_IN) != 0;
	exit->u.io.port = __SHIFTOUT(qual, VMX_QUAL_IO_PORT);

	KASSERT(__SHIFTOUT(info, VMX_INFO_IO_SEG) < 6);
	exit->u.io.seg = __SHIFTOUT(info, VMX_INFO_IO_SEG);

	if (__SHIFTOUT(info, VMX_INFO_IO_ADRSIZE) == IO_ADRSIZE_64) {
		exit->u.io.address_size = 8;
	} else if (__SHIFTOUT(info, VMX_INFO_IO_ADRSIZE) == IO_ADRSIZE_32) {
		exit->u.io.address_size = 4;
	} else if (__SHIFTOUT(info, VMX_INFO_IO_ADRSIZE) == IO_ADRSIZE_16) {
		exit->u.io.address_size = 2;
	}

	if (__SHIFTOUT(qual, VMX_QUAL_IO_SIZE) == IO_SIZE_32) {
		exit->u.io.operand_size = 4;
	} else if (__SHIFTOUT(qual, VMX_QUAL_IO_SIZE) == IO_SIZE_16) {
		exit->u.io.operand_size = 2;
	} else if (__SHIFTOUT(qual, VMX_QUAL_IO_SIZE) == IO_SIZE_8) {
		exit->u.io.operand_size = 1;
	}

	exit->u.io.rep = (qual & VMX_QUAL_IO_REP) != 0;
	exit->u.io.str = (qual & VMX_QUAL_IO_STR) != 0;

	if (exit->u.io.in && exit->u.io.str) {
		exit->u.io.seg = NVMM_X64_SEG_ES;
	}

	inslen = vmx_vmread(VMCS_INSTRUCTION_LENGTH);
	rip = vmx_vmread(VMCS_GUEST_IA32_RIP);
	exit->u.io.npc = rip + inslen;

	vmx_vcpu_state_provide(vcpu,
	    NVMM_X64_STATE_GPRS | NVMM_X64_STATE_SEGS |
	    NVMM_X64_STATE_CRS | NVMM_X64_STATE_MSRS);
}

static const uint64_t msr_ignore_list[] = {
	MSR_BIOS_SIGN,
	MSR_PLATFORM_ID
};

static bool
vmx_inkernel_handle_msr(struct nvmm_machine *mach, struct nvmm_cpu *vcpu,
    struct nvmm_vcpu_exit *exit)
{
	struct vmx_cpudata *cpudata = vcpu->cpudata;
	uint64_t val;
	size_t i;

	if (exit->reason == NVMM_VCPU_EXIT_RDMSR) {
		if (exit->u.rdmsr.msr == MSR_CR_PAT) {
			val = vmx_vmread(VMCS_GUEST_IA32_PAT);
			cpudata->gprs[NVMM_X64_GPR_RAX] = (val & 0xFFFFFFFF);
			cpudata->gprs[NVMM_X64_GPR_RDX] = (val >> 32);
			goto handled;
		}
		if (exit->u.rdmsr.msr == MSR_MISC_ENABLE) {
			val = cpudata->gmsr_misc_enable;
			cpudata->gprs[NVMM_X64_GPR_RAX] = (val & 0xFFFFFFFF);
			cpudata->gprs[NVMM_X64_GPR_RDX] = (val >> 32);
			goto handled;
		}
		if (exit->u.rdmsr.msr == MSR_ARCH_CAPABILITIES) {
			u_int descs[4];
			if (cpuid_level < 7) {
				goto error;
			}
			CPUID(7, descs[0], descs[1], descs[2], descs[3]);
			if (!(descs[3] & SEFF0EDX_ARCH_CAP)) {
				goto error;
			}
			val = rdmsr(MSR_ARCH_CAPABILITIES);
			val &= (ARCH_CAPABILITIES_RDCL_NO |
			    ARCH_CAPABILITIES_SSB_NO |
			    ARCH_CAPABILITIES_MDS_NO |
			    ARCH_CAPABILITIES_TAA_NO);
			cpudata->gprs[NVMM_X64_GPR_RAX] = (val & 0xFFFFFFFF);
			cpudata->gprs[NVMM_X64_GPR_RDX] = (val >> 32);
			goto handled;
		}
		for (i = 0; i < nitems(msr_ignore_list); i++) {
			if (msr_ignore_list[i] != exit->u.rdmsr.msr)
				continue;
			val = 0;
			cpudata->gprs[NVMM_X64_GPR_RAX] = (val & 0xFFFFFFFF);
			cpudata->gprs[NVMM_X64_GPR_RDX] = (val >> 32);
			goto handled;
		}
	} else {
		if (exit->u.wrmsr.msr == MSR_TSC) {
			cpudata->gtsc = exit->u.wrmsr.val;
			cpudata->gtsc_want_update = true;
			goto handled;
		}
		if (exit->u.wrmsr.msr == MSR_CR_PAT) {
			val = exit->u.wrmsr.val;
			if (__predict_false(!nvmm_x86_pat_validate(val))) {
				goto error;
			}
			vmx_vmwrite(VMCS_GUEST_IA32_PAT, val);
			goto handled;
		}
		if (exit->u.wrmsr.msr == MSR_MISC_ENABLE) {
			/* Don't care. */
			goto handled;
		}
		for (i = 0; i < nitems(msr_ignore_list); i++) {
			if (msr_ignore_list[i] != exit->u.wrmsr.msr)
				continue;
			goto handled;
		}
	}

	return false;

handled:
	vmx_inkernel_advance();
	return true;

error:
	vmx_inject_gp(vcpu);
	return true;
}

static void
vmx_exit_rdmsr(struct nvmm_machine *mach, struct nvmm_cpu *vcpu,
    struct nvmm_vcpu_exit *exit)
{
	struct vmx_cpudata *cpudata = vcpu->cpudata;
	uint64_t inslen, rip;

	exit->reason = NVMM_VCPU_EXIT_RDMSR;
	exit->u.rdmsr.msr = (cpudata->gprs[NVMM_X64_GPR_RCX] & 0xFFFFFFFF);

	if (vmx_inkernel_handle_msr(mach, vcpu, exit)) {
		exit->reason = NVMM_VCPU_EXIT_NONE;
		return;
	}

	inslen = vmx_vmread(VMCS_INSTRUCTION_LENGTH);
	rip = vmx_vmread(VMCS_GUEST_IA32_RIP);
	exit->u.rdmsr.npc = rip + inslen;

	vmx_vcpu_state_provide(vcpu, NVMM_X64_STATE_GPRS);
}

static void
vmx_exit_wrmsr(struct nvmm_machine *mach, struct nvmm_cpu *vcpu,
    struct nvmm_vcpu_exit *exit)
{
	struct vmx_cpudata *cpudata = vcpu->cpudata;
	uint64_t rdx, rax, inslen, rip;

	rdx = cpudata->gprs[NVMM_X64_GPR_RDX];
	rax = cpudata->gprs[NVMM_X64_GPR_RAX];

	exit->reason = NVMM_VCPU_EXIT_WRMSR;
	exit->u.wrmsr.msr = (cpudata->gprs[NVMM_X64_GPR_RCX] & 0xFFFFFFFF);
	exit->u.wrmsr.val = (rdx << 32) | (rax & 0xFFFFFFFF);

	if (vmx_inkernel_handle_msr(mach, vcpu, exit)) {
		exit->reason = NVMM_VCPU_EXIT_NONE;
		return;
	}

	inslen = vmx_vmread(VMCS_INSTRUCTION_LENGTH);
	rip = vmx_vmread(VMCS_GUEST_IA32_RIP);
	exit->u.wrmsr.npc = rip + inslen;

	vmx_vcpu_state_provide(vcpu, NVMM_X64_STATE_GPRS);
}

static void
vmx_exit_xsetbv(struct nvmm_machine *mach, struct nvmm_cpu *vcpu,
    struct nvmm_vcpu_exit *exit)
{
	struct vmx_cpudata *cpudata = vcpu->cpudata;
	uint64_t val;

	exit->reason = NVMM_VCPU_EXIT_NONE;

	val = (cpudata->gprs[NVMM_X64_GPR_RDX] << 32) |
	    (cpudata->gprs[NVMM_X64_GPR_RAX] & 0xFFFFFFFF);

	if (__predict_false(cpudata->gprs[NVMM_X64_GPR_RCX] != 0)) {
		goto error;
	} else if (__predict_false((val & ~vmx_xcr0_mask) != 0)) {
		goto error;
	} else if (__predict_false((val & XCR0_X87) == 0)) {
		goto error;
	}

	cpudata->gxcr0 = val;

	vmx_inkernel_advance();
	return;

error:
	vmx_inject_gp(vcpu);
}

#define VMX_EPT_VIOLATION_READ		__BIT(0)
#define VMX_EPT_VIOLATION_WRITE		__BIT(1)
#define VMX_EPT_VIOLATION_EXECUTE	__BIT(2)

static void
vmx_exit_epf(struct nvmm_machine *mach, struct nvmm_cpu *vcpu,
    struct nvmm_vcpu_exit *exit)
{
	uint64_t perm;
	gpaddr_t gpa;

	gpa = vmx_vmread(VMCS_GUEST_PHYSICAL_ADDRESS);

	exit->reason = NVMM_VCPU_EXIT_MEMORY;
	perm = vmx_vmread(VMCS_GUEST_EXIT_QUALIFICATION);
	if (perm & VMX_EPT_VIOLATION_WRITE)
		exit->u.mem.prot = PROT_WRITE;
	else if (perm & VMX_EPT_VIOLATION_EXECUTE)
		exit->u.mem.prot = PROT_EXEC;
	else
		exit->u.mem.prot = PROT_READ;
	exit->u.mem.gpa = gpa;
	exit->u.mem.inst_len = 0;

	vmx_vcpu_state_provide(vcpu,
	    NVMM_X64_STATE_GPRS | NVMM_X64_STATE_SEGS |
	    NVMM_X64_STATE_CRS | NVMM_X64_STATE_MSRS);
}

/* -------------------------------------------------------------------------- */

static void
vmx_vcpu_guest_fpu_enter(struct nvmm_cpu *vcpu)
{
	struct vmx_cpudata *cpudata = vcpu->cpudata;

	fpu_kernel_enter();
	/* TODO: should we use *XSAVE64 here? */
	fpu_area_restore(&cpudata->gfpu, vmx_xcr0_mask, false);

	if (vmx_xcr0_mask != 0) {
		cpudata->hxcr0 = xgetbv(0);
		xsetbv_user(0, cpudata->gxcr0);
	}
}

static void
vmx_vcpu_guest_fpu_leave(struct nvmm_cpu *vcpu)
{
	struct vmx_cpudata *cpudata = vcpu->cpudata;

	if (vmx_xcr0_mask != 0) {
		cpudata->gxcr0 = xgetbv(0);
		xsetbv_user(0, cpudata->hxcr0);
	}

	/* TODO: should we use *XSAVE64 here? */
	fpu_area_save(&cpudata->gfpu, vmx_xcr0_mask, false);
	fpu_kernel_exit();
}

#if 0
static void
vmx_vcpu_guest_dbregs_enter(struct nvmm_cpu *vcpu)
{
	struct vmx_cpudata *cpudata = vcpu->cpudata;

	x86_dbregs_save(curlwp);

	ldr7(0);

	ldr0(cpudata->drs[NVMM_X64_DR_DR0]);
	ldr1(cpudata->drs[NVMM_X64_DR_DR1]);
	ldr2(cpudata->drs[NVMM_X64_DR_DR2]);
	ldr3(cpudata->drs[NVMM_X64_DR_DR3]);
	ldr6(cpudata->drs[NVMM_X64_DR_DR6]);
}

static void
vmx_vcpu_guest_dbregs_leave(struct nvmm_cpu *vcpu)
{
	struct vmx_cpudata *cpudata = vcpu->cpudata;

	cpudata->drs[NVMM_X64_DR_DR0] = rdr0();
	cpudata->drs[NVMM_X64_DR_DR1] = rdr1();
	cpudata->drs[NVMM_X64_DR_DR2] = rdr2();
	cpudata->drs[NVMM_X64_DR_DR3] = rdr3();
	cpudata->drs[NVMM_X64_DR_DR6] = rdr6();

	x86_dbregs_restore(curlwp);
}
#endif

static void
vmx_vcpu_guest_misc_enter(struct nvmm_cpu *vcpu)
{
	struct vmx_cpudata *cpudata = vcpu->cpudata;

	/* This gets restored automatically by the CPU. */
	vmx_vmwrite(VMCS_HOST_IA32_IDTR_BASE, (uint64_t)curcpu()->ci_idtvec.iv_idt);
	vmx_vmwrite(VMCS_HOST_IA32_FS_BASE, rdmsr(MSR_FSBASE));
	vmx_vmwrite(VMCS_HOST_IA32_CR3, rcr3());
	vmx_vmwrite(VMCS_HOST_IA32_CR4, rcr4());

	cpudata->kernelgsbase = rdmsr(MSR_KERNELGSBASE);
}

static void
vmx_vcpu_guest_misc_leave(struct nvmm_cpu *vcpu)
{
	struct vmx_cpudata *cpudata = vcpu->cpudata;

	wrmsr(MSR_STAR, cpudata->star);
	wrmsr(MSR_LSTAR, cpudata->lstar);
	wrmsr(MSR_CSTAR, cpudata->cstar);
	wrmsr(MSR_SFMASK, cpudata->sfmask);
	wrmsr(MSR_KERNELGSBASE, cpudata->kernelgsbase);
}

/* -------------------------------------------------------------------------- */

#define VMX_INVVPID_ADDRESS		0
#define VMX_INVVPID_CONTEXT		1
#define VMX_INVVPID_ALL			2
#define VMX_INVVPID_CONTEXT_NOGLOBAL	3

#define VMX_INVEPT_CONTEXT		1
#define VMX_INVEPT_ALL			2

static inline void
vmx_gtlb_catchup(struct nvmm_cpu *vcpu, int hcpu)
{
	struct vmx_cpudata *cpudata = vcpu->cpudata;

	if (vcpu->hcpu_last != hcpu) {
		cpudata->gtlb_want_flush = true;
	}
}

static inline void
vmx_htlb_catchup(struct nvmm_cpu *vcpu, int hcpu)
{
	struct vmx_cpudata *cpudata = vcpu->cpudata;
	struct ept_desc ept_desc;

	if (__predict_true(!cpuset_isset(cpudata->htlb_want_flush, hcpu))) {
		return;
	}

	ept_desc.eptp = vmx_vmread(VMCS_GUEST_IA32_EPTP);
	ept_desc.mbz = 0;
	vmx_invept(vmx_ept_flush_op, &ept_desc);
	cpuset_clear(cpudata->htlb_want_flush, hcpu);
}

static inline uint64_t
vmx_htlb_flush(struct vmx_machdata *machdata, struct vmx_cpudata *cpudata)
{
	struct ept_desc ept_desc;
	uint64_t machgen;

	machgen = machdata->mach_htlb_gen;
	if (__predict_true(machgen == cpudata->vcpu_htlb_gen)) {
		return machgen;
	}

	cpuset_copy(cpudata->htlb_want_flush, cpuset_running);

	ept_desc.eptp = vmx_vmread(VMCS_GUEST_IA32_EPTP);
	ept_desc.mbz = 0;
	vmx_invept(vmx_ept_flush_op, &ept_desc);

	return machgen;
}

static inline void
vmx_htlb_flush_ack(struct vmx_cpudata *cpudata, uint64_t machgen)
{
	cpudata->vcpu_htlb_gen = machgen;
	cpuset_clear(cpudata->htlb_want_flush, cpu_number());
}

static inline void
vmx_exit_evt(struct vmx_cpudata *cpudata)
{
	uint64_t info, err, inslen;

	cpudata->evt_pending = false;

	info = vmx_vmread(VMCS_IDT_VECTORING_INFO);
	if (__predict_true((info & INTR_INFO_VALID) == 0)) {
		return;
	}
	err = vmx_vmread(VMCS_IDT_VECTORING_ERROR_CODE);

	vmx_vmwrite(VMCS_ENTRY_INTERRUPTION_INFO, info);
	vmx_vmwrite(VMCS_ENTRY_EXCEPTION_ERROR_CODE, err);

	switch (__SHIFTOUT(info, INTR_INFO_TYPE)) {
	case INTR_TYPE_SW_INT:
	case INTR_TYPE_PRIV_SW_EXC:
	case INTR_TYPE_SW_EXC:
		inslen = vmx_vmread(VMCS_INSTRUCTION_LENGTH);
		vmx_vmwrite(VMCS_ENTRY_INSTRUCTION_LENGTH, inslen);
	}

	cpudata->evt_pending = true;
}

static int
vmx_vcpu_run(struct nvmm_machine *mach, struct nvmm_cpu *vcpu,
    struct nvmm_vcpu_exit *exit)
{
	struct nvmm_comm_page *comm = vcpu->comm;
	struct vmx_machdata *machdata = mach->machdata;
	struct vmx_cpudata *cpudata = vcpu->cpudata;
	struct vpid_desc vpid_desc;
	struct cpu_info *ci;
	uint64_t exitcode;
	uint64_t intstate;
	uint64_t machgen;
	int hcpu, ret;
	bool launched;

	vmx_vmcs_enter(vcpu);

	vmx_vcpu_state_commit(vcpu);
	comm->state_cached = 0;

	if (__predict_false(vmx_vcpu_event_commit(vcpu) != 0)) {
		vmx_vmcs_leave(vcpu);
		return EINVAL;
	}

	ci = curcpu();
	hcpu = cpu_number();
	launched = cpudata->vmcs_launched;

	vmx_gtlb_catchup(vcpu, hcpu);
	vmx_htlb_catchup(vcpu, hcpu);

	if (vcpu->hcpu_last != hcpu) {
		vmx_vmwrite(VMCS_HOST_IA32_TR_SEL, ci->ci_tss_sel);
		vmx_vmwrite(VMCS_HOST_IA32_TR_BASE, (uint64_t)ci->ci_tss);
		vmx_vmwrite(VMCS_HOST_IA32_GDTR_BASE, (uint64_t)ci->ci_gdt);
		vmx_vmwrite(VMCS_HOST_IA32_GS_BASE, rdmsr(MSR_GSBASE));
		cpudata->gtsc_want_update = true;
		vcpu->hcpu_last = hcpu;
	}

#if 0
	vmx_vcpu_guest_dbregs_enter(vcpu);
#endif
	vmx_vcpu_guest_misc_enter(vcpu);

	while (1) {
		if (cpudata->gtlb_want_flush) {
			vpid_desc.vpid = cpudata->asid;
			vpid_desc.addr = 0;
			vmx_invvpid(vmx_tlb_flush_op, &vpid_desc);
			cpudata->gtlb_want_flush = false;
		}

		if (__predict_false(cpudata->gtsc_want_update)) {
			vmx_vmwrite(VMCS_TSC_OFFSET, cpudata->gtsc - rdtsc());
			cpudata->gtsc_want_update = false;
		}

		vmx_vcpu_guest_fpu_enter(vcpu);
		vmx_cli();
		machgen = vmx_htlb_flush(machdata, cpudata);
		lcr2(cpudata->gcr2);
		if (launched) {
			ret = vmx_vmresume(cpudata->gprs);
		} else {
			ret = vmx_vmlaunch(cpudata->gprs);
		}
		cpudata->gcr2 = rcr2();
		vmx_htlb_flush_ack(cpudata, machgen);
		vmx_sti();
		vmx_vcpu_guest_fpu_leave(vcpu);

		if (__predict_false(ret != 0)) {
			vmx_exit_invalid(exit, -1);
			break;
		}
		vmx_exit_evt(cpudata);

		launched = true;

		exitcode = vmx_vmread(VMCS_EXIT_REASON);
		exitcode &= __BITS(15,0);

		switch (exitcode) {
		case VMCS_EXITCODE_EXC_NMI:
			vmx_exit_exc_nmi(mach, vcpu, exit);
			break;
		case VMCS_EXITCODE_EXT_INT:
			exit->reason = NVMM_VCPU_EXIT_NONE;
			break;
		case VMCS_EXITCODE_CPUID:
			vmx_exit_cpuid(mach, vcpu, exit);
			break;
		case VMCS_EXITCODE_HLT:
			vmx_exit_hlt(mach, vcpu, exit);
			break;
		case VMCS_EXITCODE_CR:
			vmx_exit_cr(mach, vcpu, exit);
			break;
		case VMCS_EXITCODE_IO:
			vmx_exit_io(mach, vcpu, exit);
			break;
		case VMCS_EXITCODE_RDMSR:
			vmx_exit_rdmsr(mach, vcpu, exit);
			break;
		case VMCS_EXITCODE_WRMSR:
			vmx_exit_wrmsr(mach, vcpu, exit);
			break;
		case VMCS_EXITCODE_SHUTDOWN:
			exit->reason = NVMM_VCPU_EXIT_SHUTDOWN;
			break;
		case VMCS_EXITCODE_MONITOR:
			vmx_exit_insn(exit, NVMM_VCPU_EXIT_MONITOR);
			break;
		case VMCS_EXITCODE_MWAIT:
			vmx_exit_insn(exit, NVMM_VCPU_EXIT_MWAIT);
			break;
		case VMCS_EXITCODE_XSETBV:
			vmx_exit_xsetbv(mach, vcpu, exit);
			break;
		case VMCS_EXITCODE_RDPMC:
		case VMCS_EXITCODE_RDTSCP:
		case VMCS_EXITCODE_INVVPID:
		case VMCS_EXITCODE_INVEPT:
		case VMCS_EXITCODE_VMCALL:
		case VMCS_EXITCODE_VMCLEAR:
		case VMCS_EXITCODE_VMLAUNCH:
		case VMCS_EXITCODE_VMPTRLD:
		case VMCS_EXITCODE_VMPTRST:
		case VMCS_EXITCODE_VMREAD:
		case VMCS_EXITCODE_VMRESUME:
		case VMCS_EXITCODE_VMWRITE:
		case VMCS_EXITCODE_VMXOFF:
		case VMCS_EXITCODE_VMXON:
			vmx_inject_ud(vcpu);
			exit->reason = NVMM_VCPU_EXIT_NONE;
			break;
		case VMCS_EXITCODE_EPT_VIOLATION:
			vmx_exit_epf(mach, vcpu, exit);
			break;
		case VMCS_EXITCODE_INT_WINDOW:
			vmx_event_waitexit_disable(vcpu, false);
			exit->reason = NVMM_VCPU_EXIT_INT_READY;
			break;
		case VMCS_EXITCODE_NMI_WINDOW:
			vmx_event_waitexit_disable(vcpu, true);
			exit->reason = NVMM_VCPU_EXIT_NMI_READY;
			break;
		default:
			vmx_exit_invalid(exit, exitcode);
			break;
		}

		/* If no reason to return to userland, keep rolling. */
		if (nvmm_return_needed(vcpu, exit)) {
			break;
		}
		if (exit->reason != NVMM_VCPU_EXIT_NONE) {
			break;
		}
	}

	cpudata->vmcs_launched = launched;

	cpudata->gtsc = vmx_vmread(VMCS_TSC_OFFSET) + rdtsc();

	vmx_vcpu_guest_misc_leave(vcpu);
#if 0
	vmx_vcpu_guest_dbregs_leave(vcpu);
#endif

	exit->exitstate.rflags = vmx_vmread(VMCS_GUEST_IA32_RFLAGS);
	exit->exitstate.cr8 = cpudata->gcr8;
	intstate = vmx_vmread(VMCS_GUEST_INTERRUPTIBILITY_ST);
	exit->exitstate.int_shadow =
	    (intstate & (INT_STATE_STI|INT_STATE_MOVSS)) != 0;
	exit->exitstate.int_window_exiting = cpudata->int_window_exit;
	exit->exitstate.nmi_window_exiting = cpudata->nmi_window_exit;
	exit->exitstate.evt_pending = cpudata->evt_pending;

	vmx_vmcs_leave(vcpu);

	return 0;
}

/* -------------------------------------------------------------------------- */

static int
vmx_memalloc(paddr_t *pa, vaddr_t *va, size_t npages)
{
	struct pglist pglist;
	paddr_t _pa;
	vaddr_t _va;
	size_t i;
	int ret;

	ret = uvm_pglistalloc(npages * PAGE_SIZE, 0, ~0UL, PAGE_SIZE, 0,
	    &pglist, 1, 0);
	if (ret != 0)
		return ENOMEM;
	_pa = VM_PAGE_TO_PHYS(TAILQ_FIRST(&pglist));
	_va = (vaddr_t)km_alloc(npages * PAGE_SIZE, &kv_any, &kp_none,
	    &kd_nowait);
	if (_va == 0)
		goto error;

	for (i = 0; i < npages; i++) {
		pmap_kenter_pa(_va + i * PAGE_SIZE, _pa + i * PAGE_SIZE,
		    PROT_READ | PROT_WRITE);
	}
	pmap_update(pmap_kernel());

	memset((void *)_va, 0, npages * PAGE_SIZE);

	*pa = _pa;
	*va = _va;
	return 0;

error:
	for (i = 0; i < npages; i++) {
		uvm_pagefree(PHYS_TO_VM_PAGE(_pa + i * PAGE_SIZE));
	}
	return ENOMEM;
}

static void
vmx_memfree(paddr_t pa, vaddr_t va, size_t npages)
{
	size_t i;

	pmap_kremove(va, npages * PAGE_SIZE);
	pmap_update(pmap_kernel());
	km_free((void *)va, npages * PAGE_SIZE, &kv_any, &kp_none);
	for (i = 0; i < npages; i++) {
		uvm_pagefree(PHYS_TO_VM_PAGE(pa + i * PAGE_SIZE));
	}
}

/* -------------------------------------------------------------------------- */

static void
vmx_vcpu_msr_allow(uint8_t *bitmap, uint64_t msr, bool read, bool write)
{
	uint64_t byte;
	uint8_t bitoff;

	if (msr < 0x00002000) {
		/* Range 1 */
		byte = ((msr - 0x00000000) / 8) + 0;
	} else if (msr >= 0xC0000000 && msr < 0xC0002000) {
		/* Range 2 */
		byte = ((msr - 0xC0000000) / 8) + 1024;
	} else {
		panic("%s: wrong range", __func__);
	}

	bitoff = (msr & 0x7);

	if (read) {
		bitmap[byte] &= ~__BIT(bitoff);
	}
	if (write) {
		bitmap[2048 + byte] &= ~__BIT(bitoff);
	}
}

#define VMX_SEG_ATTRIB_TYPE		__BITS(3,0)
#define VMX_SEG_ATTRIB_S		__BIT(4)
#define VMX_SEG_ATTRIB_DPL		__BITS(6,5)
#define VMX_SEG_ATTRIB_P		__BIT(7)
#define VMX_SEG_ATTRIB_AVL		__BIT(12)
#define VMX_SEG_ATTRIB_L		__BIT(13)
#define VMX_SEG_ATTRIB_DEF		__BIT(14)
#define VMX_SEG_ATTRIB_G		__BIT(15)
#define VMX_SEG_ATTRIB_UNUSABLE		__BIT(16)

static void
vmx_vcpu_setstate_seg(const struct nvmm_x64_state_seg *segs, int idx)
{
	uint64_t attrib;

	attrib =
	    __SHIFTIN(segs[idx].attrib.type, VMX_SEG_ATTRIB_TYPE) |
	    __SHIFTIN(segs[idx].attrib.s, VMX_SEG_ATTRIB_S) |
	    __SHIFTIN(segs[idx].attrib.dpl, VMX_SEG_ATTRIB_DPL) |
	    __SHIFTIN(segs[idx].attrib.p, VMX_SEG_ATTRIB_P) |
	    __SHIFTIN(segs[idx].attrib.avl, VMX_SEG_ATTRIB_AVL) |
	    __SHIFTIN(segs[idx].attrib.l, VMX_SEG_ATTRIB_L) |
	    __SHIFTIN(segs[idx].attrib.def, VMX_SEG_ATTRIB_DEF) |
	    __SHIFTIN(segs[idx].attrib.g, VMX_SEG_ATTRIB_G) |
	    (!segs[idx].attrib.p ? VMX_SEG_ATTRIB_UNUSABLE : 0);

	if (idx != NVMM_X64_SEG_GDT && idx != NVMM_X64_SEG_IDT) {
		vmx_vmwrite(vmx_guest_segs[idx].selector, segs[idx].selector);
		vmx_vmwrite(vmx_guest_segs[idx].attrib, attrib);
	}
	vmx_vmwrite(vmx_guest_segs[idx].limit, segs[idx].limit);
	vmx_vmwrite(vmx_guest_segs[idx].base, segs[idx].base);
}

static void
vmx_vcpu_getstate_seg(struct nvmm_x64_state_seg *segs, int idx)
{
	uint64_t selector = 0, attrib = 0, base, limit;

	if (idx != NVMM_X64_SEG_GDT && idx != NVMM_X64_SEG_IDT) {
		selector = vmx_vmread(vmx_guest_segs[idx].selector);
		attrib = vmx_vmread(vmx_guest_segs[idx].attrib);
	}
	limit = vmx_vmread(vmx_guest_segs[idx].limit);
	base = vmx_vmread(vmx_guest_segs[idx].base);

	segs[idx].selector = selector;
	segs[idx].limit = limit;
	segs[idx].base = base;
	segs[idx].attrib.type = __SHIFTOUT(attrib, VMX_SEG_ATTRIB_TYPE);
	segs[idx].attrib.s = __SHIFTOUT(attrib, VMX_SEG_ATTRIB_S);
	segs[idx].attrib.dpl = __SHIFTOUT(attrib, VMX_SEG_ATTRIB_DPL);
	segs[idx].attrib.p = __SHIFTOUT(attrib, VMX_SEG_ATTRIB_P);
	segs[idx].attrib.avl = __SHIFTOUT(attrib, VMX_SEG_ATTRIB_AVL);
	segs[idx].attrib.l = __SHIFTOUT(attrib, VMX_SEG_ATTRIB_L);
	segs[idx].attrib.def = __SHIFTOUT(attrib, VMX_SEG_ATTRIB_DEF);
	segs[idx].attrib.g = __SHIFTOUT(attrib, VMX_SEG_ATTRIB_G);
	if (attrib & VMX_SEG_ATTRIB_UNUSABLE) {
		segs[idx].attrib.p = 0;
	}
}

static inline bool
vmx_state_tlb_flush(const struct nvmm_x64_state *state, uint64_t flags)
{
	uint64_t cr0, cr3, cr4, efer;

	if (flags & NVMM_X64_STATE_CRS) {
		cr0 = vmx_vmread(VMCS_GUEST_IA32_CR0);
		if ((cr0 ^ state->crs[NVMM_X64_CR_CR0]) & CR0_TLB_FLUSH) {
			return true;
		}
		cr3 = vmx_vmread(VMCS_GUEST_IA32_CR3);
		if (cr3 != state->crs[NVMM_X64_CR_CR3]) {
			return true;
		}
		cr4 = vmx_vmread(VMCS_GUEST_IA32_CR4);
		if ((cr4 ^ state->crs[NVMM_X64_CR_CR4]) & CR4_TLB_FLUSH) {
			return true;
		}
	}

	if (flags & NVMM_X64_STATE_MSRS) {
		efer = vmx_vmread(VMCS_GUEST_IA32_EFER);
		if ((efer ^
		     state->msrs[NVMM_X64_MSR_EFER]) & EFER_TLB_FLUSH) {
			return true;
		}
	}

	return false;
}

static void
vmx_vcpu_setstate(struct nvmm_cpu *vcpu)
{
	struct nvmm_comm_page *comm = vcpu->comm;
	const struct nvmm_x64_state *state = &comm->state;
	struct vmx_cpudata *cpudata = vcpu->cpudata;
	struct fxsave64 *fpustate;
	uint64_t ctls1, intstate;
	uint64_t flags;

	flags = comm->state_wanted;

	vmx_vmcs_enter(vcpu);

	if (vmx_state_tlb_flush(state, flags)) {
		cpudata->gtlb_want_flush = true;
	}

	if (flags & NVMM_X64_STATE_SEGS) {
		vmx_vcpu_setstate_seg(state->segs, NVMM_X64_SEG_CS);
		vmx_vcpu_setstate_seg(state->segs, NVMM_X64_SEG_DS);
		vmx_vcpu_setstate_seg(state->segs, NVMM_X64_SEG_ES);
		vmx_vcpu_setstate_seg(state->segs, NVMM_X64_SEG_FS);
		vmx_vcpu_setstate_seg(state->segs, NVMM_X64_SEG_GS);
		vmx_vcpu_setstate_seg(state->segs, NVMM_X64_SEG_SS);
		vmx_vcpu_setstate_seg(state->segs, NVMM_X64_SEG_GDT);
		vmx_vcpu_setstate_seg(state->segs, NVMM_X64_SEG_IDT);
		vmx_vcpu_setstate_seg(state->segs, NVMM_X64_SEG_LDT);
		vmx_vcpu_setstate_seg(state->segs, NVMM_X64_SEG_TR);
	}

	CTASSERT(sizeof(cpudata->gprs) == sizeof(state->gprs));
	if (flags & NVMM_X64_STATE_GPRS) {
		memcpy(cpudata->gprs, state->gprs, sizeof(state->gprs));

		vmx_vmwrite(VMCS_GUEST_IA32_RIP, state->gprs[NVMM_X64_GPR_RIP]);
		vmx_vmwrite(VMCS_GUEST_IA32_RSP, state->gprs[NVMM_X64_GPR_RSP]);
		vmx_vmwrite(VMCS_GUEST_IA32_RFLAGS, state->gprs[NVMM_X64_GPR_RFLAGS]);
	}

	if (flags & NVMM_X64_STATE_CRS) {
		/*
		 * CR0_ET must be 1 both in the shadow and the real register.
		 * CR0_NE must be 1 in the real register.
		 * CR0_NW and CR0_CD must be 0 in the real register.
		 */
		vmx_vmwrite(VMCS_CR0_READ_SHADOW,
		    (state->crs[NVMM_X64_CR_CR0] & CR0_STATIC_MASK) |
		    CR0_ET);
		vmx_vmwrite(VMCS_GUEST_IA32_CR0,
		    (state->crs[NVMM_X64_CR_CR0] & ~CR0_STATIC_MASK) |
		    CR0_ET | CR0_NE);

		cpudata->gcr2 = state->crs[NVMM_X64_CR_CR2];

		/* XXX We are not handling PDPTE here. */
		vmx_vmwrite(VMCS_GUEST_IA32_CR3, state->crs[NVMM_X64_CR_CR3]);

		/* CR4_VMXE is mandatory. */
		vmx_vmwrite(VMCS_GUEST_IA32_CR4,
		    (state->crs[NVMM_X64_CR_CR4] & CR4_VALID) | CR4_VMXE);

		cpudata->gcr8 = state->crs[NVMM_X64_CR_CR8];

		if (vmx_xcr0_mask != 0) {
			/* Clear illegal XCR0 bits, set mandatory X87 bit. */
			cpudata->gxcr0 = state->crs[NVMM_X64_CR_XCR0];
			cpudata->gxcr0 &= vmx_xcr0_mask;
			cpudata->gxcr0 |= XCR0_X87;
		}
	}

	CTASSERT(sizeof(cpudata->drs) == sizeof(state->drs));
	if (flags & NVMM_X64_STATE_DRS) {
		memcpy(cpudata->drs, state->drs, sizeof(state->drs));

		cpudata->drs[NVMM_X64_DR_DR6] &= 0xFFFFFFFF;
		vmx_vmwrite(VMCS_GUEST_IA32_DR7, cpudata->drs[NVMM_X64_DR_DR7]);
	}

	if (flags & NVMM_X64_STATE_MSRS) {
		cpudata->gmsr[VMX_MSRLIST_STAR].val =
		    state->msrs[NVMM_X64_MSR_STAR];
		cpudata->gmsr[VMX_MSRLIST_LSTAR].val =
		    state->msrs[NVMM_X64_MSR_LSTAR];
		cpudata->gmsr[VMX_MSRLIST_CSTAR].val =
		    state->msrs[NVMM_X64_MSR_CSTAR];
		cpudata->gmsr[VMX_MSRLIST_SFMASK].val =
		    state->msrs[NVMM_X64_MSR_SFMASK];
		cpudata->gmsr[VMX_MSRLIST_KERNELGSBASE].val =
		    state->msrs[NVMM_X64_MSR_KERNELGSBASE];

		vmx_vmwrite(VMCS_GUEST_IA32_EFER,
		    state->msrs[NVMM_X64_MSR_EFER]);
		vmx_vmwrite(VMCS_GUEST_IA32_PAT,
		    state->msrs[NVMM_X64_MSR_PAT]);
		vmx_vmwrite(VMCS_GUEST_IA32_SYSENTER_CS,
		    state->msrs[NVMM_X64_MSR_SYSENTER_CS]);
		vmx_vmwrite(VMCS_GUEST_IA32_SYSENTER_ESP,
		    state->msrs[NVMM_X64_MSR_SYSENTER_ESP]);
		vmx_vmwrite(VMCS_GUEST_IA32_SYSENTER_EIP,
		    state->msrs[NVMM_X64_MSR_SYSENTER_EIP]);

		cpudata->gtsc = state->msrs[NVMM_X64_MSR_TSC];
		cpudata->gtsc_want_update = true;

		/* IA32_VMX_IA32E_MODE_GUEST must match EFER_LMA. */
		ctls1 = vmx_vmread(VMCS_ENTRY_CTLS);
		if (state->msrs[NVMM_X64_MSR_EFER] & EFER_LMA) {
			ctls1 |= IA32_VMX_IA32E_MODE_GUEST;
		} else {
			ctls1 &= ~IA32_VMX_IA32E_MODE_GUEST;
		}
		vmx_vmwrite(VMCS_ENTRY_CTLS, ctls1);
	}

	if (flags & NVMM_X64_STATE_INTR) {
		intstate = vmx_vmread(VMCS_GUEST_INTERRUPTIBILITY_ST);
		intstate &= ~(INT_STATE_STI|INT_STATE_MOVSS);
		if (state->intr.int_shadow) {
			intstate |= INT_STATE_MOVSS;
		}
		vmx_vmwrite(VMCS_GUEST_INTERRUPTIBILITY_ST, intstate);

		if (state->intr.int_window_exiting) {
			vmx_event_waitexit_enable(vcpu, false);
		} else {
			vmx_event_waitexit_disable(vcpu, false);
		}

		if (state->intr.nmi_window_exiting) {
			vmx_event_waitexit_enable(vcpu, true);
		} else {
			vmx_event_waitexit_disable(vcpu, true);
		}
	}

	CTASSERT(sizeof(cpudata->gfpu.fp_fxsave) == sizeof(state->fpu));
	if (flags & NVMM_X64_STATE_FPU) {
		memcpy(&cpudata->gfpu.fp_fxsave, &state->fpu,
		    sizeof(state->fpu));

		fpustate = &cpudata->gfpu.fp_fxsave;
		fpustate->fx_mxcsr_mask &= fpu_mxcsr_mask;
		fpustate->fx_mxcsr &= fpustate->fx_mxcsr_mask;

		if (vmx_xcr0_mask != 0) {
			/* Reset XSTATE_BV, to force a reload. */
			cpudata->gfpu.fp_xstate.xstate_bv = vmx_xcr0_mask;
		}
	}

	vmx_vmcs_leave(vcpu);

	comm->state_wanted = 0;
	comm->state_cached |= flags;
}

static void
vmx_vcpu_getstate(struct nvmm_cpu *vcpu)
{
	struct nvmm_comm_page *comm = vcpu->comm;
	struct nvmm_x64_state *state = &comm->state;
	struct vmx_cpudata *cpudata = vcpu->cpudata;
	uint64_t intstate, flags;

	flags = comm->state_wanted;

	vmx_vmcs_enter(vcpu);

	if (flags & NVMM_X64_STATE_SEGS) {
		vmx_vcpu_getstate_seg(state->segs, NVMM_X64_SEG_CS);
		vmx_vcpu_getstate_seg(state->segs, NVMM_X64_SEG_DS);
		vmx_vcpu_getstate_seg(state->segs, NVMM_X64_SEG_ES);
		vmx_vcpu_getstate_seg(state->segs, NVMM_X64_SEG_FS);
		vmx_vcpu_getstate_seg(state->segs, NVMM_X64_SEG_GS);
		vmx_vcpu_getstate_seg(state->segs, NVMM_X64_SEG_SS);
		vmx_vcpu_getstate_seg(state->segs, NVMM_X64_SEG_GDT);
		vmx_vcpu_getstate_seg(state->segs, NVMM_X64_SEG_IDT);
		vmx_vcpu_getstate_seg(state->segs, NVMM_X64_SEG_LDT);
		vmx_vcpu_getstate_seg(state->segs, NVMM_X64_SEG_TR);
	}

	CTASSERT(sizeof(cpudata->gprs) == sizeof(state->gprs));
	if (flags & NVMM_X64_STATE_GPRS) {
		memcpy(state->gprs, cpudata->gprs, sizeof(state->gprs));

		state->gprs[NVMM_X64_GPR_RIP] = vmx_vmread(VMCS_GUEST_IA32_RIP);
		state->gprs[NVMM_X64_GPR_RSP] = vmx_vmread(VMCS_GUEST_IA32_RSP);
		state->gprs[NVMM_X64_GPR_RFLAGS] = vmx_vmread(VMCS_GUEST_IA32_RFLAGS);
	}

	if (flags & NVMM_X64_STATE_CRS) {
		state->crs[NVMM_X64_CR_CR0] =
		    (vmx_vmread(VMCS_CR0_READ_SHADOW) & CR0_STATIC_MASK) |
		    (vmx_vmread(VMCS_GUEST_IA32_CR0) & ~CR0_STATIC_MASK);
		state->crs[NVMM_X64_CR_CR2] = cpudata->gcr2;
		state->crs[NVMM_X64_CR_CR3] = vmx_vmread(VMCS_GUEST_IA32_CR3);
		state->crs[NVMM_X64_CR_CR4] = vmx_vmread(VMCS_GUEST_IA32_CR4);
		state->crs[NVMM_X64_CR_CR8] = cpudata->gcr8;
		state->crs[NVMM_X64_CR_XCR0] = cpudata->gxcr0;

		/* Hide VMXE. */
		state->crs[NVMM_X64_CR_CR4] &= ~CR4_VMXE;
	}

	CTASSERT(sizeof(cpudata->drs) == sizeof(state->drs));
	if (flags & NVMM_X64_STATE_DRS) {
		memcpy(state->drs, cpudata->drs, sizeof(state->drs));

		state->drs[NVMM_X64_DR_DR7] = vmx_vmread(VMCS_GUEST_IA32_DR7);
	}

	if (flags & NVMM_X64_STATE_MSRS) {
		state->msrs[NVMM_X64_MSR_STAR] =
		    cpudata->gmsr[VMX_MSRLIST_STAR].val;
		state->msrs[NVMM_X64_MSR_LSTAR] =
		    cpudata->gmsr[VMX_MSRLIST_LSTAR].val;
		state->msrs[NVMM_X64_MSR_CSTAR] =
		    cpudata->gmsr[VMX_MSRLIST_CSTAR].val;
		state->msrs[NVMM_X64_MSR_SFMASK] =
		    cpudata->gmsr[VMX_MSRLIST_SFMASK].val;
		state->msrs[NVMM_X64_MSR_KERNELGSBASE] =
		    cpudata->gmsr[VMX_MSRLIST_KERNELGSBASE].val;
		state->msrs[NVMM_X64_MSR_EFER] =
		    vmx_vmread(VMCS_GUEST_IA32_EFER);
		state->msrs[NVMM_X64_MSR_PAT] =
		    vmx_vmread(VMCS_GUEST_IA32_PAT);
		state->msrs[NVMM_X64_MSR_SYSENTER_CS] =
		    vmx_vmread(VMCS_GUEST_IA32_SYSENTER_CS);
		state->msrs[NVMM_X64_MSR_SYSENTER_ESP] =
		    vmx_vmread(VMCS_GUEST_IA32_SYSENTER_ESP);
		state->msrs[NVMM_X64_MSR_SYSENTER_EIP] =
		    vmx_vmread(VMCS_GUEST_IA32_SYSENTER_EIP);
		state->msrs[NVMM_X64_MSR_TSC] = cpudata->gtsc;
	}

	if (flags & NVMM_X64_STATE_INTR) {
		intstate = vmx_vmread(VMCS_GUEST_INTERRUPTIBILITY_ST);
		state->intr.int_shadow =
		    (intstate & (INT_STATE_STI|INT_STATE_MOVSS)) != 0;
		state->intr.int_window_exiting = cpudata->int_window_exit;
		state->intr.nmi_window_exiting = cpudata->nmi_window_exit;
		state->intr.evt_pending = cpudata->evt_pending;
	}

	CTASSERT(sizeof(cpudata->gfpu.fp_fxsave) == sizeof(state->fpu));
	if (flags & NVMM_X64_STATE_FPU) {
		memcpy(&state->fpu, &cpudata->gfpu.fp_fxsave,
		    sizeof(state->fpu));
	}

	vmx_vmcs_leave(vcpu);

	comm->state_wanted = 0;
	comm->state_cached |= flags;
}

static void
vmx_vcpu_state_provide(struct nvmm_cpu *vcpu, uint64_t flags)
{
	vcpu->comm->state_wanted = flags;
	vmx_vcpu_getstate(vcpu);
}

static void
vmx_vcpu_state_commit(struct nvmm_cpu *vcpu)
{
	vcpu->comm->state_wanted = vcpu->comm->state_commit;
	vcpu->comm->state_commit = 0;
	vmx_vcpu_setstate(vcpu);
}

/* -------------------------------------------------------------------------- */

static void
vmx_asid_alloc(struct nvmm_cpu *vcpu)
{
	struct vmx_cpudata *cpudata = vcpu->cpudata;
	size_t i, oct, bit;

	mtx_enter(&vmx_asidlock);

	for (i = 0; i < vmx_maxasid; i++) {
		oct = i / 8;
		bit = i % 8;

		if (vmx_asidmap[oct] & __BIT(bit)) {
			continue;
		}

		cpudata->asid = i;

		vmx_asidmap[oct] |= __BIT(bit);
		vmx_vmwrite(VMCS_GUEST_VPID, i);
		mtx_leave(&vmx_asidlock);
		return;
	}

	mtx_leave(&vmx_asidlock);

	panic("%s: impossible", __func__);
}

static void
vmx_asid_free(struct nvmm_cpu *vcpu)
{
	size_t oct, bit;
	uint64_t asid;

	asid = vmx_vmread(VMCS_GUEST_VPID);

	oct = asid / 8;
	bit = asid % 8;

	mtx_enter(&vmx_asidlock);
	vmx_asidmap[oct] &= ~__BIT(bit);
	mtx_leave(&vmx_asidlock);
}

static void
vmx_vcpu_init(struct nvmm_machine *mach, struct nvmm_cpu *vcpu)
{
	struct vmx_cpudata *cpudata = vcpu->cpudata;
	struct vmcs *vmcs = cpudata->vmcs;
	struct msr_entry *gmsr = cpudata->gmsr;
	extern uint8_t vmx_resume_rip;
	uint64_t rev, eptp;

	rev = vmx_get_revision();

	memset(vmcs, 0, VMCS_SIZE);
	vmcs->ident = __SHIFTIN(rev, VMCS_IDENT_REVISION);
	vmcs->abort = 0;

	vmx_vmcs_enter(vcpu);

	/* No link pointer. */
	vmx_vmwrite(VMCS_LINK_POINTER, 0xFFFFFFFFFFFFFFFF);

	/* Install the CTLSs. */
	vmx_vmwrite(VMCS_PINBASED_CTLS, vmx_pinbased_ctls);
	vmx_vmwrite(VMCS_PROCBASED_CTLS, vmx_procbased_ctls);
	vmx_vmwrite(VMCS_PROCBASED2_CTLS, vmx_procbased_ctls2);
	vmx_vmwrite(VMCS_ENTRY_CTLS, vmx_entry_ctls);
	vmx_vmwrite(VMCS_EXIT_CTLS, vmx_exit_ctls);

	/* Allow direct access to certain MSRs. */
	memset(cpudata->msrbm, 0xFF, MSRBM_SIZE);
	vmx_vcpu_msr_allow(cpudata->msrbm, MSR_EFER, true, true);
	vmx_vcpu_msr_allow(cpudata->msrbm, MSR_STAR, true, true);
	vmx_vcpu_msr_allow(cpudata->msrbm, MSR_LSTAR, true, true);
	vmx_vcpu_msr_allow(cpudata->msrbm, MSR_CSTAR, true, true);
	vmx_vcpu_msr_allow(cpudata->msrbm, MSR_SFMASK, true, true);
	vmx_vcpu_msr_allow(cpudata->msrbm, MSR_KERNELGSBASE, true, true);
	vmx_vcpu_msr_allow(cpudata->msrbm, MSR_SYSENTER_CS, true, true);
	vmx_vcpu_msr_allow(cpudata->msrbm, MSR_SYSENTER_ESP, true, true);
	vmx_vcpu_msr_allow(cpudata->msrbm, MSR_SYSENTER_EIP, true, true);
	vmx_vcpu_msr_allow(cpudata->msrbm, MSR_FSBASE, true, true);
	vmx_vcpu_msr_allow(cpudata->msrbm, MSR_GSBASE, true, true);
	vmx_vcpu_msr_allow(cpudata->msrbm, MSR_TSC, true, false);
	vmx_vmwrite(VMCS_MSR_BITMAP_ADDRESS, (uint64_t)cpudata->msrbm_pa);

	/*
	 * List of Guest MSRs loaded on VMENTRY, saved on VMEXIT. This
	 * includes the L1D_FLUSH MSR, to mitigate L1TF.
	 */
	gmsr[VMX_MSRLIST_STAR].msr = MSR_STAR;
	gmsr[VMX_MSRLIST_STAR].val = 0;
	gmsr[VMX_MSRLIST_LSTAR].msr = MSR_LSTAR;
	gmsr[VMX_MSRLIST_LSTAR].val = 0;
	gmsr[VMX_MSRLIST_CSTAR].msr = MSR_CSTAR;
	gmsr[VMX_MSRLIST_CSTAR].val = 0;
	gmsr[VMX_MSRLIST_SFMASK].msr = MSR_SFMASK;
	gmsr[VMX_MSRLIST_SFMASK].val = 0;
	gmsr[VMX_MSRLIST_KERNELGSBASE].msr = MSR_KERNELGSBASE;
	gmsr[VMX_MSRLIST_KERNELGSBASE].val = 0;
	gmsr[VMX_MSRLIST_L1DFLUSH].msr = MSR_FLUSH_CMD;
	gmsr[VMX_MSRLIST_L1DFLUSH].val = FLUSH_CMD_L1D_FLUSH;
	vmx_vmwrite(VMCS_ENTRY_LOAD_MSR_ADDRESS, cpudata->gmsr_pa);
	vmx_vmwrite(VMCS_EXIT_STORE_MSR_ADDRESS, cpudata->gmsr_pa);
	vmx_vmwrite(VMCS_ENTRY_MSR_LOAD_COUNT, vmx_msrlist_entry_nmsr);
	vmx_vmwrite(VMCS_EXIT_MSR_STORE_COUNT, VMX_MSRLIST_EXIT_NMSR);

	/* Set the CR0 mask. Any change of these bits causes a VMEXIT. */
	vmx_vmwrite(VMCS_CR0_MASK, CR0_STATIC_MASK);

	/* Force unsupported CR4 fields to zero. */
	vmx_vmwrite(VMCS_CR4_MASK, CR4_INVALID);
	vmx_vmwrite(VMCS_CR4_READ_SHADOW, 0);

	/* Set the Host state for resuming. */
	vmx_vmwrite(VMCS_HOST_IA32_RIP, (uint64_t)&vmx_resume_rip);
	vmx_vmwrite(VMCS_HOST_IA32_CS_SEL, GSEL(GCODE_SEL, SEL_KPL));
	vmx_vmwrite(VMCS_HOST_IA32_SS_SEL, GSEL(GDATA_SEL, SEL_KPL));
	vmx_vmwrite(VMCS_HOST_IA32_DS_SEL, GSEL(GDATA_SEL, SEL_KPL));
	vmx_vmwrite(VMCS_HOST_IA32_ES_SEL, GSEL(GDATA_SEL, SEL_KPL));
	vmx_vmwrite(VMCS_HOST_IA32_FS_SEL, 0);
	vmx_vmwrite(VMCS_HOST_IA32_GS_SEL, 0);
	vmx_vmwrite(VMCS_HOST_IA32_SYSENTER_CS, 0);
	vmx_vmwrite(VMCS_HOST_IA32_SYSENTER_ESP, 0);
	vmx_vmwrite(VMCS_HOST_IA32_SYSENTER_EIP, 0);
	vmx_vmwrite(VMCS_HOST_IA32_PAT, rdmsr(MSR_CR_PAT));
	vmx_vmwrite(VMCS_HOST_IA32_EFER, rdmsr(MSR_EFER));
	vmx_vmwrite(VMCS_HOST_IA32_CR0, rcr0() & ~CR0_TS);

	/* Generate ASID. */
	vmx_asid_alloc(vcpu);

	/* Enable Extended Paging, 4-Level. */
	eptp =
	    __SHIFTIN(vmx_eptp_type, EPTP_TYPE) |
	    __SHIFTIN(4-1, EPTP_WALKLEN) |
	    (pmap_ept_has_ad ? EPTP_FLAGS_AD : 0) |
	    mach->vm->vm_map.pmap->pm_pdirpa[0];
	vmx_vmwrite(VMCS_GUEST_IA32_EPTP, eptp);

	/* Init IA32_MISC_ENABLE. */
	cpudata->gmsr_misc_enable = rdmsr(MSR_MISC_ENABLE);
	cpudata->gmsr_misc_enable &=
	    ~(MISC_ENABLE_PERF_MON_AVAILABLE|
	      MISC_ENABLE_EIST_ENABLED|
	      MISC_ENABLE_ENABLE_MONITOR_FSM);
	cpudata->gmsr_misc_enable |=
	    (MISC_ENABLE_BTS_UNAVAILABLE|MISC_ENABLE_PEBS_UNAVAILABLE);

	/* Init XSAVE header. */
	cpudata->gfpu.fp_xstate.xstate_bv = vmx_xcr0_mask;
	cpudata->gfpu.fp_xstate.xstate_xcomp_bv = 0;

	/* These MSRs are static. */
	cpudata->star = rdmsr(MSR_STAR);
	cpudata->lstar = rdmsr(MSR_LSTAR);
	cpudata->cstar = rdmsr(MSR_CSTAR);
	cpudata->sfmask = rdmsr(MSR_SFMASK);

	/* Install the RESET state. */
	memcpy(&vcpu->comm->state, &nvmm_x86_reset_state,
	    sizeof(nvmm_x86_reset_state));
	vcpu->comm->state_wanted = NVMM_X64_STATE_ALL;
	vcpu->comm->state_cached = 0;
	vmx_vcpu_setstate(vcpu);

	vmx_vmcs_leave(vcpu);
}

static int
vmx_vcpu_create(struct nvmm_machine *mach, struct nvmm_cpu *vcpu)
{
	struct vmx_cpudata *cpudata;
	int error;

	/* Allocate the VMX cpudata. */
	cpudata = (struct vmx_cpudata *)km_alloc(roundup(sizeof(*cpudata), PAGE_SIZE),
	    &kv_any, &kp_zero, &kd_waitok);
	vcpu->cpudata = cpudata;

	/* VMCS */
	error = vmx_memalloc(&cpudata->vmcs_pa, (vaddr_t *)&cpudata->vmcs,
	    VMCS_NPAGES);
	if (error)
		goto error;

	/* MSR Bitmap */
	error = vmx_memalloc(&cpudata->msrbm_pa, (vaddr_t *)&cpudata->msrbm,
	    MSRBM_NPAGES);
	if (error)
		goto error;

	/* Guest MSR List */
	error = vmx_memalloc(&cpudata->gmsr_pa, (vaddr_t *)&cpudata->gmsr, 1);
	if (error)
		goto error;

//	kcpuset_create(&cpudata->htlb_want_flush, true);

	/* Init the VCPU info. */
	vmx_vcpu_init(mach, vcpu);

	return 0;

error:
	if (cpudata->vmcs_pa) {
		vmx_memfree(cpudata->vmcs_pa, (vaddr_t)cpudata->vmcs,
		    VMCS_NPAGES);
	}
	if (cpudata->msrbm_pa) {
		vmx_memfree(cpudata->msrbm_pa, (vaddr_t)cpudata->msrbm,
		    MSRBM_NPAGES);
	}
	if (cpudata->gmsr_pa) {
		vmx_memfree(cpudata->gmsr_pa, (vaddr_t)cpudata->gmsr, 1);
	}

	km_free(cpudata, roundup(sizeof(*cpudata), PAGE_SIZE), &kv_any, &kp_zero);
	return error;
}

static void
vmx_vcpu_destroy(struct nvmm_machine *mach, struct nvmm_cpu *vcpu)
{
	struct vmx_cpudata *cpudata = vcpu->cpudata;

	vmx_vmcs_enter(vcpu);
	vmx_asid_free(vcpu);
	vmx_vmcs_destroy(vcpu);

//	kcpuset_destroy(cpudata->htlb_want_flush);

	vmx_memfree(cpudata->vmcs_pa, (vaddr_t)cpudata->vmcs, VMCS_NPAGES);
	vmx_memfree(cpudata->msrbm_pa, (vaddr_t)cpudata->msrbm, MSRBM_NPAGES);
	vmx_memfree(cpudata->gmsr_pa, (vaddr_t)cpudata->gmsr, 1);
	km_free(cpudata, roundup(sizeof(*cpudata), PAGE_SIZE), &kv_any, &kp_zero);
}

/* -------------------------------------------------------------------------- */

static int
vmx_vcpu_configure_cpuid(struct vmx_cpudata *cpudata, void *data)
{
	struct nvmm_vcpu_conf_cpuid *cpuid = data;
	size_t i;

	if (__predict_false(cpuid->mask && cpuid->exit)) {
		return EINVAL;
	}
	if (__predict_false(cpuid->mask &&
	    ((cpuid->u.mask.set.eax & cpuid->u.mask.del.eax) ||
	     (cpuid->u.mask.set.ebx & cpuid->u.mask.del.ebx) ||
	     (cpuid->u.mask.set.ecx & cpuid->u.mask.del.ecx) ||
	     (cpuid->u.mask.set.edx & cpuid->u.mask.del.edx)))) {
		return EINVAL;
	}

	/* If unset, delete, to restore the default behavior. */
	if (!cpuid->mask && !cpuid->exit) {
		for (i = 0; i < VMX_NCPUIDS; i++) {
			if (!cpudata->cpuidpresent[i]) {
				continue;
			}
			if (cpudata->cpuid[i].leaf == cpuid->leaf) {
				cpudata->cpuidpresent[i] = false;
			}
		}
		return 0;
	}

	/* If already here, replace. */
	for (i = 0; i < VMX_NCPUIDS; i++) {
		if (!cpudata->cpuidpresent[i]) {
			continue;
		}
		if (cpudata->cpuid[i].leaf == cpuid->leaf) {
			memcpy(&cpudata->cpuid[i], cpuid,
			    sizeof(struct nvmm_vcpu_conf_cpuid));
			return 0;
		}
	}

	/* Not here, insert. */
	for (i = 0; i < VMX_NCPUIDS; i++) {
		if (!cpudata->cpuidpresent[i]) {
			cpudata->cpuidpresent[i] = true;
			memcpy(&cpudata->cpuid[i], cpuid,
			    sizeof(struct nvmm_vcpu_conf_cpuid));
			return 0;
		}
	}

	return ENOBUFS;
}

static int
vmx_vcpu_configure_tpr(struct vmx_cpudata *cpudata, void *data)
{
	struct nvmm_vcpu_conf_tpr *tpr = data;

	memcpy(&cpudata->tpr, tpr, sizeof(*tpr));
	return 0;
}

static int
vmx_vcpu_configure(struct nvmm_cpu *vcpu, uint64_t op, void *data)
{
	struct vmx_cpudata *cpudata = vcpu->cpudata;

	switch (op) {
	case NVMM_VCPU_CONF_MD(NVMM_VCPU_CONF_CPUID):
		return vmx_vcpu_configure_cpuid(cpudata, data);
	case NVMM_VCPU_CONF_MD(NVMM_VCPU_CONF_TPR):
		return vmx_vcpu_configure_tpr(cpudata, data);
	default:
		return EINVAL;
	}
}

/* -------------------------------------------------------------------------- */

static void
vmx_tlb_flush(struct pmap *pm)
{
	struct nvmm_machine *mach = pm->pm_data;
	struct vmx_machdata *machdata = mach->machdata;

	atomic_inc_long(&machdata->mach_htlb_gen);

	/* Generates IPIs, which cause #VMEXITs. */
	pmap_tlb_shootdown(pmap_kernel(), -1, PG_G, TLBSHOOT_NVMM);
}

static void
vmx_machine_create(struct nvmm_machine *mach)
{
	struct pmap *pmap = mach->vm->vm_map.pmap;
	struct vmx_machdata *machdata;

	/* Convert to EPT. */
	KASSERT(pmap_convert(pmap, PMAP_TYPE_EPT) == 0);

	/* Fill in pmap info. */
	pmap->pm_data = (void *)mach;
	pmap->pm_tlb_flush = vmx_tlb_flush;

	machdata = malloc(sizeof(struct vmx_machdata), M_DEVBUF,
	    M_WAITOK | M_ZERO);
	mach->machdata = machdata;

	/* Start with an hTLB flush everywhere. */
	machdata->mach_htlb_gen = 1;
}

static void
vmx_machine_destroy(struct nvmm_machine *mach)
{
	struct vmx_machdata *machdata = mach->machdata;

	free(machdata, M_DEVBUF, sizeof(struct vmx_machdata));
}

static int
vmx_machine_configure(struct nvmm_machine *mach, uint64_t op, void *data)
{
	panic("%s: impossible", __func__);
}

/* -------------------------------------------------------------------------- */

#define CTLS_ONE_ALLOWED(msrval, bitoff) \
	((msrval & __BIT(32 + bitoff)) != 0)
#define CTLS_ZERO_ALLOWED(msrval, bitoff) \
	((msrval & __BIT(bitoff)) == 0)

static int
vmx_check_ctls(uint64_t msr_ctls, uint64_t msr_true_ctls, uint64_t set_one)
{
	uint64_t basic, val, true_val;
	bool has_true;
	size_t i;

	basic = rdmsr(IA32_VMX_BASIC);
	has_true = (basic & IA32_VMX_TRUE_CTLS_AVAIL) != 0;

	val = rdmsr(msr_ctls);
	if (has_true) {
		true_val = rdmsr(msr_true_ctls);
	} else {
		true_val = val;
	}

	for (i = 0; i < 32; i++) {
		if (!(set_one & __BIT(i))) {
			continue;
		}
		if (!CTLS_ONE_ALLOWED(true_val, i)) {
			return -1;
		}
	}

	return 0;
}

static int
vmx_init_ctls(uint64_t msr_ctls, uint64_t msr_true_ctls,
    uint64_t set_one, uint64_t set_zero, uint64_t *res)
{
	uint64_t basic, val, true_val;
	bool one_allowed, zero_allowed, has_true;
	size_t i;

	basic = rdmsr(IA32_VMX_BASIC);
	has_true = (basic & IA32_VMX_TRUE_CTLS_AVAIL) != 0;

	val = rdmsr(msr_ctls);
	if (has_true) {
		true_val = rdmsr(msr_true_ctls);
	} else {
		true_val = val;
	}

	for (i = 0; i < 32; i++) {
		one_allowed = CTLS_ONE_ALLOWED(true_val, i);
		zero_allowed = CTLS_ZERO_ALLOWED(true_val, i);

		if (zero_allowed && !one_allowed) {
			if (set_one & __BIT(i))
				return -1;
			*res &= ~__BIT(i);
		} else if (one_allowed && !zero_allowed) {
			if (set_zero & __BIT(i))
				return -1;
			*res |= __BIT(i);
		} else {
			if (set_zero & __BIT(i)) {
				*res &= ~__BIT(i);
			} else if (set_one & __BIT(i)) {
				*res |= __BIT(i);
			} else if (!has_true) {
				*res &= ~__BIT(i);
			} else if (CTLS_ZERO_ALLOWED(val, i)) {
				*res &= ~__BIT(i);
			} else if (CTLS_ONE_ALLOWED(val, i)) {
				*res |= __BIT(i);
			} else {
				return -1;
			}
		}
	}

	return 0;
}

static bool
vmx_ident(void)
{
	uint64_t msr;
	int ret;

	if (!(cpu_ecxfeature & CPUIDECX_VMX)) {
		return false;
	}

	msr = rdmsr(MSR_IA32_FEATURE_CONTROL);
	if ((msr & IA32_FEATURE_CONTROL_LOCK) != 0 &&
	    (msr & IA32_FEATURE_CONTROL_VMX_EN) == 0) {
		printf("NVMM: VMX disabled in BIOS\n");
		return false;
	}

	msr = rdmsr(IA32_VMX_BASIC);
	if ((msr & IA32_VMX_ID_REPORT_AVAIL) == 0) {
		printf("NVMM: I/O reporting not supported\n");
		return false;
	}
	if (__SHIFTOUT(msr, IA32_VMX_MEM_TYPE) != MEM_TYPE_WB) {
		printf("NVMM: WB memory not supported\n");
		return false;
	}

	/* PG and PE are reported, even if Unrestricted Guests is supported. */
	vmx_cr0_fixed0 = rdmsr(IA32_VMX_CR0_FIXED0) & ~(CR0_PG|CR0_PE);
	vmx_cr0_fixed1 = rdmsr(IA32_VMX_CR0_FIXED1) | (CR0_PG|CR0_PE);
	ret = vmx_check_cr(rcr0(), vmx_cr0_fixed0, vmx_cr0_fixed1);
	if (ret == -1) {
		printf("NVMM: CR0 requirements not satisfied\n");
		return false;
	}

	vmx_cr4_fixed0 = rdmsr(IA32_VMX_CR4_FIXED0);
	vmx_cr4_fixed1 = rdmsr(IA32_VMX_CR4_FIXED1);
	ret = vmx_check_cr(rcr4() | CR4_VMXE, vmx_cr4_fixed0, vmx_cr4_fixed1);
	if (ret == -1) {
		printf("NVMM: CR4 requirements not satisfied\n");
		return false;
	}

	/* Init the CTLSs right now, and check for errors. */
	ret = vmx_init_ctls(
	    IA32_VMX_PINBASED_CTLS, IA32_VMX_TRUE_PINBASED_CTLS,
	    VMX_PINBASED_CTLS_ONE, VMX_PINBASED_CTLS_ZERO,
	    &vmx_pinbased_ctls);
	if (ret == -1) {
		printf("NVMM: pin-based-ctls requirements not satisfied\n");
		return false;
	}
	ret = vmx_init_ctls(
	    IA32_VMX_PROCBASED_CTLS, IA32_VMX_TRUE_PROCBASED_CTLS,
	    VMX_PROCBASED_CTLS_ONE, VMX_PROCBASED_CTLS_ZERO,
	    &vmx_procbased_ctls);
	if (ret == -1) {
		printf("NVMM: proc-based-ctls requirements not satisfied\n");
		return false;
	}
	ret = vmx_init_ctls(
	    IA32_VMX_PROCBASED2_CTLS, IA32_VMX_PROCBASED2_CTLS,
	    VMX_PROCBASED_CTLS2_ONE, VMX_PROCBASED_CTLS2_ZERO,
	    &vmx_procbased_ctls2);
	if (ret == -1) {
		printf("NVMM: proc-based-ctls2 requirements not satisfied\n");
		return false;
	}
	ret = vmx_check_ctls(
	    IA32_VMX_PROCBASED2_CTLS, IA32_VMX_PROCBASED2_CTLS,
	    IA32_VMX_ENABLE_INVPCID);
	if (ret != -1) {
		vmx_procbased_ctls2 |= IA32_VMX_ENABLE_INVPCID;
	}
	ret = vmx_init_ctls(
	    IA32_VMX_ENTRY_CTLS, IA32_VMX_TRUE_ENTRY_CTLS,
	    VMX_ENTRY_CTLS_ONE, VMX_ENTRY_CTLS_ZERO,
	    &vmx_entry_ctls);
	if (ret == -1) {
		printf("NVMM: entry-ctls requirements not satisfied\n");
		return false;
	}
	ret = vmx_init_ctls(
	    IA32_VMX_EXIT_CTLS, IA32_VMX_TRUE_EXIT_CTLS,
	    VMX_EXIT_CTLS_ONE, VMX_EXIT_CTLS_ZERO,
	    &vmx_exit_ctls);
	if (ret == -1) {
		printf("NVMM: exit-ctls requirements not satisfied\n");
		return false;
	}

	msr = rdmsr(IA32_VMX_EPT_VPID_CAP);
	if ((msr & IA32_EPT_VPID_CAP_PAGE_WALK_4) == 0) {
		printf("NVMM: 4-level page tree not supported\n");
		return false;
	}
	if ((msr & IA32_EPT_VPID_CAP_INVEPT) == 0) {
		printf("NVMM: INVEPT not supported\n");
		return false;
	}
	if ((msr & IA32_EPT_VPID_CAP_INVVPID) == 0) {
		printf("NVMM: INVVPID not supported\n");
		return false;
	}
	if ((msr & IA32_EPT_VPID_CAP_AD_BITS) != 0) {
		pmap_ept_has_ad = true;
	} else {
		pmap_ept_has_ad = false;
	}
	if (!(msr & IA32_EPT_VPID_CAP_UC) && !(msr & IA32_EPT_VPID_CAP_WB)) {
		printf("NVMM: EPT UC/WB memory types not supported\n");
		return false;
	}

	return true;
}

static void
vmx_init_asid(uint32_t maxasid)
{
	size_t allocsz;

	mtx_init(&vmx_asidlock, IPL_NONE);

	vmx_maxasid = maxasid;
	allocsz = roundup(maxasid, 8) / 8;
	vmx_asidmap = malloc(allocsz, M_DEVBUF, M_WAITOK | M_ZERO);

	/* ASID 0 is reserved for the host. */
	vmx_asidmap[0] |= __BIT(0);
}

static void
vmx_change_cpu(void *arg1, void *arg2)
{
	struct cpu_info *ci = curcpu();
	bool enable = arg1 != NULL;
	uint64_t msr, cr4;

	if (enable) {
		msr = rdmsr(MSR_IA32_FEATURE_CONTROL);
		if ((msr & IA32_FEATURE_CONTROL_LOCK) == 0) {
			/* Lock now, with VMX-outside-SMX enabled. */
			wrmsr(MSR_IA32_FEATURE_CONTROL, msr |
			    IA32_FEATURE_CONTROL_LOCK |
			    IA32_FEATURE_CONTROL_VMX_EN);
		}
	}

	if (!enable) {
		vmx_vmxoff();
	}

	cr4 = rcr4();
	if (enable) {
		cr4 |= CR4_VMXE;
	} else {
		cr4 &= ~CR4_VMXE;
	}
	lcr4(cr4);

	if (enable) {
		vmx_vmxon(&vmxoncpu[ci->ci_cpuid].pa);
	}
}

static void
vmx_init_l1tf(void)
{
	u_int descs[4];
	uint64_t msr;

	if (cpuid_level < 7) {
		return;
	}

	CPUID(7, descs[0], descs[1], descs[2], descs[3]);

	if (descs[3] & SEFF0EDX_ARCH_CAP) {
		msr = rdmsr(MSR_ARCH_CAPABILITIES);
		if (msr & ARCH_CAPABILITIES_SKIP_L1DFL_VMENTRY) {
			/* No mitigation needed. */
			return;
		}
	}

	if (descs[3] & SEFF0EDX_L1DF) {
		/* Enable hardware mitigation. */
		vmx_msrlist_entry_nmsr += 1;
	}
}

static void
vmx_init(void)
{
	CPU_INFO_ITERATOR cii;
	struct cpu_info *ci;
	uint64_t xc, msr;
	struct vmxon *vmxon;
	uint32_t revision;
	u_int descs[4];
	paddr_t pa;
	vaddr_t va;
	int error;

	/* Init the ASID bitmap (VPID). */
	vmx_init_asid(VPID_MAX);

	/* Init the XCR0 mask. */
	vmx_xcr0_mask = VMX_XCR0_MASK_DEFAULT & xsave_mask;

	/* Init the max basic CPUID leaf. */
	vmx_cpuid_max_basic = min(cpuid_level, VMX_CPUID_MAX_BASIC);

	/* Init the max extended CPUID leaf. */
	CPUID(0x80000000, descs[0], descs[1], descs[2], descs[3]);
	vmx_cpuid_max_extended = min(descs[0], VMX_CPUID_MAX_EXTENDED);

	/* Init the TLB flush op, the EPT flush op and the EPTP type. */
	msr = rdmsr(IA32_VMX_EPT_VPID_CAP);
	if ((msr & IA32_EPT_VPID_CAP_INVVPID_CONTEXT) != 0) {
		vmx_tlb_flush_op = VMX_INVVPID_CONTEXT;
	} else {
		vmx_tlb_flush_op = VMX_INVVPID_ALL;
	}
	if ((msr & IA32_EPT_VPID_CAP_INVEPT_CONTEXT) != 0) {
		vmx_ept_flush_op = VMX_INVEPT_CONTEXT;
	} else {
		vmx_ept_flush_op = VMX_INVEPT_ALL;
	}
	if ((msr & IA32_EPT_VPID_CAP_WB) != 0) {
		vmx_eptp_type = EPTP_TYPE_WB;
	} else {
		vmx_eptp_type = EPTP_TYPE_UC;
	}

	/* Init the L1TF mitigation. */
	vmx_init_l1tf();

	memset(vmxoncpu, 0, sizeof(vmxoncpu));
	revision = vmx_get_revision();

	CPU_INFO_FOREACH(cii, ci) {
		error = vmx_memalloc(&pa, &va, 1);
		if (error) {
			panic("%s: out of memory", __func__);
		}
		vmxoncpu[ci->ci_cpuid].pa = pa;
		vmxoncpu[ci->ci_cpuid].va = va;

		vmxon = (struct vmxon *)vmxoncpu[ci->ci_cpuid].va;
		vmxon->ident = __SHIFTIN(revision, VMXON_IDENT_REVISION);
	}

	xc = xc_broadcast(0, vmx_change_cpu, (void *)true, NULL);
	xc_wait(xc);
}

static void
vmx_fini_asid(void)
{
	size_t allocsz;

	allocsz = roundup(vmx_maxasid, 8) / 8;
	free(vmx_asidmap, M_DEVBUF, allocsz);
}

static void
vmx_fini(void)
{
	uint64_t xc;
	size_t i;

	xc = xc_broadcast(0, vmx_change_cpu, (void *)false, NULL);
	xc_wait(xc);

	for (i = 0; i < MAXCPUS; i++) {
		if (vmxoncpu[i].pa != 0)
			vmx_memfree(vmxoncpu[i].pa, vmxoncpu[i].va, 1);
	}

	vmx_fini_asid();
}

static void
vmx_capability(struct nvmm_capability *cap)
{
	cap->arch.mach_conf_support = 0;
	cap->arch.vcpu_conf_support =
	    NVMM_CAP_ARCH_VCPU_CONF_CPUID |
	    NVMM_CAP_ARCH_VCPU_CONF_TPR;
	cap->arch.xcr0_mask = vmx_xcr0_mask;
	cap->arch.mxcsr_mask = fpu_mxcsr_mask;
	cap->arch.conf_cpuid_maxops = VMX_NCPUIDS;
}

const struct nvmm_impl nvmm_x86_vmx = {
	.name = "x86-vmx",
	.ident = vmx_ident,
	.init = vmx_init,
	.fini = vmx_fini,
	.capability = vmx_capability,
	.mach_conf_max = NVMM_X86_MACH_NCONF,
	.mach_conf_sizes = NULL,
	.vcpu_conf_max = NVMM_X86_VCPU_NCONF,
	.vcpu_conf_sizes = vmx_vcpu_conf_sizes,
	.state_size = sizeof(struct nvmm_x64_state),
	.machine_create = vmx_machine_create,
	.machine_destroy = vmx_machine_destroy,
	.machine_configure = vmx_machine_configure,
	.vcpu_create = vmx_vcpu_create,
	.vcpu_destroy = vmx_vcpu_destroy,
	.vcpu_configure = vmx_vcpu_configure,
	.vcpu_setstate = vmx_vcpu_setstate,
	.vcpu_getstate = vmx_vcpu_getstate,
	.vcpu_inject = vmx_vcpu_inject,
	.vcpu_run = vmx_vcpu_run
};
