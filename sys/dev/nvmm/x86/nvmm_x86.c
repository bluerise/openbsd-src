/*	$NetBSD: nvmm_x86.c,v 1.21 2020/09/08 16:58:38 maxv Exp $	*/

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
//__KERNEL_RCSID(0, "$NetBSD: nvmm_x86.c,v 1.21 2020/09/08 16:58:38 maxv Exp $");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
//#include <sys/cpu.h>

#include <uvm/uvm_extern.h>

//#include <x86/cputypes.h>
#include <machine/specialreg.h>

#include <dev/nvmm/nvmm.h>
#include <dev/nvmm/nvmm_internal.h>
#include <dev/nvmm/x86/nvmm_x86.h>

/*
 * Code shared between x86-SVM and x86-VMX.
 */

const struct nvmm_x64_state nvmm_x86_reset_state = {
	.segs = {
		[NVMM_X64_SEG_ES] = {
			.selector = 0x0000,
			.base = 0x00000000,
			.limit = 0xFFFF,
			.attrib = {
				.type = 3,
				.s = 1,
				.p = 1,
			}
		},
		[NVMM_X64_SEG_CS] = {
			.selector = 0xF000,
			.base = 0xFFFF0000,
			.limit = 0xFFFF,
			.attrib = {
				.type = 3,
				.s = 1,
				.p = 1,
			}
		},
		[NVMM_X64_SEG_SS] = {
			.selector = 0x0000,
			.base = 0x00000000,
			.limit = 0xFFFF,
			.attrib = {
				.type = 3,
				.s = 1,
				.p = 1,
			}
		},
		[NVMM_X64_SEG_DS] = {
			.selector = 0x0000,
			.base = 0x00000000,
			.limit = 0xFFFF,
			.attrib = {
				.type = 3,
				.s = 1,
				.p = 1,
			}
		},
		[NVMM_X64_SEG_FS] = {
			.selector = 0x0000,
			.base = 0x00000000,
			.limit = 0xFFFF,
			.attrib = {
				.type = 3,
				.s = 1,
				.p = 1,
			}
		},
		[NVMM_X64_SEG_GS] = {
			.selector = 0x0000,
			.base = 0x00000000,
			.limit = 0xFFFF,
			.attrib = {
				.type = 3,
				.s = 1,
				.p = 1,
			}
		},
		[NVMM_X64_SEG_GDT] = {
			.selector = 0x0000,
			.base = 0x00000000,
			.limit = 0xFFFF,
			.attrib = {
				.type = 2,
				.s = 1,
				.p = 1,
			}
		},
		[NVMM_X64_SEG_IDT] = {
			.selector = 0x0000,
			.base = 0x00000000,
			.limit = 0xFFFF,
			.attrib = {
				.type = 2,
				.s = 1,
				.p = 1,
			}
		},
		[NVMM_X64_SEG_LDT] = {
			.selector = 0x0000,
			.base = 0x00000000,
			.limit = 0xFFFF,
			.attrib = {
				.type = SDT_SYSLDT,
				.s = 0,
				.p = 1,
			}
		},
		[NVMM_X64_SEG_TR] = {
			.selector = 0x0000,
			.base = 0x00000000,
			.limit = 0xFFFF,
			.attrib = {
				.type = SDT_SYS286BSY,
				.s = 0,
				.p = 1,
			}
		},
	},

	.gprs = {
		[NVMM_X64_GPR_RAX] = 0x00000000,
		[NVMM_X64_GPR_RCX] = 0x00000000,
		[NVMM_X64_GPR_RDX] = 0x00000600,
		[NVMM_X64_GPR_RBX] = 0x00000000,
		[NVMM_X64_GPR_RSP] = 0x00000000,
		[NVMM_X64_GPR_RBP] = 0x00000000,
		[NVMM_X64_GPR_RSI] = 0x00000000,
		[NVMM_X64_GPR_RDI] = 0x00000000,
		[NVMM_X64_GPR_R8] = 0x00000000,
		[NVMM_X64_GPR_R9] = 0x00000000,
		[NVMM_X64_GPR_R10] = 0x00000000,
		[NVMM_X64_GPR_R11] = 0x00000000,
		[NVMM_X64_GPR_R12] = 0x00000000,
		[NVMM_X64_GPR_R13] = 0x00000000,
		[NVMM_X64_GPR_R14] = 0x00000000,
		[NVMM_X64_GPR_R15] = 0x00000000,
		[NVMM_X64_GPR_RIP] = 0x0000FFF0,
		[NVMM_X64_GPR_RFLAGS] = 0x00000002,
	},

	.crs = {
		[NVMM_X64_CR_CR0] = 0x60000010,
		[NVMM_X64_CR_CR2] = 0x00000000,
		[NVMM_X64_CR_CR3] = 0x00000000,
		[NVMM_X64_CR_CR4] = 0x00000000,
		[NVMM_X64_CR_CR8] = 0x00000000,
		[NVMM_X64_CR_XCR0] = 0x00000001,
	},

	.drs = {
		[NVMM_X64_DR_DR0] = 0x00000000,
		[NVMM_X64_DR_DR1] = 0x00000000,
		[NVMM_X64_DR_DR2] = 0x00000000,
		[NVMM_X64_DR_DR3] = 0x00000000,
		[NVMM_X64_DR_DR6] = 0xFFFF0FF0,
		[NVMM_X64_DR_DR7] = 0x00000400,
	},

	.msrs = {
		[NVMM_X64_MSR_EFER] = 0x00000000,
		[NVMM_X64_MSR_STAR] = 0x00000000,
		[NVMM_X64_MSR_LSTAR] = 0x00000000,
		[NVMM_X64_MSR_CSTAR] = 0x00000000,
		[NVMM_X64_MSR_SFMASK] = 0x00000000,
		[NVMM_X64_MSR_KERNELGSBASE] = 0x00000000,
		[NVMM_X64_MSR_SYSENTER_CS] = 0x00000000,
		[NVMM_X64_MSR_SYSENTER_ESP] = 0x00000000,
		[NVMM_X64_MSR_SYSENTER_EIP] = 0x00000000,
		[NVMM_X64_MSR_PAT] =
		    PATENTRY(0, PAT_WB) | PATENTRY(1, PAT_WT) |
		    PATENTRY(2, PAT_UCMINUS) | PATENTRY(3, PAT_UC) |
		    PATENTRY(4, PAT_WB) | PATENTRY(5, PAT_WT) |
		    PATENTRY(6, PAT_UCMINUS) | PATENTRY(7, PAT_UC),
		[NVMM_X64_MSR_TSC] = 0,
	},

	.intr = {
		.int_shadow = 0,
		.int_window_exiting = 0,
		.nmi_window_exiting = 0,
		.evt_pending = 0,
	},

	.fpu = {
		.fx_fcw = 0x0040,
		.fx_fsw = 0x0000,
		.fx_ftw = 0x55,
		.fx_unused1 = 0x55,
		.fx_mxcsr = 0x1F80,
	}
};

const struct nvmm_x86_cpuid_mask nvmm_cpuid_00000001 = {
	.eax = ~0,
	.ebx = ~0,
	.ecx =
	    CPUIDECX_SSE3 |
	    CPUIDECX_PCLMUL |
	    /* CPUIDECX_DTES64 excluded */
	    /* CPUIDECX_MONITOR excluded */
	    /* CPUIDECX_DS_CPL excluded */
	    /* CPUIDECX_VMX excluded */
	    /* CPUIDECX_SMX excluded */
	    /* CPUIDECX_EST excluded */
	    /* CPUIDECX_TM2 excluded */
	    CPUIDECX_SSSE3 |
	    /* CPUIDECX_CNXTID excluded */
	    /* CPUIDECX_SDBG excluded */
	    CPUIDECX_FMA3 |
	    CPUIDECX_CX16 |
	    /* CPUIDECX_XTPR excluded */
	    /* CPUIDECX_PDCM excluded */
	    /* CPUIDECX_PCID excluded, but re-included in VMX */
	    /* CPUIDECX_DCA excluded */
	    CPUIDECX_SSE41 |
	    CPUIDECX_SSE42 |
	    /* CPUIDECX_X2APIC excluded */
	    CPUIDECX_MOVBE |
	    CPUIDECX_POPCNT |
	    /* CPUIDECX_DEADLINE excluded */
	    CPUIDECX_AES |
	    CPUIDECX_XSAVE |
	    CPUIDECX_OSXSAVE |
	    /* CPUIDECX_AVX excluded */
	    CPUIDECX_F16C |
	    CPUIDECX_RDRAND,
	    /* CPUIDECX_RAZ excluded */
	.edx =
	    CPUID_FPU |
	    CPUID_VME |
	    CPUID_DE |
	    CPUID_PSE |
	    CPUID_TSC |
	    CPUID_MSR |
	    CPUID_PAE |
	    /* CPUID_MCE excluded */
	    CPUID_CX8 |
	    CPUID_APIC |
	    CPUID_SEP |
	    /* CPUID_MTRR excluded */
	    CPUID_PGE |
	    /* CPUID_MCA excluded */
	    CPUID_CMOV |
	    CPUID_PAT |
	    CPUID_PSE36 |
	    /* CPUID_PSN excluded */
	    CPUID_CFLUSH |
	    /* CPUID_DS excluded */
	    /* CPUID_ACPI excluded */
	    CPUID_MMX |
	    CPUID_FXSR |
	    CPUID_SSE |
	    CPUID_SSE2 |
	    CPUID_SS |
	    CPUID_HTT |
	    /* CPUID_TM excluded */
	    CPUID_PBE
};

const struct nvmm_x86_cpuid_mask nvmm_cpuid_00000007 = {
	.eax = ~0,
	.ebx =
	    SEFF0EBX_FSGSBASE |
	    /* SEFF0EBX_TSC_ADJUST excluded */
	    /* SEFF0EBX_SGX excluded */
	    SEFF0EBX_BMI1 |
	    /* SEFF0EBX_HLE excluded */
	    /* SEFF0EBX_AVX2 excluded */
	    SEFF0EBX_FDPEXONLY |
	    SEFF0EBX_SMEP |
	    SEFF0EBX_BMI2 |
	    SEFF0EBX_ERMS |
	    /* SEFF0EBX_INVPCID excluded, but re-included in VMX */
	    /* SEFF0EBX_RTM excluded */
	    /* SEFF0EBX_QM excluded */
	    SEFF0EBX_FPUCSDS |
	    /* SEFF0EBX_MPX excluded */
	    SEFF0EBX_PQE |
	    /* SEFF0EBX_AVX512F excluded */
	    /* SEFF0EBX_AVX512DQ excluded */
	    SEFF0EBX_RDSEED |
	    SEFF0EBX_ADX |
	    SEFF0EBX_SMAP |
	    /* SEFF0EBX_AVX512_IFMA excluded */
	    SEFF0EBX_CLFLUSHOPT |
	    SEFF0EBX_CLWB,
	    /* SEFF0EBX_PT excluded */
	    /* SEFF0EBX_AVX512PF excluded */
	    /* SEFF0EBX_AVX512ER excluded */
	    /* SEFF0EBX_AVX512CD excluded */
	    /* SEFF0EBX_SHA excluded */
	    /* SEFF0EBX_AVX512BW excluded */
	    /* SEFF0EBX_AVX512VL excluded */
	.ecx =
	    SEFF0ECX_PREFETCHWT1 |
	    /* SEFF0ECX_AVX512_VBMI excluded */
	    SEFF0ECX_UMIP |
	    /* SEFF0ECX_PKU excluded */
	    /* SEFF0ECX_OSPKE excluded */
	    /* SEFF0ECX_WAITPKG excluded */
	    /* SEFF0ECX_AVX512_VBMI2 excluded */
	    /* SEFF0ECX_CET_SS excluded */
	    SEFF0ECX_GFNI |
	    SEFF0ECX_VAES |
	    SEFF0ECX_VPCLMULQDQ |
	    /* SEFF0ECX_AVX512_VNNI excluded */
	    /* SEFF0ECX_AVX512_BITALG excluded */
	    /* SEFF0ECX_AVX512_VPOPCNTDQ excluded */
	    /* SEFF0ECX_MAWAU excluded */
	    /* SEFF0ECX_RDPID excluded */
	    SEFF0ECX_CLDEMOTE |
	    SEFF0ECX_MOVDIRI |
	    SEFF0ECX_MOVDIR64B,
	    /* SEFF0ECX_SGXLC excluded */
	    /* SEFF0ECX_PKS excluded */
	.edx =
	    /* SEFF0EDX_AVX512_4VNNIW excluded */
	    /* SEFF0EDX_AVX512_4FMAPS excluded */
	    SEFF0EDX_FSREP_MOV |
	    /* SEFF0EDX_AVX512_VP2INTERSECT excluded */
	    /* SEFF0EDX_SRBDS_CTRL excluded */
	    SEFF0EDX_MD_CLEAR |
	    /* SEFF0EDX_TSX_FORCE_ABORT excluded */
	    SEFF0EDX_SERIALIZE |
	    /* SEFF0EDX_HYBRID excluded */
	    /* SEFF0EDX_TSXLDTRK excluded */
	    /* SEFF0EDX_CET_IBT excluded */
	    /* SEFF0EDX_IBRS excluded */
	    /* SEFF0EDX_STIBP excluded */
	    /* SEFF0EDX_L1D_FLUSH excluded */
	    SEFF0EDX_ARCH_CAP
	    /* SEFF0EDX_CORE_CAP excluded */
	    /* SEFF0EDX_SSBD excluded */
};

const struct nvmm_x86_cpuid_mask nvmm_cpuid_80000001 = {
	.eax = ~0,
	.ebx = ~0,
	.ecx =
	    CPUIDECX_LAHF |
	    CPUIDECX_CMPLEG |
	    /* CPUIDECX_SVM excluded */
	    /* CPUIDECX_EAPIC excluded */
	    CPUIDECX_AMCR8 |
	    CPUIDECX_ABM |
	    CPUIDECX_SSE4A |
	    CPUIDECX_MASSE |
	    CPUIDECX_3DNOWP |
	    /* CPUIDECX_OSVW excluded */
	    /* CPUIDECX_IBS excluded */
	    CPUIDECX_XOP |
	    /* CPUIDECX_SKINIT excluded */
	    /* CPUIDECX_WDT excluded */
	    /* CPUIDECX_LWP excluded */
	    CPUIDECX_FMA4 |
	    CPUIDECX_TCE |
	    /* CPUIDECX_NODEID excluded */
	    CPUIDECX_TBM |
	    CPUIDECX_TOPEXT,
	    /* CPUIDECX_PCEC excluded */
	    /* CPUIDECX_PCENB excluded */
	    /* CPUIDECX_SPM excluded */
	    /* CPUIDECX_DBE excluded */
	    /* CPUIDECX_PTSC excluded */
	    /* CPUIDECX_L2IPERFC excluded */
	    /* CPUIDECX_MWAITX excluded */
	.edx =
	    CPUID_SYSCALL |
	    CPUID_MPC |
	    CPUID_XD |
	    CPUID_MMXX |
	    CPUID_MMX |
	    CPUID_FXSR |
	    CPUID_FFXSR |
	    CPUID_PAGE1GB |
	    /* CPUID_RDTSCP excluded */
	    CPUID_EM64T |
	    CPUID_3DNOW2 |
	    CPUID_3DNOW
};

const struct nvmm_x86_cpuid_mask nvmm_cpuid_80000007 = {
	.eax = 0,
	.ebx = 0,
	.ecx = 0,
	.edx = CPUIDEDX_ITSC,
};

const struct nvmm_x86_cpuid_mask nvmm_cpuid_80000008 = {
	.eax = ~0,
	.ebx =
	    CPUIDEBX_CLZERO |
	    /* CPUIDEBX_IRPERF excluded */
	    CPUIDEBX_XSAVEERPTR |
	    /* CPUIDEBX_RDPRU excluded */
	    /* CPUIDEBX_MCOMMIT excluded */
	    CPUIDEBX_WBNOINVD,
	.ecx = ~0, /* TODO? */
	.edx = 0
};

bool
nvmm_x86_pat_validate(uint64_t val)
{
	uint8_t *pat = (uint8_t *)&val;
	size_t i;

	for (i = 0; i < 8; i++) {
		if (__predict_false(pat[i] & ~0x7))
			return false;
		if (__predict_false(pat[i] == 2 || pat[i] == 3))
			return false;
	}

	return true;
}
