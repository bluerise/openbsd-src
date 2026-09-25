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

#include <machine/asm.h>
#include <machine/param.h>
#include <machine/armreg.h>
#include <machine/hypervisor.h>
#include "assym.h"

#define CNTHCTL_GUEST_FLAGS \
	(CNTHCTL_EL1PCTEN | CNTHCTL_EL1PCEN | CNTHCTL_EL1PTEN | \
	 CNTHCTL_EL0VTEN | CNTHCTL_EL0PTEN)

	.text
	.align 11

/*
 * VHE Guest Exit Vector Table
 *
 * When HCR_EL2.TGE is cleared and an exception is taken from guest EL1 or EL0
 * to EL2, this vector table handles the trap.
 */
	.globl arm64_vhe_guest_vectors
arm64_vhe_guest_vectors:
	/* Current EL with SP0 */
	.align 7
	b	.
	.align 7
	b	.
	.align 7
	b	.
	.align 7
	b	.

	/* Current EL with SPx */
	.align 7
	b	.
	.align 7
	b	.
	.align 7
	b	.
	.align 7
	b	.

	/* Lower EL using AArch64 (Guest EL1/EL0 traps) */
	.align 7
	b	arm64_vhe_guest_exit_sync
	.align 7
	b	arm64_vhe_guest_exit_irq
	.align 7
	b	arm64_vhe_guest_exit_fiq
	.align 7
	b	arm64_vhe_guest_exit_serror

	/* Lower EL using AArch32 */
	.align 7
	b	arm64_vhe_guest_exit_sync
	.align 7
	b	arm64_vhe_guest_exit_irq
	.align 7
	b	arm64_vhe_guest_exit_fiq
	.align 7
	b	arm64_vhe_guest_exit_serror

arm64_vhe_guest_exit_sync:
	/*
	 * Exception taken to EL2. Stack currently holds host save frame.
	 * Save guest x2 at [sp, #24] and set x2 to exit type 0 (SYNC).
	 */
	str	x2, [sp, #24]
	mov	x2, #0
	b	arm64_vhe_guest_exit

arm64_vhe_guest_exit_irq:
	str	x2, [sp, #24]
	mov	x2, #1
	b	arm64_vhe_guest_exit

arm64_vhe_guest_exit_fiq:
	str	x2, [sp, #24]
	mov	x2, #2
	b	arm64_vhe_guest_exit

arm64_vhe_guest_exit_serror:
	str	x2, [sp, #24]
	mov	x2, #3
	b	arm64_vhe_guest_exit

arm64_vhe_guest_exit:
	/*
	 * Exception taken to EL2. Host sp still points to the host frame.
	 * Guest x2 is already saved at [sp, #24], and x2 holds the exit type.
	 * Stash guest x1 into free stack slot.
	 */
	str	x1, [sp, #8]

	/* Load vcpu pointer from [sp, #0] into x1 */
	ldr	x1, [sp, #0]
	str	w2, [x1, #VCPU_EXIT_TYPE]
	add	x1, x1, #VCPU_REGS

	/* Save guest X0 */
	str	x0, [x1, #(VRS_GPRS + 0 * 8)]

	/* Save guest X3 - X30 */
	stp	x3,  x4,  [x1, #(VRS_GPRS + 3 * 8)]
	stp	x5,  x6,  [x1, #(VRS_GPRS + 5 * 8)]
	stp	x7,  x8,  [x1, #(VRS_GPRS + 7 * 8)]
	stp	x9,  x10, [x1, #(VRS_GPRS + 9 * 8)]
	stp	x11, x12, [x1, #(VRS_GPRS + 11 * 8)]
	stp	x13, x14, [x1, #(VRS_GPRS + 13 * 8)]
	stp	x15, x16, [x1, #(VRS_GPRS + 15 * 8)]
	stp	x17, x18, [x1, #(VRS_GPRS + 17 * 8)]
	stp	x19, x20, [x1, #(VRS_GPRS + 19 * 8)]
	stp	x21, x22, [x1, #(VRS_GPRS + 21 * 8)]
	stp	x23, x24, [x1, #(VRS_GPRS + 23 * 8)]
	stp	x25, x26, [x1, #(VRS_GPRS + 25 * 8)]
	stp	x27, x28, [x1, #(VRS_GPRS + 27 * 8)]
	stp	x29, lr,  [x1, #(VRS_GPRS + 29 * 8)]

	/* Restore stashed guest x1 and x2 and save them to vcpu->vc_regs */
	ldr	x3, [sp, #8]
	ldr	x4, [sp, #24]
	stp	x3, x4, [x1, #(VRS_GPRS + 1 * 8)]

	/* Save EL2 syndrome & fault registers */
	ldr	x0, [sp, #0]
	mrs	x2, esr_el2
	mrs	x3, far_el2
	mrs	x4, hpfar_el2
	mrs	x5, elr_el2
	mrs	x6, spsr_el2

	str	w2, [x0, #VCPU_ESR_EL2]
	str	x3, [x0, #VCPU_FAR_EL2]
	str	x4, [x0, #VCPU_HPFAR_EL2]
	str	x5, [x1, #VRS_PC]
	str	x6, [x1, #VRS_SPSR]

	/* Restore host VBAR_EL2 from stack */
	ldr	x7, [sp, #16]
	msr	vbar_el2, x7
	isb

	/* Load exit type to return in x0 */
	ldr	w0, [x0, #VCPU_EXIT_TYPE]

	/* Restore host callee-saved registers x19-x30 */
	ldp	x19, x20, [sp, #32]
	ldp	x21, x22, [sp, #48]
	ldp	x23, x24, [sp, #64]
	ldp	x25, x26, [sp, #80]
	ldp	x27, x28, [sp, #96]
	ldp	x29, lr,  [sp, #112]
	add	sp, sp, #128

	ret

/*
 * int arm64_vhe_enter_guest(struct vcpu *vcpu)
 *
 * Runs the guest vCPU using ARMv8.1-A VHE mode directly from EL2.
 */
ENTRY(arm64_vhe_enter_guest)
	/* Allocate frame on host stack and save host callee-saved registers */
	sub	sp, sp, #128
	stp	x19, x20, [sp, #32]
	stp	x21, x22, [sp, #48]
	stp	x23, x24, [sp, #64]
	stp	x25, x26, [sp, #80]
	stp	x27, x28, [sp, #96]
	stp	x29, lr,  [sp, #112]

	/* Save current host VBAR_EL2 */
	mrs	x1, vbar_el2
	str	x1, [sp, #16]

	/* Store pointer to vcpu in stack frame */
	str	x0, [sp, #0]

	/* Set VBAR_EL2 to guest exit vector table */
	adr	x1, arm64_vhe_guest_vectors
	msr	vbar_el2, x1
	isb

	/* Load guest PC and SPSR into ELR_EL2 and SPSR_EL2 */
	add	x0, x0, #VCPU_REGS
	ldr	x2, [x0, #VRS_PC]
	ldr	x3, [x0, #VRS_SPSR]
	msr	elr_el2, x2
	msr	spsr_el2, x3

	/* Load guest GPRs X2 - X30 from vcpu->vc_regs */
	ldp	x2,  x3,  [x0, #(VRS_GPRS + 2 * 8)]
	ldp	x4,  x5,  [x0, #(VRS_GPRS + 4 * 8)]
	ldp	x6,  x7,  [x0, #(VRS_GPRS + 6 * 8)]
	ldp	x8,  x9,  [x0, #(VRS_GPRS + 8 * 8)]
	ldp	x10, x11, [x0, #(VRS_GPRS + 10 * 8)]
	ldp	x12, x13, [x0, #(VRS_GPRS + 12 * 8)]
	ldp	x14, x15, [x0, #(VRS_GPRS + 14 * 8)]
	ldp	x16, x17, [x0, #(VRS_GPRS + 16 * 8)]
	ldp	x18, x19, [x0, #(VRS_GPRS + 18 * 8)]
	ldp	x20, x21, [x0, #(VRS_GPRS + 20 * 8)]
	ldp	x22, x23, [x0, #(VRS_GPRS + 22 * 8)]
	ldp	x24, x25, [x0, #(VRS_GPRS + 24 * 8)]
	ldp	x26, x27, [x0, #(VRS_GPRS + 26 * 8)]
	ldp	x28, x29, [x0, #(VRS_GPRS + 28 * 8)]
	ldr	lr,       [x0, #(VRS_GPRS + 30 * 8)]

	/* Finally load guest X0 and X1 */
	ldp	x0,  x1,  [x0, #(VRS_GPRS + 0 * 8)]

	/* Enter guest EL1 */
	eret
	dsb	nsh
	isb
END(arm64_vhe_enter_guest)

/*
 * nVHE Hypervisor Vector Table
 *
 * When the hypervisor runs in nVHE mode:
 * - HVC from host EL1 vectors to Synchronous 64-bit EL1
 * - Traps and IRQ/FIQ from guest EL1/EL0 vector to Lower EL using AArch64
 */
	.align 11
	.globl arm64_nvhe_hyp_vectors
arm64_nvhe_hyp_vectors:
	/* Current EL with SP0 */
	.align 7
	b	.
	.align 7
	b	.
	.align 7
	b	.
	.align 7
	b	.

	/* Current EL with SPx */
	.align 7
	b	.
	.align 7
	b	.
	.align 7
	b	.
	.align 7
	b	.

	/* Lower EL using AArch64 (Guest EL1/EL0 traps or Host EL1 HVC) */
	.align 7
	b	arm64_nvhe_trap_sync
	.align 7
	b	arm64_nvhe_guest_exit_irq
	.align 7
	b	arm64_nvhe_guest_exit_fiq
	.align 7
	b	arm64_nvhe_guest_exit_serror

	/* Lower EL using AArch32 */
	.align 7
	b	arm64_nvhe_trap_sync
	.align 7
	b	arm64_nvhe_guest_exit_irq
	.align 7
	b	arm64_nvhe_guest_exit_fiq
	.align 7
	b	arm64_nvhe_guest_exit_serror

/*
 * HVC / Sync trap handler
 */
arm64_nvhe_trap_sync:
	msr	vmpidr_el2, x0
	mrs	x0, hcr_el2
	tbz	x0, #0, arm64_nvhe_host_hvc	/* If HCR_VM == 0, host HVC */
	mov	x0, #0	/* VCPU_EXIT_TYPE_SYNC */
	b	arm64_nvhe_guest_exit

arm64_nvhe_guest_exit_irq:
	msr	vmpidr_el2, x0
	mov	x0, #1	/* VCPU_EXIT_TYPE_IRQ */
	b	arm64_nvhe_guest_exit

arm64_nvhe_guest_exit_fiq:
	msr	vmpidr_el2, x0
	mov	x0, #2	/* VCPU_EXIT_TYPE_FIQ */
	b	arm64_nvhe_guest_exit

arm64_nvhe_guest_exit_serror:
	msr	vmpidr_el2, x0
	mov	x0, #3	/* VCPU_EXIT_TYPE_SERROR */
	b	arm64_nvhe_guest_exit

/*
 * HVC from host EL1
 */
arm64_nvhe_host_hvc:
	mrs	x0, vmpidr_el2
	cbz	x0, arm64_nvhe_hvc_enter_guest

	/* If non-zero, install new vector table address from x0 */
	msr	vbar_el2, x0
	isb
	mov	x0, #0
	eret

/*
 * Host calls HVC #0 with:
 * x0 = 0 (enter guest)
 * x1 = struct vcpu *
 */
arm64_nvhe_hvc_enter_guest:
	/* Save vcpu pointer in TPIDR_EL2 */
	msr	tpidr_el2, x1

	/* Save host EL1 system registers into vcpu->vc_host_* */
	mrs	x2, sctlr_el1
	mrs	x3, cpacr_el1
	mrs	x4, ttbr0_el1
	mrs	x5, ttbr1_el1
	mrs	x6, tcr_el1
	mrs	x7, mair_el1
	mrs	x8, vbar_el1
	mrs	x9, contextidr_el1
	mrs	x10, tpidr_el0
	mrs	x11, tpidr_el1
	mrs	x12, tpidrro_el0
	mrs	x13, sp_el0
	mrs	x14, sp_el1

	add	x0, x1, #VCPU_HOST_SCTLR_EL1
	stp	x2,  x3,  [x0, #0]
	stp	x4,  x5,  [x0, #16]
	stp	x6,  x7,  [x0, #32]
	stp	x8,  x9,  [x0, #48]
	stp	x10, x11, [x0, #64]
	stp	x12, x13, [x0, #80]
	str	x14,      [x0, #96]

	/* Allow guest access to counters and virtual timer */
	ldr	x2, =CNTHCTL_GUEST_FLAGS
	msr	cnthctl_el2, x2

	/* Set virtual timer offset */
	ldr	x2, [x1, #VCPU_CNTVOFF_EL2]
	msr	cntvoff_el2, x2

	/* Set up guest Stage-2 translation & control registers */
	ldr	x2, [x1, #VCPU_VTTBR_EL2]
	ldr	x3, [x1, #VCPU_VTCR_EL2]
	ldr	x4, [x1, #VCPU_HCR_EL2]
	msr	vttbr_el2, x2
	msr	vtcr_el2, x3
	msr	hcr_el2, x4

	/* Restore guest EL1 system registers from vcpu */
	ldr	x2,  [x1, #VCPU_SCTLR_EL1]
	ldr	x3,  [x1, #VCPU_CPACR_EL1]
	ldr	x4,  [x1, #VCPU_TTBR0_EL1]
	ldr	x5,  [x1, #VCPU_TTBR1_EL1]
	ldr	x6,  [x1, #VCPU_TCR_EL1]
	ldr	x7,  [x1, #VCPU_MAIR_EL1]
	ldr	x8,  [x1, #VCPU_VBAR_EL1]
	ldr	x9,  [x1, #VCPU_CONTEXTIDR_EL1]
	ldr	x10, [x1, #VCPU_TPIDR_EL0]
	ldr	x11, [x1, #VCPU_TPIDR_EL1]
	ldr	x12, [x1, #VCPU_TPIDRRO_EL0]
	ldr	x13, [x1, #VCPU_ESR_EL1]
	ldr	x14, [x1, #VCPU_FAR_EL1]
	ldr	x15, [x1, #VCPU_SP_EL0]
	ldr	x16, [x1, #VCPU_SP_EL1]
	ldr	x17, [x1, #VCPU_ELR_EL1]
	ldr	x18, [x1, #VCPU_SPSR_EL1]

	msr	sctlr_el1, x2
	msr	cpacr_el1, x3
	msr	ttbr0_el1, x4
	msr	ttbr1_el1, x5
	msr	tcr_el1, x6
	msr	mair_el1, x7
	msr	vbar_el1, x8
	msr	contextidr_el1, x9
	msr	tpidr_el0, x10
	msr	tpidr_el1, x11
	msr	tpidrro_el0, x12
	msr	esr_el1, x13
	msr	far_el1, x14
	msr	sp_el0, x15
	msr	sp_el1, x16
	msr	elr_el1, x17
	msr	spsr_el1, x18

	/* Restore guest PC and SPSR into ELR_EL2 and SPSR_EL2 */
	add	x0, x1, #VCPU_REGS
	ldr	x2, [x0, #VRS_PC]
	ldr	x3, [x0, #VRS_SPSR]
	msr	elr_el2, x2
	msr	spsr_el2, x3

	/* Load guest GPRs X2 - X30 from vcpu->vc_regs */
	ldp	x2,  x3,  [x0, #(VRS_GPRS + 2 * 8)]
	ldp	x4,  x5,  [x0, #(VRS_GPRS + 4 * 8)]
	ldp	x6,  x7,  [x0, #(VRS_GPRS + 6 * 8)]
	ldp	x8,  x9,  [x0, #(VRS_GPRS + 8 * 8)]
	ldp	x10, x11, [x0, #(VRS_GPRS + 10 * 8)]
	ldp	x12, x13, [x0, #(VRS_GPRS + 12 * 8)]
	ldp	x14, x15, [x0, #(VRS_GPRS + 14 * 8)]
	ldp	x16, x17, [x0, #(VRS_GPRS + 16 * 8)]
	ldp	x18, x19, [x0, #(VRS_GPRS + 18 * 8)]
	ldp	x20, x21, [x0, #(VRS_GPRS + 20 * 8)]
	ldp	x22, x23, [x0, #(VRS_GPRS + 22 * 8)]
	ldp	x24, x25, [x0, #(VRS_GPRS + 24 * 8)]
	ldp	x26, x27, [x0, #(VRS_GPRS + 26 * 8)]
	ldp	x28, x29, [x0, #(VRS_GPRS + 28 * 8)]
	ldr	lr,       [x0, #(VRS_GPRS + 30 * 8)]

	/* Finally load guest X0 and X1 */
	ldp	x0,  x1,  [x0, #(VRS_GPRS + 0 * 8)]

	/* Enter guest EL1 */
	eret
	dsb	nsh
	isb

/*
 * Guest exit back to EL2
 */
arm64_nvhe_guest_exit:
	/* Stash guest x1 into VPIDR_EL2 */
	msr	vpidr_el2, x1

	/* Load vcpu pointer from TPIDR_EL2 */
	mrs	x1, tpidr_el2

	/* Save exit type */
	str	w0, [x1, #VCPU_EXIT_TYPE]

	/* Save guest X2 - X30 to vcpu->vc_regs */
	add	x0, x1, #VCPU_REGS
	stp	x2,  x3,  [x0, #(VRS_GPRS + 2 * 8)]
	stp	x4,  x5,  [x0, #(VRS_GPRS + 4 * 8)]
	stp	x6,  x7,  [x0, #(VRS_GPRS + 6 * 8)]
	stp	x8,  x9,  [x0, #(VRS_GPRS + 8 * 8)]
	stp	x10, x11, [x0, #(VRS_GPRS + 10 * 8)]
	stp	x12, x13, [x0, #(VRS_GPRS + 12 * 8)]
	stp	x14, x15, [x0, #(VRS_GPRS + 14 * 8)]
	stp	x16, x17, [x0, #(VRS_GPRS + 16 * 8)]
	stp	x18, x19, [x0, #(VRS_GPRS + 18 * 8)]
	stp	x20, x21, [x0, #(VRS_GPRS + 20 * 8)]
	stp	x22, x23, [x0, #(VRS_GPRS + 22 * 8)]
	stp	x24, x25, [x0, #(VRS_GPRS + 24 * 8)]
	stp	x26, x27, [x0, #(VRS_GPRS + 26 * 8)]
	stp	x28, x29, [x0, #(VRS_GPRS + 28 * 8)]
	str	lr,       [x0, #(VRS_GPRS + 30 * 8)]

	/* Restore stashed guest x0 and x1 and save them */
	mrs	x2, vmpidr_el2
	mrs	x3, vpidr_el2
	stp	x2, x3, [x0, #(VRS_GPRS + 0 * 8)]

	/* Save EL2 syndrome & fault registers */
	mrs	x2, esr_el2
	mrs	x3, far_el2
	mrs	x4, hpfar_el2
	mrs	x5, elr_el2
	mrs	x6, spsr_el2

	str	w2, [x1, #VCPU_ESR_EL2]
	str	x3, [x1, #VCPU_FAR_EL2]
	str	x4, [x1, #VCPU_HPFAR_EL2]
	str	x5, [x0, #VRS_PC]
	str	x6, [x0, #VRS_SPSR]

	/* Save guest EL1 system registers into vcpu */
	mrs	x2,  sctlr_el1
	mrs	x3,  cpacr_el1
	mrs	x4,  ttbr0_el1
	mrs	x5,  ttbr1_el1
	mrs	x6,  tcr_el1
	mrs	x7,  mair_el1
	mrs	x8,  vbar_el1
	mrs	x9,  contextidr_el1
	mrs	x10, tpidr_el0
	mrs	x11, tpidr_el1
	mrs	x12, tpidrro_el0
	mrs	x13, esr_el1
	mrs	x14, far_el1
	mrs	x15, sp_el0
	mrs	x16, sp_el1
	mrs	x17, elr_el1
	mrs	x18, spsr_el1

	str	x2,  [x1, #VCPU_SCTLR_EL1]
	str	x3,  [x1, #VCPU_CPACR_EL1]
	str	x4,  [x1, #VCPU_TTBR0_EL1]
	str	x5,  [x1, #VCPU_TTBR1_EL1]
	str	x6,  [x1, #VCPU_TCR_EL1]
	str	x7,  [x1, #VCPU_MAIR_EL1]
	str	x8,  [x1, #VCPU_VBAR_EL1]
	str	x9,  [x1, #VCPU_CONTEXTIDR_EL1]
	str	x10, [x1, #VCPU_TPIDR_EL0]
	str	x11, [x1, #VCPU_TPIDR_EL1]
	str	x12, [x1, #VCPU_TPIDRRO_EL0]
	str	x13, [x1, #VCPU_ESR_EL1]
	str	x14, [x1, #VCPU_FAR_EL1]
	str	x15, [x1, #VCPU_SP_EL0]
	str	x16, [x1, #VCPU_SP_EL1]
	str	x17, [x1, #VCPU_ELR_EL1]
	str	x18, [x1, #VCPU_SPSR_EL1]

	/* Clear virtual timer offset and restore host timer access */
	msr	cntvoff_el2, xzr
	mov	x2, #(CNTHCTL_EL1PCTEN | CNTHCTL_EL1PCEN)
	msr	cnthctl_el2, x2

	/* Turn off guest Stage 2 and clear HCR_EL2 */
	mov	x2, #HCR_RW
	orr	x2, x2, #(HCR_API | HCR_APK)
	msr	hcr_el2, x2
	isb

	/* Clear TPIDR_EL2 to indicate host is running */
	msr	tpidr_el2, xzr

	/* Restore host EL1 system registers */
	add	x0, x1, #VCPU_HOST_SCTLR_EL1
	ldp	x2,  x3,  [x0, #0]
	ldp	x4,  x5,  [x0, #16]
	ldp	x6,  x7,  [x0, #32]
	ldp	x8,  x9,  [x0, #48]
	ldp	x10, x11, [x0, #64]
	ldp	x12, x13, [x0, #80]
	ldr	x14,      [x0, #96]

	msr	sctlr_el1, x2
	msr	cpacr_el1, x3
	msr	ttbr0_el1, x4
	msr	ttbr1_el1, x5
	msr	tcr_el1, x6
	msr	mair_el1, x7
	msr	vbar_el1, x8
	msr	contextidr_el1, x9
	msr	tpidr_el0, x10
	msr	tpidr_el1, x11
	msr	tpidrro_el0, x12
	msr	sp_el0, x13
	msr	sp_el1, x14
	isb

	/* Load exit type to return in x0 */
	ldr	w0, [x1, #VCPU_EXIT_TYPE]

	/* Return to host EL1 via eret */
	eret

/*
 * int arm64_nvhe_enter_guest(struct vcpu *vcpu)
 *
 * Invokes HVC to transition from host EL1 into guest via nVHE EL2.
 */
ENTRY(arm64_nvhe_enter_guest)
	/* Allocate frame on host stack and save host callee-saved registers */
	sub	sp, sp, #112
	stp	x19, x20, [sp, #0]
	stp	x21, x22, [sp, #16]
	stp	x23, x24, [sp, #32]
	stp	x25, x26, [sp, #48]
	stp	x27, x28, [sp, #64]
	stp	x29, lr,  [sp, #80]

	/* x0 = 0 (enter guest), x1 = struct vcpu * */
	mov	x1, x0
	mov	x0, #0
	hvc	#0

	/* Guest exited; return value in x0 contains exit type */
	ldp	x19, x20, [sp, #0]
	ldp	x21, x22, [sp, #16]
	ldp	x23, x24, [sp, #32]
	ldp	x25, x26, [sp, #48]
	ldp	x27, x28, [sp, #64]
	ldp	x29, lr,  [sp, #80]
	add	sp, sp, #112
	ret
END(arm64_nvhe_enter_guest)

/*
 * void arm64_nvhe_install_vectors(void)
 *
 * Installs arm64_nvhe_hyp_vectors into VBAR_EL2 via hyp stub HVC.
 */
ENTRY(arm64_nvhe_install_vectors)
	ldr	x0, =arm64_nvhe_hyp_vectors
	hvc	#0
	ret
END(arm64_nvhe_install_vectors)

