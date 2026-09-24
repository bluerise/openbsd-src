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
#include "assym.h"

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
	 * x0 has pointer to struct vcpu saved on stack.
	 */
	b	arm64_vhe_guest_exit

arm64_vhe_guest_exit_irq:
	b	arm64_vhe_guest_exit

arm64_vhe_guest_exit_fiq:
	b	arm64_vhe_guest_exit

arm64_vhe_guest_exit_serror:
	b	arm64_vhe_guest_exit

arm64_vhe_guest_exit:
	/*
	 * Exception taken to EL2. Host sp still points to the host frame.
	 * Stash guest x1 and x2 into free stack slots.
	 */
	str	x1, [sp, #8]
	str	x2, [sp, #24]

	/* Load vcpu pointer from [sp, #0] into x1 */
	ldr	x1, [sp, #0]
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

	/* Restore host callee-saved registers x19-x30 */
	ldp	x19, x20, [sp, #32]
	ldp	x21, x22, [sp, #48]
	ldp	x23, x24, [sp, #64]
	ldp	x25, x26, [sp, #80]
	ldp	x27, x28, [sp, #96]
	ldp	x29, lr,  [sp, #112]
	add	sp, sp, #128

	/* Return 0 on normal trap to host */
	mov	x0, #0
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
