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
	 * Restore x0 pointer to struct vcpu from stack top
	 */
	ldr	x0, [sp, #0]

	/* Save guest X1 - X30 to vcpu->vc_regs.vrs_gprs */
	stp	x1,  x2,  [x0, #(16 + 1 * 8)]
	stp	x3,  x4,  [x0, #(16 + 3 * 8)]
	stp	x5,  x6,  [x0, #(16 + 5 * 8)]
	stp	x7,  x8,  [x0, #(16 + 7 * 8)]
	stp	x9,  x10, [x0, #(16 + 9 * 8)]
	stp	x11, x12, [x0, #(16 + 11 * 8)]
	stp	x13, x14, [x0, #(16 + 13 * 8)]
	stp	x15, x16, [x0, #(16 + 15 * 8)]
	stp	x17, x18, [x0, #(16 + 17 * 8)]
	stp	x19, x20, [x0, #(16 + 19 * 8)]
	stp	x21, x22, [x0, #(16 + 21 * 8)]
	stp	x23, x24, [x0, #(16 + 23 * 8)]
	stp	x25, x26, [x0, #(16 + 25 * 8)]
	stp	x27, x28, [x0, #(16 + 27 * 8)]
	stp	x29, lr,  [x0, #(16 + 29 * 8)]

	/* Save guest X0 from temporary stash on stack */
	ldr	x1, [sp, #8]
	str	x1, [x0, #(16 + 0 * 8)]

	/* Save EL2 syndrome & fault registers */
	mrs	x2, esr_el2
	mrs	x3, far_el2
	mrs	x4, hpfar_el2
	mrs	x5, elr_el2
	mrs	x6, spsr_el2

	str	w2, [x0, #96]	/* vc_esr_el2 */
	str	x3, [x0, #80]	/* vc_far_el2 */
	str	x4, [x0, #72]	/* vc_hpfar_el2 */
	str	x5, [x0, #40]	/* vrs_pc */
	str	x6, [x0, #56]	/* vrs_spsr */

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
	ldr	x2, [x0, #40]	/* vrs_pc */
	ldr	x3, [x0, #56]	/* vrs_spsr */
	msr	elr_el2, x2
	msr	spsr_el2, x3

	/* Load guest GPRs X1 - X30 from vcpu->vc_regs */
	ldp	x1,  x2,  [x0, #(16 + 1 * 8)]
	ldp	x3,  x4,  [x0, #(16 + 3 * 8)]
	ldp	x5,  x6,  [x0, #(16 + 5 * 8)]
	ldp	x7,  x8,  [x0, #(16 + 7 * 8)]
	ldp	x9,  x10, [x0, #(16 + 9 * 8)]
	ldp	x11, x12, [x0, #(16 + 11 * 8)]
	ldp	x13, x14, [x0, #(16 + 13 * 8)]
	ldp	x15, x16, [x0, #(16 + 15 * 8)]
	ldp	x17, x18, [x0, #(16 + 17 * 8)]
	ldp	x19, x20, [x0, #(16 + 19 * 8)]
	ldp	x21, x22, [x0, #(16 + 21 * 8)]
	ldp	x23, x24, [x0, #(16 + 23 * 8)]
	ldp	x25, x26, [x0, #(16 + 25 * 8)]
	ldp	x27, x28, [x0, #(16 + 27 * 8)]
	ldp	x29, lr,  [x0, #(16 + 29 * 8)]

	/* Stash guest X0 and finally load it */
	ldr	x0, [x0, #(16 + 0 * 8)]
	str	x0, [sp, #8]

	/* Enter guest EL1 */
	eret
	dsb	nsh
	isb
END(arm64_vhe_enter_guest)
