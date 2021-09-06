/* $OpenBSD$ */

/*
 * Copyright (c) 2020-2021 Scott Cheloha <cheloha@openbsd.org>
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

#ifndef _DEV_CLOCKINTR_H_
#define _DEV_CLOCKINTR_H_

#ifdef _KERNEL

#include <machine/intr.h>

/*
 * Platform API
 */

struct intrclock;

typedef void (*intrclock_rearm_t)(uint64_t);

struct intrclock {
	intrclock_rearm_t ic_rearm;
	void *ic_cookie;
};

static inline void
intrclock_rearm(struct intrclock *ic, uint64_t nsecs)
{
	ic->ic_rearm(nsecs);
}

struct clockframe;

void clockintr_cpu_init(const struct intrclock *, u_int);
int clockintr_dispatch(struct clockframe *);
void clockintr_init(int, int, u_int);
void clockintr_reset_statclock_frequency(int);

/* Global state flags. */
#define CI_INIT			0x00000001	/* clockintr_init() called */
#define CI_WANTSTAT		0x00000002	/* run a separate statclock */
#define CI_STATE_MASK		0x00000003

/* Global behavior flags. */
#define CI_RNDSTAT		0x80000000	/* randomized statclock */
#define CI_FLAG_MASK		0x80000000

/* Per-CPU state flags. */
#define CICPU_INIT		0x00000001	/* ready for dispatch */
#define CICPU_HAVE_INTRCLOCK	0x00000002	/* have local intr. clock */
#define CICPU_STATE_MASK	0x00000003

/* Per-CPU behavior flags. */
#define CICPU_FLAG_MASK		0x00000000

/*
 * Kernel API
 */

int clockintr_sysctl(void *, size_t *, void *, size_t);

#endif /* _KERNEL */

struct clockintr_stat {
	uint64_t	cs_dispatch_early;
	uint64_t	cs_dispatch_prompt;
	uint64_t	cs_dispatch_lateness;
	uint64_t	cs_events_run;
};

#endif /* !_DEV_CLOCKINTR_H_ */
