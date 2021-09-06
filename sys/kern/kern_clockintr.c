/* $OpenBSD$ */

/*
 * Copyright (c) 2003 Dale Rahn <drahn@openbsd.org>
 * Copyright (c) 2020 Mark Kettenis <kettenis@openbsd.org>
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

#include <sys/param.h>
#include <sys/atomic.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/stdint.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/time.h>

#include <dev/clockintr.h>

#include <machine/intr.h>

/*
 * Locks used in this file:
 *
 *	C	global clockintr configuration mutex (clockintr_mtx)
 *	I	Immutable after initialization
 *	p	Only modified by local CPU
 */
struct mutex clockintr_mtx = MUTEX_INITIALIZER(IPL_CLOCK);

/*
 * Per-CPU clockintr state.
 */
struct clockintr_queue {
	uint64_t cq_next;		/* [p] next event expiration */
	uint64_t cq_next_hardclock;	/* [p] next hardclock expiration */
	uint64_t cq_next_statclock;	/* [p] next statclock expiration */	
	struct intrclock cq_intrclock;	/* [I] local interrupt clock */
	struct clockintr_stat cq_stat;	/* [p] dispatch statistics */
	volatile u_int cq_stat_gen;	/* [p] cq_stat update generation */ 
	u_int cq_flags;			/* [I] local state + behavior flags */
} *clockintr_cpu_queue[MAXCPUS];

u_int clockintr_flags;			/* [I] global state + behavior flags */
uint32_t hardclock_period;		/* [I] hardclock period (ns) */
volatile u_int statgen = 1;		/* [C] stat update generation */
uint32_t statavg;			/* [C] average statclock period (ns) */
uint32_t statmin;			/* [C] minimum statclock period (ns) */
uint32_t statvar;			/* [C] max statmin offset (ns) */

uint64_t nsec_advance(uint64_t *, uint64_t, uint64_t);
uint64_t nsecruntime(void);

/*
 * Initialize global clockintr state.  Must be called only once.
 */
void
clockintr_init(int hardfreq, int statfreq, u_int flags)
{
	KASSERT(clockintr_flags == 0);
	KASSERT(hardfreq > 0 && hardfreq <= 1000000000);
	KASSERT(statfreq >= 0 && statfreq <= 1000000000);
	KASSERT((flags & ~CI_FLAG_MASK) == 0);

	hardclock_period = 1000000000 / hardfreq;
	if (statfreq != 0) {
		SET(clockintr_flags, CI_WANTSTAT);
		clockintr_reset_statclock_frequency(statfreq);
	} else
		KASSERT(!ISSET(flags, CI_RNDSTAT));
	SET(clockintr_flags, flags | CI_INIT);
}

/*
 * Allocate and initialize the local CPU's state for use in
 * clockintr_dispatch().
 */
void
clockintr_cpu_init(const struct intrclock *ic, u_int flags)
{
	struct clockintr_queue *cq;
	int cpu;

	cpu = cpu_number();

	KASSERT((flags & ~CICPU_FLAG_MASK) == 0);

	if (!ISSET(clockintr_flags, CI_INIT)) {
		panic("%s: cpu%d: called before clockintr_init()",
		    __func__, cpu);
	}

	/*
	 * It is not an error if we're called multiple times for a
	 * given CPU.  Just make sure the intrclock didn't change.
	 *
	 * XXX Is M_DEVBUF appropriate?  This isn't really a "driver".
	 */
	cq = clockintr_cpu_queue[cpu];
	if (cq == NULL) {
		cq = malloc(sizeof(*cq), M_DEVBUF, M_NOWAIT | M_ZERO);
		if (ic != NULL) {
			cq->cq_intrclock = *ic;
			SET(cq->cq_flags, CICPU_HAVE_INTRCLOCK);
		}
		cq->cq_stat_gen = 1;
		SET(cq->cq_flags, flags | CICPU_INIT);
		clockintr_cpu_queue[cpu] = cq;
	} else {
		KASSERT(ISSET(cq->cq_flags, CICPU_INIT));
		if (ISSET(cq->cq_flags, CICPU_HAVE_INTRCLOCK))
			KASSERT(cq->cq_intrclock.ic_rearm == ic->ic_rearm);
		else
			KASSERT(ic == NULL);
	}
}

/*
 * Run all expired events scheduled on the local CPU.
 *
 * At the moment there two kinds of events: hardclock and statclock.
 *
 * The hardclock has a fixed period of hardclock_period nanoseconds.
 *
 * If CI_WANTSTAT is unset then the statclock is not run.  Otherwise, the
 * statclock period is determined by the CI_RNDSTAT flag:
 *
 * - If CI_RNDSTAT is unset then the statclock has a fixed period
 *   of statavg nanoseconds.
 *
 * - If CI_RNDSTAT is set then the statclock has a pseudorandom period
 *   of [statavg - (statvar / 2), statavg + (statvar / 2)] nanoseconds.
 *   We use random(9) to determine the period instead of arc4random(9)
 *   because it is faster.
 *
 * Returns 1 if any events are run, otherwise 0.
 *
 * TODO It would be great if hardclock() and statclock() took a count
 *      of ticks so we don't need to call them in a loop if the clock
 *      interrupt is delayed.  This would also allow us to organically
 *      advance the value of the global variable "ticks" when we resume
 *      from suspend.
 *
 * TODO All platforms should run a separate statclock.  We should not
 *      call statclock() from hardclock().
 */
int
clockintr_dispatch(struct clockframe *frame)
{
	uint64_t count, i, lateness, now, run;
	struct clockintr_queue *cq;
	uint32_t avg, min, off, var;
	u_int gen, ogen;

	splassert(IPL_CLOCK);
	cq = clockintr_cpu_queue[cpu_number()];

	/*
	 * If we arrived too early we have nothing to do.
	 */
	now = nsecruntime();
	if (now < cq->cq_next)
		goto done;

	lateness = now - cq->cq_next;
	run = 0;

	/*
	 * Run the dispatch.
	 */
again:
	/* Run all expired hardclock events. */
	count = nsec_advance(&cq->cq_next_hardclock, hardclock_period, now);
	for (i = 0; i < count; i++)
		hardclock(frame);
	run += count;

	/* Run all expired statclock events. */
	if (ISSET(clockintr_flags, CI_WANTSTAT)) {
		do {
			gen = statgen;
			membar_consumer();
			avg = statavg;
			min = statmin;
			var = statvar;
			membar_consumer();
		} while (gen == 0 || gen != statgen);
		if (ISSET(clockintr_flags, CI_RNDSTAT)) {
			count = 0;
			while (cq->cq_next_statclock <= now) {
				count++;
				while ((off = (random() & (var - 1))) == 0)
					continue;
				cq->cq_next_statclock += min + off;
			}
		} else 
			count = nsec_advance(&cq->cq_next_statclock, avg, now);
		for (i = 0; i < count; i++)
			statclock(frame);
		run += count;
	}

	/*
	 * Rerun the dispatch if the next event has already expired.
	 */
	if (ISSET(clockintr_flags, CI_WANTSTAT))
		cq->cq_next = MIN(cq->cq_next_hardclock, cq->cq_next_statclock);
	else
		cq->cq_next = cq->cq_next_hardclock;
	now = nsecruntime();
	if (cq->cq_next <= now)
		goto again;

	/*
	 * Dispatch complete.
	 */
done:
	if (ISSET(cq->cq_flags, CICPU_HAVE_INTRCLOCK))
		intrclock_rearm(&cq->cq_intrclock, cq->cq_next - now);

	ogen = cq->cq_stat_gen;
	cq->cq_stat_gen = 0;
	membar_producer();
	if (run > 0) {
		cq->cq_stat.cs_dispatch_prompt++;
		cq->cq_stat.cs_dispatch_lateness += lateness;
		cq->cq_stat.cs_events_run += run;
	} else
		cq->cq_stat.cs_dispatch_early++;
	membar_producer();
	cq->cq_stat_gen = MAX(1, ogen + 1);

	return run > 0;
}

/*
 * Initialize and/or update the statclock variables.  Computes
 * statavg, statmin, and statvar according to the given frequency.
 *
 * This is first called during clockintr_init() to enable a statclock
 * separate from the hardclock.
 * 
 * Subsequent calls are made from setstatclockrate() to update the
 * frequency when enabling or disabling profiling.
 *
 * TODO Isolate the profiling code from statclock() into a separate
 *      profclock() routine so we don't need to change the effective
 *      rate at runtime anymore.  Ideally we would set the statclock
 *      variables once and never reset them.  Then we can remove the
 *      atomic synchronization code from clockintr_dispatch().
 */
void
clockintr_reset_statclock_frequency(int freq)
{
	uint32_t avg, half_avg, min, var;
	unsigned int ogen;

	KASSERT(ISSET(clockintr_flags, CI_WANTSTAT));
	KASSERT(freq > 0 && freq <= 1000000000);

	avg = 1000000000 / freq;

	/* Find the largest power of two such that 2^n <= avg / 2. */
	half_avg = avg / 2;
	for (var = 1 << 31; var > half_avg; var /= 2)
		continue;

	/* Use the value we found to set a lower bound for our range. */
	min = avg - (var / 2);

	mtx_enter(&clockintr_mtx);

	ogen = statgen;
	statgen = 0;
	membar_producer();

	statavg = avg;
	statmin = min;
	statvar = var;

	membar_producer();
	statgen = MAX(1, ogen + 1);

	mtx_leave(&clockintr_mtx);
}

int
clockintr_sysctl(void *oldp, size_t *oldlenp, void *newp, size_t newlen)
{
	struct clockintr_stat stat, total = { 0 };
	struct clockintr_queue *cq;
	struct cpu_info *ci;
	CPU_INFO_ITERATOR cii;
	unsigned int gen;

	CPU_INFO_FOREACH(cii, ci) {
		cq = clockintr_cpu_queue[CPU_INFO_UNIT(ci)];
		if (cq == NULL || !ISSET(cq->cq_flags, CICPU_INIT))
			continue;
		do {
			gen = cq->cq_stat_gen;
			membar_consumer();
			stat = cq->cq_stat;
			membar_consumer();
		} while (gen == 0 || gen != cq->cq_stat_gen);
		total.cs_dispatch_early += stat.cs_dispatch_early;
		total.cs_dispatch_prompt += stat.cs_dispatch_prompt;
		total.cs_dispatch_lateness += stat.cs_dispatch_lateness;
		total.cs_events_run += stat.cs_events_run;
	}

	return sysctl_rdstruct(oldp, oldlenp, newp, &total, sizeof(total));
}

/*
 * Given an interval timer with a period of period nanoseconds whose
 * next expiration point is the absolute time *next, find the timer's
 * most imminent expiration point *after* the absolute time now and
 * write it to *next.
 *
 * Returns the number of elapsed periods.
 *
 * There are three cases here.  Each is more computationally expensive
 * than the last.
 *
 * 1. No periods have elapsed because *next has not yet elapsed.  We
 *    don't need to update *next.  Just return 0.
 *
 * 2. One period has elapsed.  *next has elapsed but (*next + period)
 *    has not elapsed.  Update *next and return 1.
 *
 * 3. More than one period has elapsed.  Compute the number of elapsed
 *    periods using integer division and update *next.
 *
 * This routine performs no overflow checks.  We assume period is less than
 * or equal to one billion, so overflow should never happen if the system
 * clock is even remotely sane.
 */
uint64_t
nsec_advance(uint64_t *next, uint64_t period, uint64_t now)
{
	uint64_t elapsed;

	if (now < *next)
		return 0;

	if (now < *next + period) {
		*next += period;
		return 1;
	}

	elapsed = (now - *next) / period + 1;
	*next += period * elapsed;
	return elapsed;
}

/*
 * TODO Move to kern_tc.c when other callers exist.
 */
uint64_t
nsecruntime(void)
{
	struct timespec now;

	nanoruntime(&now);
	return TIMESPEC_TO_NSEC(&now);
}

#ifdef DDB
#include <machine/db_machdep.h>

#include <ddb/db_interface.h>
#include <ddb/db_output.h>
#include <ddb/db_sym.h>

void db_show_clockintr_cpu(struct cpu_info *);

/*
 * ddb> show clockintr
 */
void
db_show_clockintr(db_expr_t addr, int haddr, db_expr_t count, char *modif)
{
	struct timespec now;
	struct cpu_info *info;
	CPU_INFO_ITERATOR iterator;

	nanoruntime(&now);

	db_printf("%20s\n", "RUNTIME");
	db_printf("%10lld.%09ld\n", now.tv_sec, now.tv_nsec);
	db_printf("\n");
	db_printf("%20s  %3s  %s\n", "EXPIRATION", "CPU", "FUNC");
	CPU_INFO_FOREACH(iterator, info)
		db_show_clockintr_cpu(info);
}

void
db_show_clockintr_cpu(struct cpu_info *ci)
{
	struct timespec next;
	struct clockintr_queue *cq;
	unsigned int cpu;

	cpu = CPU_INFO_UNIT(ci);
	cq = clockintr_cpu_queue[cpu];

	if (cq == NULL || !ISSET(cq->cq_flags, CICPU_INIT))
		return;

	NSEC_TO_TIMESPEC(cq->cq_next_hardclock, &next);
	db_printf("%10lld.%09ld  %3u  %s\n",
	    next.tv_sec, next.tv_nsec, cpu, "hardclock");

	if (ISSET(clockintr_flags, CI_WANTSTAT)) {
		NSEC_TO_TIMESPEC(cq->cq_next_statclock, &next);
		db_printf("%10lld.%09ld  %3u  %s\n",
		    next.tv_sec, next.tv_nsec, cpu, "statclock");
	}
}
#endif
