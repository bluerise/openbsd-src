/* $OpenBSD$ */
/*
 * Copyright (c) 2022 Patrick Wildt <patrick@blueri.se>
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
#include <sys/queue.h>
#include <sys/malloc.h>
#include <sys/sysctl.h>
#include <sys/device.h>
#include <sys/evcount.h>
#include <sys/socket.h>
#include <sys/timeout.h>

#include <machine/intr.h>
#include <machine/bus.h>
#include <machine/fdt.h>

#include <dev/ofw/openfirm.h>
#include <dev/ofw/ofw_clock.h>
#include <dev/ofw/ofw_misc.h>
#include <dev/ofw/ofw_regulator.h>
#include <dev/ofw/fdt.h>

#define HREAD4(sc, reg)							\
	(bus_space_read_4((sc)->sc_iot, (sc)->sc_ioh, (reg)))
#define HWRITE4(sc, reg, val)						\
	bus_space_write_4((sc)->sc_iot, (sc)->sc_ioh, (reg), (val))
#define HSET4(sc, reg, bits)						\
	HWRITE4((sc), (reg), HREAD4((sc), (reg)) | (bits))
#define HCLR4(sc, reg, bits)						\
	HWRITE4((sc), (reg), HREAD4((sc), (reg)) & ~(bits))

#include "qcclock_clocks.h"

struct qcclock_softc {
	struct device		sc_dev;
	bus_space_tag_t		sc_iot;
	bus_space_handle_t	sc_ioh;
	int			sc_node;
	uint32_t		sc_phandle;

	struct clock_device	sc_cd;
	struct reset_device	sc_rd;
};

int	qcclock_match(struct device *, void *, void *);
void	qcclock_attach(struct device *parent, struct device *self, void *args);

const struct cfattach	qcclock_ca = {
	sizeof (struct qcclock_softc), qcclock_match, qcclock_attach
};

struct cfdriver qcclock_cd = {
	NULL, "qcclock", DV_DULL
};

void sc8280xp_enable(void *, uint32_t *, int);
uint32_t sc8280xp_get_frequency(void *, uint32_t *);
int sc8280xp_set_frequency(void *, uint32_t *, uint32_t);
void sc8280xp_reset(void *, uint32_t *, int);

struct qcclock_compat {
	const char *compat;
	int	assign;
	void	(*init)(struct qcclock_softc *);
	void	(*enable)(void *, uint32_t *, int);
	uint32_t (*get_frequency)(void *, uint32_t *);
	int	(*set_frequency)(void *, uint32_t *, uint32_t);
	int	(*set_parent)(void *, uint32_t *, uint32_t *);
	void	(*reset)(void *, uint32_t *, int);
};

const struct qcclock_compat qcclock_compat[] = {
	{
		"qcom,gcc-sc8280xp", 0, NULL,
		sc8280xp_enable, sc8280xp_get_frequency,
		sc8280xp_set_frequency, NULL,
		sc8280xp_reset
	},
};

int
qcclock_match(struct device *parent, void *match, void *aux)
{
	struct fdt_attach_args *faa = aux;
	int i;

	for (i = 0; i < nitems(qcclock_compat); i++) {
		if (OF_is_compatible(faa->fa_node, qcclock_compat[i].compat))
			return 10;
	}

	return 0;
}

void
qcclock_attach(struct device *parent, struct device *self, void *aux)
{
	struct qcclock_softc *sc = (struct qcclock_softc *)self;
	struct fdt_attach_args *faa = aux;
	int i;

	KASSERT(faa->fa_nreg >= 1);

	sc->sc_node = faa->fa_node;
	sc->sc_iot = faa->fa_iot;
	if (bus_space_map(sc->sc_iot, faa->fa_reg[0].addr,
	    faa->fa_reg[0].size, 0, &sc->sc_ioh))
		panic("%s: bus_space_map failed!", __func__);

	printf("\n");

	sc->sc_phandle = OF_getpropint(sc->sc_node, "phandle", 0);

	for (i = 0; i < nitems(qcclock_compat); i++) {
		if (OF_is_compatible(faa->fa_node, qcclock_compat[i].compat)) {
			break;
		}
	}
	KASSERT(i < nitems(qcclock_compat));

	if (qcclock_compat[i].init)
		qcclock_compat[i].init(sc);

	sc->sc_cd.cd_node = faa->fa_node;
	sc->sc_cd.cd_cookie = sc;
	sc->sc_cd.cd_enable = qcclock_compat[i].enable;
	sc->sc_cd.cd_get_frequency = qcclock_compat[i].get_frequency;
	sc->sc_cd.cd_set_frequency = qcclock_compat[i].set_frequency;
	sc->sc_cd.cd_set_parent = qcclock_compat[i].set_parent;
	clock_register(&sc->sc_cd);

	sc->sc_rd.rd_node = faa->fa_node;
	sc->sc_rd.rd_cookie = sc;
	sc->sc_rd.rd_reset = qcclock_compat[i].reset;
	reset_register(&sc->sc_rd);

	if (qcclock_compat[i].assign)
		clock_set_assigned(faa->fa_node);
}

void
sc8280xp_enable(void *cookie, uint32_t *cells, int on)
{
	/* Clocks should already be enabled. */
}

uint32_t
sc8280xp_get_frequency(void *cookie, uint32_t *cells)
{
	uint32_t idx = cells[0];

	printf("%s: 0x%08x\n", __func__, idx);
	return 0;
}

int
sc8280xp_set_frequency(void *cookie, uint32_t *cells, uint32_t freq)
{
	/* Clocks should be set correctly. */
	return 0;
}

int
sc8280xp_set_parent(void *cookie, uint32_t *cells, uint32_t *pcells)
{
	struct qcclock_softc *sc = cookie;
	uint32_t idx = cells[0];

	if (pcells[0] != sc->sc_phandle) {
		printf("%s: 0x%08x parent 0x%08x\n", __func__, idx, pcells[0]);
		return -1;
	}

	/* Clocks should be set correctly. */
	return 0;
}

void
sc8280xp_reset(void *cookie, uint32_t *cells, int on)
{
	struct qcclock_softc *sc = cookie;
	uint32_t idx = cells[0];
	uint32_t reg;

	switch (idx) {
	case SC8280XP_PCIE_2A_BCR:
		reg = 0x9d000;
		break;
	case SC8280XP_PCIE_2B_BCR:
		reg = 0x9e000;
		break;
	case SC8280XP_PCIE_3A_BCR:
		reg = 0xa0000;
		break;
	case SC8280XP_PCIE_3B_BCR:
		reg = 0xa2000;
		break;
	case SC8280XP_PCIE_4_BCR:
		reg = 0x6b000;
		break;
	case SC8280XP_USB30_PRIM_BCR:
		reg = 0xf000;
		break;
	case SC8280XP_USB30_SEC_BCR:
		reg = 0x10000;
		break;
	default:
		printf("%s: 0x%08x\n", __func__, idx);
		return;
	}

	if (on)
		HSET4(sc, reg, 1 << 0);
	else
		HCLR4(sc, reg, 1 << 0);
}
