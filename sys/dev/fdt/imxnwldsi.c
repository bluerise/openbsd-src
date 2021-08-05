/* $OpenBSD$ */
/*
 * Copyright (c) 2021 Patrick Wildt <patrick@blueri.se>
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
#include <sys/timeout.h>

#include <machine/bus.h>
#include <machine/fdt.h>

#include <dev/ofw/openfirm.h>
#include <dev/ofw/ofw_clock.h>
#include <dev/ofw/ofw_misc.h>
#include <dev/ofw/ofw_pinctrl.h>
#include <dev/ofw/ofw_power.h>
#include <dev/ofw/fdt.h>

struct imxnwldsi_softc {
	struct device		sc_dev;
	bus_space_tag_t		sc_iot;
	bus_space_handle_t	sc_ioh;
};

int	imxnwldsi_match(struct device *, void *, void *);
void	imxnwldsi_attach(struct device *, struct device *, void *);

struct cfattach	imxnwldsi_ca = {
	sizeof (struct imxnwldsi_softc), imxnwldsi_match, imxnwldsi_attach
};

struct cfdriver imxnwldsi_cd = {
	NULL, "imxnwldsi", DV_DULL
};

int
imxnwldsi_match(struct device *parent, void *match, void *aux)
{
	struct fdt_attach_args *faa = aux;

	return OF_is_compatible(faa->fa_node, "fsl,imx8mq-nwl-dsi");
}

void
imxnwldsi_attach(struct device *parent, struct device *self, void *aux)
{
	struct fdt_attach_args *faa = aux;
	struct imxnwldsi_softc *sc = (struct imxnwldsi_softc *) self;

	if (faa->fa_nreg < 1)
		return;

	sc->sc_iot = faa->fa_iot;
	if (bus_space_map(sc->sc_iot, faa->fa_reg[0].addr,
	    faa->fa_reg[0].size, 0, &sc->sc_ioh))
		panic("%s: bus_space_map failed!", __func__);

	printf("\n");

	pinctrl_byname(faa->fa_node, "default");
	power_domain_enable(faa->fa_node);
	clock_set_assigned(faa->fa_node);
	clock_enable(faa->fa_node, "core");
	clock_enable(faa->fa_node, "rx_esc");
	clock_enable(faa->fa_node, "tx_esc");
	clock_enable(faa->fa_node, "phy_ref");
	clock_enable(faa->fa_node, "lcdif");
	delay(1000);
}
