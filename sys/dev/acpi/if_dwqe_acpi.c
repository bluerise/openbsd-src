/* $OpenBSD$ */
/*
 * Copyright (c) 2022 Patrick Wildt <patrick@blueri.se>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
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
#include <sys/malloc.h>
#include <sys/systm.h>

#include <machine/bus.h>

#include <net/if.h>
#include <net/if_media.h>

#include <dev/mii/miivar.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <dev/ic/dwqevar.h>

#include <dev/acpi/acpireg.h>
#include <dev/acpi/acpivar.h>

#define	CSR_RATE_RGMII		125000000

int	dwqe_acpi_match(struct device *, void *, void *);
void	dwqe_acpi_attach(struct device *, struct device *, void *);

struct cfattach dwqe_acpi_ca = {
	sizeof(struct dwqe_softc), dwqe_acpi_match, dwqe_acpi_attach
};

const char *dwqe_hids[] = {
	"PRP0001",
	NULL
};

int
dwqe_acpi_match(struct device *parent, void *match, void *aux)
{
	struct acpi_attach_args *aaa = aux;
	struct cfdata *cf = match;

	if (aaa->aaa_naddr < 1 || aaa->aaa_nirq < 1)
		return 0;
	if (!acpi_matchhids(aaa, dwqe_hids, cf->cf_driver->cd_name))
		return 0;
	return acpi_is_compatible(aaa->aaa_node, "snps,dwmac-4.20a");
}

void
dwqe_acpi_attach(struct device *parent, struct device *self, void *aux)
{
	struct dwqe_softc *sc = (struct dwqe_softc *)self;
	struct acpi_attach_args *aaa = aux;

	printf(" addr 0x%llx/0x%llx", aaa->aaa_addr[0], aaa->aaa_size[0]);
	printf(" irq %d", aaa->aaa_irq[0]);

	sc->sc_bst = aaa->aaa_bst[0];
	sc->sc_dmat = aaa->aaa_dmat;
	sc->sc_phy_id = 0; /* XXX */
	sc->sc_csr_clock = CSR_RATE_RGMII;

	if (bus_space_map(sc->sc_bst, aaa->aaa_addr[0], aaa->aaa_size[0],
	    0, &sc->sc_bsh)) {
		printf(": can't map registers\n");
		return;
	}

	sc->sc_ih = acpi_intr_establish(aaa->aaa_irq[0], aaa->aaa_irq_flags[0],
	    IPL_BIO, dwqe_intr, sc, sc->sc_dev.dv_xname);
	if (sc->sc_ih == NULL) {
		printf(": can't establish interrupt\n");
		return;
	}

	if (acpi_getprop(aaa->aaa_node, "local-mac-address",
	    &sc->sc_lladdr, ETHER_ADDR_LEN) != ETHER_ADDR_LEN)
		ether_fakeaddr(&sc->sc_ac.ac_if);

	sc->sc_mixed_burst = acpi_getpropint(aaa->aaa_node,
	    "snps,mixed-burst", 0);
	sc->sc_fixed_burst = acpi_getpropint(aaa->aaa_node,
	    "snps,fixed-burst", 0);
	sc->sc_wr_osr_lmt = acpi_getpropint(aaa->aaa_node,
	    "snps,wr_osr_lmt", 4);
	sc->sc_rd_osr_lmt = acpi_getpropint(aaa->aaa_node,
	    "snps,rd_osr_lmt", 8);

	dwqe_attach(sc);
}
