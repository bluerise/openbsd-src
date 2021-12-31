/*	$OpenBSD: dwmmc_acpi.c,v 1.19 2021/12/21 20:53:46 kettenis Exp $	*/
/*
 * Copyright (c) 2016 Mark Kettenis
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
#include <sys/malloc.h>
#include <sys/systm.h>

#include <dev/acpi/acpireg.h>
#include <dev/acpi/acpivar.h>
#include <dev/acpi/acpidev.h>
#include <dev/acpi/amltypes.h>
#include <dev/acpi/dsdt.h>
#undef DEVNAME

#include <dev/sdmmc/sdmmcvar.h>
#include <dev/sdmmc/sdmmc_ioreg.h>

#include <dev/ic/dwmmcvar.h>

struct dwmmc_acpi_softc {
	struct dwmmc_softc sc;
	struct acpi_softc *sc_acpi;
	struct aml_node *sc_node;

	struct aml_node *sc_gpio_int_node;
	struct aml_node *sc_gpio_io_node;
	uint16_t sc_gpio_int_pin;
	uint16_t sc_gpio_int_flags;
	uint16_t sc_gpio_io_pin;
};

int	dwmmc_acpi_match(struct device *, void *, void *);
void	dwmmc_acpi_attach(struct device *, struct device *, void *);

struct cfattach dwmmc_acpi_ca = {
	sizeof(struct dwmmc_acpi_softc), dwmmc_acpi_match, dwmmc_acpi_attach
};

const char *dwmmc_hids[] = {
	"PRP0001",
	NULL
};

int	dwmmc_acpi_parse_resources(int, union acpi_resource *, void *);
int	dwmmc_acpi_card_detect_nonremovable(struct dwmmc_softc *);
int	dwmmc_acpi_card_detect_gpio(struct dwmmc_softc *);
int	dwmmc_acpi_card_detect_intr(void *);
void	dwmmc_acpi_power_on(struct dwmmc_acpi_softc *, struct aml_node *);
void	dwmmc_acpi_explore(struct dwmmc_acpi_softc *);

int	dwmmc_attach(struct dwmmc_softc *);
int	dwmmc_intr(void *);

int
dwmmc_acpi_match(struct device *parent, void *match, void *aux)
{
	struct acpi_attach_args *aaa = aux;
	struct cfdata *cf = match;

	if (aaa->aaa_naddr < 1 || aaa->aaa_nirq < 1)
		return 0;
	if (!acpi_matchhids(aaa, dwmmc_hids, cf->cf_driver->cd_name))
		return 0;
	return acpi_is_compatible(aaa->aaa_node, "rockchip,rk3288-dw-mshc");
}

void
dwmmc_acpi_attach(struct device *parent, struct device *self, void *aux)
{
	struct dwmmc_acpi_softc *sc = (struct dwmmc_acpi_softc *)self;
	struct acpi_attach_args *aaa = aux;
	struct aml_value res;
	uint32_t width;
//	uint32_t cap, capmask;

	sc->sc_acpi = (struct acpi_softc *)parent;
	sc->sc_node = aaa->aaa_node;
	printf(" %s", sc->sc_node->name);

	if (aml_evalname(sc->sc_acpi, sc->sc_node, "_CRS", 0, NULL, &res)) {
		printf(": can't find registers\n");
		return;
	}

	aml_parse_resource(&res, dwmmc_acpi_parse_resources, sc);

	printf(" addr 0x%llx/0x%llx", aaa->aaa_addr[0], aaa->aaa_size[0]);
	printf(" irq %d", aaa->aaa_irq[0]);

	sc->sc.sc_iot = aaa->aaa_bst[0];
	sc->sc.sc_size = aaa->aaa_size[0];
	sc->sc.sc_dmat = aaa->aaa_dmat;

	if (bus_space_map(sc->sc.sc_iot, aaa->aaa_addr[0], aaa->aaa_size[0],
	    0, &sc->sc.sc_ioh)) {
		printf(": can't map registers\n");
		return;
	}

	sc->sc.sc_ih = acpi_intr_establish(aaa->aaa_irq[0], aaa->aaa_irq_flags[0],
	    IPL_BIO, dwmmc_intr, sc, sc->sc.sc_dev.dv_xname);
	if (sc->sc.sc_ih == NULL) {
		printf(": can't establish interrupt\n");
		return;
	}

//	if (sc->sc_gpio_io_node && sc->sc_gpio_io_node->gpio) {
//		sc->sc.sc_card_detect = dwmmc_acpi_card_detect_gpio;
//		printf(", gpio");
//	}

	if (sc->sc_gpio_int_node && sc->sc_gpio_int_node->gpio) {
		struct acpi_gpio *gpio = sc->sc_gpio_int_node->gpio;

		gpio->intr_establish(gpio->cookie, sc->sc_gpio_int_pin,
		    sc->sc_gpio_int_flags, dwmmc_acpi_card_detect_intr, sc);
	}

	dwmmc_acpi_power_on(sc, sc->sc_node);
	dwmmc_acpi_explore(sc);

	sc->sc.sc_clkbase = 50000000;
	sc->sc.sc_fifo_depth = acpi_getpropint(sc->sc_node, "fifo-depth", 0);
	sc->sc.sc_sdio_irq = acpi_getpropint(sc->sc_node, "cap-sdio-irq", 0);

	if (acpi_getpropint(sc->sc_node, "cap-mmc-highspeed", 0))
		sc->sc.sc_caps |= SMC_CAPS_MMC_HIGHSPEED;
	if (acpi_getpropint(sc->sc_node, "cap-sd-highspeed", 0))
		sc->sc.sc_caps |= SMC_CAPS_SD_HIGHSPEED;

	width = acpi_getpropint(sc->sc_node, "bus-width", 1);
	if (width >= 8)
		sc->sc.sc_caps |= SMC_CAPS_8BIT_MODE;
	if (width >= 4)
		sc->sc.sc_caps |= SMC_CAPS_4BIT_MODE;

	dwmmc_attach(&sc->sc);
	return;
}

int
dwmmc_acpi_parse_resources(int crsidx, union acpi_resource *crs, void *arg)
{
	struct dwmmc_acpi_softc *sc = arg;
	int type = AML_CRSTYPE(crs);
	struct aml_node *node;
	uint16_t pin;

	switch (type) {
	case LR_GPIO:
		node = aml_searchname(sc->sc_node, (char *)&crs->pad[crs->lr_gpio.res_off]);
		pin = *(uint16_t *)&crs->pad[crs->lr_gpio.pin_off];
		if (crs->lr_gpio.type == LR_GPIO_INT) {
			sc->sc_gpio_int_node = node;
			sc->sc_gpio_int_pin = pin;
			sc->sc_gpio_int_flags = crs->lr_gpio.tflags;
		} else if (crs->lr_gpio.type == LR_GPIO_IO) {
			sc->sc_gpio_io_node = node;
			sc->sc_gpio_io_pin = pin;
		}
		break;
	}

	return 0;
}

int
dwmmc_acpi_card_detect_nonremovable(struct dwmmc_softc *ssc)
{
	return 1;
}

int
dwmmc_acpi_card_detect_gpio(struct dwmmc_softc *ssc)
{
	struct dwmmc_acpi_softc *sc = (struct dwmmc_acpi_softc *)ssc;
	struct acpi_gpio *gpio = sc->sc_gpio_io_node->gpio;
	uint16_t pin = sc->sc_gpio_io_pin;

	/* Card detect GPIO signal is active-low. */
	return !gpio->read_pin(gpio->cookie, pin);
}

int
dwmmc_acpi_card_detect_intr(void *arg)
{
//	struct dwmmc_acpi_softc *sc = arg;

//	dwmmc_needs_discover(&sc->sc);

	return (1);
}

void
dwmmc_acpi_power_on(struct dwmmc_acpi_softc *sc, struct aml_node *node)
{
	node = aml_searchname(node, "_PS0");
	if (node && aml_evalnode(sc->sc_acpi, node, 0, NULL, NULL))
		printf("%s: _PS0 failed\n", sc->sc.sc_dev.dv_xname);
}

int
dwmmc_acpi_do_explore(struct aml_node *node, void *arg)
{
	struct dwmmc_acpi_softc *sc = arg;
	int64_t sta, rmv;

	/* We're only interested in our children. */
	if (node == sc->sc_node)
		return 0;

	/* Only consider devices that are actually present. */
	if (node->value == NULL ||
	    node->value->type != AML_OBJTYPE_DEVICE)
		return 1;
	if (aml_evalinteger(sc->sc_acpi, node, "_STA", 0, NULL, &sta))
		sta = STA_PRESENT | STA_ENABLED | STA_DEV_OK | 0x1000;
	if ((sta & STA_PRESENT) == 0)
		return 1;

	acpi_attach_deps(sc->sc_acpi, node);

	/* Override card detect if we have non-removable devices. */
	if (aml_evalinteger(sc->sc_acpi, node, "_RMV", 0, NULL, &rmv))
		rmv = 1;
	if (rmv == 0)
		sc->sc.sc_card_detect =
		    dwmmc_acpi_card_detect_nonremovable;

	dwmmc_acpi_power_on(sc, node);

	return 1;
}

void
dwmmc_acpi_explore(struct dwmmc_acpi_softc *sc)
{
	aml_walknodes(sc->sc_node, AML_WALK_PRE, dwmmc_acpi_do_explore, sc);
}
