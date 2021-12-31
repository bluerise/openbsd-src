/*	$OpenBSD: dwmmc.c,v 1.25 2021/10/24 17:52:26 mpi Exp $	*/
/*
 * Copyright (c) 2017 Mark Kettenis
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
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/systm.h>

#include <machine/bus.h>
#include <machine/fdt.h>
#include <machine/intr.h>

#include <dev/ofw/openfirm.h>
#include <dev/ofw/ofw_clock.h>
#include <dev/ofw/ofw_gpio.h>
#include <dev/ofw/ofw_pinctrl.h>
#include <dev/ofw/fdt.h>

#include <dev/sdmmc/sdmmcvar.h>
#include <dev/sdmmc/sdmmc_ioreg.h>

#include <dev/ic/dwmmcvar.h>

int	dwmmc_fdt_match(struct device *, void *, void *);
void	dwmmc_fdt_attach(struct device *, struct device *, void *);

const struct cfattach dwmmc_fdt_ca = {
	sizeof(struct dwmmc_softc), dwmmc_fdt_match, dwmmc_fdt_attach
};

int	dwmmc_fdt_card_detect(struct dwmmc_softc *);
void	dwmmc_fdt_pwrseq_pre(uint32_t);
void	dwmmc_fdt_pwrseq_post(uint32_t);

int	dwmmc_attach(struct dwmmc_softc *);
int	dwmmc_intr(void *);

int
dwmmc_fdt_match(struct device *parent, void *match, void *aux)
{
	struct fdt_attach_args *faa = aux;

	return (OF_is_compatible(faa->fa_node, "hisilicon,hi3660-dw-mshc") ||
	    OF_is_compatible(faa->fa_node, "hisilicon,hi3670-dw-mshc") ||
	    OF_is_compatible(faa->fa_node, "rockchip,rk3288-dw-mshc") ||
	    OF_is_compatible(faa->fa_node, "samsung,exynos5420-dw-mshc") ||
	    OF_is_compatible(faa->fa_node, "snps,dw-mshc"));
}

void
dwmmc_fdt_attach(struct device *parent, struct device *self, void *aux)
{
	struct dwmmc_softc *sc = (struct dwmmc_softc *)self;
	struct fdt_attach_args *faa = aux;
	uint32_t freq = 0, div = 0;
	uint32_t width;
	int error;

	if (faa->fa_nreg < 1) {
		printf(": no registers\n");
		return;
	}

	sc->sc_node = faa->fa_node;
	sc->sc_iot = faa->fa_iot;
	sc->sc_size = faa->fa_reg[0].size;
	sc->sc_dmat = faa->fa_dmat;

	if (bus_space_map(sc->sc_iot, faa->fa_reg[0].addr,
	    faa->fa_reg[0].size, 0, &sc->sc_ioh)) {
		printf(": can't map registers\n");
		return;
	}

	pinctrl_byname(faa->fa_node, "default");

	clock_enable_all(faa->fa_node);
	reset_deassert_all(faa->fa_node);

	sc->sc_fifo_depth = OF_getpropint(faa->fa_node, "fifo-depth", 0);

	/* Some SoCs pre-divide the clock. */
	if (OF_is_compatible(faa->fa_node, "rockchip,rk3288-dw-mshc"))
		div = 1;
	if (OF_is_compatible(faa->fa_node, "hisilicon,hi3660-dw-mshc") ||
	    OF_is_compatible(faa->fa_node, "hisilicon,hi3670-dw-mshc"))
		div = 7;

	/* Force the base clock to 50MHz on Rockchip SoCs. */
	if (OF_is_compatible(faa->fa_node, "rockchip,rk3288-dw-mshc"))
		freq = 50000000;

	freq = OF_getpropint(faa->fa_node, "clock-frequency", freq);
	if (freq > 0)
		clock_set_frequency(faa->fa_node, "ciu", (div + 1) * freq);

	sc->sc_clkbase = clock_get_frequency(faa->fa_node, "ciu");
	/* if ciu clock is missing the rate is clock-frequency */
	if (sc->sc_clkbase == 0)
		sc->sc_clkbase = freq;
	div = OF_getpropint(faa->fa_node, "samsung,dw-mshc-ciu-div", div);
	sc->sc_clkbase /= (div + 1);

	sc->sc_ih = fdt_intr_establish(faa->fa_node, IPL_BIO,
	    dwmmc_intr, sc, sc->sc_dev.dv_xname);
	if (sc->sc_ih == NULL) {
		printf(": can't establish interrupt\n");
		goto unmap;
	}

	OF_getpropintarray(faa->fa_node, "cd-gpios", sc->sc_gpio,
	    sizeof(sc->sc_gpio));
	if (sc->sc_gpio[0])
		gpio_controller_config_pin(sc->sc_gpio, GPIO_CONFIG_INPUT);

	sc->sc_sdio_irq = (OF_getproplen(sc->sc_node, "cap-sdio-irq") == 0);
	sc->sc_pwrseq = OF_getpropint(sc->sc_node, "mmc-pwrseq", 0);

	if (OF_getproplen(sc->sc_node, "cap-mmc-highspeed") == 0)
		sc->sc_caps |= SMC_CAPS_MMC_HIGHSPEED;
	if (OF_getproplen(sc->sc_node, "cap-sd-highspeed") == 0)
		sc->sc_caps |= SMC_CAPS_SD_HIGHSPEED;

	width = OF_getpropint(faa->fa_node, "bus-width", 1);
	if (width >= 8)
		sc->sc_caps |= SMC_CAPS_8BIT_MODE;
	if (width >= 4)
		sc->sc_caps |= SMC_CAPS_4BIT_MODE;

	if (OF_getproplen(sc->sc_node, "non-removable") == 0 ||
	    sc->sc_gpio[0])
		sc->sc_card_detect = dwmmc_fdt_card_detect;

	sc->sc_pwrseq_pre = dwmmc_fdt_pwrseq_pre;
	sc->sc_pwrseq_post = dwmmc_fdt_pwrseq_post;

	error = dwmmc_attach(sc);
	if (error)
		goto unmap;

	return;

unmap:
	bus_space_unmap(sc->sc_iot, sc->sc_ioh, sc->sc_size);
}

int
dwmmc_fdt_card_detect(struct dwmmc_softc *sc)
{
	if (OF_getproplen(sc->sc_node, "non-removable") == 0)
		return 1;

	if (sc->sc_gpio[0]) {
		int inverted, val;

		val = gpio_controller_get_pin(sc->sc_gpio);

		inverted = (OF_getproplen(sc->sc_node, "cd-inverted") == 0);
		return inverted ? !val : val;
	}

	return 0;
}

void
dwmmc_fdt_pwrseq_pre(uint32_t phandle)
{
	uint32_t *gpios, *gpio;
	int node;
	int len;

	node = OF_getnodebyphandle(phandle);
	if (node == 0)
		return;

	if (!OF_is_compatible(node, "mmc-pwrseq-simple"))
		return;

	pinctrl_byname(node, "default");

	clock_enable(node, "ext_clock");

	len = OF_getproplen(node, "reset-gpios");
	if (len <= 0)
		return;

	gpios = malloc(len, M_TEMP, M_WAITOK);
	OF_getpropintarray(node, "reset-gpios", gpios, len);

	gpio = gpios;
	while (gpio && gpio < gpios + (len / sizeof(uint32_t))) {
		gpio_controller_config_pin(gpio, GPIO_CONFIG_OUTPUT);
		gpio_controller_set_pin(gpio, 1);
		gpio = gpio_controller_next_pin(gpio);
	}

	free(gpios, M_TEMP, len);
}

void
dwmmc_fdt_pwrseq_post(uint32_t phandle)
{
	uint32_t *gpios, *gpio;
	int node;
	int len;

	node = OF_getnodebyphandle(phandle);
	if (node == 0)
		return;

	if (!OF_is_compatible(node, "mmc-pwrseq-simple"))
		return;

	len = OF_getproplen(node, "reset-gpios");
	if (len <= 0)
		return;

	gpios = malloc(len, M_TEMP, M_WAITOK);
	OF_getpropintarray(node, "reset-gpios", gpios, len);

	gpio = gpios;
	while (gpio && gpio < gpios + (len / sizeof(uint32_t))) {
		gpio_controller_set_pin(gpio, 0);
		gpio = gpio_controller_next_pin(gpio);
	}

	free(gpios, M_TEMP, len);
}
