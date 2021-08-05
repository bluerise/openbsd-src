/*	$OpenBSD: bd718x7.c,v 1.3 2020/11/12 10:47:07 patrick Exp $	*/
/*
 * Copyright (c) 2019 Patrick Wildt <patrick@blueri.se>
 * Copyright (c) 2017 Mark Kettenis <kettenis@openbsd.org>
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
#include <sys/malloc.h>

#include <dev/ofw/openfirm.h>
#include <dev/ofw/ofw_gpio.h>
#include <dev/ofw/fdt.h>

#include <dev/i2c/i2cvar.h>

struct tisnmeb_softc {
	struct device	sc_dev;
	i2c_tag_t	sc_tag;
	i2c_addr_t	sc_addr;
};

int	tisnmeb_match(struct device *, void *, void *);
void	tisnmeb_attach(struct device *, struct device *, void *);

void	tisnmeb_hook(struct device *);
uint8_t	tisnmeb_reg_read(struct tisnmeb_softc *, int);
void	tisnmeb_reg_write(struct tisnmeb_softc *, int, uint8_t);

struct cfattach tisnmeb_ca = {
	sizeof(struct tisnmeb_softc), tisnmeb_match, tisnmeb_attach
};

struct cfdriver tisnmeb_cd = {
	NULL, "tisnmeb", DV_DULL
};

int
tisnmeb_match(struct device *parent, void *match, void *aux)
{
	struct i2c_attach_args *ia = aux;

	return (strcmp(ia->ia_name, "ti,sn65dsi86") == 0);
}

void
tisnmeb_attach(struct device *parent, struct device *self, void *aux)
{
	struct tisnmeb_softc *sc = (struct tisnmeb_softc *)self;
	struct i2c_attach_args *ia = aux;
	int node = *(int *)ia->ia_cookie;
	uint32_t *gpios;
	int len;

	sc->sc_tag = ia->ia_tag;
	sc->sc_addr = ia->ia_addr;

	len = OF_getproplen(node, "enable-gpios");
	if (len > 0) {
		gpios = malloc(len, M_TEMP, M_WAITOK);
		OF_getpropintarray(node, "enable-gpios", gpios, len);
		gpio_controller_config_pin(&gpios[0], GPIO_CONFIG_OUTPUT);
		gpio_controller_set_pin(&gpios[0], 1);
		free(gpios, M_TEMP, len);
	}

	printf("\n");

	config_mountroot(self, tisnmeb_hook);
}

void
tisnmeb_hook(struct device *self)
{
	struct tisnmeb_softc *sc = (struct tisnmeb_softc *)self;
	uint8_t reg;
	int i;

	/* Set DSI clock to 486 MHz */
	tisnmeb_reg_write(sc, 0x0a, 0x06);
	/* Single Channel, 4 DSI lanes */
	tisnmeb_reg_write(sc, 0x10, 0x26);
	/* Enhanced framing and ASSR */
	tisnmeb_reg_write(sc, 0x5a, 0x05);
	/* 2 DP lanes w/o SSC */
	tisnmeb_reg_write(sc, 0x93, 0x20);
	/* 2.7 Gbps DP data rate */
	tisnmeb_reg_write(sc, 0x94, 0x80);
	/* Enable PLL and confirm PLL is locked */
	tisnmeb_reg_write(sc, 0x0d, 0x01);
	for (i = 50; i > 0; i--) {
		reg = tisnmeb_reg_read(sc, 0x0a);
		if (reg & (1U << 7))
			break;
		delay(1000);
	}
	if (i == 0)
		printf("%s:%d: %x\n", __func__, __LINE__, tisnmeb_reg_read(sc, 0x0a));
//	000a: 87    .

	/* Enable ASSR on display */
	tisnmeb_reg_write(sc, 0x64, 0x01);
	tisnmeb_reg_write(sc, 0x75, 0x01);
	tisnmeb_reg_write(sc, 0x76, 0x0a);
	tisnmeb_reg_write(sc, 0x77, 0x01);
	tisnmeb_reg_write(sc, 0x78, 0x81);
	/* Train link and confirm link is trained */
	tisnmeb_reg_write(sc, 0x96, 0x0a);
	for (i = 500; i > 0; i--) {
		reg = tisnmeb_reg_read(sc, 0x96);
		if (reg == 0x0 || reg == 0x01)
			break;
		delay(1000);
	}
	if (i == 0)
		printf("%s:%d: %x\n", __func__, __LINE__, tisnmeb_reg_read(sc, 0x96));
//	0096: 01    .

	/* Line length 1920 */
	tisnmeb_reg_write(sc, 0x20, 0x80);
	tisnmeb_reg_write(sc, 0x21, 0x07);
	/* Vertical display size 1080 */
	tisnmeb_reg_write(sc, 0x24, 0x38);
	tisnmeb_reg_write(sc, 0x25, 0x04);
	/* HSync pulse width 40 */
	tisnmeb_reg_write(sc, 0x2c, 0x28);
	/* VSync pulse width 4 */
	tisnmeb_reg_write(sc, 0x30, 0x04);
	/* Horizonal back porch 40 */
	tisnmeb_reg_write(sc, 0x35, 0x28);
	/* Vertical back porch 4 */
	tisnmeb_reg_write(sc, 0x36, 0x04);
	/* Horizonal front porch 40 */
	tisnmeb_reg_write(sc, 0x38, 0x28);
	/* Vertical front porch 4 */
	tisnmeb_reg_write(sc, 0x3a, 0x04);

	/* Enable color bar */
	tisnmeb_reg_write(sc, 0x3c, 0x10);
	/* Enable video stream, ASSR, enhanced framing */
	tisnmeb_reg_write(sc, 0x5a, 0x0d);
}

uint8_t
tisnmeb_reg_read(struct tisnmeb_softc *sc, int reg)
{
	uint8_t cmd = reg;
	uint8_t val;
	int error;

	iic_acquire_bus(sc->sc_tag, I2C_F_POLL);
	error = iic_exec(sc->sc_tag, I2C_OP_READ_WITH_STOP, sc->sc_addr,
	    &cmd, sizeof cmd, &val, sizeof val, I2C_F_POLL);
	iic_release_bus(sc->sc_tag, I2C_F_POLL);

	if (error) {
		printf("%s: can't read register 0x%02x\n",
		    sc->sc_dev.dv_xname, reg);
		val = 0xff;
	}

	return val;
}

void
tisnmeb_reg_write(struct tisnmeb_softc *sc, int reg, uint8_t val)
{
	uint8_t cmd = reg;
	int error;

	iic_acquire_bus(sc->sc_tag, I2C_F_POLL);
	error = iic_exec(sc->sc_tag, I2C_OP_WRITE_WITH_STOP, sc->sc_addr,
	    &cmd, sizeof cmd, &val, sizeof val, I2C_F_POLL);
	iic_release_bus(sc->sc_tag, I2C_F_POLL);

	if (error) {
		printf("%s: can't write register 0x%02x\n",
		    sc->sc_dev.dv_xname, reg);
	}
}
