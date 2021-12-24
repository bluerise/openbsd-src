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
#include <sys/kernel.h>
#include <sys/device.h>
#include <sys/malloc.h>
#include <sys/stdint.h>
#include <sys/task.h>

#include <machine/bus.h>
#include <machine/fdt.h>

#include <dev/i2c/i2cvar.h>
#include <dev/ofw/openfirm.h>
#include <dev/ofw/ofw_gpio.h>
#include <dev/ofw/ofw_misc.h>
#include <dev/ofw/ofw_pinctrl.h>

#define TPSTC_DEBUG

#ifdef TPSTC_DEBUG
#define DPRINTF(x) printf x
#else
#define DPRINTF(x)
#endif

#define TPS_VID				0x00
#define TPS_MODE			0x03
#define TPS_CMD1			0x08
#define TPS_DATA1			0x09
#define TPS_INT_EVENT1			0x14
#define  TPS_INT_PLUG_EVENT_APPLE		(1 << 1)
#define  TPS_INT_STATUS_UPDATE_APPLE		(1 << 8)
#define  TPS_INT_POWER_STATUS_UPDATE_APPLE	(1 << 9)
#define  TPS_INT_DATA_STATUS_UPDATE_APPLE	(1 << 10)
#define TPS_INT_EVENT2			0x15
#define TPS_INT_MASK1			0x16
#define TPS_INT_MASK2			0x17
#define TPS_INT_CLEAR1			0x18
#define TPS_INT_CLEAR2			0x19
#define TPS_SYSTEM_POWER_STATE		0x20
#define  TPS_SYSTEM_POWER_STATE_S0		0x00
#define  TPS_SYSTEM_POWER_STATE_S3		0x03
#define  TPS_SYSTEM_POWER_STATE_S4		0x04
#define  TPS_SYSTEM_POWER_STATE_S5		0x05
#define TPS_STATUS			0x1a
#define  TPS_STATUS_PLUG_PRESENT		(1 << 0)
#define TPS_SYSTEM_CONF			0x28
#define TPS_CTRL_CONF			0x29
#define TPS_POWER_STATUS		0x3f
#define TPS_RX_IDENTITY_SOP		0x48
#define TPS_DATA_STATUS			0x5f

#define TPS_MAX_LEN			64

#define TPS_TASK_TIMEOUT		0x01
#define TPS_TASK_REJECTED		0x03

struct tpstc_softc {
	struct device		 sc_dev;
	i2c_tag_t		 sc_tag;
	i2c_addr_t		 sc_addr;
	int			 sc_node;
	void			*sc_ih;

	struct task		 sc_task;
};

int	 tpstc_match(struct device *, void *, void *);
void	 tpstc_attach(struct device *, struct device *, void *);
int	 tpstc_detach(struct device *, int);

int	 tpstc_intr(void *);
void	 tpstc_task(void *);

int	 tpstc_exec_cmd(struct tpstc_softc *, const char *, void *, size_t);

int	 tpstc_write_block(struct tpstc_softc *, uint8_t, const void *, size_t);
int	 tpstc_read_block(struct tpstc_softc *, uint8_t, void *, size_t);
void	 tpstc_write_reg64(struct tpstc_softc *, uint8_t, uint64_t);
uint64_t tpstc_read_reg64(struct tpstc_softc *, uint8_t);
void	 tpstc_write_reg32(struct tpstc_softc *, uint8_t, uint32_t);
uint32_t tpstc_read_reg32(struct tpstc_softc *, uint8_t);
void	 tpstc_write_reg16(struct tpstc_softc *, uint8_t, uint16_t);
uint16_t tpstc_read_reg16(struct tpstc_softc *, uint8_t);
void	 tpstc_write_reg8(struct tpstc_softc *, uint8_t, uint8_t);
uint8_t	 tpstc_read_reg8(struct tpstc_softc *, uint8_t);

struct cfattach tpstc_ca = {
	sizeof(struct tpstc_softc),
	tpstc_match,
	tpstc_attach,
	tpstc_detach,
};

struct cfdriver tpstc_cd = {
	NULL, "tpstc", DV_DULL
};

int
tpstc_match(struct device *parent, void *match, void *aux)
{
	struct i2c_attach_args *ia = aux;

	if (strcmp(ia->ia_name, "apple,cd321x") == 0)
		return 1;

	return 0;
}

void
tpstc_attach(struct device *parent, struct device *self, void *aux)
{
	struct tpstc_softc *sc = (struct tpstc_softc *)self;
	struct i2c_attach_args *ia = aux;
	char mode[4] = { };

	sc->sc_tag = ia->ia_tag;
	sc->sc_addr = ia->ia_addr;
	sc->sc_node = *(int *)ia->ia_cookie;

	pinctrl_byname(sc->sc_node, "default");

	if (tpstc_read_reg8(sc, TPS_SYSTEM_POWER_STATE) !=
	    TPS_SYSTEM_POWER_STATE_S0) {
		uint8_t target = TPS_SYSTEM_POWER_STATE_S0;
		if (tpstc_exec_cmd(sc, "SSPS", &target, sizeof(target))) {
			printf(": unable to switch power state\n");
			return;
		}
		if (tpstc_read_reg8(sc, TPS_SYSTEM_POWER_STATE) !=
		    TPS_SYSTEM_POWER_STATE_S0) {
			printf(": unexpected power state\n");
			return;
		}
	}

	tpstc_read_block(sc, TPS_MODE, mode, sizeof(mode));
	if (memcmp(mode, "APP ", 4) != 0 && memcmp(mode, "BOOT", 4) != 0) {
		printf(": unsupported mode \"%c%c%c%c\"\n", mode[0], mode[1],
		    mode[2], mode[3]);
		return;
	}

//	printf("\n");
//	return;

	task_set(&sc->sc_task, tpstc_task, sc);
	sc->sc_ih = fdt_intr_establish(sc->sc_node, IPL_BIO,
	    tpstc_intr, sc, sc->sc_dev.dv_xname);
	if (sc->sc_ih == NULL) {
		printf(": unable to establish interrupt\n");
		return;
	}

	tpstc_write_reg64(sc, TPS_INT_MASK1, TPS_INT_PLUG_EVENT_APPLE);

	printf("\n");
}

int
tpstc_detach(struct device *self, int flags)
{
	return 0;
}

int
tpstc_intr(void *args)
{
	struct tpstc_softc *sc = args;
	fdt_intr_disable(sc->sc_ih);
	task_add(systq, &sc->sc_task);
	return 1;
}

void
tpstc_task(void *args)
{
	struct tpstc_softc *sc = args;
	uint64_t event;

	event = tpstc_read_reg64(sc, TPS_INT_EVENT1);
	tpstc_write_reg64(sc, TPS_INT_CLEAR1, event);

	DPRINTF(("%s: event1 %llx\n", __func__, event));

	if (event & TPS_INT_POWER_STATUS_UPDATE_APPLE)
		printf("%s: power status update\n", __func__);

	if (event & TPS_INT_DATA_STATUS_UPDATE_APPLE)
		printf("%s: data status update\n", __func__);

	if (event & TPS_INT_PLUG_EVENT_APPLE) {
		printf("%s:%d: status %x\n", __func__, __LINE__, tpstc_read_reg32(sc, TPS_STATUS));
		printf("%s:%d: power status %x\n", __func__, __LINE__, tpstc_read_reg16(sc, TPS_POWER_STATUS));
		printf("%s:%d: data status %x\n", __func__, __LINE__, tpstc_read_reg32(sc, TPS_DATA_STATUS));

		/* Switch to Host data role. */
		tpstc_exec_cmd(sc, "SWDF", NULL, 0);

		/* Switch to Source power role. */
		tpstc_exec_cmd(sc, "SWSr", NULL, 0);
	}
//		tpstc_identify(sc);

	fdt_intr_enable(sc->sc_ih);
}

#if 0
void
tpstc_identify(struct tpstc_softc *sc)
{
	uint32_t status, power;

	status = tpstc_read_reg32(sc, TPS_STATUS);
	if (!(status & TPS_STATUS_PLUG_PRESENT))
		return;

	if (

	if (tpstc_read_reg32(sc, TPS_STATUS) & TPS_STATUS_PLUG_PRESENT)
	power = 

	printf("%s\n", __func__);
}
#endif

int
tpstc_exec_cmd(struct tpstc_softc *sc, const char *cmd, void *in, size_t inlen)
{
	uint8_t data[4];
	int error, i;

	KASSERT(strlen(cmd) == 4);

	error = tpstc_read_block(sc, TPS_CMD1, &data, sizeof(data));
	if (error)
		return error;
	if (memcmp(data, "\0\0\0\0", 4) != 0 && memcmp(data, "!CMD", 4) != 0)
		return EBUSY;

	if (inlen) {
		error = tpstc_write_block(sc, TPS_DATA1, in, inlen);
		if (error)
			return error;
	}

	error = tpstc_write_block(sc, TPS_CMD1, cmd, 4);
	if (error)
		return error;

	for (i = 1000; i > 0; i--) {
		error = tpstc_read_block(sc, TPS_CMD1, &data, sizeof(data));
		if (error)
			return error;
		if (memcmp(data, "!CMD", 4) == 0)
			return EINVAL;
		if (memcmp(data, "\0\0\0\0", 4) != 0)
			break;
		delay(1000);
	}
	if (i == 0)
		return ETIMEDOUT;

	error = tpstc_read_block(sc, TPS_DATA1, &data, 1);
	if (error)
		return error;

	switch(data[0]) {
	case TPS_TASK_TIMEOUT:
		return ETIMEDOUT;
	case TPS_TASK_REJECTED:
		return EPERM;
	default:
		break;
	}

	return 0;
}

int
tpstc_read_block(struct tpstc_softc *sc, uint8_t reg, void *buf, size_t len)
{
	uint8_t data[TPS_MAX_LEN + 1];
	int error;

	if (len > TPS_MAX_LEN) {
		printf("%s: block too large (register 0x%x)\n",
		    sc->sc_dev.dv_xname, reg);
		return EFBIG;
	}

	iic_acquire_bus(sc->sc_tag, 0);
	error = iic_exec(sc->sc_tag, I2C_OP_READ_WITH_STOP,
	    sc->sc_addr, &reg, sizeof(reg), &data, len + 1, 0);
	iic_release_bus(sc->sc_tag, 0);
	if (error) {
		printf("%s: cannot read register 0x%x\n",
		    sc->sc_dev.dv_xname, reg);
		return EIO;
	}

	if (data[0] < len) {
		printf("%s: result too small (register 0x%x)\n",
		    sc->sc_dev.dv_xname, reg);
		return EIO;
	}

	memcpy(buf, &data[1], len);
	return 0;
}

int
tpstc_write_block(struct tpstc_softc *sc, uint8_t reg, const void *buf,
    size_t len)
{
	uint8_t data[TPS_MAX_LEN + 1];
	int error;

	if (len > TPS_MAX_LEN) {
		printf("%s: block too large (register 0x%x)\n",
		    sc->sc_dev.dv_xname, reg);
		return EFBIG;
	}

	data[0] = len;
	memcpy(&data[1], buf, len);

	iic_acquire_bus(sc->sc_tag, 0);
	error = iic_exec(sc->sc_tag, I2C_OP_WRITE_WITH_STOP,
	    sc->sc_addr, &reg, sizeof(reg), &data, len + 1, 0);
	iic_release_bus(sc->sc_tag, 0);
	if (error) {
		printf("%s: cannot write register 0x%x\n",
		    sc->sc_dev.dv_xname, reg);
		return EIO;
	}

	return 0;
}

uint8_t
tpstc_read_reg8(struct tpstc_softc *sc, uint8_t reg)
{
	uint8_t val = 0;

	tpstc_read_block(sc, reg, &val, sizeof(val));

	return val;
}

void
tpstc_write_reg8(struct tpstc_softc *sc, uint8_t reg, uint8_t val)
{
	tpstc_write_block(sc, reg, &val, sizeof(val));
}

uint16_t
tpstc_read_reg16(struct tpstc_softc *sc, uint8_t reg)
{
	uint16_t val = 0;

	tpstc_read_block(sc, reg, &val, sizeof(val));

	return val;
}

void
tpstc_write_reg16(struct tpstc_softc *sc, uint8_t reg, uint16_t val)
{
	tpstc_write_block(sc, reg, &val, sizeof(val));
}

uint32_t
tpstc_read_reg32(struct tpstc_softc *sc, uint8_t reg)
{
	uint32_t val = 0;

	tpstc_read_block(sc, reg, &val, sizeof(val));

	return val;
}

void
tpstc_write_reg32(struct tpstc_softc *sc, uint8_t reg, uint32_t val)
{
	tpstc_write_block(sc, reg, &val, sizeof(val));
}

uint64_t
tpstc_read_reg64(struct tpstc_softc *sc, uint8_t reg)
{
	uint64_t val = 0;

	tpstc_read_block(sc, reg, &val, sizeof(val));

	return val;
}

void
tpstc_write_reg64(struct tpstc_softc *sc, uint8_t reg, uint64_t val)
{
	tpstc_write_block(sc, reg, &val, sizeof(val));
}
