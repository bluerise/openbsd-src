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
#define TPS_SYSTEM_CONF			0x28
#define TPS_CTRL_CONF			0x29
#define TPS_POWER_STATUS		0x3f
#define TPS_RX_IDENTITY_SOP		0x48
#define TPS_DATA_STATUS			0x5f

#define TPS_MAX_LEN			64

#define TPS_TASK_TIMEOUT		0x01
#define TPS_TASK_REJECTED		0x03

enum typec_cc_status {
	TYPEC_CC_OPEN,
	TYPEC_CC_RA,
	TYPEC_CC_RD,
	TYPEC_CC_RP_DEF,
	TYPEC_CC_RP_1_5,
	TYPEC_CC_RP_3_0,
};

enum typec_data_role {
	TYPEC_DEVICE,
	TYPEC_HOST,
};

enum typec_power_role {
	TYPEC_SINK,
	TYPEC_SOURCE,
};

enum typec_polarity {
	TYPEC_POLARITY_CC1,
	TYPEC_POLARITY_CC2,
};

struct tpstc_softc {
	struct device		 sc_dev;
	i2c_tag_t		 sc_tag;
	i2c_addr_t		 sc_addr;
	int			 sc_node;
	void			*sc_ih;

	struct task		 sc_task;

	int			 sc_attached;
	enum typec_data_role	 sc_try_data;
	enum typec_power_role	 sc_try_power;

	uint32_t		*sc_ss_sel;
	uint8_t			 sc_cc;
	uint8_t			 sc_vbus_det;
};

int	 tpstc_match(struct device *, void *, void *);
void	 tpstc_attach(struct device *, struct device *, void *);
int	 tpstc_detach(struct device *, int);

int	 tpstc_intr(void *);
void	 tpstc_task(void *);
void	 tpstc_cc_change(struct tpstc_softc *);
void	 tpstc_power_change(struct tpstc_softc *);
void	 tpstc_set_polarity(struct tpstc_softc *, int);
void	 tpstc_set_vbus(struct tpstc_softc *, int, int);
void	 tpstc_set_roles(struct tpstc_softc *, enum typec_data_role,
	    enum typec_power_role);

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
	uint32_t conf, status;
	int len;

	sc->sc_tag = ia->ia_tag;
	sc->sc_addr = ia->ia_addr;
	sc->sc_node = *(int *)ia->ia_cookie;

	/* Automatic DRP toggling should try first as ... */
	sc->sc_try_data = TYPEC_HOST;
	sc->sc_try_power = TYPEC_SOURCE;

	pinctrl_byname(sc->sc_node, "default");

	len = OF_getproplen(sc->sc_node, "ss-sel-gpios");
	if (len > 0) {
		sc->sc_ss_sel = malloc(len, M_TEMP, M_WAITOK);
		OF_getpropintarray(sc->sc_node, "ss-sel-gpios",
		    sc->sc_ss_sel, len);
		gpio_controller_config_pin(sc->sc_ss_sel,
		    GPIO_CONFIG_OUTPUT);
		gpio_controller_set_pin(sc->sc_ss_sel, 1);
	}

	if (tpstc_read_reg8(sc, TPS_SYSTEM_POWER_STATE) !=
	    TPS_SYSTEM_POWER_STATE_S0) {
		uint8_t target = TPS_SYSTEM_POWER_STATE_S0;
		printf(": status %x", (tpstc_read_reg8(sc, TPS_SYSTEM_POWER_STATE)));
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

	task_set(&sc->sc_task, tpstc_task, sc);
	sc->sc_ih = fdt_intr_establish(sc->sc_node, IPL_BIO,
	    tpstc_intr, sc, sc->sc_dev.dv_xname);
	if (sc->sc_ih == NULL) {
		printf(": unable to establish interrupt\n");
		return;
	}

	tpstc_write_reg64(sc, TPS_INT_MASK1, TPS_INT_PLUG_EVENT_APPLE |
	    TPS_INT_POWER_STATUS_UPDATE_APPLE |
	    TPS_INT_DATA_STATUS_UPDATE_APPLE);
	status = tpstc_read_reg32(sc, TPS_STATUS);
	conf = tpstc_read_reg32(sc, TPS_SYSTEM_CONF);
	printf(": status %x conf %x", status, conf);

#if 0
	tpstc_write_reg16(sc, TPS_ALERT, 0xffff);
	tpstc_write_reg8(sc, TPS_FAULT_STATUS, 0x80);
	tpstc_write_reg8(sc, TPS_POWER_STATUS_MASK,
	    TPS_POWER_STATUS_VBUS_PRES);
	tpstc_write_reg8(sc, TPS_POWER_CTRL, tpstc_read_reg8(sc,
	    TPS_POWER_CTRL) & ~TPS_POWER_CTRL_DIS_VOL_ALARM);
	tpstc_write_reg16(sc, TPS_ALERT_MASK,
	    TPS_ALERT_TX_SUCCESS | TPS_ALERT_TX_FAILED |
	    TPS_ALERT_TX_DISCARDED | TPS_ALERT_RX_STATUS |
	    TPS_ALERT_RX_HARD_RST | TPS_ALERT_CC_STATUS |
	    TPS_ALERT_RX_BUF_OVF | TPS_ALERT_FAULT |
	    TPS_ALERT_V_ALARM_LO | TPS_ALERT_POWER_STATUS);

	if (sc->sc_try_data == TYPEC_HOST)
		tpstc_write_reg8(sc, TPS_ROLE_CTRL, TPS_ROLE_CTRL_DRP | 0xa);
	else
		tpstc_write_reg8(sc, TPS_ROLE_CTRL, TPS_ROLE_CTRL_DRP | 0x5);
	tpstc_write_reg8(sc, TPS_COMMAND, TPS_COMMAND_LOOK4CONNECTION);
#endif

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
	uint64_t status;

	status = tpstc_read_reg64(sc, TPS_INT_EVENT1);
	tpstc_write_reg64(sc, TPS_INT_CLEAR1, status);

	DPRINTF(("%s: event1 %llx\n", __func__, status));

	if (status & TPS_INT_POWER_STATUS_UPDATE_APPLE)
		printf("%s: power status update\n", __func__);

	if (status & TPS_INT_DATA_STATUS_UPDATE_APPLE)
		printf("%s: data status update\n", __func__);

	if (status & TPS_INT_PLUG_EVENT_APPLE)
		printf("%s: plug event update\n", __func__);

#if 0
	if (status & TPS_ALERT_CC_STATUS)
		tpstc_cc_change(sc);

	if (status & TPS_ALERT_POWER_STATUS)
		tpstc_power_change(sc);

	if (status & TPS_ALERT_V_ALARM_LO) {
		tpstc_write_reg8(sc, TPS_VBUS_VOLTAGE_ALARM_LO_CFG, 0);
		tpstc_write_reg8(sc, TPS_POWER_CTRL, tpstc_read_reg8(sc,
		    TPS_POWER_CTRL) & ~TPS_POWER_CTRL_FORCEDISCH);
	}

	if (status & TPS_ALERT_FAULT)
		tpstc_write_reg8(sc, TPS_FAULT_STATUS, tpstc_read_reg8(sc,
		    TPS_FAULT_STATUS) | TPS_FAULT_STATUS_CLEAR);
#endif

	fdt_intr_enable(sc->sc_ih);
}

#if 0
uint8_t
tpstc_typec_to_rp(int typec)
{
	switch (typec) {
	case TYPEC_CC_RP_DEF:
		return TPS_ROLE_CTRL_RP_VAL_DEF;
	case TYPEC_CC_RP_1_5:
		return TPS_ROLE_CTRL_RP_VAL_1_5;
	case TYPEC_CC_RP_3_0:
		return TPS_ROLE_CTRL_RP_VAL_3_0;
	default:
		panic("%s:%d", __func__, __LINE__);
	}
}
#endif

int
tpstc_cc_to_typec(int cc, int sink)
{
	if (sink) {
		if (cc == 0x1)
			return TYPEC_CC_RP_DEF;
		if (cc == 0x2)
			return TYPEC_CC_RP_1_5;
		if (cc == 0x3)
			return TYPEC_CC_RP_3_0;
	} else {
		if (cc == 0x1)
			return TYPEC_CC_RA;
		if (cc == 0x2)
			return TYPEC_CC_RD;
	}

	return TYPEC_CC_OPEN;
}

int
tpstc_cc_is_sink(int cc1, int cc2)
{
	if ((cc1 == TYPEC_CC_RP_DEF || cc1 == TYPEC_CC_RP_1_5 ||
	    cc1 == TYPEC_CC_RP_3_0) && cc2 == TYPEC_CC_OPEN)
		return 1;
	if ((cc2 == TYPEC_CC_RP_DEF || cc2 == TYPEC_CC_RP_1_5 ||
	    cc2 == TYPEC_CC_RP_3_0) && cc1 == TYPEC_CC_OPEN)
		return 1;
	return 0;
}

int
tpstc_cc_is_source(int cc1, int cc2)
{
	if (cc1 == TYPEC_CC_RD && cc2 != TYPEC_CC_RD)
		return 1;
	if (cc2 == TYPEC_CC_RD && cc1 != TYPEC_CC_RD)
		return 1;
	return 0;
}

int
tpstc_cc_is_audio(int cc1, int cc2)
{
	if (cc1 == TYPEC_CC_RA && cc2 == TYPEC_CC_RA)
		return 1;
	return 0;
}

int
tpstc_cc_is_audio_detached(int cc1, int cc2)
{
	if (cc1 == TYPEC_CC_RA && cc2 == TYPEC_CC_OPEN)
		return 1;
	if (cc2 == TYPEC_CC_RA && cc1 == TYPEC_CC_OPEN)
		return 1;
	return 0;
}

void
tpstc_cc_change(struct tpstc_softc *sc)
{
#if 0
	uint8_t cc, cc1, cc2;

	cc = tpstc_read_reg8(sc, TPS_CC_STATUS);
	if (sc->sc_cc == cc)
		return;

	cc1 = (cc >> TPS_ROLE_CTRL_CC1_SHIFT) & TPS_ROLE_CTRL_CC_MASK;
	cc1 = tpstc_cc_to_typec(cc1, cc & TPS_CC_STATUS_TERM);
	cc2 = (cc >> TPS_ROLE_CTRL_CC2_SHIFT) & TPS_ROLE_CTRL_CC_MASK;
	cc2 = tpstc_cc_to_typec(cc2, cc & TPS_CC_STATUS_TERM);

	if (cc1 == TYPEC_CC_OPEN && cc2 == TYPEC_CC_OPEN) {
		/* No CC, wait for new connection. */
		DPRINTF(("%s: disconnected\n", __func__));
		tpstc_write_reg8(sc, TPS_RX_DETECT, 0);
		tpstc_set_vbus(sc, 0, 0);
		tpstc_write_reg8(sc, TPS_POWER_CTRL, tpstc_read_reg8(sc,
		    TPS_POWER_CTRL) & ~TPS_POWER_CTRL_VCONN_ENABLE);
		tpstc_set_polarity(sc, TYPEC_POLARITY_CC1);
		if (sc->sc_try_data == TYPEC_HOST) {
			tpstc_write_reg8(sc, TPS_ROLE_CTRL,
			    TPS_ROLE_CTRL_DRP | 0xa);
		} else {
			tpstc_write_reg8(sc, TPS_ROLE_CTRL,
			    TPS_ROLE_CTRL_DRP | 0x5);
		}
		tpstc_write_reg8(sc, TPS_COMMAND,
		    TPS_COMMAND_LOOK4CONNECTION);
		sc->sc_attached = 0;
	} else if (tpstc_cc_is_source(cc1, cc2)) {
		/* Host */
		DPRINTF(("%s: attached as source\n", __func__));
		if (cc1 == TYPEC_CC_RD)
			tpstc_set_polarity(sc, TYPEC_POLARITY_CC1);
		else
			tpstc_set_polarity(sc, TYPEC_POLARITY_CC2);
		tpstc_set_roles(sc, TYPEC_HOST, TYPEC_SOURCE);
		tpstc_write_reg8(sc, TPS_RX_DETECT,
		    TPS_RX_DETECT_SOP | TPS_RX_DETECT_HARD_RESET);
		if ((cc1 == TYPEC_CC_RD && cc2 == TYPEC_CC_RA) ||
		    (cc2 == TYPEC_CC_RD && cc1 == TYPEC_CC_RA))
			tpstc_write_reg8(sc, TPS_POWER_CTRL, tpstc_read_reg8(sc,
			    TPS_POWER_CTRL) | TPS_POWER_CTRL_VCONN_ENABLE);
		tpstc_set_vbus(sc, 1, 0);
		sc->sc_attached = 1;
	} else if (tpstc_cc_is_sink(cc1, cc2)) {
		/* Device */
		DPRINTF(("%s: attached as sink\n", __func__));
		if (cc1 != TYPEC_CC_OPEN) {
			tpstc_set_polarity(sc, TYPEC_POLARITY_CC1);
			tpstc_write_reg8(sc, TPS_ROLE_CTRL,
			    TPS_ROLE_CTRL_CC_RD << TPS_ROLE_CTRL_CC1_SHIFT |
			    TPS_ROLE_CTRL_CC_OPEN << TPS_ROLE_CTRL_CC2_SHIFT);
		} else {
			tpstc_set_polarity(sc, TYPEC_POLARITY_CC2);
			tpstc_write_reg8(sc, TPS_ROLE_CTRL,
			    TPS_ROLE_CTRL_CC_OPEN << TPS_ROLE_CTRL_CC1_SHIFT |
			    TPS_ROLE_CTRL_CC_RD << TPS_ROLE_CTRL_CC2_SHIFT);
		}
		tpstc_set_roles(sc, TYPEC_DEVICE, TYPEC_SINK);
		tpstc_set_vbus(sc, 0, 0);
		sc->sc_attached = 1;
	} else if (tpstc_cc_is_audio_detached(cc1, cc2)) {
		/* Audio Detached */
		DPRINTF(("%s: audio detached\n", __func__));
	} else {
		panic("%s: unknown combination cc %x", __func__, cc);
	}

	sc->sc_cc = cc;
#endif
}

void
tpstc_power_change(struct tpstc_softc *sc)
{
#if 0
	uint8_t power;

	if (tpstc_read_reg8(sc, TPS_POWER_STATUS_MASK) == 0xff)
		DPRINTF(("%s: power reset\n", __func__));

	power = tpstc_read_reg8(sc, TPS_POWER_STATUS);
	power &= TPS_POWER_STATUS_VBUS_PRES;
	if (sc->sc_vbus_det == power)
		return;

	DPRINTF(("%s: power %d\n", __func__, power));
	sc->sc_vbus_det = power;
#endif
}

void
tpstc_set_roles(struct tpstc_softc *sc, enum typec_data_role data,
    enum typec_power_role power)
{
#if 0
	uint8_t reg;

	reg = TPS_MSG_HDR_INFO_PD_REV20;
	if (power == TYPEC_SOURCE)
		reg |= TPS_MSG_HDR_INFO_PWR_ROLE;
	if (data == TYPEC_HOST)
		reg |= TPS_MSG_HDR_INFO_DATA_ROLE;

	tpstc_write_reg8(sc, TPS_MSG_HDR_INFO, reg);

	if (data == TYPEC_HOST)
		printf("%s: connected in host mode\n",
		    sc->sc_dev.dv_xname);
	else
		printf("%s: connected in device mode\n",
		    sc->sc_dev.dv_xname);
#endif
}

void
tpstc_set_polarity(struct tpstc_softc *sc, int cc)
{
#if 0
	if (cc == TYPEC_POLARITY_CC1) {
		tpstc_write_reg8(sc, TPS_TPS_CTRL, 0);
		if (sc->sc_ss_sel)
			gpio_controller_set_pin(sc->sc_ss_sel, 1);
	}
	if (cc == TYPEC_POLARITY_CC2) {
		tpstc_write_reg8(sc, TPS_TPS_CTRL,
		    TPS_TPS_CTRL_ORIENTATION);
		if (sc->sc_ss_sel)
			gpio_controller_set_pin(sc->sc_ss_sel, 0);
	}
#endif
}

void
tpstc_set_vbus(struct tpstc_softc *sc, int source, int sink)
{
#if 0
	if (!source)
		tpstc_write_reg8(sc, TPS_COMMAND,
		    TPS_COMMAND_DISABLE_SRC_VBUS);

	if (!sink)
		tpstc_write_reg8(sc, TPS_COMMAND,
		    TPS_COMMAND_DISABLE_SINK_VBUS);

	if (!source && !sink) {
		tpstc_write_reg8(sc, TPS_VBUS_VOLTAGE_ALARM_LO_CFG, 0x1c);
		tpstc_write_reg8(sc, TPS_POWER_CTRL, tpstc_read_reg8(sc,
		    TPS_POWER_CTRL) | TPS_POWER_CTRL_FORCEDISCH);
	}

	if (source)
		tpstc_write_reg8(sc, TPS_COMMAND,
		    TPS_COMMAND_SRC_VBUS_DEFAULT);

	if (sink)
		tpstc_write_reg8(sc, TPS_COMMAND,
		    TPS_COMMAND_SINK_VBUS);
#endif
}

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
