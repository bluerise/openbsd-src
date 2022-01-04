/* $OpenBSD$ */
/* $NetBSD: dwc_eqos.c,v 1.1 2022/01/03 17:19:41 jmcneill Exp $ */

/*-
 * Copyright (c) 2022 Jared McNeill <jmcneill@invisible.ca>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * DesignWare Ethernet Quality-of-Service controller
 */

#include "bpfilter.h"

#include <sys/param.h>
#include <sys/device.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/mutex.h>
#include <sys/timeout.h>
#include <sys/atomic.h>
#include <sys/sockio.h>

#include <machine/bus.h>
#include <machine/intr.h>

#include <net/if.h>
#include <net/if_media.h>

#include <dev/mii/mii.h>
#include <dev/mii/miivar.h>

#if NBPFILTER > 0
#include <net/bpf.h>
#endif

#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <dev/ic/dwqereg.h>
#include <dev/ic/dwqevar.h>

CTASSERT(MCLBYTES == 2048);
#ifdef EQOS_DEBUG
#define	DPRINTF(...)	printf(##__VA_ARGS__)
#else
#define	DPRINTF(...)	((void)0)
#endif

#define	DESC_BOUNDARY		(1ULL << 32)
#define	DESC_ALIGN		sizeof(struct dwqe_dma_desc)
#define	TX_DESC_COUNT		EQOS_DMA_DESC_COUNT
#define	TX_DESC_SIZE		(TX_DESC_COUNT * DESC_ALIGN)
#define	RX_DESC_COUNT		EQOS_DMA_DESC_COUNT
#define	RX_DESC_SIZE		(RX_DESC_COUNT * DESC_ALIGN)
#define	MII_BUSY_RETRY		1000

#define	DESC_OFF(n)		((n) * sizeof(struct dwqe_dma_desc))
#define	TX_SKIP(n, o)		(((n) + (o)) % TX_DESC_COUNT)
#define	TX_NEXT(n)		TX_SKIP(n, 1)
#define	RX_NEXT(n)		(((n) + 1) % RX_DESC_COUNT)

#define	TX_MAX_SEGS		128

#define	EQOS_LOCK(sc)			mtx_enter(&(sc)->sc_lock)
#define	EQOS_UNLOCK(sc)			mtx_leave(&(sc)->sc_lock)
#define	EQOS_ASSERT_LOCKED(sc)		MUTEX_ASSERT_LOCKED(&(sc)->sc_lock)

#define	EQOS_TXLOCK(sc)			mtx_enter(&(sc)->sc_txlock)
#define	EQOS_TXUNLOCK(sc)		mtx_leave(&(sc)->sc_txlock)
#define	EQOS_ASSERT_TXLOCKED(sc)	MUTEX_ASSERT_LOCKED(&(sc)->sc_txlock)

#define	EQOS_HW_FEATURE_ADDR64_32BIT(sc)				\
	(((sc)->sc_hw_feature[1] & GMAC_MAC_HW_FEATURE1_ADDR64_MASK) ==	\
	    GMAC_MAC_HW_FEATURE1_ADDR64_32BIT)


#define	RD4(sc, reg)			\
	bus_space_read_4((sc)->sc_bst, (sc)->sc_bsh, (reg))
#define	WR4(sc, reg, val)		\
	bus_space_write_4((sc)->sc_bst, (sc)->sc_bsh, (reg), (val))

#define STUB(...)				\
	printf("%s: TODO\n", __func__);	\

struct cfdriver dwqe_cd = {
	NULL, "dwqe", DV_IFNET
};

static int
dwqe_media_change(struct ifnet *ifp)
{
	struct dwqe_softc *sc = ifp->if_softc;

	if (LIST_FIRST(&sc->sc_mii.mii_phys))
		mii_mediachg(&sc->sc_mii);

	return (0);
}

static void
dwqe_media_status(struct ifnet *ifp, struct ifmediareq *ifmr)
{
	struct dwqe_softc *sc = ifp->if_softc;

	if (LIST_FIRST(&sc->sc_mii.mii_phys))
		mii_pollstat(&sc->sc_mii);

	ifmr->ifm_active = sc->sc_mii.mii_media_active;
	ifmr->ifm_status = sc->sc_mii.mii_media_status;
}

static int
dwqe_mii_readreg(struct device *dev, int phy, int reg)
{
	struct dwqe_softc *sc = (struct dwqe_softc *)dev;
	uint32_t addr;
	int retry;

	addr = sc->sc_clock_range |
	    (phy << GMAC_MAC_MDIO_ADDRESS_PA_SHIFT) |
	    (reg << GMAC_MAC_MDIO_ADDRESS_RDA_SHIFT) |
	    GMAC_MAC_MDIO_ADDRESS_GOC_READ |
	    GMAC_MAC_MDIO_ADDRESS_GB;
	WR4(sc, GMAC_MAC_MDIO_ADDRESS, addr);

	delay(10000);

	for (retry = MII_BUSY_RETRY; retry > 0; retry--) {
		addr = RD4(sc, GMAC_MAC_MDIO_ADDRESS);
		if ((addr & GMAC_MAC_MDIO_ADDRESS_GB) == 0) {
			return RD4(sc, GMAC_MAC_MDIO_DATA) & 0xFFFF;
			break;
		}
		delay(10);
	}
	if (retry == 0) {
		printf("%s: phy read timeout, phy=%d reg=%d\n",
		    sc->sc_dev.dv_xname, phy, reg);
		return ETIMEDOUT;
	}

	return 0;
}

static void
dwqe_mii_writereg(struct device *dev, int phy, int reg, int val)
{
	struct dwqe_softc *sc = (struct dwqe_softc *)dev;
	uint32_t addr;
	int retry;

	WR4(sc, GMAC_MAC_MDIO_DATA, val);

	addr = sc->sc_clock_range |
	    (phy << GMAC_MAC_MDIO_ADDRESS_PA_SHIFT) |
	    (reg << GMAC_MAC_MDIO_ADDRESS_RDA_SHIFT) |
	    GMAC_MAC_MDIO_ADDRESS_GOC_WRITE |
	    GMAC_MAC_MDIO_ADDRESS_GB;
	WR4(sc, GMAC_MAC_MDIO_ADDRESS, addr);

	delay(10000);

	for (retry = MII_BUSY_RETRY; retry > 0; retry--) {
		addr = RD4(sc, GMAC_MAC_MDIO_ADDRESS);
		if ((addr & GMAC_MAC_MDIO_ADDRESS_GB) == 0) {
			break;
		}
		delay(10);
	}
	if (retry == 0) {
		printf("%s: phy write timeout, phy=%d reg=%d\n",
		    sc->sc_dev.dv_xname, phy, reg);
	}
}

static void
dwqe_update_link(struct dwqe_softc *sc)
{
	struct mii_data *mii = &sc->sc_mii;
	uint64_t baudrate;
	uint32_t conf;

	baudrate = ifmedia_baudrate(mii->mii_media_active);

	conf = RD4(sc, GMAC_MAC_CONFIGURATION);
	switch (baudrate) {
	case IF_Mbps(10):
		conf |= GMAC_MAC_CONFIGURATION_PS;
		conf &= ~GMAC_MAC_CONFIGURATION_FES;
		break;
	case IF_Mbps(100):
		conf |= GMAC_MAC_CONFIGURATION_PS;
		conf |= GMAC_MAC_CONFIGURATION_FES;
		break;
	case IF_Gbps(1):
		conf &= ~GMAC_MAC_CONFIGURATION_PS;
		conf &= ~GMAC_MAC_CONFIGURATION_FES;
		break;
	case IF_Mbps(2500ULL):
		conf &= ~GMAC_MAC_CONFIGURATION_PS;
		conf |= GMAC_MAC_CONFIGURATION_FES;
		break;
	}

	if ((IFM_OPTIONS(mii->mii_media_active) & IFM_FDX) != 0) {
		conf |= GMAC_MAC_CONFIGURATION_DM;
	} else {
		conf &= ~GMAC_MAC_CONFIGURATION_DM;
	}

	WR4(sc, GMAC_MAC_CONFIGURATION, conf);
}

static void
dwqe_mii_statchg(struct device *dev)
{
	struct dwqe_softc *sc = (struct dwqe_softc *)dev;

	dwqe_update_link(sc);
}

static void
dwqe_dma_sync(struct dwqe_softc *sc, bus_dmamap_t map,
    u_int start, u_int end, u_int total, int flags)
{
	if (end > start) {
		bus_dmamap_sync(sc->sc_dmat, map, DESC_OFF(start),
		    DESC_OFF(end) - DESC_OFF(start), flags);
	} else {
		bus_dmamap_sync(sc->sc_dmat, map, DESC_OFF(start),
		    DESC_OFF(total) - DESC_OFF(start), flags);
		if (DESC_OFF(end) - DESC_OFF(0) > 0) {
			bus_dmamap_sync(sc->sc_dmat, map, DESC_OFF(0),
			    DESC_OFF(end) - DESC_OFF(0), flags);
		}
	}
}

static inline int
dwqe_load_mbuf(bus_dma_tag_t dmat, bus_dmamap_t map, struct mbuf *m)
{
	int error;

	error = bus_dmamap_load_mbuf(dmat, map, m, BUS_DMA_NOWAIT);
	if (error != EFBIG)
		return (error);

	error = m_defrag(m, M_DONTWAIT);
	if (error != 0)
		return (error);

	return bus_dmamap_load_mbuf(dmat, map, m, BUS_DMA_NOWAIT);
}

static void
dwqe_setup_txdesc(struct dwqe_softc *sc, int index, int flags,
    bus_addr_t paddr, u_int len, u_int total_len)
{
	uint32_t tdes2, tdes3;

	if (paddr == 0 || len == 0) {
		KASSERT(flags == 0);
		tdes2 = 0;
		tdes3 = 0;
		--sc->sc_tx.queued;
	} else {
		tdes2 = (flags & EQOS_TDES3_LD) ? EQOS_TDES2_IOC : 0;
		tdes3 = flags;
		++sc->sc_tx.queued;
	}

	KASSERT(!EQOS_HW_FEATURE_ADDR64_32BIT(sc) || (paddr >> 32) == 0);

	sc->sc_tx.desc_ring[index].tdes0 = htole32((uint32_t)paddr);
	sc->sc_tx.desc_ring[index].tdes1 = htole32((uint32_t)(paddr >> 32));
	sc->sc_tx.desc_ring[index].tdes2 = htole32(tdes2 | len);
	sc->sc_tx.desc_ring[index].tdes3 = htole32(tdes3 | total_len);
}

static int
dwqe_setup_txbuf(struct dwqe_softc *sc, int index, struct mbuf *m)
{
	bus_dma_segment_t *segs;
	int nsegs, cur, i;
	uint32_t flags;
	bool nospace;

	/* at least one descriptor free ? */
	if (sc->sc_tx.queued >= TX_DESC_COUNT - 1)
		return -1;

	if (dwqe_load_mbuf(sc->sc_dmat, sc->sc_tx.buf_map[index].map, m) != 0)
		return -1;

	segs = sc->sc_tx.buf_map[index].map->dm_segs;
	nsegs = sc->sc_tx.buf_map[index].map->dm_nsegs;

	nospace = sc->sc_tx.queued >= TX_DESC_COUNT - nsegs;
	if (nospace) {
		bus_dmamap_unload(sc->sc_dmat,
		    sc->sc_tx.buf_map[index].map);
		/* XXX coalesce and retry ? */
		return -1;
	}

	bus_dmamap_sync(sc->sc_dmat, sc->sc_tx.buf_map[index].map,
	    0, sc->sc_tx.buf_map[index].map->dm_mapsize, BUS_DMASYNC_PREWRITE);

	/* stored in same index as loaded map */
	sc->sc_tx.buf_map[index].mbuf = m;

	flags = EQOS_TDES3_FD;

	for (cur = index, i = 0; i < nsegs; i++) {
		if (i == nsegs - 1)
			flags |= EQOS_TDES3_LD;

		dwqe_setup_txdesc(sc, cur, flags, segs[i].ds_addr,
		    segs[i].ds_len, m->m_pkthdr.len);
		flags &= ~EQOS_TDES3_FD;
		cur = TX_NEXT(cur);

		flags |= EQOS_TDES3_OWN;
	}

	/*
	 * Defer setting OWN bit on the first descriptor until all
	 * descriptors have been updated.
	 */
	membar_sync();
	sc->sc_tx.desc_ring[index].tdes3 |= htole32(EQOS_TDES3_OWN);

	return nsegs;
}

static void
dwqe_setup_rxdesc(struct dwqe_softc *sc, int index, bus_addr_t paddr)
{
	sc->sc_rx.desc_ring[index].tdes0 = htole32((uint32_t)paddr);
	sc->sc_rx.desc_ring[index].tdes1 = htole32((uint32_t)(paddr >> 32));
	sc->sc_rx.desc_ring[index].tdes2 = htole32(0);
	membar_sync();
	sc->sc_rx.desc_ring[index].tdes3 =
	    htole32(EQOS_TDES3_OWN | EQOS_TDES3_IOC | EQOS_TDES3_BUF1V);
}

static int
dwqe_setup_rxbuf(struct dwqe_softc *sc, int index, struct mbuf *m)
{
	int error;

	m_adj(m, ETHER_ALIGN);

	error = bus_dmamap_load_mbuf(sc->sc_dmat,
	    sc->sc_rx.buf_map[index].map, m, BUS_DMA_READ | BUS_DMA_NOWAIT);
	if (error != 0)
		return error;

	bus_dmamap_sync(sc->sc_dmat, sc->sc_rx.buf_map[index].map,
	    0, sc->sc_rx.buf_map[index].map->dm_mapsize,
	    BUS_DMASYNC_PREREAD);

	sc->sc_rx.buf_map[index].mbuf = m;
	dwqe_setup_rxdesc(sc, index,
	    sc->sc_rx.buf_map[index].map->dm_segs[0].ds_addr);

	return 0;
}

static struct mbuf *
dwqe_alloc_mbufcl(struct dwqe_softc *sc)
{
	struct mbuf *m;

	m = MCLGETL(NULL, M_DONTWAIT, MCLBYTES);
	if (!m)
		return NULL;
	m->m_len = m->m_pkthdr.len = MCLBYTES;

	return m;
}

static void
dwqe_enable_intr(struct dwqe_softc *sc)
{
	WR4(sc, GMAC_DMA_CHAN0_INTR_ENABLE,
	    GMAC_DMA_CHAN0_INTR_ENABLE_NIE |
	    GMAC_DMA_CHAN0_INTR_ENABLE_AIE |
	    GMAC_DMA_CHAN0_INTR_ENABLE_FBE |
	    GMAC_DMA_CHAN0_INTR_ENABLE_RIE |
	    GMAC_DMA_CHAN0_INTR_ENABLE_TIE);
}

static void
dwqe_disable_intr(struct dwqe_softc *sc)
{
	WR4(sc, GMAC_DMA_CHAN0_INTR_ENABLE, 0);
}

static void
dwqe_tick(void *softc)
{
	struct dwqe_softc *sc = softc;
	struct mii_data *mii = &sc->sc_mii;
	int s = splnet();

	EQOS_LOCK(sc);
	mii_tick(mii);
	timeout_add_sec(&sc->sc_stat_ch, 1);
	EQOS_UNLOCK(sc);

	splx(s);
}

static uint32_t
dwqe_bitrev32(uint32_t x)
{
	x = (((x & 0xaaaaaaaa) >> 1) | ((x & 0x55555555) << 1));
	x = (((x & 0xcccccccc) >> 2) | ((x & 0x33333333) << 2));
	x = (((x & 0xf0f0f0f0) >> 4) | ((x & 0x0f0f0f0f) << 4));
	x = (((x & 0xff00ff00) >> 8) | ((x & 0x00ff00ff) << 8));

	return (x >> 16) | (x << 16);
}

static void
dwqe_setup_rxfilter(struct dwqe_softc *sc)
{
	struct arpcom *ac = &sc->sc_ac;
	struct ifnet *ifp = &ac->ac_if;
	uint32_t pfil, crc, hashreg, hashbit, hash[2];
	struct ether_multi *enm;
	struct ether_multistep step;
	uint32_t val;

	EQOS_ASSERT_LOCKED(sc);

	pfil = RD4(sc, GMAC_MAC_PACKET_FILTER);
	pfil &= ~(GMAC_MAC_PACKET_FILTER_PR |
		  GMAC_MAC_PACKET_FILTER_PM |
		  GMAC_MAC_PACKET_FILTER_HMC |
		  GMAC_MAC_PACKET_FILTER_PCF_MASK);
	hash[0] = hash[1] = ~0U;

	if ((ifp->if_flags & IFF_PROMISC) != 0) {
		pfil |= GMAC_MAC_PACKET_FILTER_PR |
			GMAC_MAC_PACKET_FILTER_PCF_ALL;
	} else if ((ifp->if_flags & IFF_ALLMULTI) != 0) {
		pfil |= GMAC_MAC_PACKET_FILTER_PM;
	} else {
		hash[0] = hash[1] = 0;
		pfil |= GMAC_MAC_PACKET_FILTER_HMC;
		ETHER_FIRST_MULTI(step, ac, enm);
		while (enm != NULL) {
			crc = ether_crc32_le(enm->enm_addrlo, ETHER_ADDR_LEN);
			crc &= 0x7f;
			crc = dwqe_bitrev32(~crc) >> 26;
			hashreg = (crc >> 5);
			hashbit = (crc & 0x1f);
			hash[hashreg] |= (1 << hashbit);
			ETHER_NEXT_MULTI(step, enm);
		}
	}

	/* Write our unicast address */
	val = sc->sc_lladdr[4] | (sc->sc_lladdr[5] << 8);
	WR4(sc, GMAC_MAC_ADDRESS0_HIGH, val);
	val = sc->sc_lladdr[0] | (sc->sc_lladdr[1] << 8) |
	    (sc->sc_lladdr[2] << 16) | (sc->sc_lladdr[3] << 24);
	WR4(sc, GMAC_MAC_ADDRESS0_LOW, val);

	/* Multicast hash filters */
	WR4(sc, GMAC_MAC_HASH_TABLE_REG0, hash[1]);
	WR4(sc, GMAC_MAC_HASH_TABLE_REG1, hash[0]);

	/* Packet filter config */
	WR4(sc, GMAC_MAC_PACKET_FILTER, pfil);
}

static int
dwqe_reset(struct dwqe_softc *sc)
{
	uint32_t val;
	int retry;

	WR4(sc, GMAC_DMA_MODE, GMAC_DMA_MODE_SWR);
	for (retry = 2000; retry > 0; retry--) {
		delay(1000);
		val = RD4(sc, GMAC_DMA_MODE);
		if ((val & GMAC_DMA_MODE_SWR) == 0) {
			return 0;
		}
	}

	printf("%s: reset timeout!\n", sc->sc_dev.dv_xname);
	return ETIMEDOUT;
}

static void
dwqe_init_rings(struct dwqe_softc *sc, int qid)
{
	sc->sc_tx.queued = 0;

	WR4(sc, GMAC_DMA_CHAN0_TX_BASE_ADDR_HI,
	    (uint32_t)(sc->sc_tx.desc_ring_paddr >> 32));
	WR4(sc, GMAC_DMA_CHAN0_TX_BASE_ADDR,
	    (uint32_t)sc->sc_tx.desc_ring_paddr);
	WR4(sc, GMAC_DMA_CHAN0_TX_RING_LEN, TX_DESC_COUNT - 1);

	WR4(sc, GMAC_DMA_CHAN0_RX_BASE_ADDR_HI,
	    (uint32_t)(sc->sc_rx.desc_ring_paddr >> 32));
	WR4(sc, GMAC_DMA_CHAN0_RX_BASE_ADDR,
	    (uint32_t)sc->sc_rx.desc_ring_paddr);
	WR4(sc, GMAC_DMA_CHAN0_RX_RING_LEN, RX_DESC_COUNT - 1);
	WR4(sc, GMAC_DMA_CHAN0_RX_END_ADDR,
	    (uint32_t)sc->sc_rx.desc_ring_paddr +
	    DESC_OFF((sc->sc_rx.cur - 1) % RX_DESC_COUNT));
}

static int
dwqe_init_locked(struct dwqe_softc *sc)
{
	struct ifnet *ifp = &sc->sc_ac.ac_if;
	struct mii_data *mii = &sc->sc_mii;
	uint32_t val;

	EQOS_ASSERT_LOCKED(sc);
	EQOS_ASSERT_TXLOCKED(sc);

	if ((ifp->if_flags & IFF_RUNNING) != 0)
		return 0;

	/* Setup TX/RX rings */
	dwqe_init_rings(sc, 0);

	/* Setup RX filter */
	dwqe_setup_rxfilter(sc);

	WR4(sc, GMAC_MAC_1US_TIC_COUNTER, (sc->sc_csr_clock / 1000000) - 1);

	/* Enable transmit and receive DMA */
	val = RD4(sc, GMAC_DMA_CHAN0_CONTROL);
	val &= ~GMAC_DMA_CHAN0_CONTROL_DSL_MASK;
	val |= ((DESC_ALIGN - 16) / 8) << GMAC_DMA_CHAN0_CONTROL_DSL_SHIFT;
	val |= GMAC_DMA_CHAN0_CONTROL_PBLX8;
	WR4(sc, GMAC_DMA_CHAN0_CONTROL, val);
	val = RD4(sc, GMAC_DMA_CHAN0_TX_CONTROL);
	val |= GMAC_DMA_CHAN0_TX_CONTROL_OSP;
	val |= GMAC_DMA_CHAN0_TX_CONTROL_START;
	WR4(sc, GMAC_DMA_CHAN0_TX_CONTROL, val);
	val = RD4(sc, GMAC_DMA_CHAN0_RX_CONTROL);
	val &= ~GMAC_DMA_CHAN0_RX_CONTROL_RBSZ_MASK;
	val |= (MCLBYTES << GMAC_DMA_CHAN0_RX_CONTROL_RBSZ_SHIFT);
	val |= GMAC_DMA_CHAN0_RX_CONTROL_START;
	WR4(sc, GMAC_DMA_CHAN0_RX_CONTROL, val);

	/* Configure operation modes */
	WR4(sc, GMAC_MTL_TXQ0_OPERATION_MODE,
	    GMAC_MTL_TXQ0_OPERATION_MODE_TSF |
	    GMAC_MTL_TXQ0_OPERATION_MODE_TXQEN_EN);
	WR4(sc, GMAC_MTL_RXQ0_OPERATION_MODE,
	    GMAC_MTL_RXQ0_OPERATION_MODE_RSF |
	    GMAC_MTL_RXQ0_OPERATION_MODE_FEP |
	    GMAC_MTL_RXQ0_OPERATION_MODE_FUP);

	/* Enable flow control */
	val = RD4(sc, GMAC_MAC_Q0_TX_FLOW_CTRL);
	val |= 0xFFFFU << GMAC_MAC_Q0_TX_FLOW_CTRL_PT_SHIFT;
	val |= GMAC_MAC_Q0_TX_FLOW_CTRL_TFE;
	WR4(sc, GMAC_MAC_Q0_TX_FLOW_CTRL, val);
	val = RD4(sc, GMAC_MAC_RX_FLOW_CTRL);
	val |= GMAC_MAC_RX_FLOW_CTRL_RFE;
	WR4(sc, GMAC_MAC_RX_FLOW_CTRL, val);

	/* Enable transmitter and receiver */
	val = RD4(sc, GMAC_MAC_CONFIGURATION);
	val |= GMAC_MAC_CONFIGURATION_BE;
	val |= GMAC_MAC_CONFIGURATION_JD;
	val |= GMAC_MAC_CONFIGURATION_JE;
	val |= GMAC_MAC_CONFIGURATION_DCRS;
	val |= GMAC_MAC_CONFIGURATION_TE;
	val |= GMAC_MAC_CONFIGURATION_RE;
	WR4(sc, GMAC_MAC_CONFIGURATION, val);

	/* Enable interrupts */
	dwqe_enable_intr(sc);

	ifp->if_flags |= IFF_RUNNING;
	ifq_clr_oactive(&ifp->if_snd);

	mii_mediachg(mii);
	timeout_add_sec(&sc->sc_stat_ch, 1);

	return 0;
}

static int
dwqe_init(struct dwqe_softc *sc)
{
	int error;

	EQOS_LOCK(sc);
	EQOS_TXLOCK(sc);
	error = dwqe_init_locked(sc);
	EQOS_TXUNLOCK(sc);
	EQOS_UNLOCK(sc);

	return error;
}

static int
dwqe_stop_locked(struct dwqe_softc *sc, int disable)
{
	struct ifnet *ifp = &sc->sc_ac.ac_if;
	uint32_t val;
	int error = 0;
	int retry;

	EQOS_ASSERT_LOCKED(sc);

	timeout_del(&sc->sc_stat_ch);

	mii_down(&sc->sc_mii);

	/* Disable receiver */
	val = RD4(sc, GMAC_MAC_CONFIGURATION);
	val &= ~GMAC_MAC_CONFIGURATION_RE;
	WR4(sc, GMAC_MAC_CONFIGURATION, val);

	/* Stop receive DMA */
	val = RD4(sc, GMAC_DMA_CHAN0_RX_CONTROL);
	val &= ~GMAC_DMA_CHAN0_RX_CONTROL_START;
	WR4(sc, GMAC_DMA_CHAN0_RX_CONTROL, val);

	/* Stop transmit DMA */
	val = RD4(sc, GMAC_DMA_CHAN0_TX_CONTROL);
	val &= ~GMAC_DMA_CHAN0_TX_CONTROL_START;
	WR4(sc, GMAC_DMA_CHAN0_TX_CONTROL, val);

	if (disable) {
		/* Flush data in the TX FIFO */
		val = RD4(sc, GMAC_MTL_TXQ0_OPERATION_MODE);
		val |= GMAC_MTL_TXQ0_OPERATION_MODE_FTQ;
		WR4(sc, GMAC_MTL_TXQ0_OPERATION_MODE, val);
		/* Wait for flush to complete */
		for (retry = 10000; retry > 0; retry--) {
			val = RD4(sc, GMAC_MTL_TXQ0_OPERATION_MODE);
			if ((val & GMAC_MTL_TXQ0_OPERATION_MODE_FTQ) == 0) {
				break;
			}
			delay(1);
		}
		if (retry == 0) {
			printf("%s: timeout flushing TX queue\n",
			    sc->sc_dev.dv_xname);
			error = ETIMEDOUT;
		}
	}

	/* Disable transmitter */
	val = RD4(sc, GMAC_MAC_CONFIGURATION);
	val &= ~GMAC_MAC_CONFIGURATION_TE;
	WR4(sc, GMAC_MAC_CONFIGURATION, val);

	/* Disable interrupts */
	dwqe_disable_intr(sc);

	ifp->if_flags &= ~(IFF_RUNNING | IFF_OACTIVE);
	return error;
}

static int
dwqe_stop(struct dwqe_softc *sc)
{
	int error;

	EQOS_LOCK(sc);
	error = dwqe_stop_locked(sc, 1);
	EQOS_UNLOCK(sc);

	return error;
}

static void
dwqe_rxintr(struct dwqe_softc *sc, int qid)
{
	struct ifnet *ifp = &sc->sc_ac.ac_if;
	int error, index, len, pkts = 0;
	struct mbuf_list ml = MBUF_LIST_INITIALIZER();
	struct mbuf *m, *m0;
	uint32_t tdes3;

	for (index = sc->sc_rx.cur; ; index = RX_NEXT(index)) {
		dwqe_dma_sync(sc, sc->sc_rx.desc_map,
		    index, index + 1, RX_DESC_COUNT,
		    BUS_DMASYNC_POSTREAD | BUS_DMASYNC_POSTWRITE);

		tdes3 = le32toh(sc->sc_rx.desc_ring[index].tdes3);
		if ((tdes3 & EQOS_TDES3_OWN) != 0) {
			break;
		}

		bus_dmamap_sync(sc->sc_dmat, sc->sc_rx.buf_map[index].map,
		    0, sc->sc_rx.buf_map[index].map->dm_mapsize,
		    BUS_DMASYNC_POSTREAD);
		bus_dmamap_unload(sc->sc_dmat,
		    sc->sc_rx.buf_map[index].map);

		len = tdes3 & EQOS_TDES3_LENGTH_MASK;
		if (len != 0) {
			m = sc->sc_rx.buf_map[index].mbuf;
			//m->m_flags |= M_HASFCS;
			m->m_pkthdr.len = m->m_len = len;

			ml_enqueue(&ml, m);
			++pkts;
		}

		if ((m0 = dwqe_alloc_mbufcl(sc)) != NULL) {
			error = dwqe_setup_rxbuf(sc, index, m0);
			if (error != 0) {
				/* XXX hole in RX ring */
			}
		} else {
			ifp->if_ierrors++;
		}
		dwqe_dma_sync(sc, sc->sc_rx.desc_map,
		    index, index + 1, RX_DESC_COUNT,
		    BUS_DMASYNC_PREWRITE | BUS_DMASYNC_PREREAD);

		WR4(sc, GMAC_DMA_CHAN0_RX_END_ADDR,
		    (uint32_t)sc->sc_rx.desc_ring_paddr +
		    DESC_OFF(sc->sc_rx.cur));
	}

	sc->sc_rx.cur = index;

	ifiq_input(&ifp->if_rcv, &ml);
}

static void
dwqe_txintr(struct dwqe_softc *sc, int qid)
{
	struct ifnet *ifp = &sc->sc_ac.ac_if;
	struct dwqe_bufmap *bmap;
	struct dwqe_dma_desc *desc;
	uint32_t tdes3;
	int i, pkts = 0;

	EQOS_ASSERT_LOCKED(sc);

	for (i = sc->sc_tx.next; sc->sc_tx.queued > 0; i = TX_NEXT(i)) {
		KASSERT(sc->sc_tx.queued > 0);
		KASSERT(sc->sc_tx.queued <= TX_DESC_COUNT);
		dwqe_dma_sync(sc, sc->sc_tx.desc_map,
		    i, i + 1, TX_DESC_COUNT,
		    BUS_DMASYNC_POSTREAD | BUS_DMASYNC_POSTWRITE);
		desc = &sc->sc_tx.desc_ring[i];
		tdes3 = le32toh(desc->tdes3);
		if ((tdes3 & EQOS_TDES3_OWN) != 0) {
			break;
		}
		bmap = &sc->sc_tx.buf_map[i];
		if (bmap->mbuf != NULL) {
			bus_dmamap_sync(sc->sc_dmat, bmap->map,
			    0, bmap->map->dm_mapsize,
			    BUS_DMASYNC_POSTWRITE);
			bus_dmamap_unload(sc->sc_dmat, bmap->map);
			m_freem(bmap->mbuf);
			bmap->mbuf = NULL;
			++pkts;
		}

		dwqe_setup_txdesc(sc, i, 0, 0, 0, 0);
		dwqe_dma_sync(sc, sc->sc_tx.desc_map,
		    i, i + 1, TX_DESC_COUNT,
		    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);

		ifp->if_flags &= ~IFF_OACTIVE;

		/* Last descriptor in a packet contains DMA status */
		if ((tdes3 & EQOS_TDES3_LD) != 0) {
			if ((tdes3 & EQOS_TDES3_DE) != 0) {
				printf("%s: TX [%u] desc error: 0x%08x\n",
				    sc->sc_dev.dv_xname, i, tdes3);
				ifp->if_oerrors++;
			} else if ((tdes3 & EQOS_TDES3_ES) != 0) {
				printf("%s: TX [%u] tx error: 0x%08x\n",
				    sc->sc_dev.dv_xname, i, tdes3);
				ifp->if_oerrors++;
			} else {
				ifp->if_opackets++;
			}
		}
	}

	sc->sc_tx.next = i;

	if (pkts) {
		if (ifq_is_oactive(&ifp->if_snd))
			ifq_restart(&ifp->if_snd);
	}
}

static void
dwqe_start_locked(struct dwqe_softc *sc)
{
	struct ifnet *ifp = &sc->sc_ac.ac_if;
	struct mbuf *m;
	int cnt, nsegs, start;

	EQOS_ASSERT_TXLOCKED(sc);

	if ((ifp->if_flags & (IFF_RUNNING | IFF_OACTIVE)) != IFF_RUNNING)
		return;

	for (cnt = 0, start = sc->sc_tx.cur; ; cnt++) {
		if (sc->sc_tx.queued >= TX_DESC_COUNT - TX_MAX_SEGS) {
			ifq_set_oactive(&ifp->if_snd);
			break;
		}

		m = ifq_dequeue(&ifp->if_snd);
		if (m == NULL) {
			break;
		}

		nsegs = dwqe_setup_txbuf(sc, sc->sc_tx.cur, m);
		if (nsegs <= 0) {
			ifp->if_oerrors++;
			m_freem(m);
			continue;
		}

#if NBPFILTER > 0
		if (ifp->if_bpf)
			bpf_mtap(ifp->if_bpf, m, BPF_DIRECTION_OUT);
#endif

		sc->sc_tx.cur = TX_SKIP(sc->sc_tx.cur, nsegs);
	}

	if (cnt != 0) {
		dwqe_dma_sync(sc, sc->sc_tx.desc_map,
		    start, sc->sc_tx.cur, TX_DESC_COUNT,
		    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);

		/* Start and run TX DMA */
		WR4(sc, GMAC_DMA_CHAN0_TX_END_ADDR,
		    (uint32_t)sc->sc_tx.desc_ring_paddr +
		    DESC_OFF(sc->sc_tx.cur));
	}
}

static void
dwqe_start(struct ifnet *ifp)
{
	struct dwqe_softc *sc = ifp->if_softc;

	EQOS_TXLOCK(sc);
	dwqe_start_locked(sc);
	EQOS_TXUNLOCK(sc);
}

int
dwqe_intr(void *arg)
{
	struct dwqe_softc *sc = arg;
	uint32_t mac_status, mtl_status, dma_status, rx_tx_status;

	mac_status = RD4(sc, GMAC_MAC_INTERRUPT_STATUS);
	mac_status &= RD4(sc, GMAC_MAC_INTERRUPT_ENABLE);

	if (mac_status) {
		printf("%s: GMAC_MAC_INTERRUPT_STATUS = 0x%08X\n",
		    sc->sc_dev.dv_xname, mac_status);
	}

	mtl_status = RD4(sc, GMAC_MTL_INTERRUPT_STATUS);
	if (mtl_status) {
		printf("%s: GMAC_MTL_INTERRUPT_STATUS = 0x%08X\n",
		    sc->sc_dev.dv_xname, mtl_status);
	}

	dma_status = RD4(sc, GMAC_DMA_CHAN0_STATUS);
	dma_status &= RD4(sc, GMAC_DMA_CHAN0_INTR_ENABLE);
	if (dma_status) {
		WR4(sc, GMAC_DMA_CHAN0_STATUS, dma_status);
	}

	EQOS_LOCK(sc);
	if ((dma_status & GMAC_DMA_CHAN0_STATUS_RI) != 0) {
		dwqe_rxintr(sc, 0);
		dma_status &= ~GMAC_DMA_CHAN0_STATUS_RI;
	}

	if ((dma_status & GMAC_DMA_CHAN0_STATUS_TI) != 0) {
		dwqe_txintr(sc, 0);
		dma_status &= ~GMAC_DMA_CHAN0_STATUS_TI;
	}
	EQOS_UNLOCK(sc);

	if ((mac_status | mtl_status | dma_status) == 0) {
		printf("%s: spurious interrupt?!\n", sc->sc_dev.dv_xname);
	}

	rx_tx_status = RD4(sc, GMAC_MAC_RX_TX_STATUS);
	if (rx_tx_status) {
		printf("%s: GMAC_MAC_RX_TX_STATUS = 0x%08x\n",
		    sc->sc_dev.dv_xname, rx_tx_status);
	}

	return 1;
}

static int
dwqe_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	struct dwqe_softc *sc = ifp->if_softc;
	struct ifreq *ifr = (struct ifreq *)data;
	int error = 0, s;

	s = splnet();

	switch (cmd) {
	case SIOCSIFADDR:
		ifp->if_flags |= IFF_UP;
		/* FALLTHROUGH */

	case SIOCSIFFLAGS:
		if (ISSET(ifp->if_flags, IFF_UP)) {
			if (ISSET(ifp->if_flags, IFF_RUNNING))
				error = ENETRESET;
			else
				error = dwqe_init(sc);
		} else {
			if (ISSET(ifp->if_flags, IFF_RUNNING))
				error = dwqe_stop(sc);
		}
		break;

	case SIOCGIFMEDIA:
	case SIOCSIFMEDIA:
		error = ifmedia_ioctl(ifp, ifr, &sc->sc_media, cmd);
		break;

	default:
		error = ether_ioctl(ifp, &sc->sc_ac, cmd, data);
		break;
	}

	if (error == ENETRESET) {
		if (ifp->if_flags & IFF_RUNNING) {
			EQOS_LOCK(sc);
			dwqe_setup_rxfilter(sc);
			EQOS_UNLOCK(sc);
		}
		error = 0;
	}

	splx(s);
	return error;
}

static void
dwqe_get_eaddr(struct dwqe_softc *sc, uint8_t *eaddr)
{
	uint32_t maclo, machi;

	maclo = htobe32(RD4(sc, GMAC_MAC_ADDRESS0_LOW));
	machi = htobe16(RD4(sc, GMAC_MAC_ADDRESS0_HIGH) & 0xFFFF);

	if (maclo == 0xFFFFFFFF && machi == 0xFFFF)
		return;

	eaddr[0] = maclo & 0xff;
	eaddr[1] = (maclo >> 8) & 0xff;
	eaddr[2] = (maclo >> 16) & 0xff;
	eaddr[3] = (maclo >> 24) & 0xff;
	eaddr[4] = machi & 0xff;
	eaddr[5] = (machi >> 8) & 0xff;
}

static void
dwqe_axi_configure(struct dwqe_softc *sc)
{
	uint32_t val;

	val = RD4(sc, GMAC_DMA_SYSBUS_MODE);
	if (sc->sc_mixed_burst)
		val |= GMAC_DMA_SYSBUS_MODE_MB;
	if (sc->sc_fixed_burst)
		val |= GMAC_DMA_SYSBUS_MODE_FB;
	val &= ~GMAC_DMA_SYSBUS_MODE_WR_OSR_LMT_MASK;
	val |= sc->sc_wr_osr_lmt << GMAC_DMA_SYSBUS_MODE_WR_OSR_LMT_SHIFT;
	val &= ~GMAC_DMA_SYSBUS_MODE_RD_OSR_LMT_MASK;
	val |= sc->sc_rd_osr_lmt << GMAC_DMA_SYSBUS_MODE_RD_OSR_LMT_SHIFT;

	if (!EQOS_HW_FEATURE_ADDR64_32BIT(sc)) {
		val |= GMAC_DMA_SYSBUS_MODE_EAME;
	}

	/* XXX */
	val |= GMAC_DMA_SYSBUS_MODE_BLEN16;
	val |= GMAC_DMA_SYSBUS_MODE_BLEN8;
	val |= GMAC_DMA_SYSBUS_MODE_BLEN4;

	WR4(sc, GMAC_DMA_SYSBUS_MODE, val);
}

static int
dwqe_setup_dma(struct dwqe_softc *sc, int qid)
{
	struct mbuf *m;
	int error, nsegs, i;

	/* Setup TX ring */
	error = bus_dmamap_create(sc->sc_dmat, TX_DESC_SIZE, 1, TX_DESC_SIZE,
	    DESC_BOUNDARY, BUS_DMA_WAITOK, &sc->sc_tx.desc_map);
	if (error) {
		return error;
	}
	error = bus_dmamem_alloc(sc->sc_dmat, TX_DESC_SIZE, DESC_ALIGN,
	    DESC_BOUNDARY, &sc->sc_tx.desc_dmaseg, 1, &nsegs, BUS_DMA_WAITOK);
	if (error) {
		return error;
	}
	error = bus_dmamem_map(sc->sc_dmat, &sc->sc_tx.desc_dmaseg, nsegs,
	    TX_DESC_SIZE, (void *)&sc->sc_tx.desc_ring, BUS_DMA_WAITOK);
	if (error) {
		return error;
	}
	error = bus_dmamap_load(sc->sc_dmat, sc->sc_tx.desc_map,
	    sc->sc_tx.desc_ring, TX_DESC_SIZE, NULL, BUS_DMA_WAITOK);
	if (error) {
		return error;
	}
	sc->sc_tx.desc_ring_paddr = sc->sc_tx.desc_map->dm_segs[0].ds_addr;

	memset(sc->sc_tx.desc_ring, 0, TX_DESC_SIZE);
	bus_dmamap_sync(sc->sc_dmat, sc->sc_tx.desc_map, 0, TX_DESC_SIZE,
	    BUS_DMASYNC_PREWRITE);

	sc->sc_tx.queued = TX_DESC_COUNT;
	for (i = 0; i < TX_DESC_COUNT; i++) {
		error = bus_dmamap_create(sc->sc_dmat, MCLBYTES,
		    TX_MAX_SEGS, MCLBYTES, 0, BUS_DMA_WAITOK,
		    &sc->sc_tx.buf_map[i].map);
		if (error != 0) {
			printf("%s: cannot create TX buffer map\n",
			    sc->sc_dev.dv_xname);
			return error;
		}
		dwqe_setup_txdesc(sc, i, 0, 0, 0, 0);
	}

	/* Setup RX ring */
	error = bus_dmamap_create(sc->sc_dmat, RX_DESC_SIZE, 1, RX_DESC_SIZE,
	    DESC_BOUNDARY, BUS_DMA_WAITOK, &sc->sc_rx.desc_map);
	if (error) {
		return error;
	}
	error = bus_dmamem_alloc(sc->sc_dmat, RX_DESC_SIZE, DESC_ALIGN,
	    DESC_BOUNDARY, &sc->sc_rx.desc_dmaseg, 1, &nsegs, BUS_DMA_WAITOK);
	if (error) {
		return error;
	}
	error = bus_dmamem_map(sc->sc_dmat, &sc->sc_rx.desc_dmaseg, nsegs,
	    RX_DESC_SIZE, (void *)&sc->sc_rx.desc_ring, BUS_DMA_WAITOK);
	if (error) {
		return error;
	}
	error = bus_dmamap_load(sc->sc_dmat, sc->sc_rx.desc_map,
	    sc->sc_rx.desc_ring, RX_DESC_SIZE, NULL, BUS_DMA_WAITOK);
	if (error) {
		return error;
	}
	sc->sc_rx.desc_ring_paddr = sc->sc_rx.desc_map->dm_segs[0].ds_addr;

	memset(sc->sc_rx.desc_ring, 0, RX_DESC_SIZE);

	for (i = 0; i < RX_DESC_COUNT; i++) {
		error = bus_dmamap_create(sc->sc_dmat, MCLBYTES,
		    RX_DESC_COUNT, MCLBYTES, 0, BUS_DMA_WAITOK,
		    &sc->sc_rx.buf_map[i].map);
		if (error != 0) {
			printf("%s: cannot create RX buffer map\n",
			    sc->sc_dev.dv_xname);
			return error;
		}
		if ((m = dwqe_alloc_mbufcl(sc)) == NULL) {
			printf("%s: cannot allocate RX mbuf\n",
			    sc->sc_dev.dv_xname);
			return ENOMEM;
		}
		error = dwqe_setup_rxbuf(sc, i, m);
		if (error != 0) {
			printf("%s: cannot create RX buffer\n",
			    sc->sc_dev.dv_xname);
			return error;
		}
	}
	bus_dmamap_sync(sc->sc_dmat, sc->sc_rx.desc_map,
	    0, sc->sc_rx.desc_map->dm_mapsize,
	    BUS_DMASYNC_PREWRITE);

#if 0
	printf("%s: TX ring @ 0x%lX, RX ring @ 0x%lX\n",
	    sc->sc_dev.dv_xname, sc->sc_tx.desc_ring_paddr,
	    sc->sc_rx.desc_ring_paddr);
#endif

	return 0;
}

int
dwqe_attach(struct dwqe_softc *sc)
{
	struct ifnet *ifp = &sc->sc_ac.ac_if;
	u_int userver, snpsver;
	int error;
	int n;

	const uint32_t ver = RD4(sc, GMAC_MAC_VERSION);
	userver = (ver & GMAC_MAC_VERSION_USERVER_MASK) >>
	    GMAC_MAC_VERSION_USERVER_SHIFT;
	snpsver = ver & GMAC_MAC_VERSION_SNPSVER_MASK;

	if (snpsver != 0x51) {
		printf(": EQOS version 0x%02xx not supported\n",
		    snpsver);
		return ENXIO;
	}

	if (sc->sc_csr_clock < 20000000) {
		printf(": CSR clock too low\n");
		return EINVAL;
	} else if (sc->sc_csr_clock < 35000000) {
		sc->sc_clock_range = GMAC_MAC_MDIO_ADDRESS_CR_20_35;
	} else if (sc->sc_csr_clock < 60000000) {
		sc->sc_clock_range = GMAC_MAC_MDIO_ADDRESS_CR_35_60;
	} else if (sc->sc_csr_clock < 100000000) {
		sc->sc_clock_range = GMAC_MAC_MDIO_ADDRESS_CR_60_100;
	} else if (sc->sc_csr_clock < 150000000) {
		sc->sc_clock_range = GMAC_MAC_MDIO_ADDRESS_CR_100_150;
	} else if (sc->sc_csr_clock < 250000000) {
		sc->sc_clock_range = GMAC_MAC_MDIO_ADDRESS_CR_150_250;
	} else if (sc->sc_csr_clock < 300000000) {
		sc->sc_clock_range = GMAC_MAC_MDIO_ADDRESS_CR_300_500;
	} else if (sc->sc_csr_clock < 800000000) {
		sc->sc_clock_range = GMAC_MAC_MDIO_ADDRESS_CR_500_800;
	} else {
		printf(": CSR clock too high\n");
		return EINVAL;
	}

	for (n = 0; n < 4; n++) {
		sc->sc_hw_feature[n] = RD4(sc, GMAC_MAC_HW_FEATURE(n));
	}

	printf(":");

	if (EQOS_HW_FEATURE_ADDR64_32BIT(sc)) {
#if 0
		bus_dma_tag_t ntag;

		error = bus_dmatag_subregion(sc->sc_dmat, 0, UINT32_MAX,
		    &ntag, 0);
		if (error) {
			printf("%s: failed to restrict DMA: %d\n",
			    sc->sc_dev.dv_xname, error);
			return error;
		}
		sc->sc_dmat = ntag;
#endif
		printf(" using 32-bit DMA,");
	}

	mtx_init(&sc->sc_lock, IPL_NET);
	mtx_init(&sc->sc_txlock, IPL_NET);
	timeout_set(&sc->sc_stat_ch, dwqe_tick, sc);

	dwqe_get_eaddr(sc, sc->sc_lladdr);
	printf(" address %s\n", ether_sprintf(sc->sc_lladdr));

	/* Soft reset EMAC core */
	error = dwqe_reset(sc);
	if (error != 0) {
		return error;
	}

	/* Configure AXI Bus mode parameters */
	dwqe_axi_configure(sc);

	/* Setup DMA descriptors */
	if (dwqe_setup_dma(sc, 0) != 0) {
		printf("%s: failed to setup DMA descriptors\n",
		    sc->sc_dev.dv_xname);
		return EINVAL;
	}

	ifp->if_softc = sc;
	ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
	ifp->if_ioctl = dwqe_ioctl;
	ifp->if_start = dwqe_start;
	ifq_set_maxlen(&ifp->if_snd, IFQ_MAXLEN);
	bcopy(sc->sc_dev.dv_xname, ifp->if_xname, IFNAMSIZ);

	ifp->if_capabilities = IFCAP_VLAN_MTU;

	sc->sc_mii.mii_ifp = ifp;
	sc->sc_mii.mii_readreg = dwqe_mii_readreg;
	sc->sc_mii.mii_writereg = dwqe_mii_writereg;
	sc->sc_mii.mii_statchg = dwqe_mii_statchg;

	ifmedia_init(&sc->sc_media, 0, dwqe_media_change, dwqe_media_status);

	mii_attach(&sc->sc_dev, &sc->sc_mii, 0xffffffff, sc->sc_phy_id,
	    (sc->sc_phy_id  == MII_PHY_ANY) ? 0 : MII_OFFSET_ANY, 0);
	if (LIST_FIRST(&sc->sc_mii.mii_phys) == NULL) {
		printf("%s: no PHY found!\n", sc->sc_dev.dv_xname);
		ifmedia_add(&sc->sc_media, IFM_ETHER|IFM_MANUAL, 0, NULL);
		ifmedia_set(&sc->sc_media, IFM_ETHER|IFM_MANUAL);
	} else
		ifmedia_set(&sc->sc_media, IFM_ETHER|IFM_AUTO);

	if_attach(ifp);
	ether_ifattach(ifp);

	return 0;
}
