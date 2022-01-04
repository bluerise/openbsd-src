/* $OpenBSD$ */
/* $NetBSD: dwc_eqos_var.h,v 1.1 2022/01/03 17:19:41 jmcneill Exp $ */

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

#ifndef _DWQE_VAR_H
#define _DWQE_VAR_H

#include <dev/ic/dwqereg.h>

#define	EQOS_DMA_DESC_COUNT	256

struct dwqe_bufmap {
	bus_dmamap_t		map;
	struct mbuf		*mbuf;
};

struct dwqe_ring {
	bus_dmamap_t		desc_map;
	bus_dma_segment_t	desc_dmaseg;
	struct dwqe_dma_desc	*desc_ring;
	bus_addr_t		desc_ring_paddr;
	struct dwqe_bufmap	buf_map[EQOS_DMA_DESC_COUNT];
	u_int			cur, next, queued;
};

struct dwqe_softc {
	struct device		sc_dev;
	bus_space_tag_t		sc_bst;
	bus_space_handle_t	sc_bsh;
	bus_dma_tag_t		sc_dmat;
	void			*sc_ih;
	int			sc_phy_id;
	uint32_t		sc_csr_clock;
	uint32_t		sc_clock_range;

	uint32_t		sc_hw_feature[4];

	struct arpcom		sc_ac;
#define sc_lladdr	sc_ac.ac_enaddr
	struct mii_data		sc_mii;
#define sc_media	sc_mii.mii_media
	struct timeout		sc_stat_ch;
	struct mutex		sc_lock;
	struct mutex		sc_txlock;

	struct dwqe_ring	sc_tx;
	struct dwqe_ring	sc_rx;

	int			sc_mixed_burst;
	int			sc_fixed_burst;
	int			sc_wr_osr_lmt;
	int			sc_rd_osr_lmt;
};

int	dwqe_attach(struct dwqe_softc *);
int	dwqe_intr(void *);

#endif /* !_DWQE_VAR_H */
