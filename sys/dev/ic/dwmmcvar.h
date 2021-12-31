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

struct dwmmc_softc {
	struct device		sc_dev;
	bus_space_tag_t		sc_iot;
	bus_space_handle_t	sc_ioh;
	bus_size_t		sc_size;
	bus_dma_tag_t		sc_dmat;
	bus_dmamap_t		sc_dmap;
	int			sc_node;

	void			*sc_ih;

	uint32_t		sc_caps;
	uint32_t		sc_clkbase;
	uint32_t		sc_fifo_depth;
	uint32_t		sc_fifo_width;
	void (*sc_read_data)(struct dwmmc_softc *, u_char *, int);
	void (*sc_write_data)(struct dwmmc_softc *, u_char *, int);
	int (*sc_card_detect)(struct dwmmc_softc *);
	void (*sc_pwrseq_pre)(uint32_t);
	void (*sc_pwrseq_post)(uint32_t);
	int			sc_blklen;

	bus_dmamap_t		sc_desc_map;
	bus_dma_segment_t	sc_desc_segs[1];
	caddr_t			sc_desc;
	int			sc_dma64;
	int			sc_dmamode;
	uint32_t		sc_idsts;

	uint32_t		sc_gpio[4];
	int			sc_sdio_irq;
	uint32_t		sc_pwrseq;
	uint32_t		sc_vdd;

	struct device		*sc_sdmmc;
};
