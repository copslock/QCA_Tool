/*
 * Copyright (c) 2017-2020, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#include <common.h>
#include <net.h>
#include <asm-generic/errno.h>
#include <asm/io.h>
#include <malloc.h>
#include <phy.h>
#include <net.h>
#include <miiphy.h>
#include "ipq5018_uniphy.h"
#include "ipq_phy.h"

static int ppe_uniphy_calibration(void)
{
	int retries = 100, calibration_done = 0;
	uint32_t reg_value = 0;

	while(calibration_done != UNIPHY_CALIBRATION_DONE) {
		mdelay(1);
		if (retries-- == 0) {
			printf("uniphy callibration time out!\n");
			return -1;
		}
		reg_value = readl(PPE_UNIPHY_BASE + PPE_UNIPHY_OFFSET_CALIB_4);
		calibration_done = (reg_value >> 0x7) & 0x1;
	}

	return 0;
}

static void ppe_gcc_uniphy_soft_reset(void)
{
	uint32_t reg_value;

	reg_value = readl(GCC_UNIPHY0_MISC);

	reg_value |= GCC_UNIPHY_SGMII_SOFT_RESET;

	writel(reg_value, GCC_UNIPHY0_MISC);

	udelay(500);

	reg_value &= ~GCC_UNIPHY_SGMII_SOFT_RESET;

	writel(reg_value, GCC_UNIPHY0_MISC);
}

static void ppe_uniphy_sgmii_mode_set(uint32_t mode)
{
	writel(UNIPHY_MISC2_REG_SGMII_MODE,
		PPE_UNIPHY_BASE + UNIPHY_MISC2_REG_OFFSET);

	writel(UNIPHY_PLL_RESET_REG_VALUE, PPE_UNIPHY_BASE +
		UNIPHY_PLL_RESET_REG_OFFSET);
	mdelay(500);
	writel(UNIPHY_PLL_RESET_REG_DEFAULT_VALUE, PPE_UNIPHY_BASE +
		UNIPHY_PLL_RESET_REG_OFFSET);
	mdelay(500);

	writel(0x0, GCC_UNIPHY_RX_CBCR);
	writel(0x0, GCC_UNIPHY_TX_CBCR);
	writel(0x0, GCC_GMAC1_RX_CBCR);
	writel(0x0, GCC_GMAC1_TX_CBCR);

	switch (mode) {
		case PORT_WRAPPER_SGMII_FIBER:
			writel(UNIPHY_SG_MODE, PPE_UNIPHY_BASE + PPE_UNIPHY_MODE_CONTROL);
			break;

		case PORT_WRAPPER_SGMII0_RGMII4:
		case PORT_WRAPPER_SGMII1_RGMII4:
		case PORT_WRAPPER_SGMII4_RGMII4:
			writel((UNIPHY_SG_MODE | UNIPHY_PSGMII_MAC_MODE),
					PPE_UNIPHY_BASE + PPE_UNIPHY_MODE_CONTROL);
			break;

		case PORT_WRAPPER_SGMII_PLUS:
			writel((UNIPHY_SG_PLUS_MODE | UNIPHY_PSGMII_MAC_MODE),
					PPE_UNIPHY_BASE + PPE_UNIPHY_MODE_CONTROL);
			break;

		default:
			printf("SGMII Config. wrongly");
			break;
	}

	ppe_gcc_uniphy_soft_reset();

	writel(0x1, GCC_UNIPHY_RX_CBCR);
	writel(0x1, GCC_UNIPHY_TX_CBCR);
	writel(0x1, GCC_GMAC1_RX_CBCR);
	writel(0x1, GCC_GMAC1_TX_CBCR);

	ppe_uniphy_calibration();
}

void ppe_uniphy_mode_set(uint32_t mode)
{
	/*
	 * SGMII and SHMII plus confugure in same function
	 */
	ppe_uniphy_sgmii_mode_set(mode);
}

