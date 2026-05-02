// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2018 MediaTek Inc.
 */

#include <config.h>
#include <dm.h>
#include <button.h>
#include <env.h>
#include <init.h>
#include <mmc.h>
#include <part.h>
#include <asm/global_data.h>
#include <linux/delay.h>

#ifndef CONFIG_RESET_BUTTON_LABEL
#define CONFIG_RESET_BUTTON_LABEL "reset"
#endif

DECLARE_GLOBAL_DATA_PTR;

int board_init(void)
{
	/* address of boot parameters */
	gd->bd->bi_boot_params = CFG_SYS_SDRAM_BASE + 0x100;

	return 0;
}

#ifdef CONFIG_MMC
int mmc_get_boot_dev(void)
{
	int g_mmc_devid = -1;
	char *uflag = (char *)0x81DFFFF0;
	struct blk_desc *desc;

	if (blk_get_device_by_str("mmc", "1", &desc) < 0)
		return 0;

	if (strncmp(uflag,"eMMC",4)==0) {
		g_mmc_devid = 0;
		printf("Boot From Emmc(id:%d)\n\n", g_mmc_devid);
	} else {
		g_mmc_devid = 1;
		printf("Boot From SD(id:%d)\n\n", g_mmc_devid);
	}
	return g_mmc_devid;
}

int mmc_get_env_dev(void)
{
	struct udevice *dev;
	const char *mmcdev;

	switch (mmc_get_boot_dev()) {
	case 0:
		mmcdev = "mmc@11230000";
		break;
	case 1:
		mmcdev = "mmc@11240000";
		break;
	default:
		return -1;
	}

	if (uclass_get_device_by_name(UCLASS_MMC, mmcdev, &dev))
		return -1;

	return dev_seq(dev);
}
#endif

int board_late_init(void)
{
	struct udevice *dev;

	if (!button_get_by_label(CONFIG_RESET_BUTTON_LABEL, &dev)) {
		puts("reset button found\n");
#ifdef CONFIG_RESET_BUTTON_SETTLE_DELAY
		if (CONFIG_RESET_BUTTON_SETTLE_DELAY > 0) {
			button_get_state(dev);
			mdelay(CONFIG_RESET_BUTTON_SETTLE_DELAY);
		}
#endif
		if (button_get_state(dev) == BUTTON_ON) {
			puts("button pushed, resetting environment\n");
			gd->env_valid = ENV_INVALID;
		}
	}

	env_relocate();
	return 0;
}

int ft_system_setup(void *blob, struct bd_info *bd)
{
	const u32 *media_handle_p;
	int chosen, len, ret;
	const char *media;
	u32 media_handle;

#ifdef CONFIG_MMC
	switch (mmc_get_boot_dev()) {
	case 0:
		media = "rootdisk-emmc";
		break
		;;
	case 1:
		media = "rootdisk-sd";
		break
		;;
	}

	chosen = fdt_path_offset(blob, "/chosen");
	if (chosen <= 0)
		return 0;

	media_handle_p = fdt_getprop(blob, chosen, media, &len);
	if (media_handle_p <= 0 || len != 4)
		return 0;

	media_handle = *media_handle_p;
	ret = fdt_setprop(blob, chosen, "rootdisk", &media_handle, sizeof(media_handle));
	if (ret) {
		printf("cannot set media phandle %s as rootdisk /chosen node\n", media);
		return ret;
	}

	printf("set /chosen/rootdisk to bootrom media: %s (phandle 0x%08x)\n", media, fdt32_to_cpu(media_handle));
#endif

	return 0;
}
