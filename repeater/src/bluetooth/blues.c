/* main.c - Application main entry point */

/*
 * Copyright (c) 2015-2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <zephyr/types.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <misc/printk.h>
#include <misc/byteorder.h>
#include <zephyr.h>
#include <shell/shell.h>


#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/conn.h>
#include <bluetooth/uuid.h>
#include <bluetooth/gatt.h>

#include <i2c.h>

#include <uki_utlis.h>
#include "blues.h"
#include "throughput.h"
#include "wifi_manager_service.h"

#define DEVICE_NAME		CONFIG_BT_DEVICE_NAME
#define DEVICE_NAME_LEN		(sizeof(DEVICE_NAME) - 1)

blues_config_t  blues_config;

static const struct bt_data ad[] = {
	BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR)),
};

static struct bt_data sd[] = {
	BT_DATA(BT_DATA_NAME_COMPLETE, DEVICE_NAME, DEVICE_NAME_LEN),
};

extern void get_mac_address(char *addr);
char bt_name[32] = {0};

static void change_device_name(void)
{
	uint8_t addr[6];
	char mac[10] = {0};
	int i;
	char hex_str[]= "0123456789ABCDEF";

	get_mac_address(addr);
	strcat(bt_name, DEVICE_NAME);
	strcat(bt_name, "_");

	for (i = 0; i < 2; i++) {
		mac[(i * 2) + 0] = hex_str[(addr[1-i] >> 4) & 0x0F];
		mac[(i * 2) + 1] = hex_str[(addr[1-i]     ) & 0x0F];
	}

	strcat(bt_name, mac);

	BTI("bt_name = %s,len = %d\n", bt_name,strlen(bt_name));
	sd[0].data = bt_name;
	sd[0].data_len = strlen(bt_name);
}

static void bt_ready(int err)
{
	if (err) {
		printk("Bluetooth init failed (err %d)\n", err);
		return;
	}

	printk("Bluetooth initialized\n");

	throughput_init();
#ifdef CONFIG_WIFIMGR
	/*wifi_manager_service_init();*/
#endif
	change_device_name();

	err = bt_le_adv_start(BT_LE_ADV_CONN, ad, ARRAY_SIZE(ad),
			      sd, ARRAY_SIZE(sd));
	if (err) {
		printk("Advertising failed to start (err %d)\n", err);
		return;
	}
	printk("Advertising successfully started\n");
}

static int cmd_init(const struct shell *shell, size_t argc, char *argv[])
{
	int err;

	err = bt_enable(bt_ready);
	if (err) {
		printk("Bluetooth init failed (err %d)\n", err);
	}
	return err;
}

static int cmd_vlog(const struct shell *shell, size_t argc, char *argv[])
{
	if (argc < 2) {
		printk("%s, argc: %d", __func__, argc);
		return -1;
	}
	int level = strtoul(argv[1], NULL, 0);
	set_vendor_log_level(level);
	return 0;
}

static int cmd_slog(const struct shell *shell, size_t argc, char *argv[])
{
	if (argc < 2) {
		printk("%s, argc: %d", __func__, argc);
		return -1;
	}
	int level = strtoul(argv[1], NULL, 0);
	set_stack_log_level(level);
	return 0;
}

void blues_init(void)
{
	BTD("%s\n", __func__);
	cmd_init(0 ,0, NULL);
}

static int cmd_btmac(const struct shell *shell, size_t argc, char *argv[])
{
    uint8_t addr[6];
    get_mac_address(addr);
    BTI("Current bt addr = %02X:%02X:%02X:%02X:%02X:%02X\n", addr[5], addr[4], addr[3], addr[2], addr[1], addr[0]);
    return 0;
}


static int cmd_test(const struct shell *shell, size_t argc, char *argv[])
{
	struct device *i2c = device_get_binding("uwp56xx_i2c");

	u8_t data[] = {0x55};
	struct i2c_msg msgs[1];


	/* Setup I2C messages */

	/* Send the address to read */
	msgs[0].buf = data;
	msgs[0].len = sizeof(data);
	msgs[0].flags = I2C_MSG_WRITE;

	return i2c_transfer(i2c, &msgs[0], 1, 0x34);
}



SHELL_CREATE_STATIC_SUBCMD_SET(blues_cmds) {
	SHELL_CMD(init, NULL, "void", cmd_init),
	SHELL_CMD(vlog, NULL, "void", cmd_vlog),
	SHELL_CMD(slog, NULL, "void", cmd_slog),
	SHELL_CMD(test, NULL, "void", cmd_test),
	SHELL_CMD(btmac, NULL, "void", cmd_btmac),
	SHELL_SUBCMD_SET_END
};

//SHELL_REGISTER("blues", blues_commands);
SHELL_CMD_REGISTER(blues, &blues_cmds, "Function blues commands", NULL);

