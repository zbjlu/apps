/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include "logging/log.h"
LOG_MODULE_REGISTER(REPEATER);

#include <zephyr.h>
#include <misc/printk.h>

extern void blues_init(void);
extern void wifi_repeater(void);
void main(void)
{
	LOG_INF("   [UNISOC Wi-Fi Repeater]");

#ifdef CONFIG_BT_UWP5661
	blues_init();
#endif
#ifdef CONFIG_WIFIMGR
	wifi_repeater();
#endif
}
