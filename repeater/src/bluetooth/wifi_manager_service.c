#include <zephyr/types.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <misc/printk.h>
#include <misc/byteorder.h>
#include <zephyr.h>


#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/conn.h>
#include <bluetooth/uuid.h>
#include <bluetooth/gatt.h>

#include "host/hci_core.h"

#include "wifi_manager_service.h"
#include <uki_utlis.h>

#define UINT32_TO_STREAM(p, u32) {*(p)++ = (uint8_t)(u32); *(p)++ = (uint8_t)((u32) >> 8); *(p)++ = (uint8_t)((u32) >> 16); *(p)++ = (uint8_t)((u32) >> 24);}
#define UINT24_TO_STREAM(p, u24) {*(p)++ = (uint8_t)(u24); *(p)++ = (uint8_t)((u24) >> 8); *(p)++ = (uint8_t)((u24) >> 16);}
#define UINT16_TO_STREAM(p, u16) {*(p)++ = (uint8_t)(u16); *(p)++ = (uint8_t)((u16) >> 8);}
#define UINT8_TO_STREAM(p, u8)   {*(p)++ = (uint8_t)(u8);}

#define GET_STATUS_TIMEOUT  K_SECONDS(5)
#define SCAN_TIMEOUT        K_SECONDS(10)
#define SCAN_NUM    1
#define HCI_OP_ENABLE_CMD 0xFCA1


static struct bt_uuid_128 wifimgr_service_uuid = BT_UUID_INIT_128(
	0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
	0x00, 0x10, 0x00, 0x00, 0xa5, 0xff, 0x00, 0x00);

static struct bt_uuid_128 wifimgr_char_uuid = BT_UUID_INIT_128(
	0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
	0x00, 0x10, 0x00, 0x00, 0xa6, 0xff, 0x00, 0x00);


static u8_t wifimgr_long_value[256] = {0};

static struct bt_gatt_ccc_cfg wifimgr_ccc_cfg[BT_GATT_CCC_MAX] = {};
static u8_t wifimgr_is_enabled;

static struct k_sem get_status_sem;

static struct wifi_status wifimgr_sta_status;
static struct wifi_status wifimgr_ap_status;

static wifi_config_type wifimgr_sta_conf;
static wifi_config_type wifimgr_ap_conf;

static wifi_status_type cur_wifi_status = {};

static u8_t wait_disconnect_done = 0;
static int disconnect_result = -1;

static struct k_sem disconnect_sem;

struct wifimgr_ctrl_cbs *get_wifimgr_cbs(void);

extern int get_disable_buf(void *buf);
extern void sprd_bt_irq_disable(void);

static void wifimgr_ctrl_iface_notify_connect(union wifi_notifier_val val)
{
	int result = val.val_char;
	BTD("%s ,result = %d\n", __func__, result);
	char data[2] = {0};
	u8_t res_result = RESULT_SUCCESS;

	if (0 == result) {
		BTD("%s, connect succesfully\n", __func__);
		res_result = RESULT_SUCCESS;
	} else {
		BTD("%s, connect failed\n", __func__);
		res_result = RESULT_FAIL;
	}

	data[0] = RESULT_SET_CONF_AND_CONNECT;
	data[1] = res_result;

	BTD("%s  enter wifi_manager_notify", __func__);
	wifi_manager_notify(data, sizeof(data));
}

static void wifimgr_ctrl_iface_notify_disconnect(union wifi_notifier_val val)
{
	int reason = val.val_char;
	BTD("%s ,reason = %d\n", __func__,reason);
	char data[2] = {0};
	u8_t res_result = RESULT_SUCCESS;

	data[0] = RESULT_DISCONNECT;
	data[1] = res_result;

	if (1 == wait_disconnect_done) {
		disconnect_result = 0;
		k_sem_give(&disconnect_sem);
	} else {
		wifi_manager_notify(data, sizeof(data));
	}
}

static void wifimgr_ctrl_iface_notify_station(int status, char *mac)
{
	BTD("%s\n", __func__);

	u8_t res_result = RESULT_SUCCESS;
	char data[20] = {0};
	u8_t data_len = 0;

	if (!mac) {
		BTD("mac = NULL\n");
		res_result = RESULT_FAIL;
		data_len = 2;
		goto error;
	}

	BTD("status : %d, mac : %02x:%02x:%02x:%02x:%02x:%02x\n", status, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	data[2] = status;
	memcpy(&data[3], mac, BSSID_LEN);
	res_result = RESULT_SUCCESS;
	data_len = 9;

error:
	data[0] = RESULT_STATION_REPORT;
	data[1] = res_result;

	wifi_manager_notify(data, data_len);
}

static void wifimgr_ctrl_iface_notify_new_station(union wifi_notifier_val val)
{
	BTD("%s\n", __func__);

	int status = 0x01;
	char *mac = (char *)(val.val_ptr);
	wifimgr_ctrl_iface_notify_station(status, mac);
}

static void wifimgr_ctrl_iface_notify_station_leave(union wifi_notifier_val val)
{
	BTD("%s\n", __func__);

	int status = 0x00;
	char *mac = (char *)(val.val_ptr);
	wifimgr_ctrl_iface_notify_station(status, mac);
}

static void wifimgr_ctrl_iface_notify_scan_res(wifi_scan_res_type *scan_res)
{
	BTD("%s\n", __func__);
	u8_t res_result = RESULT_SUCCESS;
	char data[255] = {0};
	u16_t data_len = 0;
	u16_t ssid_len = 0;
	u16_t bssid_len = 0;

	char *p = NULL;
	int i;

	if (scan_res->ssid) {
		ssid_len = strlen(scan_res->ssid);
		BTD("ssid = %s\n", scan_res->ssid);
	} else {
		BTD("ssid = NULL\n");
		ssid_len = 0;
	}

	if (scan_res->bssid) {
		bssid_len = BSSID_LEN;
		BTD("bssid = %02x:%02x:%02x:%02x:%02x:%02x\n", scan_res->bssid[0], scan_res->bssid[1], scan_res->bssid[2], scan_res->bssid[3], scan_res->bssid[4], scan_res->bssid[5]);
	} else {
		BTD("%s ,bssid = NULL\n", __func__);
		bssid_len = 0;
	}

	if ((scan_res->security>=1) && (scan_res->security<=3)) {
		BTD("security:%u\n", scan_res->security);
	} else {
		BTE("%s ,security err = %d\n", __func__, scan_res->security);
	}

	BTD("band:%d, channel:%d, rssi:%d, security:%d\n", scan_res->band, scan_res->channel, scan_res->rssi, scan_res->security);

	if ((ssid_len > MAX_SSID_LEN)
		|| (bssid_len > BSSID_LEN)) {
		res_result = RESULT_FAIL;
		data[0] = RESULT_SCAN_DONE;
		data[1] = res_result;

		BTD("%s ,len error\n", __func__);
		BTD("%s  enter wifi_manager_notify", __func__);
		wifi_manager_notify(data, 2);
		return;
	}

	data_len = 4 + 1 + ssid_len + bssid_len;
	BTD("data_len:%u, ssid_len:%u, bssid_len:%u\n", data_len, ssid_len, bssid_len);
	res_result = RESULT_SUCCESS;

	p = data;
	UINT8_TO_STREAM(p, RESULT_SCAN_REPORT);
	UINT8_TO_STREAM(p, res_result);
	UINT16_TO_STREAM(p, data_len);

	UINT16_TO_STREAM(p, ssid_len);
	for (i = 0; i < ssid_len; i++) {
		UINT8_TO_STREAM(p, scan_res->ssid[i]);
	}

	UINT16_TO_STREAM(p, bssid_len);
	for (i = 0; i < bssid_len; i++) {
		UINT8_TO_STREAM(p, scan_res->bssid[i]);
	}

	UINT8_TO_STREAM(p, scan_res->security);

	BTD("%s  enter wifi_manager_notify", __func__);
	wifi_manager_notify(data, data_len + 4);
}

static void wifimgr_ccc_cfg_changed(const struct bt_gatt_attr *attr, u16_t value)
{
	BTD("%s\n", __func__);
	wifimgr_is_enabled = (value == BT_GATT_CCC_NOTIFY) ? 1 : 0;
}

static void wifimgr_update_sta_status(void)
{
	BTD("%s, status:%d, signal:%d\n", __func__, wifimgr_sta_status.state, wifimgr_sta_status.u.sta.host_rssi);
	BTD("%s, mac = %02X:%02X:%02X:%02X:%02X:%02X\n", __func__, wifimgr_sta_status.own_mac[0],wifimgr_sta_status.own_mac[1],wifimgr_sta_status.own_mac[2],wifimgr_sta_status.own_mac[3],wifimgr_sta_status.own_mac[4],wifimgr_sta_status.own_mac[5]);

	cur_wifi_status.sta_status = wifimgr_sta_status.state;
	memcpy(cur_wifi_status.sta_mac, wifimgr_sta_status.own_mac, 6);

	if (WIFI_STATE_STA_CONNECTED == wifimgr_sta_status.state) {
		if (wifimgr_sta_status.u.sta.host_bssid) {
			memset(cur_wifi_status.u.sta.host_bssid, 0, sizeof(cur_wifi_status.u.sta.host_bssid));
			memcpy(cur_wifi_status.u.sta.host_bssid, wifimgr_sta_status.u.sta.host_bssid, BSSID_LEN);
			cur_wifi_status.u.sta.h_bssid_len = BSSID_LEN;
			BTD("%s, host_bssid = %02X:%02X:%02X:%02X:%02X:%02X\n", __func__,wifimgr_sta_status.u.sta.host_bssid[0],wifimgr_sta_status.u.sta.host_bssid[1],wifimgr_sta_status.u.sta.host_bssid[2],wifimgr_sta_status.u.sta.host_bssid[3],wifimgr_sta_status.u.sta.host_bssid[4],wifimgr_sta_status.u.sta.host_bssid[5]);
		} else {
			cur_wifi_status.u.sta.h_bssid_len = 0;
			BTD("%s ,host_bssid = NULL\n", __func__);
		}
	} else {
		cur_wifi_status.u.sta.h_ssid_len = 0;
		cur_wifi_status.u.sta.h_bssid_len = 0;
	}

	k_sem_give(&get_status_sem);
}

static void wifimgr_update_ap_status(void)
{
	BTD("%s, status:%d, nr_sta:%d\n", __func__,wifimgr_ap_status.state, wifimgr_ap_status.u.ap.nr_sta);
	BTD("%s, mac = %02X:%02X:%02X:%02X:%02X:%02X\n", __func__,wifimgr_ap_status.own_mac[0],wifimgr_ap_status.own_mac[1],wifimgr_ap_status.own_mac[2],wifimgr_ap_status.own_mac[3],wifimgr_ap_status.own_mac[4],wifimgr_ap_status.own_mac[5]);

	cur_wifi_status.ap_status = wifimgr_ap_status.state;
	memcpy(cur_wifi_status.ap_mac, wifimgr_ap_status.own_mac, 6);

	if (WIFI_STATE_AP_STARTED == wifimgr_ap_status.state) {
		memset(cur_wifi_status.u.ap.sta_mac_addrs,0,sizeof(cur_wifi_status.u.ap.sta_mac_addrs));
		cur_wifi_status.u.ap.sta_nr = (wifimgr_ap_status.u.ap.nr_sta > WIFI_MAX_STA_NR ? WIFI_MAX_STA_NR : wifimgr_ap_status.u.ap.nr_sta);
		memcpy(&cur_wifi_status.u.ap.sta_mac_addrs[0][0], wifimgr_ap_status.u.ap.sta_mac_addrs, BSSID_LEN * cur_wifi_status.u.ap.sta_nr);
	} else {
		cur_wifi_status.u.ap.sta_nr = 0;
	}

	k_sem_give(&get_status_sem);
}

static void wifimgr_update_cur_wifi_status(enum wifimgr_iface_type wifi_iface_type)
{
	BTD("%s, wifi_iface_type = %u\n", __func__, wifi_iface_type);

	if (wifi_iface_type == WIFIMGR_IFACE_STA) {
		wifimgr_update_sta_status();
    } else if (wifi_iface_type == WIFIMGR_IFACE_AP) {
		wifimgr_update_ap_status();
    } else {
		BTD("%s, wifi_iface_type error :%u\n", __func__, wifi_iface_type);
	}

	BTD("%s, cur_wifi_status updated successfully!\n", __func__);
}

int wifimgr_check_wifi_status(enum wifimgr_iface_type wifi_iface_type)
{
	BTD("%s, wifi_iface_type = %u\n", __func__, wifi_iface_type);
	int ret = -1;

	if (wifi_iface_type == WIFIMGR_IFACE_STA) {
    	ret = wifi_sta_get_status(&wifimgr_sta_status);
    } else if (wifi_iface_type == WIFIMGR_IFACE_AP) {
		ret = wifi_ap_get_status(&wifimgr_ap_status);
    } else {
		BTD("%s, wifi_iface_type error :%u\n", __func__, wifi_iface_type);
	}

	if (0 != ret) {
		BTD("%s, get_status fail,err = %d\n", __func__,ret);
		goto error;
	} else {
		wifimgr_update_cur_wifi_status(wifi_iface_type);
		if (0 != k_sem_take(&get_status_sem, GET_STATUS_TIMEOUT)) {
			BTD("%s, take get_status_sem fail\n", __func__);
			ret = -1;
		} else {
			BTD("%s, get_status success\n", __func__);
			ret = 0;
		}
	}

error:
	return ret;
}

static u8_t wifimgr_set_conf(const void *buf)
{
	BTD("%s\n", __func__);
	wifi_config_type conf;
	const u8_t *p = (u8_t *)buf;
	u16_t vlen = 0;
	int ret = -1;
	u8_t res_result = RESULT_SUCCESS;
	u16_t bssid_len = 0;
	u16_t pwd_len = 0;
	u16_t ssid_len = 0;

	memset(&conf, 0, sizeof(conf));
	vlen = sys_get_le16(p);
	p += 2;
	BTD("%s, AllDateLen = 0x%x\n", __func__, vlen);

	ssid_len = sys_get_le16(p);
	p += 2;
	BTD("%s, SsidDataLen = 0x%x\n", __func__, ssid_len);

	memcpy(conf.wifi_conf.ssid,p,ssid_len);
	p+=ssid_len;
	BTD("%s, ssid = %s\n", __func__, conf.wifi_conf.ssid);

	bssid_len = sys_get_le16(p);
	p += 2;
	BTD("%s, bSsidDataLen = 0x%x\n", __func__, bssid_len);

	memcpy(conf.wifi_conf.bssid,p,bssid_len);
	p+=bssid_len;
	for (int i = 0; i < bssid_len; i++) {
		BTD("bssid = 0x%02x\n", conf.wifi_conf.bssid[i]);
	}

	pwd_len = sys_get_le16(p);
	p += 2;
	BTD("%s, PsdDataLen = 0x%x\n", __func__, pwd_len);

	memcpy(conf.wifi_conf.passphrase,p,pwd_len);
	p+=pwd_len;
	BTD("%s, passwd = %s\n", __func__, conf.wifi_conf.passphrase);
	strcpy(cur_wifi_status.passwd, conf.wifi_conf.passphrase);

	conf.wifi_conf.security = p[0];
	p += 1;
	if ((conf.wifi_conf.security >= 1) && (conf.wifi_conf.security <= 3)) {
		BTD("security:%u\n", conf.wifi_conf.security);
	} else {
		BTE("%s ,security err = %u\n", __func__, conf.wifi_conf.security);
		res_result = RESULT_FAIL;
	}

	conf.wifi_conf.autorun = (int)sys_get_le32(p);
	p += 4;
	BTD("%s, conf.wifi_conf.autorun = %d\n", __func__, conf.wifi_conf.autorun);

	conf.wifi_type = WIFIMGR_IFACE_STA;
	BTD("%s, conf.wifi_type = %d\n", __func__, conf.wifi_type);

	ret = wifi_sta_set_conf(&(conf.wifi_conf));
	if (0 != ret) {
		BTD("%s, wifi_sta_set_conf fail,error = %d\n", __func__,ret);
		res_result = RESULT_FAIL;
		goto error;
	}

	ret = wifimgr_check_wifi_status(conf.wifi_type);
	if (0 == ret) {
		switch(cur_wifi_status.sta_status){
			case WIFI_STATE_STA_UNAVAIL:
				if (0 != wifimgr_do_open(conf.wifi_type)) {
					BTD("%s, open fail\n", __func__);
					res_result = RESULT_FAIL;
					goto error;
				}
			break;
			case WIFI_STATE_STA_READY:
			break;
			case WIFI_STATE_STA_CONNECTED:
				if (0 != wifimgr_do_disconnect(1)) {
					BTD("%s, STATUS_CONNECTED and do_disconnect fail\n", __func__);
					res_result = RESULT_FAIL;
					goto error;
				}
			break;
			case WIFI_STATE_STA_SCANNING:
			case WIFI_STATE_STA_CONNECTING:
			case WIFI_STATE_STA_DISCONNECTING:
				BTD("%s,status = %d ,wifi is busy\n", __func__, cur_wifi_status.sta_status);
				res_result = RESULT_FAIL;
				goto error;
			break;
			case WIFI_STATE_STA_RTTING:
				BTD("%s,status = %d ,wifi is for rtt!\n", __func__, cur_wifi_status.sta_status);
				res_result = RESULT_FAIL;
				goto error;
			break;

			default:
				BTD("%s,status = %d not found\n", __func__, cur_wifi_status.sta_status);
				res_result = RESULT_FAIL;
				goto error;
			break;
		}
	} else {
		res_result = RESULT_FAIL;
		goto error;
	}

error:
	return res_result;
}

void wifimgr_set_conf_and_connect(const void *buf)
{
	char data[2] = {0};
	u8_t res_result = RESULT_SUCCESS;

	if (RESULT_SUCCESS != wifimgr_set_conf(buf)) {
		BTE("%s, wifimgr_set_conf fail\n", __func__);
		res_result = RESULT_FAIL;
		goto error;
	}

	if (RESULT_SUCCESS != wifimgr_do_connect()) {
		BTD("%s, connect fail\n", __func__);
		res_result = RESULT_FAIL;
	} else {
		BTD("%s, connect success\n", __func__);
		return;
	}

error:
	data[0] = RESULT_SET_CONF_AND_CONNECT;
	data[1] = res_result;

	BTD("%s  enter wifi_manager_notify", __func__);
	wifi_manager_notify(data, sizeof(data));
}

void wifimgr_set_conf_and_interval(const void *buf)
{
	char data[2] = {0};
	u8_t res_result = RESULT_SUCCESS;

	if (RESULT_SUCCESS != wifimgr_set_conf(buf)) {
		BTE("%s, wifimgr_set_conf fail\n", __func__);
		res_result = RESULT_FAIL;
	}

	data[0] = RESULT_SET_CONF_AND_INTERVAL;
	data[1] = res_result;

	BTD("%s  enter wifi_manager_notify", __func__);
	wifi_manager_notify(data, sizeof(data));
}

static void wifimgr_ctrl_iface_get_sta_conf(void)
{
	BTD("%s\n", __func__);
	u8_t res_result = RESULT_SUCCESS;
	char data[255] = {0};
	u16_t data_len = 0;
	u16_t ssid_len = 0;
	u16_t bssid_len = 0;
	u16_t passwd_len = 0;
	char *p = NULL;
	int i;

	if (wifimgr_sta_conf.wifi_conf.ssid) {
		ssid_len = strlen(wifimgr_sta_conf.wifi_conf.ssid);
		BTD("%s ,ssid = %s\n", __func__,wifimgr_sta_conf.wifi_conf.ssid);
	} else {
		BTD("%s ,ssid = NULL\n", __func__);
		ssid_len = 0;
	}

	if (wifimgr_sta_conf.wifi_conf.passphrase) {
		BTD("%s ,pwd = %s\n", __func__,wifimgr_sta_conf.wifi_conf.passphrase);
		passwd_len = strlen(wifimgr_sta_conf.wifi_conf.passphrase);
	} else {
		BTD("%s ,pwd = NULL\n", __func__);
		passwd_len = 0;
	}

	if (wifimgr_sta_conf.wifi_conf.bssid) {
		bssid_len = BSSID_LEN;
		for (i = 0; i < bssid_len; i++) {
			BTD("bssid = 0x%02x\n", wifimgr_sta_conf.wifi_conf.bssid[i]);
		}
	} else {
		BTD("%s ,bssid = NULL\n", __func__);
		bssid_len = 0;
	}

	BTD("%s, band:%d, channel:%d security:%u, autorun:%d\n", __func__,wifimgr_sta_conf.wifi_conf.band,wifimgr_sta_conf.wifi_conf.channel,wifimgr_sta_conf.wifi_conf.security,wifimgr_sta_conf.wifi_conf.autorun);

	if ((ssid_len > MAX_SSID_LEN)
		|| (bssid_len > BSSID_LEN)
		|| (passwd_len > MAX_PSWD_LEN)) {
		res_result = RESULT_FAIL;
		data[0] = RESULT_GET_CONF;
		data[1] = res_result;

		BTD("%s ,len error\n", __func__);
		BTD("%s  enter wifi_manager_notify", __func__);
		wifi_manager_notify(data, 2);
		return;
	}

	data_len = 1 + 6 + 7 + ssid_len + bssid_len +passwd_len;
	res_result = RESULT_SUCCESS;

	p = data;
	UINT8_TO_STREAM(p, RESULT_GET_CONF);
	UINT8_TO_STREAM(p, res_result);
	UINT8_TO_STREAM(p, wifimgr_sta_conf.wifi_type);
	UINT16_TO_STREAM(p, data_len);

	UINT16_TO_STREAM(p, ssid_len);
	for (i = 0; i < ssid_len; i++) {
		UINT8_TO_STREAM(p, wifimgr_sta_conf.wifi_conf.ssid[i]);
	}

	UINT16_TO_STREAM(p, bssid_len);
	for (i = 0; i < bssid_len; i++) {
		UINT8_TO_STREAM(p, wifimgr_sta_conf.wifi_conf.bssid[i]);
	}

	UINT16_TO_STREAM(p, passwd_len);
	for (i = 0; i < passwd_len; i++) {
		UINT8_TO_STREAM(p, wifimgr_sta_conf.wifi_conf.passphrase[i]);
	}

	UINT8_TO_STREAM(p, wifimgr_sta_conf.wifi_conf.band);
	UINT8_TO_STREAM(p, wifimgr_sta_conf.wifi_conf.channel);
	UINT8_TO_STREAM(p, wifimgr_sta_conf.wifi_conf.security);
	UINT32_TO_STREAM(p, wifimgr_sta_conf.wifi_conf.autorun);

	BTD("%s  enter wifi_manager_notify", __func__);
	wifi_manager_notify(data, data_len + 4);
}

static void wifimgr_ctrl_iface_get_ap_conf(void)
{
	BTD("%s\n", __func__);
	u8_t res_result = RESULT_SUCCESS;
	char data[255] = {0};
	u16_t data_len = 0;
	u16_t ssid_len = 0;
	u16_t passwd_len = 0;
	char *p = NULL;
	int i;

	if (wifimgr_ap_conf.wifi_conf.ssid) {
		ssid_len = strlen(wifimgr_ap_conf.wifi_conf.ssid);
		BTD("%s ,ssid = %s\n", __func__,wifimgr_ap_conf.wifi_conf.ssid);
	} else {
		BTD("%s ,ssid = NULL\n", __func__);
		ssid_len = 0;
	}

	if (wifimgr_ap_conf.wifi_conf.passphrase) {
		BTD("%s ,pwd = %s\n", __func__,wifimgr_ap_conf.wifi_conf.passphrase);
		passwd_len = strlen(wifimgr_ap_conf.wifi_conf.passphrase);
	} else {
		BTD("%s ,pwd = NULL\n", __func__);
		passwd_len = 0;
	}

	BTD("%s, band:%d, channel:%d, ch_width:%d, security:%u, autorun:%d\n", __func__,wifimgr_ap_conf.wifi_conf.band,wifimgr_ap_conf.wifi_conf.channel,wifimgr_ap_conf.wifi_conf.ch_width,wifimgr_ap_conf.wifi_conf.security,wifimgr_ap_conf.wifi_conf.autorun);

	if ((ssid_len > MAX_SSID_LEN) || (passwd_len > MAX_PSWD_LEN)) {
		res_result = RESULT_FAIL;
		data[0] = RESULT_GET_CONF;
		data[1] = res_result;

		BTD("%s ,len error\n", __func__);
		BTD("%s  enter wifi_manager_notify", __func__);
		wifi_manager_notify(data, 2);
		return;
	}

	data_len = 1 + 4 + 7 + ssid_len + passwd_len;
	res_result = RESULT_SUCCESS;

	p = data;
	UINT8_TO_STREAM(p, RESULT_GET_CONF);
	UINT8_TO_STREAM(p, res_result);
	UINT8_TO_STREAM(p, wifimgr_ap_conf.wifi_type);
	UINT16_TO_STREAM(p, data_len);

	UINT16_TO_STREAM(p, ssid_len);
	for (i = 0; i < ssid_len; i++) {
		UINT8_TO_STREAM(p, wifimgr_ap_conf.wifi_conf.ssid[i]);
	}

	UINT16_TO_STREAM(p, passwd_len);
	for (i = 0; i < passwd_len; i++) {
		UINT8_TO_STREAM(p, wifimgr_ap_conf.wifi_conf.passphrase[i]);
	}

	UINT8_TO_STREAM(p, wifimgr_ap_conf.wifi_conf.band);
	UINT8_TO_STREAM(p, wifimgr_ap_conf.wifi_conf.channel);
	UINT8_TO_STREAM(p, wifimgr_ap_conf.wifi_conf.security);
	UINT32_TO_STREAM(p, wifimgr_ap_conf.wifi_conf.autorun);

	BTD("%s  enter wifi_manager_notify", __func__);
	wifi_manager_notify(data, data_len + 4);
}

void wifimgr_get_conf(enum wifimgr_iface_type wifi_iface_type, const void *buf)
{
	BTD("%s, wifi_iface_type = %u\n", __func__, wifi_iface_type);
	char data[2] = {0};
	int ret = -1;
	u8_t res_result = RESULT_SUCCESS;

	if (wifi_iface_type == WIFIMGR_IFACE_STA) {
		wifimgr_sta_conf.wifi_type = WIFIMGR_IFACE_STA; 
		
		ret = wifi_sta_get_conf(&(wifimgr_sta_conf.wifi_conf));
		if (0 != ret) {
			BTE("%s, wifi_sta_get_conf fail,err = %d\n", __func__, ret);
			goto err;
		}

		wifimgr_ctrl_iface_get_sta_conf();
    } else if (wifi_iface_type == WIFIMGR_IFACE_AP) {
		wifimgr_ap_conf.wifi_type = WIFIMGR_IFACE_AP; 
		
		ret = wifi_ap_get_conf(&(wifimgr_ap_conf.wifi_conf));
		if (0 != ret) {
			BTE("%s, wifi_ap_get_conf fail,err = %d\n", __func__, ret);
			goto err;
		}

		wifimgr_ctrl_iface_get_ap_conf();
    } else {
		BTD("%s, wifi_iface_type error :%u\n", __func__, wifi_iface_type);
	}

err:
	if (0 != ret) {
		BTD("%s, get_conf fail,ret = %d\n", __func__,ret);
		res_result = RESULT_FAIL;
	} else {
		BTD("%s, get_conf success,ret = %d\n", __func__,ret);
		return;
	}
	
	data[0] = RESULT_GET_CONF;
	data[1] = res_result;

	BTD("%s  enter wifi_manager_notify", __func__);
	wifi_manager_notify(data, sizeof(data));
}

void wifimgr_get_status(const void *buf)
{
	BTD("%s\n", __func__);
	int ret = -1;
	char data[200] = {0};
	u8_t res_result = RESULT_SUCCESS;
	int data_len = 2;
	char *p = NULL;
	int i;

	p = &data[2];

	ret = wifimgr_check_wifi_status(WIFIMGR_IFACE_STA);
	if (0 != ret) {
		data_len = 2;
		res_result = RESULT_FAIL;
		goto error;
	} else {
		UINT8_TO_STREAM(p, cur_wifi_status.sta_status);
		for (i = 0; i < BSSID_LEN; i++) {
			UINT8_TO_STREAM(p, cur_wifi_status.sta_mac[i]);
		}
		data_len += 7;

		UINT16_TO_STREAM(p, cur_wifi_status.u.sta.h_ssid_len);
		if (0 != cur_wifi_status.u.sta.h_ssid_len) {
			for (i = 0; i < cur_wifi_status.u.sta.h_ssid_len; i++) {
				UINT8_TO_STREAM(p, cur_wifi_status.u.sta.host_ssid[i]);
			}
		}
		data_len += (2 + cur_wifi_status.u.sta.h_ssid_len);

		UINT16_TO_STREAM(p, cur_wifi_status.u.sta.h_bssid_len);
		if (0 != cur_wifi_status.u.sta.h_bssid_len) {
			for (i = 0; i < cur_wifi_status.u.sta.h_bssid_len; i++) {
				UINT8_TO_STREAM(p, cur_wifi_status.u.sta.host_bssid[i]);
			}
		}
		data_len += (2 + cur_wifi_status.u.sta.h_bssid_len);
	}

	ret = wifimgr_check_wifi_status(WIFIMGR_IFACE_AP);
	if (0 != ret) {
		data_len = 2;
		res_result = RESULT_FAIL;
		goto error;
	} else {
		UINT8_TO_STREAM(p, cur_wifi_status.ap_status);
		for (i = 0; i < BSSID_LEN; i++) {
			UINT8_TO_STREAM(p, cur_wifi_status.ap_mac[i]);
		}
		data_len += 7;

		UINT16_TO_STREAM(p, cur_wifi_status.u.ap.sta_nr * BSSID_LEN);
		if (0 != cur_wifi_status.u.ap.sta_nr) {
			memcpy(p, &cur_wifi_status.u.ap.sta_mac_addrs[0][0], BSSID_LEN * cur_wifi_status.u.ap.sta_nr);
		}
		data_len += (2 + BSSID_LEN * cur_wifi_status.u.ap.sta_nr);
	}

error:
	data[0] = RESULT_GET_STATUS;
	data[1] = res_result;

	BTD("%s  enter wifi_manager_notify", __func__);
	wifi_manager_notify(data, data_len);
}

void wifimgr_open(const void *buf)
{
	BTD("%s\n", __func__);
	char data[2] = {0};
	u8_t res_result = RESULT_SUCCESS;

	if (0 != wifimgr_do_open(WIFIMGR_IFACE_STA)) {
		BTD("%s, open fail\n", __func__);
		res_result = RESULT_FAIL;
	} else {
		BTD("%s, open success\n", __func__);
		res_result = RESULT_SUCCESS;
	}

	data[0] = RESULT_OPEN;
	data[1] = res_result;

	BTD("%s  enter wifi_manager_notify", __func__);
	wifi_manager_notify(data, sizeof(data));
}

void wifimgr_close(const void *buf)
{
	BTD("%s\n", __func__);
	char data[2] = {0};
	u8_t res_result = RESULT_SUCCESS;

	if (0 != wifimgr_do_close(WIFIMGR_IFACE_STA)) {
		BTD("%s, close fail\n", __func__);
		res_result = RESULT_FAIL;
	} else {
		BTD("%s, close success\n", __func__);
		res_result = RESULT_SUCCESS;
	}

	data[0] = RESULT_CLOSE;
	data[1] = res_result;

	BTD("%s  enter wifi_manager_notify", __func__);
	wifi_manager_notify(data, sizeof(data));
}

void wifimgr_scan(const void *buf)
{
	BTD("%s\n", __func__);
	int ret = -1;
	char data[2] = {0};
	u8_t res_result = RESULT_SUCCESS;

	ret = wifimgr_do_scan(SCAN_NUM);
	if (0 != ret) {
		res_result = RESULT_FAIL;
	}

	data[0] = RESULT_SCAN_DONE;
	data[1] = res_result;

	BTD("%s  enter wifi_manager_notify", __func__);
	wifi_manager_notify(data, sizeof(data));
}

extern char *net_byte_to_hex(char *ptr, u8_t byte, char base, bool pad);
void wifimgr_start_ap(const void *buf)
{
	BTD("%s\n", __func__);

	wifi_config_type conf = {};
	char data[2] = {0};
	char *ptr, mac_nic[7] = {0};
	char ssid[MAX_SSID_LEN+1] = "UNISOC_";
	u8_t res_result = RESULT_SUCCESS;
	int i;
	int ret = -1;
	u8_t data_len = 0;
	const u8_t *p = (u8_t *)buf;

	data_len = sys_get_le16(p);
	BTD("%s, data_len = %d\n", __func__, data_len);
	p += 2;

	if (1 == data_len && 0 == p[0]) {
		ptr = mac_nic;
		for (i = 0; i < 3; i++) {
			net_byte_to_hex(ptr, cur_wifi_status.ap_mac[3 + i], 'A', true);
			ptr += 2;
		}
		strcat(ssid, mac_nic);
	} else {
		memset(ssid, 0, sizeof(ssid));
		memcpy(ssid, p, data_len);
	}

	memcpy(conf.wifi_conf.ssid, ssid, strlen(ssid));

	memset(conf.wifi_conf.passphrase, 0, MAX_PSWD_LEN + 1);
	if (!strlen(cur_wifi_status.passwd)) {
		conf.wifi_conf.security = WIFI_SECURITY_OPEN;
	} else {
		memcpy(conf.wifi_conf.passphrase, cur_wifi_status.passwd, strlen(cur_wifi_status.passwd));
		conf.wifi_conf.security = WIFI_SECURITY_PSK;
	}

	conf.wifi_type = WIFIMGR_IFACE_AP;
	ret = wifi_ap_set_conf(&(conf.wifi_conf));
	if (0 != ret) {
		BTD("%s, wifi_ap_set_conf fail,error = %d\n", __func__,ret);
		res_result = RESULT_FAIL;
		goto error;
	}

	if (0 != wifimgr_do_open(WIFIMGR_IFACE_AP)) {
		BTD("%s, open fail\n", __func__);
		res_result = RESULT_FAIL;
		goto error;
	}

	ret = wifi_ap_start_ap();
	if (0 != ret) {
		BTD("%s, start_ap fail,error = %d\n", __func__,ret);
		res_result = RESULT_FAIL;
	}

error:
	data[0] = RESULT_START_AP;
	data[1] = res_result;

	BTD("%s  enter wifi_manager_notify", __func__);
	wifi_manager_notify(data, sizeof(data));
}

void wifimgr_stop_ap(const void *buf)
{
	BTD("%s\n", __func__);
	char data[2] = {0};
	u8_t res_result = RESULT_SUCCESS;
	int ret = -1;

	ret = wifi_ap_stop_ap();
	if (0 != ret) {
		BTD("%s, stop_ap fail,error = %d\n", __func__,ret);
		res_result = RESULT_FAIL;
		goto error;
	}

	if (0 != wifimgr_do_close(WIFIMGR_IFACE_AP)) {
		BTD("%s, close fail\n", __func__);
		res_result = RESULT_FAIL;
	}

error:
	data[0] = RESULT_STOP_AP;
	data[1] = res_result;

	BTD("%s  enter wifi_manager_notify", __func__);
	wifi_manager_notify(data, sizeof(data));
}

void wifimgr_set_mac_acl(const void *buf)
{
	BTD("%s\n", __func__);
	int ret = -1;
	char data[20] = {0};
	u8_t data_len = 0;
	char station_mac[BSSID_LEN+1] = {0};
	u8_t res_result = RESULT_SUCCESS;
	u16_t vlen = 0;
	char *pmac = NULL;
	u8_t acl_subcmd = 0;
	u8_t bssid_len = 0;
	const u8_t *p = (u8_t *)buf;

	vlen = sys_get_le16(p);
	p += 2;
	BTD("%s, AllDateLen = 0x%x\n", __func__, vlen);

	acl_subcmd = p[0];
	p += 1;
	BTD("%s, acl_subcmd = %d\n", __func__, acl_subcmd);
	if (acl_subcmd <= 0) {
		BTD("%s: failed to get acl_subcmd! %d\n", __func__, acl_subcmd);
		res_result = RESULT_FAIL;
		data_len = 2;
		goto error;
	}

	if (vlen > 1)
	{
		bssid_len = sys_get_le16(p);
		BTD("%s, bssid_len = %d\n", __func__, bssid_len);

		if (BSSID_LEN != bssid_len && 1 != bssid_len)
		{
			BTD("%s, error! station mac len = %d\n", __func__, bssid_len);
			res_result = RESULT_FAIL;
			goto error_1;
		}
		else if (BSSID_LEN == bssid_len)
		{
			p += 2;
			memcpy(station_mac, p, bssid_len);
		}
	}

	pmac = bssid_len == BSSID_LEN ? station_mac : NULL;
	p += bssid_len;

	ret = wifi_ap_set_mac_acl((char)acl_subcmd, pmac);
	BTD("%s, set_mac_acl ret = %d\n", __func__,ret);
	if (0 != ret) {
		BTD("%s, set_mac_acl fail,err = %d\n", __func__,ret);
		res_result = RESULT_FAIL;
	} else {
		BTD("%s, set_mac_acl success,ret = %d\n", __func__, ret);
		res_result = RESULT_SUCCESS;
	}

error_1:
	data[2] = acl_subcmd;

	if (!pmac) {
		BTD("res_result : %d, mac = NULL, AllDateLen = %u\n", res_result, vlen);
		data_len = 3;
	} else {
		BTD("res_result : %d, mac : %02x:%02x:%02x:%02x:%02x:%02x\n", res_result, pmac[0], pmac[1], pmac[2], pmac[3], pmac[4], pmac[5]);
		memcpy(&data[3], pmac, BSSID_LEN);
		data_len = 9;
	}

error:
	data[0] = RESULT_MAC_ACL_REPORT;
	data[1] = res_result;

	BTD("%s  enter wifi_manager_notify", __func__);
	wifi_manager_notify(data, data_len);
}

int wifimgr_do_scan(int retry_num)
{
	//before connect need scan
	BTD("%s\n", __func__);
	int ret = -1;
	int i =0;

	for (i = 0; i < retry_num; i++) {
		BTD("%s,do the %dth scan\n", __func__,i+1);

		ret = wifi_sta_scan(NULL, wifimgr_ctrl_iface_notify_scan_res);
		if (0 != ret) {
			BTD("%s, scan fail,err = %d\n", __func__,ret);
		}
	}
	return ret;
}

int wifimgr_do_connect(void)
{
	BTD("%s\n", __func__);
	int ret = -1;
	
	ret = wifi_sta_connect();

	if (0 != ret) {
		BTD("%s, connect fail,err = %d\n", __func__,ret);
		goto error;
	} else {
		ret = 0;
		goto error;
	}
error:
	return ret;
}

int wifimgr_do_disconnect(u8_t flags)
{
	BTD("%s\n", __func__);
	int ret = -1;

	ret = wifi_sta_disconnect();

	if (0 != ret) {
		BTD("%s, disconnect fail-1,err = %d\n", __func__,ret);
	} else {
		if (1 == flags) {
			wait_disconnect_done = 1;
			k_sem_take(&disconnect_sem, K_FOREVER);
			if (-1 == disconnect_result) {
				BTD("%s, disconnect fail-2\n", __func__);
				ret = -1;
			} else {
				ret = 0;
			}
			wait_disconnect_done = 0;
			disconnect_result = -1;
		} else {
			ret = 0;
		}
	}
error:
	return ret;
}

int wifimgr_do_open(enum wifimgr_iface_type wifi_iface_type)
{

	BTD("%s, wifi_iface_type = %u\n", __func__, wifi_iface_type);
	int ret = -1;

	if (wifi_iface_type == WIFIMGR_IFACE_STA) {
    	ret = wifi_sta_open();
    } else if (wifi_iface_type == WIFIMGR_IFACE_AP) {
		ret = wifi_ap_open();
    } else {
		BTD("%s, wifi_iface_type error :%u\n", __func__, wifi_iface_type);
	}

	if (0 != ret) {
		BTD("%s, open fail,err = %d\n", __func__,ret);
		goto error;
	} else {
		ret = 0;
		goto error;
	}
error:
	return ret;
}

int wifimgr_do_close(enum wifimgr_iface_type wifi_iface_type)
{

	BTD("%s, wifi_iface_type = %u\n", __func__, wifi_iface_type);
	int ret = -1;

	if (wifi_iface_type == WIFIMGR_IFACE_STA) {
    	ret = wifi_sta_close();
    } else if (wifi_iface_type == WIFIMGR_IFACE_AP) {
		ret = wifi_ap_close();
    } else {
		BTD("%s, wifi_iface_type error :%u\n", __func__, wifi_iface_type);
	}

	if (0 != ret) {
		BTD("%s, close fail,err = %d\n", __func__,ret);
		goto error;
	} else {
		ret = 0;
		goto error;
	}
error:
	return ret;
}

void wifimgr_disable_bt(const void *buf)
{
	struct net_buf *buf_cmd;
	int size;
	char data[256] = {0};

	BTD("%s, ->bt_unpair\n",__func__);
	bt_unpair(BT_ID_DEFAULT, NULL);

	BTD("%s, ->send disable\n",__func__);
	size = get_disable_buf(data);
	buf_cmd = bt_hci_cmd_create(HCI_OP_ENABLE_CMD, size);
	net_buf_add_mem(buf_cmd, data, size);
	bt_hci_cmd_send_sync(HCI_OP_ENABLE_CMD, buf_cmd, NULL);

	BTD("%s, ->disable bt_irq\n",__func__);
	sprd_bt_irq_disable();
}

void wifimgr_disconnect(const void *buf)
{
	BTD("%s\n", __func__);
	char data[2] = {0};
	u8_t res_result = RESULT_SUCCESS;

	if (0 != wifimgr_do_disconnect(0)) {
		BTD("%s, disconnect fail\n", __func__);
		res_result = RESULT_FAIL;
	} else {
		BTD("%s, disconnect success\n", __func__);
		return;
	}

	data[0] = RESULT_DISCONNECT;
	data[1] = res_result;

	BTD("%s  enter wifi_manager_notify", __func__);
	wifi_manager_notify(data, sizeof(data));
}

static ssize_t wifi_manager_write(struct bt_conn *conn, const struct bt_gatt_attr *attr,
			const void *buf, u16_t len, u16_t offset,
			u8_t flags)
{
	u8_t op_code = 0;
	u8_t *value = (u8_t *)(attr->user_data);
	static u16_t total_len = 0;

	BTD("%s, len = %d, offset = %d, flags = %d\n", __func__,len,offset,flags);
	//cur_conn = conn;

	if (flags & BT_GATT_WRITE_FLAG_PREPARE) {
		return 0;
	}

	if (offset + len > sizeof(wifimgr_long_value)) {
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);
	}

	if (0 == offset) {
		memset(value, 0, sizeof(wifimgr_long_value));
		total_len = sys_get_le16((u8_t *)buf + OPCODE_BYTE) + OPCODE_BYTE + LEN_BYTE;
		BTD("%s,total_len = %d\n", __func__, total_len);
	}
	memcpy(value + offset, buf, len);
	total_len -= len;

	if (0 != total_len)
		return len;

	op_code = (u8_t)(*(value));
	BTD("%s,op_code=0x%x\n", __func__,op_code);
	switch(op_code) {
		case CMD_SET_CONF_AND_CONNECT:
			wifimgr_set_conf_and_connect(&value[1]);
		break;
		case CMD_GET_CONF:
			wifimgr_get_conf(WIFIMGR_IFACE_STA, &value[1]);
		break;
		case CMD_GET_STATUS:
			wifimgr_get_status(&value[1]);
		break;
		case CMD_OPEN:
			wifimgr_open(&value[1]);
		break;
		case CMD_CLOSE:
			wifimgr_close(&value[1]);
		break;
		case CMD_DISCONNECT:
			wifimgr_disconnect(&value[1]);
		break;
		case CMD_START_AP:
			wifimgr_start_ap(&value[1]);
		break;
		case CMD_DISABLE_BT:
			wifimgr_disable_bt(&value[1]);
		break;
		case CMD_SCAN:
			wifimgr_scan(&value[1]);
		break;
		case CMD_STOP_AP:
			wifimgr_stop_ap(&value[1]);
		break;
		case CMD_SET_MAC_ACL:
			wifimgr_set_mac_acl(&value[1]);
		break;
		case CMD_SET_INTERVAL:
			wifimgr_set_conf_and_interval(&value[1]);
		break;

		default:
			BTD("%s,op_code=0x%x not found\n", __func__,op_code);
		break;
	}
	return len;
}

/* WiFi Manager Service Declaration */
static struct bt_gatt_attr attrs[] = {
	BT_GATT_PRIMARY_SERVICE(&wifimgr_service_uuid),
	BT_GATT_CHARACTERISTIC(&wifimgr_char_uuid.uuid, BT_GATT_CHRC_WRITE|BT_GATT_CHRC_NOTIFY,
				BT_GATT_PERM_READ|BT_GATT_PERM_WRITE|BT_GATT_PERM_PREPARE_WRITE, NULL, wifi_manager_write,
				&wifimgr_long_value),
	BT_GATT_CCC(wifimgr_ccc_cfg, wifimgr_ccc_cfg_changed),
};

static struct bt_gatt_service wifi_manager_svc = BT_GATT_SERVICE(attrs);

void wifi_manager_notify(const void *data, u16_t len)
{
	BTD("%s, len = %d\n", __func__, len);
	if (!wifimgr_is_enabled) {
		BTD("%s, rx is not enabled\n", __func__);
		return;
	}
	/*
	if(len > bt_gatt_get_mtu(cur_conn)){
		BTD("%s, len > MTU\n", __func__);
		do_gatt_exchange_mtu();
	}*/
	bt_gatt_notify(NULL, &attrs[2], data, len);
}

void wifi_manager_service_init(void)
{
	BTD("%s bt service register\n ", __func__);
	bt_gatt_service_register(&wifi_manager_svc);

	BTD("%s wifi service register\n ", __func__);
	wifi_register_connection_notifier(wifimgr_ctrl_iface_notify_connect);
	wifi_register_disconnection_notifier(wifimgr_ctrl_iface_notify_disconnect);

	wifi_register_new_station_notifier(wifimgr_ctrl_iface_notify_new_station);
	wifi_register_station_leave_notifier(wifimgr_ctrl_iface_notify_station_leave);

	k_sem_init(&get_status_sem, 0, 1);
	k_sem_init(&disconnect_sem, 0, 1);
}