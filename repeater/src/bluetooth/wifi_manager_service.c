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

#include <net/wifimgr_api.h>
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
static struct k_sem scan_sem;

static wifi_status_type cur_wifi_status = {};

static u8_t wait_disconnect_done = 0;
static int disconnect_result = -1;

static struct k_sem disconnect_sem;

struct wifimgr_ctrl_cbs *get_wifimgr_cbs(void);
static int scan_result = 0;

extern int get_disable_buf(void *buf);
extern void sprd_bt_irq_disable(void);

static void wifimgr_ccc_cfg_changed(const struct bt_gatt_attr *attr, u16_t value)
{
	BTD("%s\n", __func__);
	wifimgr_is_enabled = (value == BT_GATT_CCC_NOTIFY) ? 1 : 0;
}

int wifimgr_check_wifi_status(char *iface_name)
{
	BTD("%s, iface_name = %s\n", __func__,iface_name);
	int ret = -1;

	ret = wifimgr_get_ctrl(iface_name);
	if (ret) {
		BTD("%s: failed to get ctrl! %d\n", __func__, ret);
		goto error;
	}
	if (wifimgr_get_ctrl_ops()->get_status) {
		ret = wifimgr_get_ctrl_ops_cbs(get_wifimgr_cbs())->get_status(iface_name);
	} else {
		BTD("%s, get_status = NULL\n", __func__);
		goto error;
	}
	wifimgr_release_ctrl(iface_name);

	if (0 != ret) {
		BTD("%s, get_status fail,err = %d\n", __func__,ret);
		goto error;
	} else {
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

void wifimgr_set_conf_and_connect(const void *buf)
{
	BTD("%s\n", __func__);
	wifi_config_type conf;
	const u8_t *p = buf;
	u16_t vlen = 0;
	int ret = -1;
	char data[2] = {0};
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

	memcpy(conf.ssid,p,ssid_len);
	p+=ssid_len;
	BTD("%s, ssid = %s\n", __func__, conf.ssid);

	bssid_len = sys_get_le16(p);
	p += 2;
	BTD("%s, bSsidDataLen = 0x%x\n", __func__, bssid_len);

	memcpy(conf.bssid,p,bssid_len);
	p+=bssid_len;
	for (int i = 0; i < bssid_len; i++) {
		BTD("bssid = 0x%02x\n", conf.bssid[i]);
	}

	pwd_len = sys_get_le16(p);
	p += 2;
	BTD("%s, PsdDataLen = 0x%x\n", __func__, pwd_len);

	memcpy(conf.passwd,p,pwd_len);
	p+=pwd_len;
	BTD("%s, passwd = %s\n", __func__, conf.passwd);
	strcpy(cur_wifi_status.passwd, conf.passwd);

	conf.wifi_type = WIFIMGR_IFACE_STA;
	BTD("%s, conf.wifi_type = %d\n", __func__, conf.wifi_type);

	if (wifimgr_get_ctrl_ops()->set_conf) {
		ret = wifimgr_get_ctrl_ops_cbs(get_wifimgr_cbs())->set_conf(WIFIMGR_IFACE_NAME_STA,
									(ssid_len > 0 ? conf.ssid : NULL),
									(bssid_len > 0 ? conf.bssid : NULL),
									conf.security,
									(pwd_len > 0 ? conf.passwd : ""),
									conf.band,
									conf.channel,
									0,
									conf.autorun);
	} else {
		BTD("%s, set_conf = NULL\n", __func__);
		res_result = RESULT_FAIL;
		goto error;
	}

	if (0 != ret) {
		BTD("%s, set_conf fail,error = %d\n", __func__,ret);
		res_result = RESULT_FAIL;
		goto error;
	}

	ret = wifimgr_check_wifi_status(WIFIMGR_IFACE_NAME_STA);
	if (0 == ret) {
		switch(cur_wifi_status.sta_status){
			case WIFI_STA_STATUS_NODEV:
				if (0 != wifimgr_do_open(WIFIMGR_IFACE_NAME_STA)) {
					BTD("%s, open fail\n", __func__);
					res_result = RESULT_FAIL;
					goto error;
				}
			break;
			case WIFI_STA_STATUS_READY:
			break;
			case WIFI_STA_STATUS_CONNECTED:
				if (0 != wifimgr_do_disconnect(1)) {
					BTD("%s, STATUS_CONNECTED and do_disconnect fail\n", __func__);
					res_result = RESULT_FAIL;
					goto error;
				}
			break;
			case WIFI_STA_STATUS_SCANNING:
			case WIFI_STA_STATUS_CONNECTING:
			case WIFI_STA_STATUS_DISCONNECTING:
				BTD("%s,status = %d ,wifi is busy\n", __func__, cur_wifi_status.sta_status);
				res_result = RESULT_FAIL;
				goto error;
			break;

			default:
				BTD("%s,status = %d not found\n", __func__, cur_wifi_status.sta_status);
				res_result = RESULT_FAIL;
				goto error;
			break;
		}
	}else {
		res_result = RESULT_FAIL;
		goto error;
	}

	if (0 != wifimgr_do_connect()) {
		BTD("%s, connect fail\n", __func__);
		res_result = RESULT_FAIL;
		goto error;
	} else {
		return;
	}

error:
	data[0] = RESULT_SET_CONF_AND_CONNECT;
	data[1] = res_result;

	wifi_manager_notify(data, sizeof(data));
}

void wifimgr_set_conf_and_interval(const void *buf)
{
	BTD("%s\n", __func__);
	wifi_config_type conf;
	const u8_t *p = buf;
	u16_t vlen = 0;
	int ret = -1;
	char data[2] = {0};
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

	memcpy(conf.ssid,p,ssid_len);
	p+=ssid_len;
	BTD("%s, ssid = %s\n", __func__, conf.ssid);

	bssid_len = sys_get_le16(p);
	p += 2;
	BTD("%s, bSsidDataLen = 0x%x\n", __func__, bssid_len);

	memcpy(conf.bssid,p,bssid_len);
	p+=bssid_len;
	for (int i = 0; i < bssid_len; i++) {
		BTD("bssid = 0x%02x\n", conf.bssid[i]);
	}

	pwd_len = sys_get_le16(p);
	p += 2;
	BTD("%s, PsdDataLen = 0x%x\n", __func__, pwd_len);

	memcpy(conf.passwd,p,pwd_len);
	p+=pwd_len;
	BTD("%s, passwd = %s\n", __func__, conf.passwd);
	strcpy(cur_wifi_status.passwd, conf.passwd);

	conf.autorun = sys_get_le32(p);
	p += 4;
	BTD("%s, conf.autorun = %d\n", __func__, conf.autorun);

	conf.wifi_type = WIFIMGR_IFACE_STA;
	BTD("%s, conf.wifi_type = %d\n", __func__, conf.wifi_type);

	if (wifimgr_get_ctrl_ops()->set_conf) {
		ret = wifimgr_get_ctrl_ops_cbs(get_wifimgr_cbs())->set_conf(WIFIMGR_IFACE_NAME_STA,
									(ssid_len > 0 ? conf.ssid : NULL),
									(bssid_len > 0 ? conf.bssid : NULL),
									conf.security,
									(pwd_len > 0 ? conf.passwd : ""),
									conf.band,
									conf.channel,
									0,
									conf.autorun);
	} else {
		BTD("%s, set_conf = NULL\n", __func__);
		res_result = RESULT_FAIL;
		goto error;
	}

	if (0 != ret) {
		BTD("%s, set_conf fail,error = %d\n", __func__,ret);
		res_result = RESULT_FAIL;
		goto error;
	}

	ret = wifimgr_check_wifi_status(WIFIMGR_IFACE_NAME_STA);
	if (0 == ret) {
		switch(cur_wifi_status.sta_status){
			case WIFI_STA_STATUS_NODEV:
				if (0 != wifimgr_do_open(WIFIMGR_IFACE_NAME_STA)) {
					BTD("%s, open fail\n", __func__);
					res_result = RESULT_FAIL;
					goto error;
				}
			break;
			case WIFI_STA_STATUS_READY:
			break;
			case WIFI_STA_STATUS_CONNECTED:
				if (0 != wifimgr_do_disconnect(1)) {
					BTD("%s, STATUS_CONNECTED and do_disconnect fail\n", __func__);
					res_result = RESULT_FAIL;
					goto error;
				}
			break;
			case WIFI_STA_STATUS_SCANNING:
			case WIFI_STA_STATUS_CONNECTING:
			case WIFI_STA_STATUS_DISCONNECTING:
				BTD("%s,status = %d ,wifi is busy\n", __func__, cur_wifi_status.sta_status);
				res_result = RESULT_FAIL;
				goto error;
			break;

			default:
				BTD("%s,status = %d not found\n", __func__, cur_wifi_status.sta_status);
				res_result = RESULT_FAIL;
				goto error;
			break;
		}
	}else {
		res_result = RESULT_FAIL;
		goto error;
	}

error:
	data[0] = RESULT_SET_CONF_AND_INTERVAL;
	data[1] = res_result;

	wifi_manager_notify(data, sizeof(data));
}

void wifimgr_ctrl_iface_notify_connect(char result)
{
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

	wifi_manager_notify(data, sizeof(data));
}

void wifimgr_ctrl_iface_notify_connect_timeout(void)
{
	BTD("%s\n", __func__);
	char data[2] = {0};
	u8_t res_result = RESULT_FAIL;

	data[0] = RESULT_SET_CONF_AND_CONNECT;
	data[1] = res_result;

	wifi_manager_notify(data, sizeof(data));
}

void wifimgr_get_conf(const void *buf)
{
	BTD("%s\n", __func__);
	int ret = -1;
	char data[2] = {0};
	u8_t res_result = RESULT_SUCCESS;

	ret = wifimgr_get_ctrl(WIFIMGR_IFACE_NAME_STA);
	if (ret) {
		BTD("%s: failed to get ctrl! %d\n", __func__, ret);
		res_result = RESULT_FAIL;
		goto err;
	}
	if (wifimgr_get_ctrl_ops()->get_conf) {
		ret = wifimgr_get_ctrl_ops_cbs(get_wifimgr_cbs())->get_conf(WIFIMGR_IFACE_NAME_STA);
	} else {
		BTD("%s, get_conf = NULL\n", __func__);
		res_result = RESULT_FAIL;
	}
	wifimgr_release_ctrl(WIFIMGR_IFACE_NAME_STA);

	if (0 != ret) {
		BTD("%s, get_conf fail,err = %d\n", __func__,ret);
		res_result = RESULT_FAIL;
	} else {
		return;
	}

err:
	data[0] = RESULT_GET_CONF;
	data[1] = res_result;

	wifi_manager_notify(data, sizeof(data));
}

void wifimgr_ctrl_iface_get_sta_conf_cb(char *ssid, char *bssid, char *passphrase,
				unsigned char band, unsigned char channel,
				enum wifimgr_security security, int autorun)
{
	BTD("%s\n", __func__);
	wifi_config_type conf;
	u8_t res_result = RESULT_SUCCESS;
	char data[255] = {0};
	u16_t data_len = 0;
	u16_t ssid_len = 0;
	u16_t bssid_len = 0;
	u16_t passwd_len = 0;
	char *p = NULL;
	int i;

	if (ssid) {
		ssid_len = strlen(ssid);
		BTD("%s ,ssid = %s\n", __func__,ssid);
	} else {
		BTD("%s ,ssid = NULL\n", __func__);
		ssid_len = 0;
	}

	if (passphrase) {
		BTD("%s ,pwd = %s\n", __func__,passphrase);
		passwd_len = strlen(passphrase);
	} else {
		BTD("%s ,pwd = NULL\n", __func__);
		passwd_len = 0;
	}

	if (bssid) {
		bssid_len = BSSID_LEN;
		for (i = 0; i < bssid_len; i++) {
			BTD("bssid = 0x%02x\n", bssid[i]);
		}
	} else {
		BTD("%s ,bssid = NULL\n", __func__);
		bssid_len = 0;
	}

	BTD("%s, band:%d, channel:%d security:%u, autorun:%d\n", __func__, band, channel, security, autorun);

	if ((ssid_len > MAX_SSID_LEN)
		|| (bssid_len > BSSID_LEN)
		|| (passwd_len > MAX_PSWD_LEN)) {
		res_result = RESULT_FAIL;
		data[0] = RESULT_GET_CONF;
		data[1] = res_result;

		BTD("%s ,len error\n", __func__);
		wifi_manager_notify(data, 2);
		return;
	}

	memset(&conf, 0, sizeof(conf));
	conf.wifi_type = WIFIMGR_IFACE_STA;
	memcpy(conf.ssid, ssid, ssid_len);
	memcpy(conf.bssid, bssid, bssid_len);
	memcpy(conf.passwd, passphrase, passwd_len);
	conf.band = band;
	conf.channel = channel;
	conf.security = security;
	conf.autorun = autorun;

	data_len = 1 + 6 + 7 + ssid_len + bssid_len +passwd_len;
	res_result = RESULT_SUCCESS;

	p = data;
	UINT8_TO_STREAM(p, RESULT_GET_CONF);
	UINT8_TO_STREAM(p, res_result);
	UINT8_TO_STREAM(p, conf.wifi_type);
	UINT16_TO_STREAM(p, data_len);

	UINT16_TO_STREAM(p, ssid_len);
	for (i = 0; i < ssid_len; i++) {
		UINT8_TO_STREAM(p, conf.ssid[i]);
	}

	UINT16_TO_STREAM(p, bssid_len);
	for (i = 0; i < bssid_len; i++) {
		UINT8_TO_STREAM(p, conf.bssid[i]);
	}

	UINT16_TO_STREAM(p, passwd_len);
	for (i = 0; i < passwd_len; i++) {
		UINT8_TO_STREAM(p, conf.passwd[i]);
	}

	UINT8_TO_STREAM(p, conf.band);
	UINT8_TO_STREAM(p, conf.channel);
	UINT8_TO_STREAM(p, conf.security);
	UINT32_TO_STREAM(p, conf.autorun);

	wifi_manager_notify(data, data_len + 4);
}

void wifimgr_ctrl_iface_get_ap_conf_cb(char *ssid, char *passphrase, unsigned char band,
			       unsigned char channel, unsigned char ch_width,
			       enum wifimgr_security security, int autorun)
{
	BTD("%s\n", __func__);
	wifi_config_type conf;
	u8_t res_result = RESULT_SUCCESS;
	char data[255] = {0};
	u16_t data_len = 0;
	u16_t ssid_len = 0;
	u16_t passwd_len = 0;
	char *p = NULL;
	int i;

	if (ssid) {
		ssid_len = strlen(ssid);
		BTD("%s ,ssid = %s\n", __func__,ssid);
	} else {
		BTD("%s ,ssid = NULL\n", __func__);
		ssid_len = 0;
	}

	if (passphrase) {
		BTD("%s ,pwd = %s\n", __func__,passphrase);
		passwd_len = strlen(passphrase);
	} else {
		BTD("%s ,pwd = NULL\n", __func__);
		passwd_len = 0;
	}

	BTD("%s, band:%d, channel:%d, ch_width:%d, security:%u, autorun:%d\n", __func__, band, channel, ch_width, security, autorun);

	if ((ssid_len > MAX_SSID_LEN) || (passwd_len > MAX_PSWD_LEN)) {
		res_result = RESULT_FAIL;
		data[0] = RESULT_GET_CONF;
		data[1] = res_result;

		BTD("%s ,len error\n", __func__);
		wifi_manager_notify(data, 2);
		return;
	}

	memset(&conf, 0, sizeof(conf));
	conf.wifi_type = WIFIMGR_IFACE_AP;
	memcpy(conf.ssid, ssid, ssid_len);
	memcpy(conf.passwd, passphrase, passwd_len);
	conf.band = band;
	conf.channel = channel;
	conf.security = security;
	conf.autorun = autorun;

	data_len = 1 + 4 + 7 + ssid_len + passwd_len;
	res_result = RESULT_SUCCESS;

	p = data;
	UINT8_TO_STREAM(p, RESULT_GET_CONF);
	UINT8_TO_STREAM(p, res_result);
	UINT8_TO_STREAM(p, conf.wifi_type);
	UINT16_TO_STREAM(p, data_len);

	UINT16_TO_STREAM(p, ssid_len);
	for (i = 0; i < ssid_len; i++) {
		UINT8_TO_STREAM(p, conf.ssid[i]);
	}

	UINT16_TO_STREAM(p, passwd_len);
	for (i = 0; i < passwd_len; i++) {
		UINT8_TO_STREAM(p, conf.passwd[i]);
	}

	UINT8_TO_STREAM(p, conf.band);
	UINT8_TO_STREAM(p, conf.channel);
	UINT8_TO_STREAM(p, conf.security);
	UINT32_TO_STREAM(p, conf.autorun);

	wifi_manager_notify(data, data_len + 4);
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

	ret = wifimgr_check_wifi_status(WIFIMGR_IFACE_NAME_STA);
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

	ret = wifimgr_check_wifi_status(WIFIMGR_IFACE_NAME_AP);
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

	wifi_manager_notify(data, data_len);
}

void wifimgr_ctrl_iface_get_sta_status_cb(char status, char *own_mac, char *host_bssid,
				  signed char host_rssi)
{
	BTD("%s, status:%d, signal:%d\n", __func__,status,host_rssi);
	BTD("%s, mac = %02X:%02X:%02X:%02X:%02X:%02X\n", __func__,own_mac[0],own_mac[1],own_mac[2],own_mac[3],own_mac[4],own_mac[5]);

	cur_wifi_status.sta_status = status;
	memcpy(cur_wifi_status.sta_mac, own_mac, 6);

	if (WIFI_STA_STATUS_CONNECTED == status) {
		/*if (host_ssid) {
			memset(cur_wifi_status.u.sta.host_ssid, 0, sizeof(cur_wifi_status.u.sta.host_ssid));
			memcpy(cur_wifi_status.u.sta.host_ssid, host_ssid, strlen(host_ssid));
			cur_wifi_status.u.sta.h_ssid_len = strlen(host_ssid);
			BTD("%s ,host_ssid = %s\n", __func__,host_ssid);
		} else {
			cur_wifi_status.u.sta.h_ssid_len = 0;
			BTD("%s ,host_ssid = NULL\n", __func__);
		}*/

		if (host_bssid) {
			memset(cur_wifi_status.u.sta.host_bssid, 0, sizeof(cur_wifi_status.u.sta.host_bssid));
			memcpy(cur_wifi_status.u.sta.host_bssid, host_bssid, BSSID_LEN);
			cur_wifi_status.u.sta.h_bssid_len = BSSID_LEN;
			BTD("%s, host_bssid = %02X:%02X:%02X:%02X:%02X:%02X\n", __func__,host_bssid[0],host_bssid[1],host_bssid[2],host_bssid[3],host_bssid[4],host_bssid[5]);
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

void wifimgr_ctrl_iface_get_ap_status_cb(char status, char *own_mac,
				 unsigned char sta_nr, char sta_mac_addrs[][6],
				 unsigned char acl_nr, char acl_mac_addrs[][6])
{
	BTD("%s, status:%d, sta_nr:%d\n", __func__,status,sta_nr);
	BTD("%s, mac = %02X:%02X:%02X:%02X:%02X:%02X\n", __func__,own_mac[0],own_mac[1],own_mac[2],own_mac[3],own_mac[4],own_mac[5]);

	cur_wifi_status.ap_status = status;
	memcpy(cur_wifi_status.ap_mac, own_mac, 6);

	if (WIFI_AP_STATUS_STARTED == status) {
		memset(cur_wifi_status.u.ap.sta_mac_addrs,0,sizeof(cur_wifi_status.u.ap.sta_mac_addrs));
		cur_wifi_status.u.ap.sta_nr = (sta_nr > WIFI_MAX_STA_NR ? WIFI_MAX_STA_NR : sta_nr);
		memcpy(&cur_wifi_status.u.ap.sta_mac_addrs[0][0], &sta_mac_addrs[0][0], BSSID_LEN * cur_wifi_status.u.ap.sta_nr);
	} else {
		cur_wifi_status.u.ap.sta_nr = 0;
	}

	k_sem_give(&get_status_sem);
}

void wifimgr_open(const void *buf)
{
	BTD("%s\n", __func__);
	char data[2] = {0};
	u8_t res_result = RESULT_SUCCESS;

	if (0 != wifimgr_do_open(WIFIMGR_IFACE_NAME_STA)) {
		BTD("%s, open fail\n", __func__);
		res_result = RESULT_FAIL;
	} else {
		BTD("%s, open success\n", __func__);
		res_result = RESULT_SUCCESS;
	}

	data[0] = RESULT_OPEN;
	data[1] = res_result;

	wifi_manager_notify(data, sizeof(data));
}

void wifimgr_close(const void *buf)
{
	BTD("%s\n", __func__);
	char data[2] = {0};
	u8_t res_result = RESULT_SUCCESS;

	if (0 != wifimgr_do_close(WIFIMGR_IFACE_NAME_STA)) {
		BTD("%s, close fail\n", __func__);
		res_result = RESULT_FAIL;
	} else {
		BTD("%s, close success\n", __func__);
		res_result = RESULT_SUCCESS;
	}

	data[0] = RESULT_CLOSE;
	data[1] = res_result;

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

	wifi_manager_notify(data, sizeof(data));
}

extern char *net_byte_to_hex(char *ptr, u8_t byte, char base, bool pad);
void wifimgr_start_ap(const void *buf)
{
	BTD("%s\n", __func__);
	char data[2] = {0};
	char *ptr, mac_nic[7] = {0};
	char ssid[MAX_SSID_LEN+1] = "UNISOC_";
	char *passwd;
	char security;
	u8_t res_result = RESULT_SUCCESS;
	int i;
	int ret = -1;
	u8_t data_len = 0;
	const u8_t *p = buf;

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

	if (!strlen(cur_wifi_status.passwd)) {
		passwd = "";
		security = WIFIMGR_SECURITY_OPEN;
	} else {
		passwd = cur_wifi_status.passwd;
		security = WIFIMGR_SECURITY_PSK;
	}

	if (wifimgr_get_ctrl_ops()->set_conf) {
		ret = wifimgr_get_ctrl_ops_cbs(get_wifimgr_cbs())->set_conf(WIFIMGR_IFACE_NAME_AP,
									ssid,
									NULL,
									security,
									passwd,
									0, 0, 0,
									0);
	/* Set channel: 0 to tell the firmware using STA channle */
	} else {
		BTD("%s, set_conf = NULL\n", __func__);
		res_result = RESULT_FAIL;
		goto error;
	}

	if (0 != ret) {
		BTD("%s, set_conf fail,error = %d\n", __func__,ret);
		res_result = RESULT_FAIL;
		goto error;
	}

	if (0 != wifimgr_do_open(WIFIMGR_IFACE_NAME_AP)) {
		BTD("%s, open fail\n", __func__);
		res_result = RESULT_FAIL;
		goto error;
	}

	ret = wifimgr_get_ctrl(WIFIMGR_IFACE_NAME_AP);
	if (ret) {
		BTD("%s: failed to get ctrl! %d\n", __func__, ret);
		goto error;
	}
	if (wifimgr_get_ctrl_ops()->start_ap) {
		ret = wifimgr_get_ctrl_ops()->start_ap();
	} else {
		BTD("%s, start_ap = NULL\n", __func__);
		res_result = RESULT_FAIL;
		goto error;
	}
	wifimgr_release_ctrl(WIFIMGR_IFACE_NAME_AP);

	if (0 != ret) {
		BTD("%s, start_ap fail,error = %d\n", __func__,ret);
		res_result = RESULT_FAIL;
		goto error;
	}

error:
	data[0] = RESULT_START_AP;
	data[1] = res_result;

	wifi_manager_notify(data, sizeof(data));
}

void wifimgr_stop_ap(const void *buf)
{
	BTD("%s\n", __func__);
	char data[2] = {0};
	u8_t res_result = RESULT_SUCCESS;
	int ret = -1;

	ret = wifimgr_get_ctrl(WIFIMGR_IFACE_NAME_AP);
	if (ret) {
		BTD("%s: failed to get ctrl! %d\n", __func__, ret);
		goto error;
	}
	if (wifimgr_get_ctrl_ops()->stop_ap) {
		ret = wifimgr_get_ctrl_ops()->stop_ap();
	} else {
		BTD("%s, stop_ap = NULL\n", __func__);
		res_result = RESULT_FAIL;
		goto error;
	}
	wifimgr_release_ctrl(WIFIMGR_IFACE_NAME_AP);

	if (0 != ret) {
		BTD("%s, stop_ap fail,error = %d\n", __func__,ret);
		res_result = RESULT_FAIL;
		goto error;
	}

	if (0 != wifimgr_do_close(WIFIMGR_IFACE_NAME_AP)) {
		BTD("%s, close fail\n", __func__);
		res_result = RESULT_FAIL;
		goto error;
	}

error:
	data[0] = RESULT_STOP_AP;
	data[1] = res_result;

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

	ret = wifimgr_get_ctrl(WIFIMGR_IFACE_NAME_AP);
	if (ret) {
		BTD("%s: failed to get ctrl! %d\n", __func__, ret);
		res_result = RESULT_FAIL;
		goto error_2;
	}
	if (wifimgr_get_ctrl_ops()->set_mac_acl) {
		ret = wifimgr_get_ctrl_ops()->set_mac_acl((char)acl_subcmd, pmac);
	} else {
		BTD("%s, set_mac_acl = NULL\n", __func__);
		res_result = RESULT_FAIL;
		goto error_2;
	}

	BTD("%s, set_mac_acl ret = %d\n", __func__,ret);
	if (0 != ret) {
		BTD("%s, set_mac_acl fail,err = %d\n", __func__,ret);
		res_result = RESULT_FAIL;
	} else {
		BTD("%s, set_mac_acl fail,err = %d\n", __func__, ret);
		res_result = RESULT_SUCCESS;
	}

error_2:
	wifimgr_release_ctrl(WIFIMGR_IFACE_NAME_AP);
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

	wifi_manager_notify(data, data_len);
}

int wifimgr_do_scan(int retry_num)
{
	//before connect need scan
	BTD("%s\n", __func__);
	int ret = -1;
	int i =0;

	for (i = 0, scan_result = 0; (i < retry_num) && (1 != scan_result); i++) {
		BTD("%s,do the %dth scan\n", __func__,i+1);
		ret = wifimgr_get_ctrl(WIFIMGR_IFACE_NAME_STA);
		if (ret) {
			BTD("%s: failed to get ctrl! %d\n", __func__, ret);
			goto error;
		}
		if(wifimgr_get_ctrl_ops()->scan) {
			ret = wifimgr_get_ctrl_ops_cbs(get_wifimgr_cbs())->scan();
		} else {
			BTD("%s, scan = NULL\n", __func__);
			goto error;
		}
		wifimgr_release_ctrl(WIFIMGR_IFACE_NAME_STA);

		if (0 != ret) {
			BTD("%s, scan fail,err = %d\n", __func__,ret);
			goto error;
		} else {
			if (0 != k_sem_take(&scan_sem, SCAN_TIMEOUT)) {
				BTD("%s, take scan_sem fail\n", __func__);
				scan_result = 0;
				ret = -1;
			} else {
				ret = ((1 == scan_result) ? 0 : -1);
			}
		}
	}
error:
	return ret;
}

int wifimgr_do_connect(void)
{
	BTD("%s\n", __func__);
	int ret = -1;

	ret = wifimgr_get_ctrl(WIFIMGR_IFACE_NAME_STA);
	if (ret) {
		BTD("%s: failed to get ctrl! %d\n", __func__, ret);
		goto error;
	}
	if (wifimgr_get_ctrl_ops()->connect) {
		ret = wifimgr_get_ctrl_ops_cbs(get_wifimgr_cbs())->connect();
	} else {
		BTD("%s, connect = NULL\n", __func__);
		goto error;
	}
	wifimgr_release_ctrl(WIFIMGR_IFACE_NAME_STA);

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

	ret = wifimgr_get_ctrl(WIFIMGR_IFACE_NAME_STA);
	if (ret) {
		BTD("%s: failed to get ctrl! %d\n", __func__, ret);
		goto error;
	}
	if(wifimgr_get_ctrl_ops()->disconnect) {
		ret = wifimgr_get_ctrl_ops_cbs(get_wifimgr_cbs())->disconnect();
	} else {
		BTD("%s, disconnect = NULL\n", __func__);
		goto error;
	}
	wifimgr_release_ctrl(WIFIMGR_IFACE_NAME_STA);

	if (0 != ret) {
		BTD("%s, disconnect fail-1,err = %d\n", __func__,ret);
		goto error;
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
		} else {
			ret = 0;
		}
		goto error;
	}
error:
	return ret;
}

int wifimgr_do_open(char *iface_name)
{
	BTD("%s\n", __func__);
	int ret = -1;

	ret = wifimgr_get_ctrl(iface_name);
	if (ret) {
		BTD("%s: failed to get ctrl! %d\n", __func__, ret);
		goto error;
	}
	if (wifimgr_get_ctrl_ops()->open) {
		ret = wifimgr_get_ctrl_ops()->open(iface_name);
	} else {
		BTD("%s, open = NULL\n", __func__);
		goto error;
	}
	wifimgr_release_ctrl(iface_name);

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

int wifimgr_do_close(char *iface_name)
{
	BTD("%s\n", __func__);
	int ret = -1;

	ret = wifimgr_get_ctrl(iface_name);
	if (ret) {
		BTD("%s: failed to get ctrl! %d\n", __func__, ret);
		goto error;
	}
	if (wifimgr_get_ctrl_ops()->close) {
		ret = wifimgr_get_ctrl_ops()->close(iface_name);
	} else {
		BTD("%s, close = NULL\n", __func__);
		goto error;
	}
	wifimgr_release_ctrl(iface_name);

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
		return;
	}

	data[0] = RESULT_DISCONNECT;
	data[1] = res_result;

	wifi_manager_notify(data, sizeof(data));
}

void wifimgr_ctrl_iface_notify_disconnect(char reason)
{
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

void wifimgr_ctrl_iface_notify_disconnect_timeout(void)
{
	BTD("%s \n", __func__);
	char data[2] = {0};
	u8_t res_result = RESULT_FAIL;

	data[0] = RESULT_DISCONNECT;
	data[1] = res_result;

	if (1 == wait_disconnect_done) {
		disconnect_result = -1;
		k_sem_give(&disconnect_sem);
	} else {
		wifi_manager_notify(data, sizeof(data));
	}
}

static ssize_t wifi_manager_write(struct bt_conn *conn, const struct bt_gatt_attr *attr,
			const void *buf, u16_t len, u16_t offset,
			u8_t flags)
{
	u8_t op_code = 0;
	u8_t *value = attr->user_data;
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
			wifimgr_get_conf(&value[1]);
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

void wifi_manager_service_init(void)
{
	BTD("%s\n", __func__);
	bt_gatt_service_register(&wifi_manager_svc);
	k_sem_init(&get_status_sem, 0, 1);
	k_sem_init(&scan_sem, 0, 1);
	k_sem_init(&disconnect_sem, 0, 1);
}

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

void wifimgr_ctrl_iface_notify_scan_res(char *ssid, char *bssid, unsigned char band,
				unsigned char channel, signed char signal,
				enum wifimgr_security security)
{
	BTD("%s\n", __func__);
	wifi_scan_res_type scan_res;
	u8_t res_result = RESULT_SUCCESS;
	char data[255] = {0};
	u16_t data_len = 0;
	u16_t ssid_len = 0;
	u16_t bssid_len = 0;

	char *p = NULL;
	int i;

	if (ssid) {
		ssid_len = strlen(ssid);
		BTD("ssid = %s\n", ssid);
	} else {
		BTD("ssid = NULL\n");
		ssid_len = 0;
	}

	if (bssid) {
		bssid_len = BSSID_LEN;
		BTD("bssid = %02x:%02x:%02x:%02x:%02x:%02x\n", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
	} else {
		BTD("%s ,bssid = NULL\n", __func__);
		bssid_len = 0;
	}

	if ((security>=1) && (security<=3)) {
		BTD("security:%u\n", security);
	} else {
		BTE("%s ,security err = %d\n", __func__, security);
	}

	BTD("band:%d, channel:%d, signal:%d, security:%d\n", band, channel, signal, security);

	if ((ssid_len > MAX_SSID_LEN)
		|| (bssid_len > BSSID_LEN)) {
		res_result = RESULT_FAIL;
		data[0] = RESULT_SCAN_DONE;
		data[1] = res_result;

		BTD("%s ,len error\n", __func__);
		wifi_manager_notify(data, 2);
		return;
	}

	memset(&scan_res, 0, sizeof(scan_res));
	memcpy(scan_res.ssid, ssid, ssid_len);
	memcpy(scan_res.bssid, bssid, bssid_len);
	scan_res.band = band;
	scan_res.channel = channel;
	scan_res.signal = signal;
	scan_res.security = security;
	data_len = 4 + 1 + ssid_len + bssid_len;
	BTD("data_len:%u, ssid_len:%u, bssid_len:%u\n", data_len, ssid_len, bssid_len);
	res_result = RESULT_SUCCESS;

	p = data;
	UINT8_TO_STREAM(p, RESULT_SCAN_REPORT);
	UINT8_TO_STREAM(p, res_result);
	UINT16_TO_STREAM(p, data_len);

	UINT16_TO_STREAM(p, ssid_len);
	for (i = 0; i < ssid_len; i++) {
		UINT8_TO_STREAM(p, scan_res.ssid[i]);
	}

	UINT16_TO_STREAM(p, bssid_len);
	for (i = 0; i < bssid_len; i++) {
		UINT8_TO_STREAM(p, scan_res.bssid[i]);
	}

	UINT8_TO_STREAM(p, scan_res.security);

	wifi_manager_notify(data, data_len + 4);
}

void wifimgr_ctrl_iface_notify_scan_done(char result)
{
	BTD("%s,result = %d\n", __func__,result);
	scan_result = result;
	k_sem_give(&scan_sem);
}

void wifimgr_ctrl_iface_notify_scan_timeout(void)
{
	BTD("%s\n", __func__);
	scan_result = 0;
	k_sem_give(&scan_sem);
}

void wifimgr_ctrl_iface_notify_new_station(char status, char *mac)
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

/*
void wifimgr_ctrl_iface_notify_set_mac_acl_timeout(void)
{
	BTD("%s \n", __func__);
	char data[2] = {0};
	u8_t res_result = RESULT_FAIL;

	data[0] = RESULT_STATION_REPORT;
	data[1] = res_result;

	wifi_manager_notify(data, sizeof(data));
}
*/
static struct wifimgr_ctrl_cbs wifi_ctrl_cbs = {
	.get_sta_conf_cb = wifimgr_ctrl_iface_get_sta_conf_cb,
	.get_ap_conf_cb = wifimgr_ctrl_iface_get_ap_conf_cb,
	.get_sta_status_cb = wifimgr_ctrl_iface_get_sta_status_cb,
	.get_ap_status_cb = wifimgr_ctrl_iface_get_ap_status_cb,
	.notify_scan_res = wifimgr_ctrl_iface_notify_scan_res,
	.notify_scan_done = wifimgr_ctrl_iface_notify_scan_done,
	.notify_connect = wifimgr_ctrl_iface_notify_connect,
	.notify_disconnect = wifimgr_ctrl_iface_notify_disconnect,
	.notify_scan_timeout = wifimgr_ctrl_iface_notify_scan_timeout,
	.notify_connect_timeout = wifimgr_ctrl_iface_notify_connect_timeout,
	.notify_disconnect_timeout = wifimgr_ctrl_iface_notify_disconnect_timeout,
	.notify_new_station = wifimgr_ctrl_iface_notify_new_station,
};

struct wifimgr_ctrl_cbs *get_wifimgr_cbs(void)
{
	return &wifi_ctrl_cbs;
}
