#ifndef __WIFI_MANAGER_SERVICE_H__
#define __WIFI_MANAGER_SERVICE_H__

#define MAX_SSID_LEN    32
#define MAX_PSWD_LEN    63
#define BSSID_LEN   6
#define OPCODE_BYTE   1
#define LEN_BYTE   2
#define WIFI_MAX_STA_NR   16

#define CMD_OPEN                       0x01
#define CMD_CLOSE                      0x02
#define CMD_SET_CONF_AND_CONNECT       0x03
#define CMD_DISCONNECT                 0x04
#define CMD_GET_STATUS                 0x05
#define CMD_GET_CONF                   0x06
#define CMD_START_AP                   0x07
#define CMD_DISABLE_BT                 0x08
#define CMD_SCAN                       0x09
#define CMD_STOP_AP                    0x0B
#define CMD_SET_MAC_ACL                0x0C
#define CMD_SET_INTERVAL			   0x0D

#define RESULT_OPEN                    0x81
#define RESULT_CLOSE                   0x82
#define RESULT_SET_CONF_AND_CONNECT    0x83
#define RESULT_DISCONNECT              0x84
#define RESULT_GET_STATUS              0x85
#define RESULT_GET_CONF                0x86
#define RESULT_START_AP                0x87
#define RESULT_SCAN_DONE               0x89
#define RESULT_SCAN_REPORT             0x8A
#define RESULT_STOP_AP                 0x8B
#define RESULT_STATION_REPORT          0x8C
#define RESULT_SET_CONF_AND_INTERVAL   0x8D
#define RESULT_MAC_ACL_REPORT          0x8E

enum wifimgr_iface_type {
	WIFIMGR_IFACE_STA = 0,
	WIFIMGR_IFACE_AP,
};

typedef struct {
	unsigned char wifi_type;
	char ssid[MAX_SSID_LEN+1];
	char bssid[BSSID_LEN+1];
	char passwd[MAX_PSWD_LEN+1];
	char security;
	unsigned char band;
	unsigned char channel;
	unsigned char ch_width;
	int autorun;
}wifi_config_type;

typedef struct {
	char ssid[MAX_SSID_LEN+1];
	char bssid[BSSID_LEN+1];
	unsigned char band;
	unsigned char channel;
	signed char signal;
	unsigned char security;
}wifi_scan_res_type;

typedef struct {
	unsigned char sta_status;
	unsigned char ap_status;
	char sta_mac[6];
	char ap_mac[6];
	char passwd[MAX_PSWD_LEN+1];
	union {
		struct {
			char host_rssi;
			u8_t h_ssid_len;
			u8_t h_bssid_len;
			char host_ssid[MAX_SSID_LEN + 1];
			char host_bssid[BSSID_LEN + 1];
		} sta;
		struct {
			unsigned char sta_nr;
			char sta_mac_addrs[WIFI_MAX_STA_NR][BSSID_LEN];
			unsigned char acl_nr;
			char acl_mac_addrs[WIFI_MAX_STA_NR][BSSID_LEN];
		} ap;
	} u;
}wifi_status_type;

enum {
	WIFI_STA_STATUS_NODEV,
	WIFI_STA_STATUS_READY,
	WIFI_STA_STATUS_SCANNING,
	WIFI_STA_STATUS_CONNECTING,
	WIFI_STA_STATUS_CONNECTED,
	WIFI_STA_STATUS_DISCONNECTING,
};

enum wifimgr_sm_ap_state {
	WIFI_AP_STATUS_NODEV,
	WIFI_AP_STATUS_READY,
	WIFI_AP_STATUS_STARTED,
};

enum {
	RESULT_SUCCESS,
	RESULT_FAIL,
};

void wifi_manager_service_init(void);
void wifi_manager_notify(const void *data, u16_t len);
int wifimgr_do_scan(int retry_num);
int wifimgr_do_connect(void);
int wifimgr_do_disconnect(u8_t flags);
int wifimgr_do_open(char *iface_name);
int wifimgr_check_wifi_status(char *iface_name);
int wifimgr_do_close(char *iface_name);
#endif
