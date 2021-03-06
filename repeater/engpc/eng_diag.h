#ifndef __ENG_DIAG_H__
#define __ENG_DIAG_H__

#define ENG_DIAG_SIZE 1800

#define MAX_IMEI_LENGTH 8
#define MAX_IMEI_STR_LENGTH 15
#define MAX_BTADDR_LENGTH 6
#define MAX_WIFIADDR_LENGTH 6
#define GPS_NVINFO_LENGTH 44
#define DIAG_HEADER_LENGTH 8

#define DIAG_CMD_VER 0x00
#define DIAG_CMD_IMEIBTWIFI 0x5E
#define DIAG_CMD_READ 0x80
#define DIAG_CMD_GETVOLTAGE 0x1E
#define DIAG_CMD_APCALI 0x62
#define DIAG_CMD_FACTORYMODE 0x0D
#define DIAG_CMD_ADC_F \
  0x0F  // add by kenyliu on 2013 07 12 for get ADCV  bug 188809
#define DIAG_FM_TEST_F 0x41  // FM pandora
#define DIAG_CMD_AT 0x68
#define DIAG_CMD_CHANGEMODE DIAG_CHANGE_MODE_F

#define DIAG_CMD_DIRECT_PHSCHK 0x5F

#define DIAG_CMD_IMEI1BIT 0x01
#define DIAG_CMD_IMEI2BIT 0x02
#define DIAG_CMD_IMEI3BIT 0x10
#define DIAG_CMD_IMEI4BIT 0x20
#define DIAG_CMD_BTBIT 0x04
#define DIAG_CMD_WIFIBIT 0x40
#define DIAG_CMD_AUTOTEST 0x38
#define DIAG_CMD_PQ 0x5D

#define DIAG_CMD_CURRENT_TEST 0x11

#define DIAG_SYSTEM_F 0x5
#define DIAG_CMD_WIFI_TEST_F 0x36
#define DIAG_CMD_BUSMONITOR 0xFD

#define AUDIO_NV_ARM_INDI_FLAG 0x02
#define AUDIO_ENHA_EQ_INDI_FLAG 0x04
#define AUDIO_DATA_READY_INDI_FLAG \
  (AUDIO_NV_ARM_INDI_FLAG | AUDIO_ENHA_EQ_INDI_FLAG)

#define DIAG_SUB_MMICIT_READ 0x1A

typedef enum {
  EUT_REQ_INDEX = 0,  // sprd
  EUT_INDEX,
  WIFICH_REQ_INDEX,
  WIFICH_INDEX,
  WIFIMODE_REQ_INDEX,
  WIFIMODE_INDEX,  // sprd
  WIFIRATIO_REQ_INDEX,
  WIFIRATIO_INDEX,
  WIFITX_FACTOR_REQ_INDEX,
  WIFITX_FACTOR_INDEX,
  TX_REQ_INDEX,  // 10
  TX_INDEX,
  RX_REQ_INDEX,
  RX_INDEX,
  WIFIRX_PACKCOUNT_INDEX,
  WIFICLRRXPACKCOUNT_INDEX,
  GPSSEARCH_REQ_INDEX,
  GPSSEARCH_INDEX,
  GPSPRNSTATE_REQ_INDEX,
  GPSSNR_REQ_INDEX,
  GPSPRN_INDEX,  // 20
                 //------------------------------------------------
  ENG_WIFIRATE_INDEX,
  ENG_WIFIRATE_REQ_INDEX,
  ENG_WIFITXGAININDEX_INDEX,
  ENG_WIFITXGAININDEX_REQ_INDEX,
  ENG_WIFIRSSI_REQ_INDEX,
  //------------------------------------------------
  /* LNA */
  WIFILNA_REQ_INDEX,
  WIFILNA_INDEX,

  /* Band */
  WIFIBAND_REQ_INDEX,
  WIFIBAND_INDEX,

  /* Band Width */
  WIFIBANDWIDTH_REQ_INDEX,  // 30
  WIFIBANDWIDTH_INDEX,

  /* Signal Band Width */
  WIFISIGBANDWIDTH_REQ_INDEX,
  WIFISIGBANDWIDTH_INDEX,

  /* Tx Power Level */
  WIFITXPWRLV_REQ_INDEX,
  WIFITXPWRLV_INDEX,

  /* Pkt Length */
  WIFIPKTLEN_REQ_INDEX,
  WIFIPKTLEN_INDEX,

  /* TX Mode */
  WIFITXMODE_REQ_INDEX,
  WIFITXMODE_INDEX,

  /* Preamble */
  WIFIPREAMBLE_REQ_INDEX,
  WIFIPREAMBLE_INDEX,

  /* Payload */
  WIFIPAYLOAD_REQ_INDEX,  // 40
  WIFIPAYLOAD_INDEX,

  /* Guard Interval */
  WIFIGUARDINTERVAL_REQ_INDEX,
  WIFIGUARDINTERVAL_INDEX,

  /* MAC Filter */
  WIFIMACFILTER_REQ_INDEX,
  WIFIMACFILTER_INDEX,

  WIFIANT_REQ_INDEX,
  WIFIANT_INDEX,

  WIFINETMODE_INDEX,

  WIFIDECODEMODE_REQ_INDEX,
  WIFIDECODEMODE_INDEX,

  /* cbank */
  WIFICBANK_INDEX,
  WIFICDECEFUSE_INDEX,
  WIFICDECEFUSE_REQ_INDEX,

  /* wifi mac efuse*/
  WIFIMACEFUSE_REQ_INDEX,
  WIFIMACEFUSE_INDEX,

  WIFIANTINFO_REQ_INDEX,

  /* wifi set cal tx power*/
  WIFICALTXPWR_INDEX,
  WIFICALTXPWREFUSEEN_INDEX,

  /*set tpc mode*/
  WIFITPCMODE_INDEX,

  /* wifi set tssi*/
  WIFITSSI_INDEX,
  WIFIEFUSEINFO_REQ_INDEX,
} eut_cmd_enum;

typedef enum {
  NORMAL_MODE = 0,
  LAYER1_TEST_MODE = 1,
  ASSERT_BACK_MODE = 2,
  CALIBRATION_MODE = 3,
  DSP_CODE_DOWNLOAD_BACK = 4,
  DSP_CODE_DOWNLOAD_BACK_CALIBRATION = 5,
  BOOT_RESET_MODE = 6,
  PRODUCTION_MODE = 7,
  RESET_MODE = 8,
  CALIBRATION_POST_MODE = 9,
  PIN_TEST_MODE = 10,
  IQC_TEST_MODE = 11,
  WATCHDOG_RESET_MODE = 12,

  CALIBRATION_NV_ACCESS_MODE = 13,
  CALIBRATION_POST_NO_LCM_MODE = 14,

  TD_CALIBRATION_POST_MODE = 15,
  TD_CALIBRATION_MODE = 16,
  TD_CALIBRATION_POST_NO_LCM_MODE = 17,

  MODE_MAX_TYPE,

  MODE_MAX_MASK = 0x7F

} MCU_MODE_E;

typedef enum {
  CMD_COMMON = -1,
  CMD_USER_VER,
  CMD_USER_BTWIFIIMEI,
  CMD_USER_FACTORYMODE,
  CMD_USER_AUDIO,
  CMD_USER_RESET,
  CMD_USER_GETVOLTAGE,
  CMD_USER_APCALI,
  CMD_USER_APCMD,
  CMD_USER_ADC,
  CMD_USER_FM,
  CMD_USER_PRODUCT_CTRL,
  CMD_USER_PRODUCT_CTRL_EXT,//offset+data len::uint32 + uint32
  CMD_USER_DIRECT_PHSCHK,
  CMD_USER_MMICIT_READ,
  CMD_USER_DEEP_SLEEP,
  CMD_USER_FILE_OPER,
  CMD_USER_CFT_SWITCH,
  CMD_USER_BKLIGHT,
  CMD_USER_TXDATA,
  CMD_USER_TXDATA_EXT,
  CMD_USER_PWMODE,
  CMD_USER_SET_CONFIGURE_IP,
  CMD_USER_READ_REGISTER,
  CMD_USER_WRITE_REGISTER,
  CMD_USER_SHUT_DOWN,
  CMD_USER_GPS_AUTO_TEST,
  CMD_USER_AUTOTEST,
  CMD_USER_AUTOTEST_PATH_CONFIRM = 0x1c,
  CMD_USER_ENABLE_CHARGE_ONOFF,
  CMD_USER_GET_CHARGE_CURRENT,
  CMD_USER_READ_EFUSE,
  CMD_USER_READ_EFUSE_V2,
  CMD_USER_WRITE_EFUSE,
  CMD_USER_READ_PUBLICKEY,
  CMD_USER_ENABLE_SECURE,
  CMD_USER_READ_ENABLE_SECURE_BIT,
  CMD_USER_GET_MODEM_MODE,
  CMD_USER_ENABLE_BUSMOINITOR,
  CMD_USER_DISABLE_BUSMOINITOR,
  CMD_USER_GET_CHANINFO,
  CMD_USER_GET_RTCTIME,
  CMD_USER_GET_MONITORDATA,
  CMD_USER_MODEM_DB_ATTR,
  CMD_USER_MODEM_DB_READ,
  CMD_USER_READ_MMI = 0x3c,/* 0x3c*/
  CMD_USER_WRITE_MMI,
  CMD_USER_GET_TIME_SYNC_INFO,
  CMD_USER_TEE_PRODUCTION,
  CMD_USER_SET_MAX_CURRENT,
  CMD_USER_IFFA_SOFTER_REQ,
  CMD_USER_TRACE_DUMP,
  CMD_INVALID
} DIAG_CMD_TYPE;

typedef struct msg_head_tag {
  unsigned int seq_num;  // Message sequence number, used for flow control
  unsigned short len;    // The totoal size of the packet "sizeof(MSG_HEAD_T)
  // + packet size"
  unsigned char type;     // Main command type
  unsigned char subtype;  // Sub command type
} __attribute__((packed)) MSG_HEAD_T;


int eng_diag(struct device *uart, char *buf, int len);
void eng_dump(unsigned char *buf, int len, int col, int flag, char *keyword);

#endif
