#ifndef __M2M_H__
#define __M2M_H__
#include	<stdio.h>      
#include	<stdlib.h>     
#include	<string.h>
#include	<sys/socket.h>
#include	<sys/select.h>
#include	<sys/types.h> 
#include	<sys/stat.h>
#include	<sys/time.h>
#include	<sys/ioctl.h>
#include	<netinet/in.h>
#include	<netinet/ether.h>
#include	<netinet/ip_icmp.h> 
#include	<arpa/inet.h>
#include	<netdb.h>
#include 	<sys/un.h>
#include 	<dirent.h>

#include	<unistd.h>     
#include	<signal.h>
#include 	<sys/wait.h>
#include	<fcntl.h>      
#include	<termios.h>   
#include	<errno.h>    
#include	<pthread.h>
#include 	<stdarg.h>

#include <sys/reboot.h>
#include <stdint.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <ctype.h>



#pragma pack(1)

#define FTP_FILE_TMP_PATH "/tmp/"
#define UDP_MAX_SEND_COUNT 1
#define SEND 1
#define RECV 0
#define M2M_PID_FILE "/var/run/m2m.pid"

typedef struct _M2M_CONFIG
{
	char svr_domain[128];
	unsigned long svr_domain_ip;
	char svr_ip_str[16];
	unsigned long svr_ip;
	int svr_port;
	char bind_ip_str[16];
	unsigned long bind_ip;
	int bind_port;
	int heartbeat_intval;
}M2M_CONFIG;

#define M2M_HEAD_LEN 28
#define M2M_TLV_VALUE 7168
#define M2M_REQ_PDU_BUF 4500
#define M2M_RES_PDU_BUF 1024*64
#define SN_LENGTH 16
#define BUF_LEN  2048
#define M2M_VERSION 0x0300
#define TCP_UPLOAD_DOWNLOAD_LEN 64000
#define UDP_UPLOAD_DOWNLOAD_LEN 2000

#define MODEM_SN_TAG 0x0001 //模块序号
#define MODEM_IMEI_TAG 0x0002 //IMEI
#define MODEM_TYPE_TAG 0x0003 //模块型号
#define MODEM_PRODUCT_TAG 0x0004 //模块生产厂家
#define SIM_SN_TAG  0x0005 //SIM卡序号
#define MODEM_IMSI_TAG 0x0006 //IMSI
#define MODEM_ICCID_TAG   0x0007 //ICCID
#define SIM_NUM_TAG 0x0008 //SIM卡号
#define OPERATOR_NAME_TAG 0x0009 //运营商名称
#define NETWORK_MODE_TAG  0x000A //网络模式
#define NETWORK_FRAME_TAG 0x000B //网络频段
#define DEVICE_TYPE_TAG   0x000C //设备制式
#define FIRMWARE_TAG   0x000D //软件版本号
#define TACH_FIRMWARE_TAG 0x000E //附属软件版本号
#define DEVICE_NETWORK_TAG   0x000F //设备型号
#define DEVICE_RENAME_TAG 0x0010 //设备别名
#define DEVICE_PRODUCT_SN_TAG   0x0011 //设备出厂产品序号,贴在设备背后的条码
#define BASE_STATION1_MNC_TAG   0x0012 //基站1 mnc
#define BASE_STATION1_LAC_TAG   0x0013 //基站1 lac
#define BASE_STATION1_CELLID_TAG   0x0014 //基站1 cellid
#define BASE_STATION2_MNC_TAG   0x0015 //基站2 mnc
#define BASE_STATION2_LAC_TAG   0x0016 //基站2 lac
#define BASE_STATION2_CELLID_TAG   0x0017 //基站2 cellid
#define BASE_STATION3_MNC_TAG   0x0018 //基站3 mnc
#define BASE_STATION3_LAC_TAG   0x0019 //基站3 lac
#define BASE_STATION3_CELLID_TAG   0x001A //基站3 cellid
#define WIFI_AP_LIST_TAG  0x001B //Wifi AP列表
#define HOST_SN_TAG 0x001C //宿主机host SN
#define USER_CONFIG1_TAG  0x001D //用户配置信息1
#define USER_CONFIG2_TAG  0x001E //用户配置信息2
#define USER_CONFIG3_TAG  0x002F //用户配置信息3
#define SERIAL_STATUS_REPORT_TAG   0x0020 //串口状态上报
#define LAN_STATUS_REPORT_TAG   0x0021 //以太网(LAN)口状态
#define USB_STATUS_REPORT_TAG   0x0022 //USB口状态
#define RELAY_STATUS_TAG  0x0023 //外接继电器状态
#define CPU_TAG  0x0024 //CPU使用率
#define MEMORY_TAG  0x0025 //内存使用率
#define FLASH_TAG   0x0026 //内部存储使用率
#define DISK_TAG 0x0027 //扩展存储使用率
#define CHIP_TEMPRETURE_TAG  0x0028 //芯片温度
#define BATTERY_VAL_TAG   0x0029 //电池电压
#define BACKUP_BATTERY_VAL_TAG  0x002A //备用电池电压
#define PUBLISH_DATA_TLV_CMD 0x0130
#define PUBLISH_TIME_TLV_CMD 0x0131

#define SERIAL  "/dev/ttyS0"

typedef struct _M2M_PROTOCOL_HDR
{
	unsigned short len;		//00 2A
	unsigned short cmd_id;	//80 05
	unsigned int packet_id;	//00 00 00 01
	unsigned short version;	//01 00
	unsigned char safe_flag;
   unsigned char data_type;//0 is for router, 1 is for lora
	char product_id[SN_LENGTH];		//31 38 39 31 32 33 34 35 36 37 38 00 00 00 00 00
}M2M_PROTOCOL_HDR;

typedef struct _M2M_PROTOCOL_DOWNLOAD_PARAM
{
   unsigned char protocol;
   unsigned char file_number;
   unsigned char file_type;
   unsigned char unused;
}M2M_PROTOCOL_DOWNLOAD_PARAM;

typedef struct _M2M_PROTOCOL_DOWNLOAD_FILE
{
   unsigned int file_len;
   unsigned int file_id;
   unsigned char file_name[64];
   unsigned char file_md5[32];
}M2M_PROTOCOL_DOWNLOAD_FILE;

typedef struct _M2M_PROTOCOL_FILE_REQ
{
   unsigned int file_id;
   unsigned int offset;
   unsigned int req_len;
   unsigned int task_id;
}M2M_PROTOCOL_FILE_REQ;

typedef struct _M2M_PROTOCOL_TLV
{
	unsigned short tlv_tag;		//00 00
	unsigned short tlv_len;		//00 0B
	char tlv_value[M2M_TLV_VALUE];		//61 3D 31 30 30 26 62 3D 32 30 30 //a=100&b=200
}M2M_PROTOCOL_TLV;

typedef struct _RTU_PUBLISH_DATA
{
   unsigned char data_type;//00: 系统数据 01: 采集数据 02:告警数据
   unsigned char slave_id;
   unsigned short regaddr;
}RTU_PUBLISH_DATA;

typedef struct _DOWNLOAD_REPORT_HEAD
{
	unsigned char status;
	unsigned int cmd_sn;
	unsigned int filesize;
	unsigned short filename_len;
}DOWNLOAD_REPORT_HEAD;


typedef struct _M2M_TL
{
	unsigned short tag;
	unsigned short len;
}M2M_TL;

typedef struct _FILE_INFO
{
	unsigned int size;
	unsigned int id;
	unsigned char filename[64];
	unsigned char md5[32];
}FILE_INFO;

typedef struct _ST_FILE_REQ
{
	unsigned int id;
	unsigned int off;
	unsigned int len;
	unsigned int cmd_sn;
}ST_FILE_REQ;


#define M2M_UDP	1
#define M2M_TCP	2
#define M2M_FTP	3
typedef struct _ST_DOWNLOAD_INFO_EX
{
	unsigned char type;
	unsigned char filecount;
	unsigned short reserve;
	FILE_INFO filelist[];
}ST_DOWNLOAD_INFO_EX;

typedef struct _ST_PACKET_CAP
{
	unsigned int  id;
	unsigned int  start;
	unsigned int  end;
	unsigned char type;
}ST_PACKET_CAP;

typedef struct _ST_PACKET_CAP_UPLOAD
{
	unsigned int  	id;
   unsigned int offset;
	unsigned int	total;
   unsigned char md5[32];
}ST_PACKET_CAP_UPLOAD;


#define M2M_LOGIN				0x0001
#define M2M_LOGIN_ACK			0x8001

#define M2M_LOGOUT				0x0002
#define M2M_LOGOUT_ACK		0x8002

#define M2M_HEARTBEAT			0x0003
#define M2M_HEARTBEAT_ACK		0x8003

#define M2M_CONFIG_GET			0x0005
#define M2M_CONFIG_GET_ACK	0x8005

#define M2M_CONFIG_SET			0x0006
#define M2M_CONFIG_SET_ACK	0x8006

#define M2M_CONFIG_TRAP		0x0007
#define M2M_CONFIG_TRAP_ACK	0x8007

#define M2M_REGISTER			0x0008
#define M2M_REGISTER_ACK		0x8008

#define REPORT_STATUS			0x0009
#define REPORT_STATUS_ACK		0x8009

#define M2M_CONFIG_REQ			0x000A
#define M2M_CONFIG_REQ_ACK	0x800A

#define REMOTE_CTRL				0x000B
#define REMOTE_CTRL_ACK		0x800B

#define DOWNLOAD_INFO			0x000C
#define DOWNLOAD_INFO_ACK		0x800C

#define FILE_REQ           0x000D
#define FILE_REQ_ACK           0x800D

#define UPLOAD_FILE			0x000E
#define UPLOAD_FILE_ACK		0x800E

#define DOWNLOAD_REPORT			0x000F
#define DOWNLOAD_REPORT_ACK		0x800F

#define RTU_PUBLISH			0x0010
#define RTU_PUBLISH_ACK		0x8010

#define RTU_SUB 		0x0011
#define RTU_SUB_ACK	0x8011

#define OUTPUT_CNTL				0x0012
#define OUTPUT_CNTL_ACK			0x8012

#define RTU_SCRIPT_GET			0x0013
#define RTU_SCRIPT_GET_ACK		0x8013

#define RTU_SCRIPT_SET		0x0014
#define RTU_SCRIPT_SET_ACK	0x8014

#define RTU_SCRIPT_TRAP				0x0015
#define RTU_SCRIPT_TRAP_ACK			0x8015

#define DOWNLOAD_CFG_FILE		0x0016
#define DOWNLOAD_CFG_FILE_ACK	0x8016

#define DOWNLOAD_INFO_EX		0x0019
#define DOWNLOAD_INFO_EX_ACK	0x8019

#define PACKET_CAP				0x0021
#define PACKET_CAP_ACK			0x8021

#define CAP_FILE_UPLOAD			0x0022
#define CAP_FILE_UPLOAD_ACK		0x8022

#define DOWNLOAD_CFG_UDP		0x0023
#define DOWNLOAD_CFG_UDP_ACK	0x8023

#define CFG_FILE_REQ			0x0024
#define CFG_FILE_REQ_ACK		0x8024



#define QUERY_DEVICE			0x0026
#define QUERY_DEVICE_ACK		0x8026

#define SYNC_TIME				0x0027
#define SYNC_TIME_ACK			0x8027

#define SEND_SMS				0x0028
#define SEND_SMS_ACK			0x8028

#ifdef TCONFIG_N2N
#define M2M_VT_IP_REQ           0x0029
#define M2M_VT_IP_ACK           0x8029

#define M2M_VT_CH_REPORT        0x0030
#define M2M_VT_CH_REPORT_ACK    0x8030
#endif
#define OEM_CAMERA_CONFIG_SET		0x00A0
#define OEM_CAMERA_CONFIG_SET_ACK	0x80A0

#define OEM_CAMERA_CONFIG_GET		0x00A1
#define OEM_CAMERA_CONFIG_GET_ACK	0x80A1

#define OEM_CAMERA_RESET		0x00A2
#define OEM_CAMERA_RESET_ACK	0x80A2

#define CLIENT_MAC				0x0001
#define CLINET_TRAFIC			0x0002
#define CLIENT_STATUS			0x0003
#define TAG0004					0x0004
#define CLIENT_VISITED_URL		0x0005
#define CLIENT_MAIL				0x0006
#define CLIENT_PHONE			0x0007
#define CLIENT_WEIXIN			0x0008
#define CLIENT_AUTH_CODE		0x0009
#define ID_CARD					0x000a
#define CLIENT_NAME				0x000b
#define PACKET_TOTAL			0x0010
#define PACKET_CURRENT			0x0011
#define FILE_NAME				0x0012
#define FILE_SIZE				0x0013

#define CLIENT_MAC_LEN		12
#define CLIENT_TRAFIC_LEN	4
#define CLIENT_STATUS_LEN	1

#define CLIENT_STATUS_UP	0x01
#define CLIENT_STATUS_HB	0x02
#define CLIENT_STATUS_DOWN	0x03
#define CLIENT_STATUS_CONN	0x05
#define CMD_DEVICE_OFFLINE	"device_offline"


#define M2M_TCP_LOGIN				0x0001
#define M2M_TCP_LOGIN_ACK			0x8001
#define M2M_TCP_LOGOUT				0x0002
#define M2M_TCP_LOGOUT_ACK			0x8002
#define M2M_TCP_FILE_REQ			0x0003
#define M2M_TCP_FILE_REQ_ACK		0x8003
#define M2M_TCP_MD5					0x0004
#define M2M_TCP_MD5_ACK				0x8004
#define	M2M_TCP_FILE_PUT_REQ		0x0005
#define	M2M_TCP_FILE_PUT_REQ_ACK	0x8005
#define M2M_TCP_FILE_PUT			0x0006
#define M2M_TCP_FILE_PUT_ACK		0x8006

typedef struct _M2M_TCP_HDR
{
	unsigned short prefix;
	unsigned short cmd_id;
	unsigned int len;
	unsigned int serial;
	unsigned short version;
}M2M_TCP_HDR;

typedef struct _TCP_FILE_REQ
{
	unsigned int id;
	unsigned int cmd_sn;
	unsigned int off;
	unsigned int len;
}TCP_FILE_REQ;

#define SF_BOX_PORT	1566
#define SF_JSON_ELM_COUNT 20
#define JSON_BUF_LEN 1024
typedef struct _elm{
	char *name;
	char *value;
}json_elm;

typedef struct _json{
	char *buf;
	int elm_count;
}json;

typedef struct serialHead{
	unsigned char serHead;
	unsigned char type;
	unsigned short length;
}SERIALHEAD;

typedef struct serialTail{
	unsigned char check;
	unsigned char tail;
}SERIALTAIL;

typedef struct snNode{
	struct snNode *next;
	unsigned char sn[SN_LENGTH];
	unsigned char report;//the flag indicate whether the sn is reported to server
}SNNODE;

typedef struct serial_config
{
    int rate;
    char parity;
    char databits;
    char stopbits;
    char streamcontrol;
} SERIAL_CONFIG_T;

typedef struct baudmap
{
	unsigned int	 baud;
	unsigned int	 flag;
}baudmap_t;

typedef struct baudmap_struct
{
	unsigned int baud;
	unsigned int flag;
}baudmap_st;

/*

SN: 18912345678

心跳：
00 1F 00 03 00 00 00 01 01 00 31 38 39 31 32 33 34 35 36 37 38 00 00 00 00 00 64 00 00 FF FF
登出
00 1A 00 02 00 00 00 01 01 00 31 38 39 31 32 33 34 35 36 37 38 00 00 00 00 00
参数上报
00 2A 80 05 00 00 00 01 01 00 31 38 39 31 32 33 34 35 36 37 38 00 00 00 00 00 00 00 00 00 0B 61 3D 31 30 30 26 62 3D 32 30 30
*/

#pragma pack()

#endif //__M2M_H__

