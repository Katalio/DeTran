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

#pragma pack(1)

#define FTP_FILE_TMP "tmp.trx"
#define UDP_MAX_SEND_COUNT 1
#define SEND 1
#define RECV 0

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

#define M2M_HEAD_LEN 26
#define M2M_TLV_VALUE 1024
#define M2M_REQ_PDU_BUF 4500
#define M2M_RES_PDU_BUF 4500

typedef struct _M2M_PROTOCOL_HDR
{
	unsigned short len;		//00 2A
	unsigned short cmd_id;	//80 05
	unsigned int packet_id;	//00 00 00 01
	unsigned short version;	//01 00
	char product_id[24];		//31 38 39 31 32 33 34 35 36 37 38 00 00 00 00 00
}M2M_PROTOCOL_HDR;

typedef struct _M2M_PROTOCOL_HDR_T
{
	unsigned short len;
	unsigned short cmd_id;
	unsigned int packet_id;
	unsigned short version;
	unsigned char safe_flag;
	unsigned char type;
	char product_id[16];
} M2M_PROTOCOL_HDR_T;

typedef struct _M2M_PROTOCOL_TLV
{
	unsigned short tlv_tag;		//00 00
	unsigned short tlv_len;		//00 0B
	char tlv_value[1024];		//61 3D 31 30 30 26 62 3D 32 30 30 //a=100&b=200
}M2M_PROTOCOL_TLV;

typedef struct _M2M_LOGIN_NVRAM
{
	unsigned short tag_id;
	char *name;
} M2M_LOGIN_NVRAM;

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
	unsigned short	total;
	unsigned short	current;
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

#define M2M_CONFIG_REQ			0x000A
#define M2M_CONFIG_REQ_ACK	0x800A

#define REMOTE_CTRL				0x000B
#define REMOTE_CTRL_ACK		0x800B

#define DOWNLOAD_INFO			0x000C
#define DOWNLOAD_INFO_ACK		0x800C

#define DOWNLOAD_AD			0x000E
#define DOWNLOAD_AD_ACK		0x800E

#define DOWNLOAD_REPORT			0x000F
#define DOWNLOAD_REPORT_ACK		0x800F

#define REPORT_DEVICE			0x0010
#define REPORT_DEVICE_ACK		0x8010

#define REMOTE_DEVICE_CTRL 		0x0011
#define REMOTE_DEVICE_CTRL_ACK	0x8011

#define REPORT_URL				0x0012
#define REPORT_URL_ACK			0x8012

#define FILE_LIST_GET			0x0013
#define FILE_LIST_GET_ACK		0x8013

#define REPORT_FILE_LIST		0x0014
#define REPORT_FILE_LIST_ACK	0x8014

#define DELETE_FILE				0x0015
#define DELETE_FILE_ACK			0x8015

#define DOWNLOAD_CFG_FILE		0x0016
#define DOWNLOAD_CFG_FILE_ACK	0x8016

#define DOWNLOAD_INFO_EX		0x0019
#define DOWNLOAD_INFO_EX_ACK	0x8019

#define FILE_REQ				0x0020
#define FILE_REQ_ACK			0x8020

#define PACKET_CAP				0x0021
#define PACKET_CAP_ACK			0x8021

#define CAP_FILE_UPLOAD			0x0022
#define CAP_FILE_UPLOAD_ACK		0x8022

#define DOWNLOAD_CFG_UDP		0x0023
#define DOWNLOAD_CFG_UDP_ACK	0x8023

#define CFG_FILE_REQ			0x0024
#define CFG_FILE_REQ_ACK		0x8024

#define REPORT_STATUS			0x0025
#define REPORT_STATUS_ACK		0x8025

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

/* TAG INFORMATION */
#define TAG_DEVICE_TYPE				0x000F
#define TAG_DEVICE_SN				0x0011
#define TAG_OS_VERSION				0x000D
#define TAG_NULL					0xFFFF

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

