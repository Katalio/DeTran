/*************************************************************************
	> File Name: dtu_new.h
	> Author: zhangguocheng
	> Mail: gczhang@detran.com.cn
	> Created Time: Mon 09 May 2016 03:42:42 PM CST
 ************************************************************************/

#ifndef _DTU_NEW_H
#define _DTU_NEW_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <net/if.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <getopt.h>
#include <errno.h>
#include <sys/termios.h>
#include <dirent.h>
#include <syslog.h>
#include <pthread.h>

#define DTU_PID_FILE "/var/run/dtu.pid"

#define MAX_CIRCLE_QUEUE_SIZE		8192
#define MAX_SVR_CENTER	2	
#define DEFAULT_MAX_LEN 1024
 
typedef struct table{
	char *modem_name;
	char *port_name;
}MODEM_TO_PORT_TABLE;

typedef struct _CircleQueue  
{  
    char *data;
    int front;
    int rear;
    int count;
    int maxItem;
} CIRCLEQUEUE_T;  


typedef struct baudmap
{
	unsigned int	 baud;
	unsigned int	 flag;
}baudmap_t;


enum {
	DTU_MODE_DISABLED=0x00,
	DTU_MODE_CLIENT,
	DTU_MODE_SERVER
};

enum {
	DTU_SOCKET_TCP=0x00,
	DTU_SOCKET_UDP
};



typedef struct serial_config
{
	int rate;
	char parity;
	char databits;
	char stopbits;
	char streamcontrol;
} SERIAL_CONFIG_T;

typedef struct server_param_st
{
	char svr_addr[128];		
	char svr_port[8];

	unsigned long svr_ip;

	int  svr_connect_times;	
	int  svr_connect_timeout;
	int  svr_connect_interval;
} SERVER_PARAM_T;

typedef struct data_frame_st
{
	int max_len;
	int timeout;
	int serial_timeout;
} DATA_FRAME_T;


typedef struct heartbeat_param_st
{
	char heartbeat;	
	int  heartbeat_interval;
	char router_id[12];
	char content[65];
} HEARTBEAT_PARAM_T;

typedef struct _mqtt_config_t
{
	char usrname[32];
	char passwd[16];
	char pub_topic[255];
	char sub_topic[255];
} MQTT_CONFIG_T;

#define RCVBUFSIZE 8192 


typedef struct _dtu_config_t
{
	int 	keepalive_interval;
	int 	connect_times;
	int 	reconnect_interval;
	int 	sleeptime;
	char 	mode;
	char 	protocol;
	char 	keepalive;
	DATA_FRAME_T 	data;
	SERVER_PARAM_T 	server[MAX_SVR_CENTER];
	SERVER_PARAM_T 	local;
	HEARTBEAT_PARAM_T heartbeat;
//#ifdef TCONFIG_NEWBEI_RELAY
    char 	relay_proto[16];
	char 	nb_router_id[25];
	int 	nb_router_id_len;
	char 	nb_ht_content[24];
	int 	nb_ht_length;
	int 	prefix_type;
	int 	del_prefix_index;
	char 	prefix_content[24];
	int 	prefix_content_len;
//#endif
}DTU_CONFIG_T;



typedef struct data_process_hook
{
	char name[16];
	char portName[24];
	int	(*init_config)(DTU_CONFIG_T *dtuConf, SERIAL_CONFIG_T *serConf, MQTT_CONFIG_T *mqttConf);
	void *(*data_process)(int serialFd, DTU_CONFIG_T *dtuConfig, SERIAL_CONFIG_T *serConf, MQTT_CONFIG_T *mqttConf);
} DATA_PROCESS_HOOT_T;




#endif
