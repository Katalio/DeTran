#ifndef __CLOUDAXS_H__
#define __CLOUDAXS_H__
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
#include <sys/sysinfo.h>

#define CLOUDAXS_PID_FILE "/var/run/cloudAXS.pid"
#define DATA_USAGE 4
#define SYS_INFO 6
#define NET_INFO 15
#define GPS_INFO 5

#define SEND 1
#define RECV 0

/*typedef enum _DATATYPE
{
    DATA_USAGE = 4,
    SYS_INFO = 6,
    NET_INFO = 15
}DATATYPE;*/

typedef struct {
	unsigned long total;
	unsigned long free;
	unsigned long shared;
	unsigned long buffers;
	unsigned long cached;
	unsigned long swaptotal;
	unsigned long swapfree;
	unsigned long maxfreeram;
} meminfo_t;

typedef struct _CLOUDAXS_CONFIG
{
	char svr_domain[128];
	unsigned long svr_domain_ip;
	int svr_port;
	int heartbeat_intval;
}CLOUDAXS_CONFIG;

typedef struct _CLOUD_CHECKBOX_NVRAM
{
   unsigned char flag;
   unsigned char name[64];
   int (*nvram_progress)(unsigned char *buff, int length);
}CLOUD_CHECKBOX_NVRAM;

int data_package(unsigned char *data, int len);
void send_data_to_server(void *arg);
void send_heartbeat_to_server(void *arg);
char *recv_data_from_server(char *recvdata, int *len);
void analysis_data(char *data);
char *reltime(char *buf, time_t t);
int get_memory(meminfo_t *m);

static int router_firmwire(unsigned char *buff, int length);
static int router_time(unsigned char *buff, int length);
static int router_uptime(unsigned char *buff, int length);
static int router_memory(unsigned char *buff, int length);
static int router_dns(unsigned char *buff, int length);
static int router_connection_uptime(unsigned char *buff, int length);
static int router_total_data_translate(unsigned char *buff, int length);
static int router_access_lan_device(unsigned char *buff, int length);
static int get_all_vpn_connect(unsigned char *buff, int length);
static int sim_select(unsigned char *buff, int length);
static int wan_status(unsigned char *buff, int length);
static int sim_status(unsigned char *buff, int length);
static int modem_status(unsigned char *buff, int length);
static int connect_status(unsigned char *buff, int length);
static int gps_time(unsigned char *buff, int length);
static int gps_position(unsigned char *buff, int length);

#endif //end __CLOUDAXS_H__
