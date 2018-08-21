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
#include 	<syslog.h>

#include <sys/reboot.h>
#include <stdint.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <linux/sysinfo.h>

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

typedef struct {
	int count;
	struct {
		struct in_addr addr;
		unsigned short port;
	} dns[6];
} dns_list_t;

static void minimum_data(char *data);
static int connect_to_cloudAXS_server(const char *svr_ip, unsigned long svr_port);
static int data_package(char *data);
void *send_data_to_server(void *sockfd);
void *send_heartbeat_to_server(void *sockfd);
static char *recv_data_from_server(int sockfd, char *recvdata, int *len);
static void analysis_data(char *data);

#endif //end __CLOUDAXS_H__
