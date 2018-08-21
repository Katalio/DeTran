#include "cloudAXS.h"

#define PORT 51061
#define BUFF_SIZE 1024
#define TMP_LEN 128 

const char dest_ip[16] = "89.151.126.222";
char comma[] = ",";
char quote[] = "'";
static int rate = 0;

void get_router_time(char *s);
void get_uptime(char *s);
void get_memory(char *s);
void get_dns_info(char *s);
void get_connection_uptime(char *s);
static void compare_with_comma(char *buf);

static int connect_to_cloudAXS_server(const char *svr_ip, unsigned long svr_port)
{
	struct sockaddr_in serveraddr;
	int sockfd;
	int flag = 1;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (-1 == sockfd)
	{
//		syslog(LOG_ERR, "M2M TCP Socket Creat Error!!!");
		return -1;
	}

	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&flag, sizeof(flag));

	bzero(&serveraddr, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(svr_port);
//	serveraddr.sin_addr.s_addr = inet_addr(svr_ip);
	serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);

	if((flag = connect(sockfd, (struct sockaddr*)&serveraddr, sizeof(serveraddr))) < 0)
	{
		return -1;
	}

	return sockfd;
}

void get_router_time(char *s)
{
    time_t t;

	t = time(NULL);
 	strftime(s, TMP_LEN, "%a,%d %b %Y %H:%M:%S %z", localtime(&t));
}

#if 0
void get_uptime(char *s)
{
	struct sysinfo si;
	sysinfo(&si);
	reltime(s, si.uptime);
}

void get_memory(char *s)
{
	meminfo_t mem;
	get_memory(&mem);
	mem.total;
	mem.free;
	sprintf(s, "%s/%s", mem.total, mem.free);
}

void get_dns_info(char *s)
{
	int i;
	const dns_list_t *dns;
	dns = get_dns();        // static buffer
	for (i = 0 ; i < dns->count; ++i) 
	{
		sprintf(s + strlen(s), "%s'%s:%u'", i ? "," : "", inet_ntoa(dns->dns[i].addr), dns->dns[i].port);
	}
}

void get_connection_uptime(char *s)
{
	struct sysinfo si;
	long uptime;
	
	s[0] = '-';
	s[1] = 0;
	sysinfo(&si);
	if(f_read("/var/lib/misc/wantime", &uptime, sizeof(uptime)) == sizeof(uptime))
	{
		reltime(s, si.uptime - uptime);
	}
}
#endif

static void compare_with_comma(char *buf)
{
	int len = strlen(buf);

	do
	{
		buf[len -2] = buf[len - 1];
		buf[len -1] = 0;

		len -= 1;
	}while (buf[len-2] == comma[0]);
}

static void minimum_data(char *data)
{
	char main_buff[BUFF_SIZE] = {0};
 	strncpy(main_buff, "i=>'", strlen("i=>'"));

	strcat(main_buff, "867377020199547");		
	strcat(main_buff, comma);
	strcat(main_buff, "12345678");
	strcat(main_buff, quote);

	strncpy(data, main_buff, strlen(main_buff));
}

static int data_package(char *data)
{
	char sysinfo_buff[BUFF_SIZE] = {0};
	char netinfo_buff[BUFF_SIZE] = {0};
	char data_usage_buff[BUFF_SIZE] = {0};
    char s[TMP_LEN] = {0};
    time_t t;

 	strncpy(sysinfo_buff, "s=>'", strlen("s=>'"));
 	strncpy(netinfo_buff, "n=>'", strlen("n=>'"));
 	strncpy(data_usage_buff, "d=>'", strlen("d=>'"));

	minimum_data(data);
	
	strcat(sysinfo_buff, "router_name");	
	strcat(sysinfo_buff, comma);
	strcat(sysinfo_buff, "router_hw");	
	strcat(sysinfo_buff, comma);
	strncpy(s, "router_", strlen("router_"));
	strcat(s, "os_version");	
	strcat(sysinfo_buff, s);	
	memset(s, 0, TMP_LEN);
	strcat(sysinfo_buff, comma);

	/* router time */
//	t = time(NULL);
// 	strftime(s, sizeof(s), "%a,%d %b %Y %H:%M:%S %z", localtime(&t));
	get_router_time(s);
	strcat(sysinfo_buff, s);	
	strcat(sysinfo_buff, comma);
//	memset(s, 0, TMP_LEN);
	///* uptime */
	//get_uptime(s);
	//strcat(sysinfo_buff, s);	
	//strcat(sysinfo_buff, comma);
	//memset(s, 0, TMP_LEN);
	///* total/free memory */
	//get_memory(s);
	//strcat(sysinfo_buff, s);	
	//strcat(sysinfo_buff, comma);
	//memset(s, 0, TMP_LEN);
		
	strcat(sysinfo_buff, quote);
	/* Judge whether the last one is comma */
	compare_with_comma(sysinfo_buff);

	//network information
	strcat(netinfo_buff, "wan_iface");	
	strcat(netinfo_buff, comma);
	strcat(netinfo_buff, "wan_hwaddr");	
	strcat(netinfo_buff, comma);
	strcat(netinfo_buff, "modem_type");	
	strcat(netinfo_buff, comma);
	strcat(netinfo_buff, "modem_state");	
	strcat(netinfo_buff, comma);
	strcat(netinfo_buff, "sim_selected");	
	strcat(netinfo_buff, comma);
	strcat(netinfo_buff, "cops");	
	strcat(netinfo_buff, comma);
	strcat(netinfo_buff, "cell_network");	
	strcat(netinfo_buff, comma);
	strcat(netinfo_buff, "sim_state");	
	strcat(netinfo_buff, comma);
	strcat(netinfo_buff, "csq");	
	strcat(netinfo_buff, comma);
	strcat(netinfo_buff, "wanip");	
	strcat(netinfo_buff, comma);
	strcat(netinfo_buff, "wannetmask");	
	strcat(netinfo_buff, comma);
	strcat(netinfo_buff, "wangateway");	
	strcat(netinfo_buff, comma);
	///* DNS */
	//get_dns_info(s);
	//strcat(netinfo_buff, s);	
	//strcat(netinfo_buff, comma);
	//memset(s, 0, TMP_LEN);

	strcat(netinfo_buff, "wanstatus");	
	strcat(netinfo_buff, comma);
	/* connection uptime */
	//get_connection_uptime(s);
	//strcat(netinfo_buff, s);	
	//strcat(netinfo_buff, comma);
	//memset(s, 0, TMP_LEN);

	strcat(netinfo_buff, quote);
	compare_with_comma(netinfo_buff);

	//data usage 
	strcat(data_usage_buff, "active lan");	
	strcat(data_usage_buff, comma);
	strcat(data_usage_buff, "wl_radio");	
	strcat(data_usage_buff, comma);
	strcat(data_usage_buff, "active_vpns");	
	strcat(data_usage_buff, comma);
	strcat(data_usage_buff, "data send");	
	strcat(data_usage_buff, comma);
	strcat(data_usage_buff, "data received");	

	strcat(data_usage_buff, quote);
	compare_with_comma(data_usage_buff);

	strcat(data, "|");
	strcat(data, sysinfo_buff);
	strcat(data, "|");
	strcat(data, netinfo_buff);
	strcat(data, "|");
	strcat(data, data_usage_buff);

	data[strlen(data)] = '\n';

	return 0;
}

void *send_data_to_server(void *sockfd)
{
	int n = 0;
	char sendbuff[BUFF_SIZE];

	while(1)
	{
		sleep(10);		//数据上报时间间隔
		memset(sendbuff, 0, BUFF_SIZE);
		if(data_package(sendbuff) != 0)
		{
//			syslog(LOG_ERR, "Package Data Error!!!");
//			return -1;
		}
		n = send(*(int *)sockfd, sendbuff, strlen(sendbuff), 0); 
		if(n < 0) {
//			syslog(LOG_ERR, "Send to Server Error!!!");
//			return -1;
		}

		printf("send to server: %s\n", sendbuff);
	}

//	return 0;
}

void *send_heartbeat_to_server(void *sockfd)
{
	int n = 0;
	char sendbuff[BUFF_SIZE];

	while(1)
	{
		sleep(5);		//心跳包发送时间间隔
		memset(sendbuff, 0, BUFF_SIZE);
		strncpy(sendbuff, "Heartbeat data(online)", strlen("Heartbeat data(online)"));
		n = send(*(int *)sockfd, sendbuff, strlen(sendbuff), 0); 
		if(n < 0) {
//			syslog(LOG_ERR, "Send to Server Error!!!");
//			return -1;
		}
	
		printf("send to server: %s\n", sendbuff);
	}

//	return 0;
}

static char *recv_data_from_server(int sockfd, char *recvdata, int *len)
{
	int n = 0;

	n = recv(sockfd, recvdata, BUFF_SIZE, 0);
	if(n < 0)
	{
//		syslog(LOG_ERR, "Receive from Server Error!!!");
		return NULL;
	}

	return recvdata;
}

static void analysis_data(char *data)
{
	char s[5] = {};
	int i, j;

	if(data[4] == '0')
	{
//		syslog(LOG_ERR, "Successfully receive data on cloudAXS server");
		printf("Successfully receive data on cloudAXS server\n");

		if(data[7] == 'u')
		{
			if(data[11] == '0')
			{
//				syslog(LOG_ERR, "System option off");
				printf("System option off\n");
//				sys_option_off();
			}
			else if(data[11] == '1')
			{
//				syslog(LOG_ERR, "System option on");
				printf("System option on\n");
//				sys_option_on();
			}
			else
			{
//				syslog(LOG_ERR, "Unknown System option flag");
				printf("Unknown System option flag\n");
				
			}

			if(data[13] == '0')
			{
//				syslog(LOG_ERR, "Network option off");
				printf("Network option off\n");
//				net_option_off();
			}
			else if(data[13] == '1')
			{
//				syslog(LOG_ERR, "Network option on");
				printf("Network option on\n");
//				net_option_on();
			}
			else
			{
//				syslog(LOG_ERR, "Unknown Network option flag");
				printf("Unknown Network option flag\n");
				
			}

			if(data[15] == '0')
			{
//				syslog(LOG_ERR, "Data option off");
				printf("Data option off\n");
//				data_option_off();
			}
			else if(data[15] == '1')
			{
//				syslog(LOG_ERR, "Data option on");
				printf("Data option on\n");
//				data_option_on();
			}
			else
			{
//				syslog(LOG_ERR, "Unknown Data option flag");
				printf("Unknown Data option flag\n");
				
			}
			
			for(i = 17, j = 0; i <= 19; i ++, j ++)
			{
				s[j] = data[i];
			}

			rate = atoi(s) / 60;
			printf("rate is %d mins\n", rate);

//			update(rate);	//上报速率，待完成
		}
	}
	else if(data[4] == '1')
	{
//		syslog(LOG_ERR, "Account ID or IMEI Number is blank on cloudAXS server");
		printf("Account ID or IMEI Number is blank on cloudAXS server\n");
	}
	else if(data[4] == '2')
	{
//		syslog(LOG_ERR, "Unknown Account ID on cloudAXS server");
		printf("Unknown Account ID on cloudAXS server\n");
	}
	else if(data[4] == '3')
	{
//		syslog(LOG_ERR, "Unknown IMEI Number on cloudAXS server");
		printf("Unknown IMEI Number on cloudAXS server\n");
	}
	else if(data[4] == '4')
	{
//		syslog(LOG_ERR, "IMEI Number not registered with Account ID");
		printf("IMEI Number not registered with Account ID\n");
	}
	else if(data[4] == '5')
	{
		printf("Reboot router asap\n");
//		reboot_router();	//待完成
	}
	else
	{
		printf("Unknown command\n");
	}
}

int main()
{
	int sockfd = 0;
	char recvbuff[BUFF_SIZE];
	int len = 0;
	int n = 0, ret = 0;
	pthread_t data_pid = 0;
	pthread_t hb_pid = 0;

	sockfd = connect_to_cloudAXS_server(dest_ip, PORT);
	if(sockfd < 0) 
	{
	//	syslog(LOG_ERR, "cloudAXS Server Connect Error!!!");
		return -1;
	}

	ret = pthread_create(&data_pid, NULL, &send_data_to_server, &sockfd);	//线程1, 发送数据
	if(ret < 0)
	{
		perror("create data pid failed");
		return -1;
	}
	ret = pthread_create(&hb_pid, NULL, &send_heartbeat_to_server, &sockfd);	//线程2, 发送心跳包
	if(ret < 0)
	{
		perror("create data pid failed");
		return -1;
	}

	fd_set rfds;

	while(1)
	{
		FD_ZERO(&rfds);
		FD_SET(0, &rfds);
		FD_SET(sockfd, &rfds);

		n = select(sockfd + 1, &rfds, NULL, NULL, NULL);
		if(n < 0) 
		{
		//	syslog(LOG_ERR, "select() Error!!!");
			return -1;
		}

		if(FD_ISSET(sockfd, &rfds))
		{
			memset(recvbuff, 0, BUFF_SIZE);
			if(NULL == recv_data_from_server(sockfd, recvbuff, &len))
			{
			//	syslog(LOG_ERR, "Receive Data Error!!!");
				return -1;
			}
			printf("receive data success\n");

			analysis_data(recvbuff);
		}
	}

	close(sockfd);

	return 0;
}



