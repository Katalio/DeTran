#include "cloudAXS.h"

#define port 51061
#define BUFF_SIZE 1024

const char dest_ip[16] = "89.151.126.222";
char main_buff[BUFF_SIZE];
char sysinfo_buff[BUFF_SIZE];
char netinfo_buff[BUFF_SIZE];
char data_usage_buff[BUFF_SIZE];
char comma[] = ",";
char quote[] = "'";
static int rate = 0;

int connect_to_cloudAXS_server(const char *svr_ip, unsigned long svr_port)
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
	serveraddr.sin_addr.s_addr = inet_addr(svr_ip);
//	serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);

	if((flag = connect(sockfd, (struct sockaddr*)&serveraddr, sizeof(serveraddr))) < 0)
	{
		return -1;
	}

	return sockfd;
}

char *minimum_data(void)
{
 	strncpy(main_buff, "i=>'", strlen("i=>'"));
	strcat(main_buff, "867377020199547");		
	strcat(main_buff, comma);
	strcat(main_buff, "12345678");
	strcat(main_buff, quote);

	return main_buff;
}

int data_package(char *data)
{
    char s[128] = {};
    time_t t;

 	strncpy(main_buff, "i=>'", strlen("i=>'"));
 	strncpy(sysinfo_buff, "s=>'", strlen("s=>'"));
 	strncpy(netinfo_buff, "n=>'", strlen("n=>'"));
 	strncpy(data_usage_buff, "d=>'", strlen("d=>'"));

	strncpy(data, minimum_data(), strlen(minimum_data()));
	
	strcat(sysinfo_buff, nvram_get("router_name"));	
	strcat(sysinfo_buff, comma);
	strcat(sysinfo_buff, nvram_get("router_hw"));	
	strcat(sysinfo_buff, comma);
	strncpy(s, "router_", strlen("router_"));
	strcat(s, nvram_get("os_version"));	
	strcat(sysinfo_buff, s);	
	memset(s, 0, 128);
	strcat(sysinfo_buff, comma);

//	printf("ready for getting router time\n");
//    t = time(NULL);
//    strftime(s, sizeof(s), "%a, %d %b %Y %H:%M:%S %z", localtime(&t));
//	strcat(sysinfo_buff, s);	
//	strcat(sysinfo_buff, comma);
//	memset(s, 0, 128);
	strcat(sysinfo_buff, quote);
	if(sysinfo_buff[strlen(sysinfo_buff) -2] == comma[0])
	{
		sysinfo_buff[strlen(sysinfo_buff) -2] = sysinfo_buff[strlen(sysinfo_buff) - 1];
		sysinfo_buff[strlen(sysinfo_buff) -1] = NULL;
	}

	//network information
	strcat(netinfo_buff, nvram_get("wan_iface"));	
	strcat(netinfo_buff, comma);
	strcat(netinfo_buff, nvram_get("wan_hwaddr"));	
	strcat(netinfo_buff, comma);
	strcat(netinfo_buff, nvram_get("modem_type"));	
	strcat(netinfo_buff, comma);
	strcat(netinfo_buff, nvram_get("modem_state"));	
	strcat(netinfo_buff, comma);
	strcat(netinfo_buff, nvram_get("sim_selected"));	
	strcat(netinfo_buff, comma);
	strcat(netinfo_buff, nvram_get("cops"));	
	strcat(netinfo_buff, comma);
	strcat(netinfo_buff, nvram_get("cell_network"));	
	strcat(netinfo_buff, comma);
	strcat(netinfo_buff, nvram_get("sim_state"));	
	strcat(netinfo_buff, comma);
	strcat(netinfo_buff, nvram_get("csq"));	
	strcat(netinfo_buff, comma);
	strcat(netinfo_buff, nvram_get("wanip"));	
	strcat(netinfo_buff, comma);
	strcat(netinfo_buff, nvram_get("wannetmask"));	
	strcat(netinfo_buff, comma);
	strcat(netinfo_buff, nvram_get("wangateway"));	
	strcat(netinfo_buff, comma);
	strcat(netinfo_buff, nvram_get("wanstatus"));	
	strcat(netinfo_buff, comma);
	strcat(netinfo_buff, quote);
	if(netinfo_buff[strlen(netinfo_buff) -2] == comma[0])
	{
		netinfo_buff[strlen(netinfo_buff) -2] = netinfo_buff[strlen(netinfo_buff) - 1];
		netinfo_buff[strlen(netinfo_buff) -1] = NULL;
	}

	//data usage 
	strcat(data_usage_buff, "active lan");	
	strcat(data_usage_buff, comma);
	strcat(data_usage_buff, nvram_get("wl_radio"));	
	strcat(data_usage_buff, comma);
	strcat(data_usage_buff, "data send");	
	strcat(data_usage_buff, comma);
	strcat(data_usage_buff, "data received");	
	strcat(data_usage_buff, quote);
	if(data_usage_buff[strlen(data_usage_buff) -2] == comma)
	{
		data_usage_buff[strlen(data_usage_buff) -2] = data_usage_buff[strlen(data_usage_buff) - 1];
		data_usage_buff[strlen(data_usage_buff) -1] = NULL;
	}

	strcat(data, "|");
	strcat(data, sysinfo_buff);
	strcat(data, "|");
	strcat(data, netinfo_buff);
	strcat(data, "|");
	strcat(data, data_usage_buff);

	data[strlen(data)] = '\n';

	/* reset buffs */
	memset(main_buff, 0, BUFF_SIZE);
	memset(sysinfo_buff, 0, BUFF_SIZE);
	memset(netinfo_buff, 0, BUFF_SIZE);
	memset(data_usage_buff, 0, BUFF_SIZE);
 	strncpy(main_buff, "i=>'", strlen("i=>'"));
 	strncpy(sysinfo_buff, "s=>'", strlen("s=>'"));
 	strncpy(netinfo_buff, "n=>'", strlen("n=>'"));
 	strncpy(data_usage_buff, "d=>'", strlen("d=>'"));

	return 0;
}

int send_to_server(int sockfd, char *senddata)
{
	int n = 0;
	n = send(sockfd, senddata, strlen(senddata), 0); if(n < 0) {
//		syslog(LOG_ERR, "Send to Server Error!!!");
		return -1;
	}

	printf("send to server: %s\n", senddata);
	return 0;
}

char *recv_from_server(int sockfd, char *recvdata, int *len)
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

void analysis_data(char *data)
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
//		syslog(LOG_ERR, "Unknown Account ID on cloudAXS server");
		printf("Unknown Account ID on cloudAXS server\n");
	}
	else if(data[4] == '2')
	{
//		syslog(LOG_ERR, "Unknown IMEI Number on cloudAXS server");
		printf("Unknown IMEI Number on cloudAXS server\n");
	}
	else if(data[4] == '3')
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
	char sendbuff[BUFF_SIZE];
	char recvbuff[BUFF_SIZE];
	int len = 0;
	struct timeval tv;
	time_t t;
	struct tm *p;
	int report_intval = 0;
	unsigned int now = 0, last = 0;		//当前系统时间变量
	int n = 0;

//	tv.tv_sec = nvram_get_int("heartbeat_intval");	//心跳包发送间隔时间
	tv.tv_sec = 5;	//心跳包发送间隔时间
	tv.tv_usec = 0;

	sockfd = connect_to_cloudAXS_server(dest_ip, port);
	if(sockfd < 0) 
	{
	//	syslog(LOG_ERR, "cloudAXS Server Connect Error!!!");
		return -1;
	}

	fd_set rfds, wfds;

	while(1)
	{
		FD_ZERO(&rfds);
		FD_SET(0, &rfds);
		FD_SET(sockfd, &rfds);
		wfds = rfds;

		n = select(sockfd + 1, &rfds, &wfds, NULL, &tv);
		if(n < 0) 
		{
		//	syslog(LOG_ERR, "select() Error!!!");
			return -1;
		}
		else if(n == 0)	//超过设置心跳时间没数据通讯, 发送心跳包 
		{
			printf("send heart data\n");
			if(send_to_server(sockfd, "online") < 0)
			{
		//		syslog(LOG_ERR, "Send Heartbeat Intval Error!!!");
				return -1;
			}
		}
		else
		{
			time(&t);
			p = localtime(&t);
			now = p->tm_hour * 60 * 60 + p->tm_min * 60 + p->tm_sec;
			if(now < last)
			{
				last -= 86400;	
				report_intval = (last + now) / 60;
			}
			else
			{
			//	report_intval = (now - last) / 60;	//以分钟计数
				report_intval = now - last;	//以秒计数
			}

			if(report_intval >= 10)	//上报时间间隔
			{
				if(FD_ISSET(sockfd, &wfds))
				{
					memset(sendbuff, 0, BUFF_SIZE);
					if(data_package(sendbuff) != 0)
					{
		//				syslog(LOG_ERR, "Package Data Error!!!");
						return -1;
					}
	
					if(send_to_server(sockfd, sendbuff) < 0)
					{
		//				syslog(LOG_ERR, "Send Data Error!!!");
						return -1;
					}
					//记下当前发送完成时间
					time(&t);
					p = localtime(&t);
					last = p->tm_hour * 60 * 60 + p->tm_min * 60 + p->tm_sec;
				}
			}

			if(FD_ISSET(sockfd, &rfds))
			{
				memset(recvbuff, 0, BUFF_SIZE);
				if(NULL == recv_from_server(sockfd, recvbuff, &len))
				{
		//			syslog(LOG_ERR, "Receive Data Error!!!");
					return -1;
				}
				printf("receive data success\n");

				analysis_data(recvbuff);
			}
		}
	}

	close(sockfd);

	return 0;
}



