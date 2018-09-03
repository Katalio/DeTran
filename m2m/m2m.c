#include "rc.h"
#include	"m2m.h"

volatile int m2m_gothup = 0;
volatile int m2m_gotuser = 0;
volatile int m2m_gotterm = 0;
volatile int trafic_flag = 0;
volatile int N_ACK = 0;
volatile int AD_UPGRADE_flag = 0;
unsigned char g_downloading=0;
unsigned char g_exdev_running=0;
unsigned int g_packet_id=0;
M2M_CONFIG m2m_config;
char m2m_res_buf[M2M_RES_PDU_BUF];
unsigned char product_id[24];
unsigned char product_report_id[24];
unsigned int packet_id = 0;
unsigned int report_packet_id = 0;

char g_query_ack=0;
char g_m2m_sms_ack=0;
int g_login_ack=0,g_report_status_ack=0,g_sync_time_ack=0,r_login_ack = 0, r_report_status_ack = 0;
int g_tcp_serial_num=0;
unsigned long g_m2m_server_ip = 0;
ST_PACKET_CAP g_pcap_info;
int g_pcap_working=0;
int g_get_cap_upload_ack=0;

ST_DOWNLOAD_INFO_EX *g_down_info;
FILE *g_recv_file_fd=NULL;
int g_get_file_req_ack=0;
typedef struct _MAC_LIST{
	char mac[18];
	int rssi;
}MAC_LIST;

M2M_LOGIN_NVRAM info[] = 
{
	{TAG_DEVICE_TYPE, "router_type"},
	{TAG_OS_VERSION, "os_version"},
	{TAG_NULL, NULL}
};

char* router_config[] = {
	"CelldialApn",
	"CelldialUser",
	"CelldialPwd",
	"cellType",
	"cell_mode",
	"cell_mode2",
	"cellType2",
	"CelldialApn2",
	"CelldialUser2",
	"CelldialPwd2",
	"PingEnable",
	"UtmsPingAddr",
	"UtmsPingAddr1",
	"PingInterval",
	"PingMax",
	"wl0_radio",
	"wl0_ssid",
	"m2m_server_domain",
	"m2m_server_port",
	"m2m_heartbeat_intval",
	"m2m_heartbeat_retry",
	"m2m_error_action",
	"ND_enable",
	"GatewayName",
	"RedirectURL",
	"ClientIdleTimeout",
	"ClientForceTimeout",
	"TrustedMACList",
	"TrafficControl",
	"DownloadLimit",
	"UploadLimit",
	"server_ip",
	"server_port",
	"socket_type",
	"heartbeat_intval",
	"vpn_mode",
	"pptp_client_enable",
	"pptp_client_srvip",
	"pptp_client_username",
	"pptp_client_passwd",
	"ipsec_mode",
	"ipsec_ext",
	"left",
	"leftsubnet",
	"leftfirewall",
	"right",
	"rightsubnet",
	"rightfirewall",
	"authby",
	"ph1_group",
	"ike_enc",
	"ike_auth",
	"ikelifetime",
	"ph2_group",
	"esp_enc",
	"esp_auth",
	"keylife",
	"pskkey",
	"http_passwd",
	"portfilterenabled",
	"defaultfirewallpolicy",
	"webhostfilters",
	"weburlfilters",
	"ipportfilterrules",
	"keywordfilters",
	"mtu_enable",
	"wan_demand",
	"ppp_demand",
	"ppp_mlppp",
	"ppp_idletime",
	"ppp_passwd",
	"ppp_redialperiod",
	"ppp_service",
	"ppp_username",
	"ppp_custome",
	"wan_gateway",
	"wan_ipaddr",
	"wan_netmask",
	"wan_proto",
	"wan_mtu",
	"wan_dns",
	"sch_rboot",
	"vrrp_enable",
	"vrrp_state",
	"vrrp_vrid",
	"vrrp_priority",
	"vrrp_auth",
	"vrrp_pass",
	"vrrp_vip",
	"vrrp_script_type",
	"vrrp_script_ip",
	"vrrp_script_interval",
	"vrrp_script_weight",
	"xdog_on",
	"xdog_root",
	"xdog_iglan",
	"xdog_whost",
	"xdog_phost",
	"xdog_redir",
	"xdog_login_timeout",
	"xdog_idle_timeout",
	"xdog_trustmac",
	"xdog_qos_don",
	"xdog_qos_dt",
	"xdog_qos_ds",
	"xdog_qos_dsc",
	"xdog_qos_uon",
	"xdog_qos_ut",
	"xdog_qos_us",
	"xdog_qos_usc",
	NULL
};

struct sockaddr_in fromaddr;
struct sockaddr_in fromaddr_r;
struct sockaddr_in serveraddr;
struct sockaddr_in serveraddr_r;

#define MAX_RTU_PACKET_LENGTH		1024
static int socket_fd = -1;
#define M2M_PID_FILE "/var/run/m2m.pid"

static void m2m_sig_handler(int sig)
{
	switch (sig) 
	{
		case SIGTERM:
		case SIGKILL:
		case SIGINT:
			m2m_gotterm = 1;
			syslog(LOG_NOTICE, "Got a signal! exit!!");
			sleep(3);
			exit(0);
			break;
		case SIGHUP:
			syslog(LOG_NOTICE, "Got a signal! exit!!");
			exit(0);
			m2m_gothup = 1;
			break;
		case SIGUSR1:
			m2m_gotuser = 1;
			break;
		case SIGUSR2:
			m2m_gotuser = 2;
			break;
	}
}

static void m2m_deamon()
{
	struct sigaction sa;
	FILE *fp;

	if ( fork()  !=0 ) 
		exit(0); 
	
	openlog("m2m", LOG_PID, LOG_USER);

	sa.sa_handler = m2m_sig_handler;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGUSR2, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGKILL, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	

	if ( setsid() < 0 ) 
		exit(1);
	
	//if ( fork()  !=0 ) 
	//	exit(0); 
	
	if ( chdir("/") == -1 )
		exit(1);

	
	kill_pidfile_tk(M2M_PID_FILE);
	if ((fp = fopen(M2M_PID_FILE, "w")) != NULL)
	{
		fprintf(fp, "%d", getpid());
		fclose(fp);
	}
	
	syslog(LOG_NOTICE, "====M2M Copyright (C) 2012-2013 Fyang====");

}

static int check_online()
{
	return check_wanup();
}
#ifdef TCONFIG_N2N
int start_n2n(char *ipaddr)
{
    char buf[32] = {0};
	struct in_addr ip_buf;
	char cmd[256] = {0};

	//stop_n2n( );
	
	memcpy(&ip_buf.s_addr, &g_m2m_server_ip, 4);
    snprintf(buf, sizeof(buf) - 1, "%s:%d", inet_ntoa(ip_buf), nvram_get_int("n2n_server"));
    syslog(LOG_INFO, "buf is %s, server ip = %x", buf, g_m2m_server_ip);

    snprintf(cmd, sizeof(cmd) - 1, 
    		"name_client -a %s -s 255.0.0.0 -l %s -S %s", ipaddr, buf, product_id);

    //system(cmd);
    xstart("name_client", "-a", ipaddr, "-s", "255.0.0.0", "-l", buf, "-S", product_id);

    sleep(2);
    
    nvram_set("n2n_ipaddr", ipaddr);
    nvram_set("n2n_online", "1");
    
    system("service firewall restart");
    system("service httpd restart");
    return 0;
}

int stop_n2n(  )
{
    system("killall -9 name_client");
    nvram_set("n2n_ipaddr", "0.0.0.0");
    nvram_set("n2n_online", "0");
}
#endif
//get the host name
static int m2m_get_host(const char *name, char *ipbuf)
{
    struct hostent *hp;
    if (NULL == (hp = gethostbyname(name)))
    {
        return 0;
    }
    snprintf(ipbuf, 20, "%s", inet_ntoa(*((struct in_addr *)hp->h_addr)));
    syslog(LOG_NOTICE, "--->gethostname ip :%s\n", ipbuf);
    return 1; 
}

static unsigned long m2m_inet_addr(char *ipbuf, unsigned short len)
{
	struct in_addr sin_addr;
	unsigned long ip;

	if ( (len>7) && (1 == inet_pton( AF_INET, ipbuf, &sin_addr) ) )
	{
		ip = sin_addr.s_addr;
		return ip;
	}
	else
		return 0;
#if 0
	unsigned short i;
	unsigned long ip;
	unsigned long byte;
	unsigned short count;

	i = 0;
	count = 0;
	ip = 0;
	while(1)
	{
		byte = 0;
		for (i=0 ; i < len; i++ )
		{
			if ('.' == ipbuf[i] )
			{
				count++;
				break;
			}
			else if ((ipbuf[i] >= '0') && (ipbuf[i] <= '9' ) )
			{
				byte = byte * 10 + ipbuf[i] - 0x30;
				if (byte > 255 )
					return 0;
			}
			else
				return 0;
		}
		ip = (ip << 8) | byte;
		if (i >= len )
			break;
		i++;
	}
	if (3 != count )
	{
		return 0;
	}
	else
	{
		return ip;
	}
#endif
}

//create the socket and init remote addr struct
static int udp_socket_create(unsigned long local_ip, unsigned short local_port, unsigned long dest_ip, unsigned long dest_port)
{
	struct sockaddr_in local_addr;
	int sockfd;
	
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);//type = SOCK_DGRAM UDP
	
	if (-1 == sockfd) 
	{
		syslog(LOG_ERR, "M2M UDP Socket Creat Error!!!");
		return -1;
	}
	bzero(&local_addr,sizeof(local_addr));
	local_addr.sin_family = AF_INET;
	local_addr.sin_port = htons(local_port);
	local_addr.sin_addr.s_addr = htonl(INADDR_ANY);//INADDR_ANY
	
	int flag=1;
    	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&flag, sizeof(flag));
	//bind local ip address
	if(bind(sockfd, (struct sockaddr *)&local_addr, sizeof(local_addr)) < 0)
	{
		syslog(LOG_ERR, "M2M UDP Socket Bind Error!!!");
		return -1;
	}
	/*
	//set socket nonblock
	if(fcntl(sockfd, F_SETFL, O_NONBLOCK) == -1) 
	{
		syslog(LOG_ERR, "M2M UDP Socket O_NONBLOCK Error!!!");
	}*/
	//set serveraddr addr
	bzero(&serveraddr, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(dest_port);
	serveraddr.sin_addr.s_addr = dest_ip;//INADDR_ANY
/*

	   connect(sockfd, (struct sockaddr*)&serveraddr, sizeof(serveraddr));
	 */
	return sockfd;
}
static int report_udp_socket_create(unsigned long local_ip, unsigned short local_port, unsigned long dest_ip, unsigned long dest_port)
{
	struct sockaddr_in local_addr;
	int sockfd;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);//type = SOCK_DGRAM UDP

	if (-1 == sockfd) 
	{
		syslog(LOG_ERR, "M2M UDP Socket Creat Error!!!");
		return -1;
	}
	bzero(&local_addr,sizeof(local_addr));
	local_addr.sin_family = AF_INET;
	local_addr.sin_port = htons(local_port);
	local_addr.sin_addr.s_addr = htonl(INADDR_ANY);//INADDR_ANY

	int flag=1;
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&flag, sizeof(flag));
	//bind local ip address
	if(bind(sockfd, (struct sockaddr *)&local_addr, sizeof(local_addr)) < 0)
	{
		syslog(LOG_ERR, "M2M UDP Socket Bind Error!!!");
		return -1;
	}
	/*
	//set socket nonblock
	if(fcntl(sockfd, F_SETFL, O_NONBLOCK) == -1) 
	{
	syslog(LOG_ERR, "M2M UDP Socket O_NONBLOCK Error!!!");
	}*/
	//set serveraddr addr
	bzero(&serveraddr_r, sizeof(serveraddr_r));
	serveraddr_r.sin_family = AF_INET;
	serveraddr_r.sin_port = htons(dest_port);
	serveraddr_r.sin_addr.s_addr = dest_ip;//INADDR_ANY
	/*

	   connect(sockfd, (struct sockaddr*)&serveraddr_r, sizeof(serveraddr_r));
	 */
	return sockfd;
}

void HexToStr(const char *ibuf, unsigned char *obuf, int len)
{
	int i;

	for (i = 0; i < len; i++)
	{
		sprintf(obuf + i*3, "%02x ", ibuf[i]);
	}
}

void print_hex(char *data, int len, int op)
{
	int i;
	int max;
	char str[3050] = {0};
	char *ptr;

	if ( len > 1000)
		max = 1000;
	else
		max = len;
	
	for(i=0; i<max; i++)
	{
		ptr=&str[i*3];
		sprintf(ptr,"%02x ",(unsigned char )*(data+i));
	}
	//syslog(LOG_DEBUG, "%s---%s---", (op==SEND)?"SEND>>":"RECV<<", str);

}

//socket send interface
static int udp_socket_send(char *pdu_buf, int pdu_len)
{
	int send_len = -1;
	int count = 0;

	while (count < UDP_MAX_SEND_COUNT)
	{
		if (( send_len = sendto(socket_fd, pdu_buf, pdu_len, 0 ,(struct sockaddr *)&serveraddr, sizeof(serveraddr))) == -1)
		{
			syslog(LOG_ERR, "M2M UDP Socket Send Error(%d):%s", errno, strerror(errno));
		}    
		count ++;
	}  

	print_hex(pdu_buf, pdu_len, SEND);

	return send_len;
}
static int report_udp_socket_send(int fd,char *pdu_buf, int pdu_len)
{
	int send_len = -1;
	int count = 0;

	while (count < UDP_MAX_SEND_COUNT)
	{
		if (( send_len = sendto(fd, pdu_buf, pdu_len, 0 ,(struct sockaddr *)&serveraddr_r, sizeof(serveraddr_r))) == -1)
		{
			syslog(LOG_ERR, "M2M UDP Socket Send Error(%d):%s", errno, strerror(errno));
		}    
		count ++;
	}  

	print_hex(pdu_buf, pdu_len, SEND);

	return send_len;
}

static int wait_sock(int fd, int sec, int usec)
{
	struct timeval tv;
	fd_set fdvar;
	int res;
	
	FD_ZERO(&fdvar);
	FD_SET(fd, &fdvar);
	tv.tv_sec = sec;
	tv.tv_usec = usec;
	res = select(fd+1, &fdvar, NULL, NULL, &tv);

	return res;
}

static int close_socket(int sockfd)
{
	/* Clear the UDP socket */
	char dummy[1024];
	int  iLen , res;

	res = wait_sock(sockfd , 1, 0);

	if (res == 1)
	{
		iLen  = recvfrom(sockfd, dummy , sizeof(dummy) , 0, NULL,0 );    
	}
	else
	{
		iLen = 0;
	}

	if (iLen == sizeof(dummy))
	{
		res = wait_sock(sockfd, 1, 0);
	}
	else
	{
		return 0;
	}

	while (res == 1)
	{
		iLen  = recvfrom(sockfd, dummy , sizeof(dummy) , 0,NULL,0 );    
		res = wait_sock(sockfd , 0 , 100);
	}

	return 0;
    
}

//socket receive interface
static int udp_socket_recv(char *pdu_buf, int pdu_len)
{
	int recv_len = -1;
	int fromaddr_len = sizeof(fromaddr);

	if (wait_sock(socket_fd, 2, 0)<=0)
	{
		syslog(LOG_NOTICE, "M2M UDP Recv Timeout");
		return -1;
	}

	recv_len = recvfrom(socket_fd, pdu_buf, pdu_len, 0 , (struct sockaddr *)&fromaddr, &fromaddr_len);
	
	print_hex(pdu_buf, recv_len, RECV);
	
	if(fromaddr.sin_addr.s_addr != m2m_config.svr_domain_ip)
	{
		syslog(LOG_ERR,"------Ambitious data from :%x------------",fromaddr.sin_addr.s_addr);
		return 0;
	}

	return recv_len;
}
static int report_udp_socket_recv(int fd, char *pdu_buf, int pdu_len, unsigned long svrip)
{
	int recv_len = -1;
	int fromaddr_len = sizeof(fromaddr_r);

	if (wait_sock(fd, 2, 0)<=0)
	{
		syslog(LOG_NOTICE, "M2M UDP Recv Timeout");
		return -1;
	}

	recv_len = recvfrom(fd, pdu_buf, pdu_len, 0 , (struct sockaddr *)&fromaddr_r, &fromaddr_len);

	print_hex(pdu_buf, recv_len, RECV);

	if(fromaddr_r.sin_addr.s_addr != svrip)
	{
		syslog(LOG_ERR,"------Ambitious data from :%x------------",fromaddr_r.sin_addr.s_addr);
		return 0;
	}

	return recv_len;
}

static void m2m_config_init()
{
	syslog(LOG_NOTICE, "----M2M Parameters Init. Start----");
	//memset(m2m_config, 0, sizeof(m2m_config));
	
	strcpy(m2m_config.bind_ip_str, nvram_safe_get("m2m_local_ip"));
	m2m_config.bind_port = nvram_get_int("m2m_local_port");
	syslog(LOG_NOTICE, "M2M Bind Address(%s:%d)", m2m_config.bind_ip_str, m2m_config.bind_port);
	
	strcpy(m2m_config.svr_domain, nvram_safe_get("m2m_server_domain"));
	m2m_config.svr_domain_ip = 0;
	
	strcpy(m2m_config.svr_ip_str, nvram_safe_get("m2m_server_ip"));
	m2m_config.svr_ip = 0;
	
	m2m_config.svr_port= nvram_get_int("m2m_server_port");
	syslog(LOG_NOTICE, "M2M Server Address(%s:%d)", m2m_config.svr_ip_str, m2m_config.svr_port);
	
	m2m_config.heartbeat_intval= nvram_get_int("m2m_heartbeat_intval");
	syslog(LOG_NOTICE, "M2M Heartbeat Interval(%d)", m2m_config.heartbeat_intval);
	syslog(LOG_NOTICE, "----M2M Parameters Init. End----");
}

static int make_router_config(char *conf_buf)
{
	char **rtconfig_ptr = router_config;
	int rtconfig_len = 0;
	char *p = NULL;
	
	while( *rtconfig_ptr)
	{
		p = nvram_safe_get(*rtconfig_ptr);
		snprintf(conf_buf + rtconfig_len, M2M_TLV_VALUE - rtconfig_len - 1, "%s=%s&", *rtconfig_ptr, p);
		//sprintf(conf_buf+rtconfig_len, "%s=%s&", *rtconfig_ptr, p);
		rtconfig_len += strlen(*rtconfig_ptr);
		rtconfig_len += strlen(p);
		rtconfig_len += strlen("=&");

		rtconfig_ptr++;
	}
	rtconfig_len = strlen(conf_buf);
	
	conf_buf[rtconfig_len-1] = 0;
	rtconfig_len--;
	
	return rtconfig_len;
}

static unsigned long trafic_calc(void)
{
	FILE *f;
	char buf[256];
	char *ifname;
	char *p;
	unsigned long counter[3] = {0};
	static unsigned long pre_trafic = 0;
	unsigned long trafic = 0;
	
	if ((f = fopen("/proc/net/dev", "r")) == NULL) return 0;
	fgets(buf, sizeof(buf), f);	// header
	fgets(buf, sizeof(buf), f);	// "
	while (fgets(buf, sizeof(buf), f)) 
	{
		if ((p = strchr(buf, ':')) == NULL) continue;
		*p = 0;
		if ((ifname = strrchr(buf, ' ')) == NULL) ifname = buf;
			else ++ifname;

		if(is_lte()?(strcmp(ifname, "usb0") == 0):(nvram_match("wan_proto","dhcp")?strcmp(ifname, "vlan1") == 0:strcmp(ifname, "ppp0") == 0))
		{
			// <rx bytes, packets, errors, dropped, fifo errors, frame errors, compressed, multicast><tx ...>
			if (sscanf(p + 1, "%lu%*u%*u%*u%*u%*u%*u%*u%lu", &counter[0], &counter[1]) == 2)
			{
				counter[2] = (counter[0] + counter[1])/1024;
				pre_trafic = nvram_get_int("m2m_trafic");
				if(counter[2] < pre_trafic)
				{
					trafic = counter[2];
				}
				else
				{
					trafic = counter[2] - pre_trafic;
				}
				if (1)
				{
					trafic_flag = 1;
					pre_trafic = counter[2];
					sprintf(buf,"%lu",pre_trafic);
					nvram_set("m2m_trafic",buf);
				}
				break;
			}
		}
	}
	fclose(f);
	syslog(LOG_NOTICE, "trafic: %lu+%lu=%lu:pre=%lu:new=%lu", counter[0], counter[1], counter[2], pre_trafic, trafic);
	return trafic;
}

static unsigned char parse_exdev_config(char *param_ptr, int param_len ,char *op)
{
	FILE *fp=NULL;
	char word[256]={0}, *next;
	char *tmp=NULL;

	syslog(LOG_NOTICE, "----parse_exdev_config %d:%s----", param_len, param_ptr);
	if((fp=fopen("/tmp/.oem.req","w")) == NULL)
	{
		return 0;
	}

	nvram_set("oem_op",op);
	foreach_26(word, param_ptr, next)
	{
		if(tmp=strchr(word,'='))
		{
			word[tmp-word]='\0';
			if(!strcmp(word,"username"))
				nvram_set("oemusr",tmp+1);
			else if(!strcmp(word,"password"))
				nvram_set("oempss",tmp+1);
			else if(!strcmp(word,"req_url"))
				nvram_set("oemurl",tmp+1);
			else if(!strcmp(word,"req_xml"))
			{
				fprintf(fp,"%s",tmp+1);
			}
		}
	}
	fclose(fp);
	return 1;
}

static unsigned char parse_router_config(char *param_ptr, int param_len )
{
	char cmd[512] = {0};
	char word[256]={0}, *next;
	unsigned int count = 0;
	syslog(LOG_NOTICE, "----parse_router_config %d:%s----", param_len, param_ptr);

	syslog(LOG_NOTICE, "----NVRAM Set Command Start----");
	foreach_26(word, param_ptr, next)
	{
		memset(cmd, 0, 512);
		sprintf(cmd, "nvram set %s", word);
		syslog(LOG_NOTICE, "%s", cmd);
		system(cmd);
		count++;
	}
	syslog(LOG_NOTICE, "----NVRAM Set Command End----");
	return (system("nvram commit"));
}

static int ignore_path(char *path)
{
	char *cp;

	if(cp = rindex(path, '/'))
	{
		return cp-path+1;
	}
	else
	{
		return 0;
	}
}

int send_download_report(unsigned char status,unsigned int cmd_sn,char *filename,unsigned int filesize)
{
	char hb_buf[1024] = {0};
	int hb_len = 0;
	M2M_PROTOCOL_HDR* hb = (M2M_PROTOCOL_HDR*)hb_buf;
	DOWNLOAD_REPORT_HEAD *report;
	int head_len=0;

	if(socket_fd >= 0)
	{
		memset(hb_buf, 0, 512);
		hb_len = 0;

		hb->cmd_id = htons(DOWNLOAD_REPORT);
		hb->packet_id = htonl(packet_id++);
		hb->version = htons(0x0100);
		memcpy(hb->product_id, product_id, sizeof(hb->product_id));

		report=(DOWNLOAD_REPORT_HEAD *)(hb_buf+sizeof(M2M_PROTOCOL_HDR));
		report->status=status;
		report->cmd_sn=htonl(cmd_sn);
		report->filesize=htonl(filesize);
		report->filename_len=htons((unsigned short)strlen(filename));
		head_len=sizeof(M2M_PROTOCOL_HDR)+sizeof(DOWNLOAD_REPORT_HEAD);
		memcpy(hb_buf+head_len,filename,sizeof(hb_buf)-head_len);

		hb_len = head_len+strlen(filename);
		hb->len = htons(hb_len);
		udp_socket_send(hb_buf, hb_len);
		return 1;
	}

	return 0;
}

void download_thread(void *arg)
{
	int filecount = 0;
	char fileN[16] = {0};
	char sizeN[16] = {0};
	int chk_jffs = 3;
	char ctrl_cmd[256] = {0};
	char save_path[1024];
	struct stat st;
	int try_count=0;
	unsigned int tmp_size,idel_count;
	unsigned int pack_id=g_packet_id;
	g_downloading=1;
	filecount = nvram_get_int("filecount");
	if(filecount<=0)
	{
		syslog(LOG_ERR,"m2m download_info invalid file count.");
		return;
	}
#ifdef TCONFIG_UDISK
	if(nvram_get_int("storage_udisk"))
	{
		strcpy(save_path,nvram_safe_get("udisk_mountpoint"));
	}
	else
	{
		while(chk_jffs>0 && !check_jffs2()) chk_jffs--;
		if (chk_jffs<=0)
			syslog(LOG_NOTICE, "JFFS2 Error------->>");
		system("rm -rf /jffs/*");
		strcpy(save_path,"/jffs");
	}
#else

	while(chk_jffs>0 && !check_jffs2()) chk_jffs--;
	if (chk_jffs<=0)
		syslog(LOG_NOTICE, "JFFS2 Error------->>");
	system("rm -rf /jffs/*");
	strcpy(save_path,"/jffs");
#endif
	while (filecount)
	{
		sprintf(fileN, "file%d", filecount);
		sprintf(sizeN, "size%d", filecount);

		try_count=nvram_get_int("m2m_down_try")>0?:10;
		while(try_count--)
		{
			AD_UPGRADE_flag = 1;
			N_ACK = 0;
			sprintf(ctrl_cmd, "rm -rf %s/%s &",save_path,nvram_safe_get(fileN)+ignore_path(nvram_safe_get(fileN)));
			system(ctrl_cmd);
			sprintf(ctrl_cmd, "wget -t 2 -c ftp://%s:%s@%s:%d/%s -O %s/%s &",
				nvram_safe_get("username"), nvram_safe_get("password"),
				nvram_safe_get("ip"),nvram_get_int("port")>0?nvram_get_int("port"):21, nvram_safe_get(fileN), save_path,nvram_safe_get(fileN)+ignore_path(nvram_safe_get(fileN)));
			syslog(LOG_NOTICE, "M2M download command: %s", ctrl_cmd);
			system(ctrl_cmd);
			sleep(2);
			sprintf(ctrl_cmd,"%s/%s",save_path,nvram_safe_get(fileN)+ignore_path(nvram_safe_get(fileN)));

			idel_count=0;
			tmp_size=0;
			while (pidof("wget")>0)
			{
				N_ACK = 0;

				if(stat(ctrl_cmd,&st)==0)
				{
					syslog(LOG_ERR,"%s===%d------------%d",__FUNCTION__,__LINE__,st.st_size);
					send_download_report(0,pack_id,nvram_safe_get(fileN),st.st_size);
					if(tmp_size==st.st_size)
					{
						if(idel_count++>=30)
						{
							syslog(LOG_ERR,"M2M Idel time out");
							system("killall -9 wget");
						}
					}
					else
					{
						idel_count=0;
					}
					tmp_size=st.st_size;
				}
				sleep(1);
			}
			syslog(LOG_ERR,"%s===%d----------%d==========%d",__FUNCTION__,__LINE__,st.st_size,nvram_get_int(sizeN));
			if((stat(ctrl_cmd,&st)==0)&&(st.st_size==nvram_get_int(sizeN)))
			{
				syslog(LOG_ERR,"%s===%d",__FUNCTION__,__LINE__);
				send_download_report(0,pack_id,nvram_safe_get(fileN),st.st_size);
				break;
			}
		}
		filecount--;
	}

	eval("service", "xdog", "restart");

	g_downloading=0;
}

int m2m_send_ack(unsigned short cmd,unsigned int packid,unsigned char status)
{
	char hb_buf[1024] = {0};
	int hb_len = 0;
	M2M_PROTOCOL_HDR* hb = (M2M_PROTOCOL_HDR*)hb_buf;

	if(socket_fd >= 0)
	{
		memset(hb_buf, 0, 512);
		hb_len = 0;

		hb->cmd_id = htons(cmd);
		hb->packet_id = htonl(packid);
		hb->version = htons(0x0100);
		memcpy(hb->product_id, product_id, sizeof(hb->product_id));

		*(hb_buf + sizeof(M2M_PROTOCOL_HDR)) = status;

		hb_len = sizeof(M2M_PROTOCOL_HDR) + 1;
		hb->len = htons(hb_len);
		udp_socket_send(hb_buf, hb_len);
		return 1;
	}

	return 0;
}

int execute_remote_ctrl(char *param_ptr)
{
	char cmd[256] = {0};
	char param[256] = {0};
	char word[256]={0}, *next;
	int count=0;

	foreach_26(word, param_ptr, next)
	{
		if((count==0)&&(strcmp("cmd=device_offline",word)))
		{
			return 1;
		}
		if(count==1)
		{
			char *tmp=NULL;
			if(tmp=strchr(word,'='))
			{
				word[tmp-word]='\0';
				strcpy(cmd,word);
				strcpy(param,tmp+1);
			}
		}
		count++;
	}
	if(strlen(param)==12)
	{
		sprintf(word,"cmd=3&mac=%c%c:%c%c:%c%c:%c%c:%c%c:%c%c\r\n",param[0],param[1],param[2],param[3],param[4],param[5],param[6],param[7],param[8],param[9],param[10],param[11]);
		if(pidof("xdog")>1)
		{
			m2m_2_nd(word);
		}
		return 0;
	}

	return 1;
}

static int delete_files(char *param_ptr, int param_len)
{
	int ret=0,cur_pos=0,dirlen=0;
	char *buf=NULL,*pdir=NULL;
	M2M_PROTOCOL_TLV *m2m_tlv;

	pdir=nvram_get_int("storage_udisk")?nvram_safe_get("udisk_mountpoint"):"/jffs";
	dirlen=strlen(pdir) + 1 ;//1 for '/'
	while(param_len>cur_pos)
	{
		m2m_tlv = (M2M_PROTOCOL_TLV*)(param_ptr+cur_pos);
		if((ntohs(m2m_tlv->tlv_tag) != FILE_NAME) || (ntohs(m2m_tlv->tlv_len) > (param_len-cur_pos)))
		{
			ret=1;
			break;
		}

		if((buf=calloc(dirlen +10+ ntohs(m2m_tlv->tlv_len)+1,sizeof(char))) == NULL)
			return 1;

		sprintf(buf,"rm -rf %s/%s &",pdir,m2m_tlv->tlv_value);
		syslog(LOG_INFO,"Deleting file :%s",buf+7);
		system(buf);

		free(buf);
		cur_pos += (ntohs(m2m_tlv->tlv_len)+4);
	}

	return ret;
}

int pack_sub_elem(char *buf,unsigned int *cur_pos,unsigned short id,unsigned short value_len,void *value)
{
	M2M_TL *tl;

	tl=(M2M_TL *)(buf+ *cur_pos);
	tl->tag=htons(id);
	tl->len=htons(value_len);
	memcpy(buf + *cur_pos + sizeof(M2M_TL),(char *)value,value_len);
	*cur_pos += sizeof(M2M_TL) + value_len;

	return 1;
}

int send_file_list()
{
	DIR *dir;
	struct dirent *dp;
	char *file_list_buf;
	struct stat st;
	unsigned int dir_name_len=0,dir_count=0,cur_pos=0,file_size=0,total_len=0;
	unsigned short ntmp=0;
	char *pdir=NULL,tmp[1025];

	pdir=nvram_get_int("storage_udisk")?nvram_safe_get("udisk_mountpoint"):"/jffs";
	if ((dir = opendir(pdir)))
	{
		while ((dp = readdir(dir)))
		{
			if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0)
				continue;

			dir_count++;
			dir_name_len += strlen(dp->d_name);
		}
		total_len = sizeof(M2M_PROTOCOL_HDR) + dir_name_len + 12 * dir_count + 12;
		syslog(LOG_ERR,"entry count:%d,name len:%d,total:%d",dir_count,dir_name_len,total_len);
		if((file_list_buf=calloc(total_len,sizeof(char))) == NULL)
			return 0;

		cur_pos = sizeof(M2M_PROTOCOL_HDR);

		ntmp=htons(1);
		pack_sub_elem(file_list_buf,&cur_pos,PACKET_TOTAL,2,&ntmp);
		pack_sub_elem(file_list_buf,&cur_pos,PACKET_CURRENT,2,&ntmp);

		rewinddir(dir);
		while ((dp = readdir(dir)))
		{
			if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0)
				continue;

			snprintf(tmp,sizeof(tmp)-1,"%s/%s",pdir,dp->d_name);
			if(stat(tmp,&st)<0)
				return 0;
			syslog(LOG_ERR,"%s",dp->d_name);
			pack_sub_elem(file_list_buf,&cur_pos,FILE_NAME,strlen(dp->d_name),dp->d_name);
			file_size=htonl(st.st_size);
			pack_sub_elem(file_list_buf,&cur_pos,FILE_SIZE,4,&file_size);
		}

		closedir(dir);
	}
	else
	{
		syslog(LOG_ERR,"%s---%s",pdir,strerror(errno));
		return 0;
	}

	M2M_PROTOCOL_HDR* fl = (M2M_PROTOCOL_HDR*)file_list_buf;

	if(socket_fd >= 0)
	{
		//fl->cmd_id = htons(REPORT_FILE_LIST);
		fl->cmd_id = htons(0x0014);
		fl->packet_id = htonl(packet_id++);
		fl->version = htons(0x0100);
		memcpy(fl->product_id, product_id, sizeof(fl->product_id));
		fl->len = htons(total_len);
		udp_socket_send(file_list_buf,total_len);
		if(file_list_buf)
			free(file_list_buf);
		return 1;
	}

	if(file_list_buf)
		free(file_list_buf);
	return 0;
}

int list_rssi_min(MAC_LIST *maclist,int list_len)
{
	int i;
	int min=1000;
	int ret=0;

	for(i=0;i<list_len;i++)
	{
		if(min > maclist[i].rssi)
		{
			ret=i;
			min=maclist[i].rssi;
		}
	}
	return ret;
}

int m2m_report_status_send_cmd(int fd,unsigned short cmd)
{
	char hb_buf[1024];
	int hb_len = 0;
	char *temp = NULL;
	M2M_PROTOCOL_HDR* hb = (M2M_PROTOCOL_HDR*)hb_buf;

	if(fd >= 0)
	{
		memset(hb_buf, 0, sizeof(hb_buf));

		hb->cmd_id = htons(cmd);
		hb->packet_id = htonl(report_packet_id++);
		hb->version = htons(0x0100);
		memcpy(hb->product_id, product_report_id, sizeof(hb->product_id));
		hb_len += sizeof(M2M_PROTOCOL_HDR);

		if(cmd == M2M_LOGIN)
		{
			strncpy(hb_buf+hb_len,nvram_safe_get("router_sn"),32);
			hb_len += 32;
			strncpy(hb_buf+hb_len,nvram_safe_get("os_version"),16);
			hb_len += 16;
			strncpy(hb_buf+hb_len,nvram_safe_get("modem_imei"),16);
			hb_len += 16;
			strncpy(hb_buf+hb_len,nvram_safe_get("modem_imsi"),16);
			hb_len += 16;
			strncpy(hb_buf+hb_len,nvram_safe_get("sim_ccid"),20);
			hb_len += 20;
		}
		else if(cmd == REPORT_STATUS)
		{
			char tmp[128];
			char *start,*end;
			int mnc=0;

			memset(tmp,0,sizeof(tmp));
			strncpy(tmp,nvram_safe_get("cops"),sizeof(tmp)-1);
			start=tmp;
			if(start=strchr(start,'"'))
				start++;
			else
				start=tmp;

			start += 3;

			if(start)
				mnc=atoi(start);

			syslog(LOG_ERR,"Report MNC:%d",mnc);
			if(nvram_get_int("cell_cops") == 7)
			{
				sprintf(hb_buf+hb_len,"lac=%s&cellid=%s&mnc=%02d",nvram_safe_get("celle_lac"),nvram_safe_get("celle_cid"),mnc);
				nvram_set("cell_lac",nvram_safe_get("celle_lac"));
				nvram_set("cell_cid",nvram_safe_get("celle_cid"));
			}
			else
			{
				sprintf(hb_buf+hb_len,"lac=%s&cellid=%s&mnc=%02d",nvram_safe_get("cellg_lac"),nvram_safe_get("cellg_cid"),mnc);
				nvram_set("cell_lac",nvram_safe_get("cellg_lac"));
				nvram_set("cell_cid",nvram_safe_get("cellg_cid"));
			}
			hb_len += strlen(hb_buf+hb_len);

			sprintf(hb_buf+hb_len,"&vpn_status=%s",get_if_ip("ppp101",0,0,0)?"on":"off");
			hb_len += strlen(hb_buf+hb_len);

			if(strlen(nvram_safe_get("psn")))
			{
				sprintf(hb_buf+hb_len,"&psn=%s",nvram_safe_get("psn"));
				hb_len += strlen(hb_buf+hb_len);
			}

			if(1)
			{
				char mtype[128],*p;
				memset(mtype,0,sizeof(mtype));
				strncpy(mtype,nvram_safe_get("modem_type"),sizeof(mtype)-1);
				p=mtype;
				if((p=strchr(p,':')) != NULL)
				{
					*p=0;
				}
				syslog(LOG_ERR,"mtype:%s",mtype);
				sprintf(hb_buf+hb_len,"&operator=%s&module_vendor=%s&module_type=%s&router_mode=%s",nvram_safe_get("cops"),nvram_safe_get("module_vendor"),mtype,nvram_safe_get("modem_mode"));
				hb_len += strlen(hb_buf+hb_len);
			}

		}
		hb->len = htons(hb_len);
		report_udp_socket_send(fd, hb_buf, hb_len);
		return 1;
	}

	return 0;
}

int m2m_send_cmd(unsigned short cmd)
{
	int i = 0;
	unsigned char hb_buf[1024];
	unsigned char tlv_buf[1024];
	unsigned char tlv_total_buf[1024];
	int hb_len = 0;
	int tlv_len = 0;	//single tlv length
	int length = 0;		//total tlv length
    char *temp = NULL;
	M2M_PROTOCOL_HDR_T *hb = (M2M_PROTOCOL_HDR_T *)hb_buf;
	M2M_PROTOCOL_TLV *tlv = (M2M_PROTOCOL_TLV *)tlv_buf;

	if(socket_fd >= 0)
	{
		memset(hb_buf, 0, sizeof(hb_buf));

		hb->cmd_id = htons(cmd);
		hb->packet_id = htonl(packet_id++);
		hb->version = htons(0x0300);
		hb->safe_flag = 0;		//安全标识:1启用, 0不启用
		hb->type = 0;	//0: M2M指令，1: Lora指令
		memcpy(hb->product_id, product_id, sizeof(hb->product_id));
		hb_len += sizeof(M2M_PROTOCOL_HDR_T);

		if(cmd == M2M_LOGIN)
		{
			memset(tlv_total_buf, 0, sizeof(tlv_total_buf));
			
			while(info[i].name != NULL)
			{
				tlv_len = 0;
				memset(tlv_buf, 0, sizeof(tlv_buf));

				tlv->tlv_tag = htons(info[i].tag_id);
				sprintf(tlv->tlv_value, "%s", nvram_safe_get(info[i].name));
				tlv_len = strlen(tlv->tlv_value);
				tlv->tlv_len = htons(tlv_len);
				memcpy(tlv_total_buf + length, tlv_buf, tlv_len + 4);
				length += tlv_len + 4;

				i++;
			}

			memcpy(hb_buf + hb_len, tlv_total_buf, length);
			hb_len += length;
		}
		else if (cmd == M2M_VT_CH_REPORT)
		{
			*(hb_buf + hb_len) = 0x0;
			hb_len++;
		}
		else if(cmd == REPORT_STATUS)
		{
			char tmp[128];
			char *start,*end;
			int mnc=0;

			memset(tmp,0,sizeof(tmp));
			strncpy(tmp,nvram_safe_get("cops"),sizeof(tmp)-1);
			start=tmp;
			if(start=strchr(start,'"'))
				start++;
			else
				start=tmp;

			start += 3;

			if(start)
				mnc=atoi(start);

			syslog(LOG_ERR,"MNC:%d",mnc);
			if(nvram_get_int("cell_cops") == 7)
			{
				sprintf(hb_buf+hb_len,"lac=%s&cellid=%s&mnc=%02d",nvram_safe_get("celle_lac"),nvram_safe_get("celle_cid"),mnc);
				nvram_set("cell_lac",nvram_safe_get("celle_lac"));
				nvram_set("cell_cid",nvram_safe_get("celle_cid"));
			}
			else
			{
				sprintf(hb_buf+hb_len,"lac=%s&cellid=%s&mnc=%02d",nvram_safe_get("cellg_lac"),nvram_safe_get("cellg_cid"),mnc);
				nvram_set("cell_lac",nvram_safe_get("cellg_lac"));
				nvram_set("cell_cid",nvram_safe_get("cellg_cid"));
			}
			hb_len += strlen(hb_buf+hb_len);

			sprintf(hb_buf+hb_len,"&vpn_status=%s",get_if_ip("ppp101",0,0,0)?"on":"off");
			hb_len += strlen(hb_buf+hb_len);

			if(strlen(nvram_safe_get("psn")))
			{
				sprintf(hb_buf+hb_len,"&psn=%s",nvram_safe_get("psn"));
				hb_len += strlen(hb_buf+hb_len);
			}

			if(1)
			{
				char mtype[128],*p;
				memset(mtype,0,sizeof(mtype));
				strncpy(mtype,nvram_safe_get("modem_type"),sizeof(mtype)-1);
				p=mtype;
				if((p=strchr(p,':')) != NULL)
				{
					*p=0;
				}
				syslog(LOG_ERR,"mtype:%s",mtype);
				sprintf(hb_buf+hb_len,"&operator=%s&module_vendor=%s&module_type=%s&router_mode=%s",nvram_safe_get("cops"),nvram_safe_get("module_vendor"),mtype,nvram_safe_get("modem_mode"));
				hb_len += strlen(hb_buf+hb_len);
			}

			if(strlen(nvram_safe_get("near_apmac")))
			{
				char *nv, *nvp, *b;
				const char *mac, *rssi;
				MAC_LIST maclist[6];
				char macs[256];
				int i=0;

				nvp = nv = strdup(nvram_safe_get("near_apmac"));
				if (nv)
				{
					memset(maclist,0,sizeof(maclist));
					for(i=0;i<6;i++)
					{
						maclist[i].rssi=-1000;
					}
					while ((b = strsep(&nvp, ",")) != NULL)
					{
						if ((vstrsep(b, "-", &mac, &rssi) != 2) ) continue;
						syslog(LOG_ERR,"%s---[%d]",mac,atoi(rssi));

						i=list_rssi_min(maclist,6);

						if(atoi(rssi)>maclist[i].rssi)
						{
							strncpy(maclist[i].mac,mac,17);
							maclist[i].rssi=atoi(rssi);
						}
					}
					free(nv);
					memset(macs,0,sizeof(macs));
					for(i=0;i<6;i++)
					{
					    temp = macs;
						if(strlen(maclist[i].mac))
							snprintf(macs,sizeof(macs)-1,"%s%s,",temp,maclist[i].mac);
						syslog(LOG_ERR,"%s",macs);
					}

					if(macs[strlen(macs)-1]==',')
						macs[strlen(macs)-1]='\0';
					syslog(LOG_ERR,"==%s==",macs);
					sprintf(hb_buf+hb_len,"&apmac=%s",macs);
					hb_len += strlen(hb_buf+hb_len);
					nvram_set("near_apmac_check",nvram_safe_get("near_apmac"));
				}
			}
		}
		else if (cmd == M2M_LOGOUT)
		{
			*(hb_buf + hb_len) = 0x0;
			hb_len++;
		}

		hb->len = htons(hb_len);
		udp_socket_send(hb_buf, hb_len);
		return 1;
	}

	return 0;
}

int m2m_send_file_req(unsigned short cmd,unsigned int id,unsigned int off,unsigned int len,unsigned int cmd_sn)
{
	char hb_buf[1024];
	int hb_len = 0;
	M2M_PROTOCOL_HDR* hb = (M2M_PROTOCOL_HDR*)hb_buf;
	ST_FILE_REQ *fr;

	if(socket_fd >= 0)
	{
		memset(hb_buf, 0, sizeof(hb_buf));

		hb->cmd_id = htons(cmd);
		hb->packet_id = htonl(packet_id++);
		hb->version = htons(0x0100);
		memcpy(hb->product_id, product_id, sizeof(hb->product_id));
		hb_len += sizeof(M2M_PROTOCOL_HDR);

		fr=(ST_FILE_REQ *)(hb_buf+ sizeof(M2M_PROTOCOL_HDR));
		fr->id=htonl(id);
		fr->off=htonl(off);
		fr->len=htonl(len);
		fr->cmd_sn=htonl(cmd_sn);
		hb_len+= 16;

		hb->len = htons(hb_len);
		udp_socket_send(hb_buf, hb_len);
		return 1;
	}
	return 0;
}

int check_md5(char *file,char *md5)
{
	char buf[512];
	FILE *fpmd5=NULL;
	sprintf(buf,"md5sum %s > /tmp/.trx.md5",file);
	system(buf);
	if((fpmd5=fopen("/tmp/.trx.md5","r")) != NULL)
	{
		memset(buf,0,sizeof(buf));
		fgets(buf, sizeof(buf), fpmd5);
		fclose(fpmd5);
		if(!strncasecmp(buf,md5,32))
		{
			syslog(LOG_ERR,"MD5 check OK");
			return 1;
		}
	}
	syslog(LOG_ERR,"MD5 check NK");
	return 0;
}

void exdev_handle_thread(void *arg)
{
	unsigned int pack_id=(int)arg;
	char res_buf[M2M_RES_PDU_BUF];
	M2M_PROTOCOL_HDR* res = (M2M_PROTOCOL_HDR*)res_buf;
	struct stat st;
	FILE *fp=NULL;
	char *value;
	int res_len = 0,read_len=0,len;

	g_exdev_running=1;

	if(nvram_match("oem_op","set"))
	{
		sprintf(res_buf,"curl -T %s -u %s:%s %s >/tmp/.oem.res","/tmp/.oem.req",nvram_safe_get("oemusr"),nvram_safe_get("oempss"),nvram_safe_get("oemurl"));
	}
	else if(nvram_match("oem_op","get"))
	{
		sprintf(res_buf,"curl -u %s:%s %s >/tmp/.oem.res",nvram_safe_get("oemusr"),nvram_safe_get("oempss"),nvram_safe_get("oemurl"));
	}
	else if(nvram_match("oem_op","upgrade"))
	{
		sprintf(res_buf,"curl -T %s -H 'Content-type:application/octet-stream' -H 'Connection:keep-alive' -H 'Expect:' -u %s:%s %s >/tmp/.oem.res","/tmp/tmp.trx",nvram_safe_get("req_username"),nvram_safe_get("req_password"),nvram_safe_get("req_url"));
	}
	else
	{
		system("rm -rf /tmp/.oem.req");
		system("touch /tmp/.oem.req");
		sprintf(res_buf,"curl -T %s -u %s:%s %s >/tmp/.oem.res","/tmp/.oem.req",nvram_safe_get("oemusr"),nvram_safe_get("oempss"),nvram_safe_get("oemurl"));
	}
	system(res_buf);

	if((stat("/tmp/.oem.res",&st)==0) && (st.st_size>0) && ((fp=fopen("/tmp/.oem.res","r")) != NULL))
	{
		if(socket_fd >= 0)
		{
			if(nvram_match("oem_op","set"))
				res->cmd_id = htons(OEM_CAMERA_CONFIG_SET_ACK);
			else if(nvram_match("oem_op","get"))
				res->cmd_id = htons(OEM_CAMERA_CONFIG_GET_ACK);
			else if(nvram_match("oem_op","upgrade"))
				res->cmd_id = htons(DOWNLOAD_INFO_ACK);
			else
				res->cmd_id = htons(OEM_CAMERA_RESET_ACK);
			res->packet_id = htonl(pack_id);
			res->version = htons(0x0100);
			memcpy(res->product_id, product_id, sizeof(res->product_id));
			*(res_buf + sizeof(M2M_PROTOCOL_HDR)) = 0;
			value=res_buf + sizeof(M2M_PROTOCOL_HDR)+1;
			len=M2M_RES_PDU_BUF-100;
			res_len=0;
			while((read_len=fread(value,1,len,fp)) >0)
			{
				res_len += read_len;
				value += read_len;
				len -= read_len;
			}
			res_len += (sizeof(M2M_PROTOCOL_HDR) + 1);
			res->len = htons(res_len);
			udp_socket_send(res_buf, res_len);
		}
		fclose(fp);
	}
	else
	{
		if(nvram_match("oem_op","set"))
			m2m_send_ack(OEM_CAMERA_CONFIG_SET_ACK,pack_id,1);
		else if(nvram_match("oem_op","get"))
			m2m_send_ack(OEM_CAMERA_CONFIG_GET_ACK,pack_id,1);
		else if(nvram_match("oem_op","upgrade"))
			m2m_send_ack(DOWNLOAD_INFO_ACK,pack_id,1);
		else
			m2m_send_ack(OEM_CAMERA_RESET_ACK,pack_id,1);
	}

	g_exdev_running=0;
}

void download_thread_ex(void *arg)
{
	unsigned int pack_recv_count,pack_total_count;
	unsigned int pack_size,def_pack_size,last_pack_size,try_count=0;
	unsigned int wait;
	int got_error=0;
	int pid = -1,n;
	int type=(int)arg;

	g_downloading=1;
	def_pack_size=nvram_get_int("m2m_big_pack_size")>0?4096:2048;

	pack_total_count=htonl(g_down_info->filelist[0].size)/def_pack_size;
	if((last_pack_size=htonl(g_down_info->filelist[0].size)%def_pack_size) !=0)
		pack_total_count++;
	else
		last_pack_size=def_pack_size;
	syslog(LOG_ERR,"total packet count %d,default packet size %d,last packet size %d",pack_total_count,def_pack_size,last_pack_size);
	if(type==1)
		g_recv_file_fd=fopen("/tmp/tmp.trx","wb");
	else
		g_recv_file_fd=fopen("/tmp/tmp.cfg","wb");
	if(g_recv_file_fd != NULL)
	{
		AD_UPGRADE_flag = 1;
		N_ACK = 0;
		pack_recv_count=0;
		try_count=5;
		while(pack_recv_count<pack_total_count)
		{
			syslog(LOG_ERR,"down:%d",pack_recv_count);
			if(type==1)
			{
				if(pack_recv_count+1==pack_total_count)
					m2m_send_file_req(FILE_REQ,htonl(g_down_info->filelist[0].id),  pack_recv_count*def_pack_size ,last_pack_size,g_packet_id);
				else
					m2m_send_file_req(FILE_REQ,htonl(g_down_info->filelist[0].id),  pack_recv_count*def_pack_size ,def_pack_size,g_packet_id);
			}
			else
			{
				if(pack_recv_count+1==pack_total_count)
					m2m_send_file_req(CFG_FILE_REQ,htonl(g_down_info->filelist[0].id),pack_recv_count*def_pack_size,last_pack_size,g_packet_id);
				else
					m2m_send_file_req(CFG_FILE_REQ,htonl(g_down_info->filelist[0].id),pack_recv_count*def_pack_size,def_pack_size,g_packet_id);
			}
			g_get_file_req_ack=0;
			wait=2000;
			while((wait>0)&&(!g_get_file_req_ack))
			{
				usleep(10000);
				wait-=10;
			}
			if(wait<=0)
			{
				if(try_count-- == 0)
				{
					syslog(LOG_ERR,"try count over");
					break;
				}
			}
			if(g_get_file_req_ack)
			{
				pack_recv_count++;
				try_count=5;
			}
		}
		fclose(g_recv_file_fd);
		syslog(LOG_ERR,"Download end");
		if(pack_recv_count==pack_total_count)
		{
			if(type==1)
			{
				if(check_md5("/tmp/tmp.trx",g_down_info->filelist[0].md5))
				{
					if(strstr(g_down_info->filelist[0].filename,".patch"))
					{
						syslog(LOG_ERR,"mod upgrade");
						if(!mod_upgrade("/tmp/tmp.trx"))
						{
							set_action(ACT_IDLE);
							m2m_send_ack(DOWNLOAD_INFO_EX_ACK,g_packet_id,1);
							m2m_send_cmd(M2M_LOGOUT);
							sleep(2);
							reboot(RB_AUTOBOOT);
						}
						if(nvram_match("mod_upgrade_test","1"))
							exit(1);
					}
					m2m_send_ack(DOWNLOAD_INFO_EX_ACK,g_packet_id,0);
					eval("service", "upgrade", "start");
					set_action(ACT_IDLE);
					char *wargv[] = { "mtd-write", "-w", "-i", "/tmp/tmp.trx", "-d", "linux", NULL };
					if (_eval(wargv, ">/tmp/mtd-write-m2m", 0, &pid) != 0) {
						system("rm -rf /tmp/tmp.trx");
						set_action(ACT_IDLE);
						m2m_send_ack(DOWNLOAD_INFO_EX_ACK,g_packet_id,1);
						m2m_send_cmd(M2M_LOGOUT);
						sleep(2);
						reboot(RB_AUTOBOOT);
					}
					if (pid != -1) waitpid(pid, &n, 0);
					AD_UPGRADE_flag = 0;
					N_ACK = 0;
					set_action(ACT_REBOOT);
					syslog(LOG_NOTICE, "M2M Reboot System");
					m2m_send_cmd(M2M_LOGOUT);
					sleep(2);
					reboot(RB_AUTOBOOT);
				}
				else
					got_error=1;
			}
			else
			{
				if(check_md5("/tmp/tmp.cfg",g_down_info->filelist[0].md5))
				{
					static char *args[] = {"nvram", "restore", "/tmp/tmp.cfg", NULL};
					if (_eval(args, ">/tmp/tmp.cfg.msg", 0, NULL) != 0)
						m2m_send_ack(DOWNLOAD_CFG_UDP_ACK,g_packet_id,1);
					else
						m2m_send_ack(DOWNLOAD_CFG_UDP_ACK,g_packet_id,0);

					set_action(ACT_REBOOT);
					syslog(LOG_NOTICE, "M2M Reboot System");
					m2m_send_cmd(M2M_LOGOUT);
					sleep(2);
					reboot(RB_AUTOBOOT);
				}
				else
					got_error=1;
			}
		}
		else
			got_error=1;
	}
	else
	{
		syslog(LOG_ERR,"Create local file error.");
		got_error=1;
	}
	if(got_error)
	{

		if(type==1)
			m2m_send_ack(DOWNLOAD_INFO_EX_ACK,g_packet_id,1);
		else
			m2m_send_ack(DOWNLOAD_CFG_UDP_ACK,g_packet_id,1);
	}

	free(g_down_info);
	g_downloading=0;
	syslog(LOG_ERR,"All download end");
}

static int connect_m2m_tcp_server(unsigned long local_ip, unsigned short local_port, unsigned long dest_ip, unsigned long dest_port)
{
	struct sockaddr_in local_addr;
	int sockfd;
	int flag=1;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (-1 == sockfd)
	{
		syslog(LOG_ERR, "M2M TCP Socket Creat Error!!!");
		return -1;
	}

	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&flag, sizeof(flag));

	bzero(&local_addr,sizeof(local_addr));
	local_addr.sin_family = AF_INET;
	local_addr.sin_port = htons(local_port);
	local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	if(bind(sockfd, (struct sockaddr *)&local_addr, sizeof(local_addr)) < 0)
	{
		syslog(LOG_ERR, "M2M TCP Socket Bind Error!!!");
		return -1;
	}

	bzero(&serveraddr, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(dest_port);
	serveraddr.sin_addr.s_addr = dest_ip;//INADDR_ANY

	if((flag=connect(sockfd, (struct sockaddr*)&serveraddr, sizeof(serveraddr)))<0)
	{
		return -1;
	}

	return sockfd;
}

int send_m2m_tcp_cmd(int fd,unsigned short cmd)
{
	unsigned char buf[256];
	M2M_TCP_HDR *tcp_hdr;
	int pack_len=0;

	tcp_hdr=(M2M_TCP_HDR *)buf;
	buf[0]=0x7A;
	buf[1]=0x7B;
	tcp_hdr->cmd_id=htons(cmd);
	tcp_hdr->serial=htonl(g_tcp_serial_num);
	buf[12]=0x02;
	buf[13]=0x00;

	if(cmd == M2M_TCP_LOGIN)
	{
		pack_len=sizeof(M2M_TCP_HDR)+32;
		tcp_hdr->len=htonl(pack_len);
		memcpy(buf+sizeof(M2M_TCP_HDR),product_id,sizeof(product_id));
	}
	else if(cmd == M2M_TCP_LOGOUT)
	{
		pack_len=sizeof(M2M_TCP_HDR);
		tcp_hdr->len=htonl(pack_len);
	}

	if(send(fd,buf,pack_len,0)<0)
	{
		syslog(LOG_ERR,"tcp send err");
		return 0;
	}
	g_tcp_serial_num++;
	print_hex(buf,pack_len,SEND);

	if(wait_sock(fd,2,0)>0)
	{
		if((pack_len=recv(fd,buf,sizeof(buf),0))<0)
		{
			syslog(LOG_ERR,"tcp recv err");
			return 0;
		}
		print_hex(buf,pack_len,RECV);
	}
	return 1;
}

int handle_cfg()
{
	FILE *fp=NULL;
	char line[1024],cmd[1024],*p;

	if(access("/dev/tmp/target/cfg",F_OK) == 0)
	{
		if((fp=fopen("/dev/tmp/target/cfg","r")) != NULL)
		{
			while(fgets(line,sizeof(line)-1,fp))
			{
				p=line;
				while(*p != '\r' && *p != '\n' && *p != '\0')
					p++;
				if(*p == '\r' || *p == '\n')
					*p='\0';

				if(strlen(line)<3)
					continue;

				if((line[0] == 'd') || (line[0] == 'D'))
				{
					sprintf(cmd,"rm -rf \"/dev/tmp/squashfs-root/%s\"",line+2);
					system(cmd);
				}
			}
			fclose(fp);
			return 1;
		}
		return 0;
	}

	return 1;
}

int mod_upgrade(char *patch)
{
	char cmd[1024];

	if(access(patch,F_OK) != 0)
	{
		syslog(LOG_ERR,"Patch file not exist.\n");
		return 0;
	}
	if(access("/dev/tmp/",F_OK) != 0)
	{
		system("mkdir /dev/tmp");
	}
	sprintf(cmd,"tar jxvf %s -C /dev/tmp/",patch);
	system(cmd);
	if(access("/dev/tmp/target",F_OK) != 0)
	{
		printf("Invalid patch file format.\n");
		return 0;
	}
	if(access("/dev/tmp/target/kernel",F_OK) == 0)
	{
		system("dd if=/dev/mtd2 of=/dev/tmp/segment2");
		system("unpack_rootfs -d /dev/tmp/squashfs-root /dev/tmp/segment2");
		system("mv /dev/tmp/target/kernel /dev/tmp/segment1");
		syslog(LOG_ERR,"Have kernel");
	}
	else
	{
		system("dd if=/dev/mtd1 of=/dev/tmp/linux");
		system("unpack_linux /dev/tmp/linux /dev/tmp/");
		system("rm -rf /dev/tmp/linux");
		system("unpack_rootfs -d /dev/tmp/squashfs-root /dev/tmp/segment2");
		syslog(LOG_ERR,"No kernel");
	}
	system("rm -rf /dev/tmp/segment2");

	handle_cfg();

	if(access("/dev/tmp/target/rootfs",F_OK) == 0)
	{
		system("cp -r /dev/tmp/target/rootfs/* /dev/tmp/squashfs-root");
	}
	system("rm -rf /dev/tmp/target");
	system("pack_rootfs /dev/tmp/squashfs-root /tmp/rootfs -noappend -all-root");
	if(access("/tmp/.pack_rootfs",F_OK) == 0)
	{
		system("rm -rf /dev/tmp/squashfs-root");
		system("mv /tmp/rootfs /dev/tmp/");
		system("pack_linux -o /tmp/tmp.trx /dev/tmp/segment1 /dev/tmp/rootfs");
		return 1;
	}

	syslog(LOG_ERR,"pack rootfs error.\n");
	return 0;
}

#define TCP_BUF_SIZE 1024*100
void download_thread_ex_tcp(void *arg)
{
	unsigned int pack_recv_count,pack_total_count;
	unsigned int pack_size,def_pack_size,last_pack_size,try_count=0;
	int tmp=0,pid = -1,recv_file_fd,tcp_fd=0,tcp_pack_len=0,need_recv_len=-1;
	unsigned char tcp_buf[TCP_BUF_SIZE];
	M2M_TCP_HDR *tcp_hdr;
	TCP_FILE_REQ *tcp_file_req;
	int read_count=0,sutime,sstime;

	syslog(LOG_ERR,"Start tcp donwload");
	g_downloading=1;

	while((tcp_fd = connect_m2m_tcp_server( 0, m2m_config.bind_port, g_m2m_server_ip, m2m_config.svr_port) ) < 0)
	{
		tmp++;
		if(tmp>=3)
		{
			syslog(LOG_ERR,"Fail to connect server");
			goto ERROR0;
		}
		sleep(1);
	}

	send_m2m_tcp_cmd(tcp_fd,M2M_TCP_LOGIN);

	def_pack_size=1024*(nvram_get_int("tcp_pack_size")?:64);
	pack_total_count=htonl(g_down_info->filelist[0].size)/def_pack_size;
	if((last_pack_size=htonl(g_down_info->filelist[0].size)%def_pack_size) !=0)
		pack_total_count++;
	else
		last_pack_size=def_pack_size;
	syslog(LOG_ERR,"tcp total packet count %d,default packet size %d,last packet size %d",pack_total_count,def_pack_size,last_pack_size);

	recv_file_fd=fopen("/tmp/tmp.trx","wb");
	if(recv_file_fd != NULL)
	{
		AD_UPGRADE_flag = 1;
		N_ACK = 0;
		pack_recv_count=0;
		try_count=5;
		sstime=nvram_get_int("tcp_timeout_sec")?:1;
		sutime=nvram_get_int("tcp_timeout_usec");
		while(pack_recv_count<pack_total_count)
		{
			syslog(LOG_ERR,"tcp down:%d",pack_recv_count);

			tcp_pack_len=sizeof(M2M_TCP_HDR)+sizeof(TCP_FILE_REQ);
			tcp_hdr=(M2M_TCP_HDR *)tcp_buf;
			tcp_buf[0]=0x7A;
			tcp_buf[1]=0x7B;
			tcp_hdr->cmd_id=htons(M2M_TCP_FILE_REQ);
			tcp_hdr->len=htonl(tcp_pack_len);
			tcp_hdr->serial=htonl(g_tcp_serial_num);
			tcp_buf[12]=0x02;
			tcp_buf[13]=0x00;

			tcp_file_req=(TCP_FILE_REQ *)(tcp_buf+sizeof(M2M_TCP_HDR));
			tcp_file_req->id=g_down_info->filelist[0].id;
			tcp_file_req->cmd_sn=htonl(g_packet_id);
			tcp_file_req->off=htonl(pack_recv_count*def_pack_size);
			if(pack_recv_count+1==pack_total_count)
			{
				need_recv_len=	last_pack_size + sizeof(M2M_TCP_HDR) + 1;
				tcp_file_req->len=htonl(last_pack_size);
			}
			else
			{
				need_recv_len=	def_pack_size + sizeof(M2M_TCP_HDR) + 1;
				tcp_file_req->len=htonl(def_pack_size);
			}

			if(send(tcp_fd,tcp_buf,tcp_pack_len,0)<0)
			{
				goto ERROR1;
			}

			g_tcp_serial_num++;
			print_hex(tcp_buf,tcp_pack_len,SEND);
			tcp_pack_len=0;

			while(1)
			{
				if(wait_sock(tcp_fd,sstime,sutime)>0)
				{
					tcp_pack_len += recv(tcp_fd,tcp_buf+tcp_pack_len,TCP_BUF_SIZE-tcp_pack_len,0);
					if(need_recv_len ==tcp_pack_len)
					{
						tcp_hdr=(M2M_TCP_HDR *)tcp_buf;
						if(tcp_pack_len == ntohl(tcp_hdr->len) && tcp_buf[0]==0x7A && tcp_buf[1]==0x7B && tcp_buf[12]==0x02 && tcp_buf[13]==0x00
							 && tcp_buf[sizeof(M2M_TCP_HDR)] == 0)
						{
							fwrite(tcp_buf + sizeof(M2M_TCP_HDR) +1,1,tcp_pack_len - sizeof(M2M_TCP_HDR) -1,recv_file_fd);
							pack_recv_count++;
							try_count=6;
							break;
						}
					}
					else if(tcp_pack_len > need_recv_len)
					{
						syslog(LOG_ERR,"recv too many data");
						break;
					}
					read_count=0;
				}
				else
				{
					read_count++;
					if(read_count==20)
					{
						syslog(LOG_ERR,"wait too many times");
						break;
					}
				}
			}
			try_count--;
			if(try_count<=0)
			{
				break;
			}
		}
		fclose(recv_file_fd);

		syslog(LOG_ERR,"Download end");
		send_m2m_tcp_cmd(tcp_fd,M2M_TCP_LOGOUT);

		if((pack_recv_count==pack_total_count) && (check_md5("/tmp/tmp.trx",g_down_info->filelist[0].md5)))
		{
			if(strstr(g_down_info->filelist[0].filename,".patch"))
			{
				syslog(LOG_ERR,"mod upgrade");
				if(!mod_upgrade("/tmp/tmp.trx"))
				{
					set_action(ACT_IDLE);
					m2m_send_ack(DOWNLOAD_INFO_EX_ACK,g_packet_id,1);
					m2m_send_cmd(M2M_LOGOUT);
					sleep(2);
					reboot(RB_AUTOBOOT);
				}
				if(nvram_match("mod_upgrade_test","1"))
					exit(1);
			}
			m2m_send_ack(DOWNLOAD_INFO_EX_ACK,g_packet_id,0);
			eval("service", "upgrade", "start");
			set_action(ACT_IDLE);
			char *wargv[] = { "mtd-write", "-w", "-i", "/tmp/tmp.trx", "-d", "linux", NULL };
			if (_eval(wargv, ">/tmp/mtd-write-m2m", 0, &pid) != 0) {
				system("rm -rf /tmp/tmp.trx");
				set_action(ACT_IDLE);
				m2m_send_ack(DOWNLOAD_INFO_EX_ACK,g_packet_id,1);
				m2m_send_cmd(M2M_LOGOUT);
				sleep(2);
				reboot(RB_AUTOBOOT);
			}
			if (pid != -1) waitpid(pid, &tmp, 0);
			AD_UPGRADE_flag = 0;
			N_ACK = 0;
			set_action(ACT_REBOOT);
			syslog(LOG_NOTICE, "M2M Reboot System");
			m2m_send_cmd(M2M_LOGOUT);
			sleep(2);
			reboot(RB_AUTOBOOT);
		}
		else
			goto ERROR1;
	}
	else
	{
		syslog(LOG_ERR,"tcp Create local file error.");
		goto ERROR1;
	}

ERROR1:
	fclose(recv_file_fd);
ERROR0:

	m2m_send_ack(DOWNLOAD_INFO_EX_ACK,g_packet_id,1);
	free(g_down_info);
	g_downloading=0;
	syslog(LOG_ERR,"All tcp download end");
}

#define YEAR2015 1420041600 			//2015-01-01 00:00:00
#define PCAP_FILE "/tmp/m2m_pcap.pcap"

#define TCPDUMP_MAGIC       0xa1b2c3d4
#ifndef PCAP_VERSION_MAJOR
#define PCAP_VERSION_MAJOR 2
#endif
#ifndef PCAP_VERSION_MINOR
#define PCAP_VERSION_MINOR 4
#endif

#define DLT_NULL	0	/* BSD loopback encapsulation */
#define DLT_EN10MB	1	/* Ethernet (10Mb) */
#define DLT_EN3MB	2	/* Experimental Ethernet (3Mb) */
#define DLT_AX25	3	/* Amateur Radio AX.25 */
#define DLT_PRONET	4	/* Proteon ProNET Token Ring */
#define DLT_CHAOS	5	/* Chaos */
#define DLT_IEEE802	6	/* 802.5 Token Ring */
#define DLT_ARCNET	7	/* ARCNET, with BSD-style header */
#define DLT_SLIP	8	/* Serial Line IP */
#define DLT_PPP		9	/* Point-to-point Protocol */
#define DLT_FDDI	10	/* FDDI */

#define LINKTYPE_NULL       DLT_NULL
#define LINKTYPE_ETHERNET   DLT_EN10MB  /* also for 100Mb and up */
#define LINKTYPE_EXP_ETHERNET   DLT_EN3MB   /* 3Mb experimental Ethernet */
#define LINKTYPE_AX25       DLT_AX25
#define LINKTYPE_PRONET     DLT_PRONET
#define LINKTYPE_CHAOS      DLT_CHAOS
#define LINKTYPE_TOKEN_RING DLT_IEEE802 /* DLT_IEEE802 is used for Token Ring */
#define LINKTYPE_ARCNET     DLT_ARCNET  /* BSD-style headers */
#define LINKTYPE_SLIP       DLT_SLIP
#define LINKTYPE_PPP        DLT_PPP
#define LINKTYPE_FDDI       DLT_FDDI

typedef int bpf_int32 ;
typedef unsigned int bpf_u_int32 ;

struct pcap_file_header {
        bpf_u_int32 magic;
        u_short version_major;
        u_short version_minor;
        bpf_int32 thiszone;     /* gmt to local correction */
        bpf_int32 sigfigs;    /* accuracy of timestamps */
        bpf_u_int32 snaplen;    /* max length saved portion of each pkt */
        bpf_u_int32 linktype;   /* data link type (LINKTYPE_*) */
};

struct pcap_pkthdr {
        struct timeval ts;      /* time stamp */
        bpf_u_int32 caplen;     /* length of portion present */
        bpf_u_int32 len;        /* length this packet (off wire) */
};

struct pcap_timeval {
    bpf_int32 tv_sec;		/* seconds */
    bpf_int32 tv_usec;		/* microseconds */
};

struct pcap_sf_pkthdr {
    struct pcap_timeval ts;	/* time stamp */
    bpf_u_int32 caplen;		/* length of portion present */
    bpf_u_int32 len;		/* length this packet (off wire) */
};


static int pcap_write_header(FILE *fp, int linktype, int thiszone, int snaplen)
{
    struct pcap_file_header hdr;

    hdr.magic = TCPDUMP_MAGIC;
    hdr.version_major = PCAP_VERSION_MAJOR;
    hdr.version_minor = PCAP_VERSION_MINOR;

    hdr.thiszone = thiszone;
    hdr.snaplen = snaplen;
    hdr.sigfigs = 0;
    hdr.linktype = linktype;

    if (fwrite((char *)&hdr, sizeof(hdr), 1, fp) != 1)
        return (-1);

    return (0);
}

void pcap_dump(uint8_t *user, const struct pcap_pkthdr *h, const uint8_t *sp)
{
	register FILE *f;
	struct pcap_sf_pkthdr sf_hdr;

	f = (FILE *)user;
	sf_hdr.ts.tv_sec  = h->ts.tv_sec;
	sf_hdr.ts.tv_usec = h->ts.tv_usec;
	sf_hdr.caplen     = h->caplen;
	sf_hdr.len        = h->len;
	/* XXX we should check the return status */
	(void)fwrite(&sf_hdr, sizeof(sf_hdr), 1, f);
	(void)fwrite(sp, h->caplen, 1, f);
}

static int if_get_index(int sock, char *interface)
{
    struct ifreq req;
    int ret;

    memset(&req, 0, sizeof(req));
    strncpy(req.ifr_name, interface, sizeof(req.ifr_name));

	ret = ioctl(sock, SIOCGIFINDEX, &req);
    if (ret != 0)
	{
		printf("if_get_index: for interface %s: %s\n",interface, strerror(errno));
	}

    return req.ifr_ifindex;
}

static int if_get_flag(int sock, char *interface)
{
	struct ifreq req;
	int ret,flag;

	memset(&req, 0, sizeof(req));
	strncpy(req.ifr_name, interface, sizeof(req.ifr_name));

	ret = ioctl(sock, SIOCGIFFLAGS, &req);
	if (ret != 0)
	{
		syslog(LOG_ERR,"ifflags: for interface %s: %s\n",interface, strerror(errno));
	}

	flag=req.ifr_flags;

	if(flag&IFF_POINTOPOINT)
	{
		return 1;
	}
	return 2;
}

#define PCAP_FILE_SIZE 1024*1024*10
int start_capture(char *ifname,unsigned int duration,unsigned int caplen)
{
	unsigned int now=0,end=0;
	unsigned int total_size=0;
	unsigned int limit=0;
	int sock, n,i;
	int prefix_len=0;
	FILE *fp = NULL;
	struct pcap_pkthdr pcaphdr;
	struct sockaddr_ll addr;
	unsigned char buffer[2048];

	end=time(NULL)+duration;

	if ((sock=socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))<0)
	{
		syslog(LOG_ERR,"socekt:%s\n",strerror(errno));
		return 0;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sll_family=AF_PACKET;
	addr.sll_protocol=htons(ETH_P_ALL);
	addr.sll_ifindex=if_get_index(sock,ifname);

	if ((bind(sock, (struct sockaddr*)&addr, sizeof(addr)))<0)
	{
		syslog(LOG_ERR,"bind:%s\n",strerror(errno));
		close(sock);
		return 0;
	}

	fp = fopen(PCAP_FILE, "wb");
	if (!fp)
	{
		syslog(LOG_ERR,"fopen %s for write failed. errno=%d desc=%s\n", PCAP_FILE, errno, strerror(errno));
		close(sock);
		return 0;
	}

	if(if_get_flag(sock,ifname) == 1)
	{
		prefix_len = 16;
		buffer[14] = 0x08;
		buffer[15] = 0x00;
		pcap_write_header(fp, 0x71, 0x0, 0x0000ffff);
	}
	else
	{
		pcap_write_header(fp, LINKTYPE_ETHERNET, 0x0, 0x0000ffff);
	}
	i=0;
	now=time(NULL);
	limit=PCAP_FILE_SIZE;
	while(now < end && total_size<limit)
	{
		n = recvfrom(sock,buffer+prefix_len,sizeof(buffer)-prefix_len,0,NULL,NULL);
		if(n>0)
		{
			gettimeofday(&pcaphdr.ts, NULL);
			pcaphdr.caplen = caplen>0?caplen:(n+prefix_len);
			pcaphdr.len    = n+prefix_len;
			pcap_dump((uint8_t *)fp, &pcaphdr, buffer);
			fflush(fp);
			total_size+=pcaphdr.caplen;
		}
		now=time(NULL);
	}

	close(sock);
	fflush(fp);
	fclose(fp);

	return 1;
}

int get_md5(char *file,char *md5)
{
	char buf[512];
	FILE *fpmd5=NULL;
	sprintf(buf,"md5sum %s > /tmp/.cap.md5",file);
	system(buf);
	if((fpmd5=fopen("/tmp/.cap.md5","r")) != NULL)
	{
		memset(buf,0,sizeof(buf));
		fgets(buf, sizeof(buf), fpmd5);
		fclose(fpmd5);
		syslog(LOG_ERR,"%s",buf);
		memcpy(md5,buf,32);
		return 1;
	}
	syslog(LOG_ERR,"MD5 get NK");
	return 0;
}

int send_pcap_file(unsigned int id,unsigned short total,unsigned short current,char *buf,unsigned int len)
{
	int try_count=0,wait=0;
	int pdu_len = 0;
	ST_PACKET_CAP_UPLOAD *pcap_upload;
	M2M_PROTOCOL_HDR* hb = (M2M_PROTOCOL_HDR *)buf;

	hb->cmd_id = htons(CAP_FILE_UPLOAD);
	hb->packet_id = htonl(packet_id++);
	hb->version = htons(0x0100);
	memcpy(hb->product_id, product_id, sizeof(hb->product_id));

	pcap_upload=(ST_PACKET_CAP_UPLOAD *)(buf+sizeof(M2M_PROTOCOL_HDR));
	pcap_upload->id=htonl(id);
	pcap_upload->total=htons(total);
	pcap_upload->current=htons(current);

	if(current == total)
	{
		char md5[33];
		memset(md5,0,sizeof(md5));
		if(get_md5(PCAP_FILE,md5))
		{
			syslog(LOG_ERR,"File MD5 : %s",md5);
			memcpy(buf+len,md5,32);
			len+=32;
		}
	}
	hb->len = htons(len);
	syslog(LOG_ERR,"id:%d---%d/%d",id,current,total);
	if(socket_fd >= 0)
	{
		try_count=0;
		while(try_count++ <= 5)
		{
			g_get_cap_upload_ack=0;
			udp_socket_send(buf,len);
			wait=2000;
			while((wait>0)&&(!g_get_cap_upload_ack))
			{
				usleep(10000);
				wait-=10;
			}
			if(g_get_cap_upload_ack)
			{
				return 1;
			}
			syslog(LOG_ERR,"Try:%d",try_count);
		}
	}

	return 0;
}

int start_pcap_upload(unsigned int id,unsigned int pack_size)
{
	struct stat st;
	unsigned int pack_count=0,cur_count=0,file_size=0,read_len=0;
	int ret=0,st_len=0;
	FILE *fp;
	char *buf;

	if(stat(PCAP_FILE,&st)==0)
	{
		file_size=st.st_size;
	}

	if((pack_count=(file_size+(pack_size-1))/pack_size) <= 0)
		return ret;

	if((fp=fopen(PCAP_FILE,"r")) == NULL)
		return ret;

	if((buf=malloc(sizeof(M2M_PROTOCOL_HDR)+sizeof(ST_PACKET_CAP_UPLOAD)+pack_size+32)) == NULL) //32 for md5
	{
		fclose(fp);
		return ret;
	}
	cur_count=1;
	st_len=sizeof(M2M_PROTOCOL_HDR)+sizeof(ST_PACKET_CAP_UPLOAD);
	while(cur_count <= pack_count)
	{
		if((read_len = fread(buf+st_len,1,pack_size,fp)) != pack_size)
		{
			syslog(LOG_ERR,"%s---%d",__FUNCTION__,__LINE__);
			if(ferror(fp))
			{
				syslog(LOG_ERR,"%s---%d",__FUNCTION__,__LINE__);
				ret=0;
				break;
			}
		}
		if(send_pcap_file(id,pack_count,cur_count,buf,read_len+st_len))
		{
			cur_count++;
		}
		else
		{
			syslog(LOG_ERR,"m2m sending cap %d/%d error",cur_count,pack_count);
			break;
		}
	}

	if(cur_count>pack_count)
		ret=1;

	fclose(fp);
	free(buf);
	return ret;
}

void pcap_thread(void *arg)
{
	unsigned int now;
	unsigned int pack_id=(int)arg;
	unsigned int cap_size=0;

	g_pcap_working=1;
	now=time(NULL);

	while((g_pcap_info.start > now) && (now > YEAR2015))
	{
		sleep(1);
		now=time(NULL);
	}

	if(g_pcap_info.type==1)
		cap_size=68;
	else if(g_pcap_info.type==2)
		cap_size=500;
	else
		cap_size=0;

	if(start_capture(nvram_safe_get("wan_iface"),g_pcap_info.end - g_pcap_info.start,cap_size))
	{
		if(start_pcap_upload(g_pcap_info.id,2048))
		{
			m2m_send_ack(PACKET_CAP_ACK,pack_id,0);
		}
		else
		{
			m2m_send_ack(PACKET_CAP_ACK,pack_id,1);
		}
	}
	unlink(PCAP_FILE);
	g_pcap_working=0;
}
static int process_report_packet(char* pdu_ptr, int pdu_len, int socketfd)
{
	M2M_PROTOCOL_HDR *m2m_req, *m2m_res;
	M2M_PROTOCOL_TLV *m2m_tlv;
	int try_count=0;
	unsigned int tmp_size,idel_count;
	char *param_buf;
	char ctrl_cmd_flag;
	char ctrl_cmd[256] = {0};
	char m2m_report_res_buf[M2M_RES_PDU_BUF];
	int tlv_len = 0, res_buf_len = 0;
	int pid = -1;
	int n;
	int fuc_ret=1;
	struct stat st;

	memset(m2m_report_res_buf,0,sizeof(m2m_report_res_buf));
	m2m_req = (M2M_PROTOCOL_HDR*)pdu_ptr;
	m2m_res = (M2M_PROTOCOL_HDR*)m2m_report_res_buf;

	syslog(LOG_DEBUG, "[Report] Request: len(%02x) cmdid(%02x) pkid(%02x) ver(%02x) pid(%s)", 
			ntohs(m2m_req->len), ntohs(m2m_req->cmd_id), ntohl(m2m_req->packet_id), ntohs(m2m_req->version), m2m_req->product_id);

	if (ntohs(m2m_req->len) > pdu_len)
	{
		syslog(LOG_ERR, "Recv M2M Len: %d > pdu_len: %d", m2m_req->len, pdu_len);
		return -1;
	}

	m2m_res->packet_id = m2m_req->packet_id;
	report_packet_id = ntohl(m2m_req->packet_id) +1;
	m2m_res->version = m2m_req->version;
	memcpy(m2m_res->product_id, product_report_id, sizeof(m2m_res->product_id));

	switch (ntohs(m2m_req->cmd_id))
	{
		case M2M_LOGIN_ACK:
			r_login_ack=1;
			m2m_report_status_send_cmd(socketfd, REPORT_STATUS);
			syslog(LOG_NOTICE, "[Report] M2M Command(%02x) M2M_LOGIN_ACK!!!", ntohs(m2m_req->cmd_id));
			break;
		case M2M_LOGOUT_ACK:
			syslog(LOG_NOTICE, "[Report] M2M Command(%02x) M2M_LOGOUT_ACK!!!", ntohs(m2m_req->cmd_id));
			break;
		case M2M_HEARTBEAT_ACK:
			syslog(LOG_NOTICE, "[Report] M2M Command(%02x) M2M_HEARTBEAT_ACK!!!", ntohs(m2m_req->cmd_id));
			break;
		case REPORT_STATUS_ACK:
			r_report_status_ack=1;
			syslog(LOG_NOTICE, "[Report] M2M Command(%02x) REPORT_STATUS_ACK!!!", ntohs(m2m_req->cmd_id));
			break; 
	//	case REPORT_DEVICE_ACK:
	//		syslog(LOG_NOTICE, "[Report] M2M Command(%02x) REPORT_DEVICE_ACK!!!", ntohs(m2m_req->cmd_id));
			break;
		default:
			syslog(LOG_NOTICE, "[Report] M2M Command(%02x) Unsupport!!!", ntohs(m2m_req->cmd_id));
			break;
	}
}


static int process_packet(char* pdu_ptr, int pdu_len)
{
	M2M_PROTOCOL_HDR_T *m2m_req, *m2m_res;
	M2M_PROTOCOL_TLV *m2m_tlv;
	int try_count=0;
	unsigned int tmp_size,idel_count;
	char *param_buf;
	char ctrl_cmd_flag;
	char ctrl_cmd[256] = {0};
	char *m2m_buf, tmp_buf[1024];
	int len = 0, tlv_len = 0, tmp_len = 0, res_buf_len = 0;
	int pid = -1;
	int n;
	int fuc_ret=1;
	struct stat st;
	unsigned char str[1024] = {0};

	m2m_req = (M2M_PROTOCOL_HDR_T *)pdu_ptr;
	m2m_res = (M2M_PROTOCOL_HDR_T *)m2m_res_buf;

	HexToStr(pdu_ptr, str, pdu_len);
	syslog(LOG_NOTICE, "M2M Recv: %s, len: %d", str, pdu_len);
	syslog(LOG_DEBUG, "M2M Request: len(%02x) cmdid(%02x) pkid(%02x) ver(%02x) pid(%s)", 
		ntohs(m2m_req->len), ntohs(m2m_req->cmd_id), ntohl(m2m_req->packet_id), ntohs(m2m_req->version), m2m_req->product_id);
	
	if (N_ACK > 0)
	{
		N_ACK = 0;
		AD_UPGRADE_flag = 0;
	}
	if (ntohs(m2m_req->len) > pdu_len)
	{
		syslog(LOG_ERR, "Recv M2M Len: %d > pdu_len: %d", m2m_req->len, pdu_len);
		return -1;
	}

	m2m_res->packet_id = m2m_req->packet_id;
	packet_id = ntohl(m2m_req->packet_id) +1;
	m2m_res->version = m2m_req->version;
	m2m_res->safe_flag = m2m_req->safe_flag;
	m2m_res->type = m2m_req->type;
	memcpy(m2m_res->product_id, product_id, sizeof(m2m_res->product_id));
	
	switch (ntohs(m2m_req->cmd_id))
	{
		case M2M_LOGIN_ACK:
			g_login_ack=1;
			m2m_send_cmd(REPORT_STATUS);
			m2m_send_cmd(SYNC_TIME);
			syslog(LOG_NOTICE, "M2M Command(%02x) M2M_LOGIN_ACK!!!", ntohs(m2m_req->cmd_id));
			break;
		case M2M_LOGOUT_ACK:
			syslog(LOG_NOTICE, "M2M Command(%02x) M2M_LOGOUT_ACK!!!", ntohs(m2m_req->cmd_id));
			break;
		case M2M_HEARTBEAT_ACK:
			trafic_flag = 0;
			syslog(LOG_NOTICE, "M2M Command(%02x) M2M_HEARTBEAT_ACK!!!", ntohs(m2m_req->cmd_id));
			break;
		case REPORT_STATUS_ACK:
			g_report_status_ack=1;
			nvram_unset("near_apmac");
			syslog(LOG_NOTICE, "M2M Command(%02x) REPORT_STATUS_ACK!!!", ntohs(m2m_req->cmd_id));
			break;
		case M2M_CONFIG_GET:
			syslog(LOG_NOTICE, "M2M Command(%02x) M2M_CONFIG_GET!!!", ntohs(m2m_req->cmd_id));
			m2m_res->cmd_id = htons(M2M_CONFIG_GET_ACK);
			*(m2m_res_buf + sizeof(M2M_PROTOCOL_HDR)) = 0x00;
			m2m_tlv = (M2M_PROTOCOL_TLV*)(m2m_res_buf + sizeof(M2M_PROTOCOL_HDR) + 1);
			m2m_tlv->tlv_tag = htons(0x0000);
			tlv_len = make_router_config(m2m_tlv->tlv_value);
			m2m_tlv->tlv_len = htons(tlv_len);
			res_buf_len = sizeof(M2M_PROTOCOL_HDR) + 1 + 4 + tlv_len;
			m2m_res->len = htons(res_buf_len);
			udp_socket_send(m2m_res_buf, res_buf_len);
			break;
		case M2M_CONFIG_SET:
			syslog(LOG_NOTICE, "M2M Command(%02x) M2M_CONFIG_SET!!!", ntohs(m2m_req->cmd_id));
			m2m_res->cmd_id = htons(M2M_CONFIG_SET_ACK);
			m2m_tlv = (M2M_PROTOCOL_TLV*)(pdu_ptr + sizeof(M2M_PROTOCOL_HDR));
			syslog(LOG_NOTICE, "M2M_CONIFG_SET %d:%s", ntohs(m2m_tlv->tlv_len), m2m_tlv->tlv_value);
			*(m2m_res_buf + sizeof(M2M_PROTOCOL_HDR)) = parse_router_config(m2m_tlv->tlv_value, ntohs(m2m_tlv->tlv_len));
			res_buf_len = sizeof(M2M_PROTOCOL_HDR) + 1;
			m2m_res->len = htons(res_buf_len);
			udp_socket_send(m2m_res_buf, res_buf_len);
			m2m_send_cmd(M2M_LOGOUT);
			system("killall -9 modem_watchdog&");
			syslog(LOG_NOTICE, "M2M config set reboot!!");
			reboot(RB_AUTOBOOT);
			break;
		case OEM_CAMERA_CONFIG_SET:
			syslog(LOG_NOTICE, "M2M Command(%02x) OEM_CAMERA_CONFIG_SET!!!", ntohs(m2m_req->cmd_id));
			if((!g_exdev_running) && parse_exdev_config(pdu_ptr + sizeof(M2M_PROTOCOL_HDR) ,pdu_len-sizeof(M2M_PROTOCOL_HDR),"set"))
			{
				pthread_t exdev_handle_id;
				if (pthread_create(&exdev_handle_id, NULL, (void *)exdev_handle_thread, ntohl(m2m_req->packet_id)) != 0)
				{
					syslog(LOG_ERR, "!!M2M Failed to Create EXDEV Thread");
				}
				else
				{
					pthread_detach(exdev_handle_id);
					syslog(LOG_NOTICE, "M2M EXDEV Thread %d", exdev_handle_id);
					break;
				}
			}

			m2m_res->cmd_id = htons(OEM_CAMERA_CONFIG_SET_ACK);
			*(m2m_res_buf + sizeof(M2M_PROTOCOL_HDR))=1;
			res_buf_len = sizeof(M2M_PROTOCOL_HDR) + 1;
			m2m_res->len = htons(res_buf_len);
			udp_socket_send(m2m_res_buf, res_buf_len);

			break;
		case OEM_CAMERA_CONFIG_GET:
			syslog(LOG_NOTICE, "M2M Command(%02x) OEM_CAMERA_CONFIG_GET!!!", ntohs(m2m_req->cmd_id));
			if((!g_exdev_running) && parse_exdev_config(pdu_ptr + sizeof(M2M_PROTOCOL_HDR) ,pdu_len-sizeof(M2M_PROTOCOL_HDR),"get"))
			{
				pthread_t exdev_handle_id;
				if (pthread_create(&exdev_handle_id, NULL, (void *)exdev_handle_thread, ntohl(m2m_req->packet_id)) != 0)
				{
					syslog(LOG_ERR, "!!M2M Failed to Create EXDEV Thread");
				}
				else
				{
					pthread_detach(exdev_handle_id);
					syslog(LOG_NOTICE, "M2M EXDEV Thread %d", exdev_handle_id);
					break;
				}
			}

			m2m_res->cmd_id = htons(OEM_CAMERA_CONFIG_GET_ACK);
			*(m2m_res_buf + sizeof(M2M_PROTOCOL_HDR))=1;
			res_buf_len = sizeof(M2M_PROTOCOL_HDR) + 1;
			m2m_res->len = htons(res_buf_len);
			udp_socket_send(m2m_res_buf, res_buf_len);

			break;
		case OEM_CAMERA_RESET:
			syslog(LOG_NOTICE, "M2M Command(%02x) OEM_CAMERA_RESET!!!", ntohs(m2m_req->cmd_id));
			if((!g_exdev_running) && parse_exdev_config(pdu_ptr + sizeof(M2M_PROTOCOL_HDR) ,pdu_len-sizeof(M2M_PROTOCOL_HDR),"reset"))
			{
				pthread_t exdev_handle_id;
				if (pthread_create(&exdev_handle_id, NULL, (void *)exdev_handle_thread, ntohl(m2m_req->packet_id)) != 0)
				{
					syslog(LOG_ERR, "!!M2M Failed to Create EXDEV Thread");
				}
				else
				{
					pthread_detach(exdev_handle_id);
					syslog(LOG_NOTICE, "M2M EXDEV Thread %d", exdev_handle_id);
					break;
				}
			}

			m2m_res->cmd_id = htons(OEM_CAMERA_RESET_ACK);
			*(m2m_res_buf + sizeof(M2M_PROTOCOL_HDR))=1;
			res_buf_len = sizeof(M2M_PROTOCOL_HDR) + 1;
			m2m_res->len = htons(res_buf_len);
			udp_socket_send(m2m_res_buf, res_buf_len);

			break;
		case DOWNLOAD_INFO_EX:
			syslog(LOG_NOTICE, "M2M Command(%02x) DOWNLOAD_INFO_EX!!!", ntohs(m2m_req->cmd_id));
			g_down_info = (ST_DOWNLOAD_INFO_EX *)(pdu_ptr + sizeof(M2M_PROTOCOL_HDR));
			if((!g_downloading) && ((pdu_len - sizeof(M2M_PROTOCOL_HDR)) == (g_down_info->filecount * sizeof(FILE_INFO) + 4)))
			{
				int jjj=0;
				char tmp_md5[35];
				syslog(LOG_ERR,"Filecount %d",g_down_info->filecount);
				for(jjj=0;jjj<g_down_info->filecount;jjj++)
				{
					memset(tmp_md5,0,sizeof(tmp_md5));
					strncpy(tmp_md5,g_down_info->filelist[jjj].md5,32);
					syslog(LOG_ERR,"id:%u---size:%u---name:%s---md5:%s",ntohl(g_down_info->filelist[jjj].id),ntohl(g_down_info->filelist[jjj].size),g_down_info->filelist[jjj].filename,tmp_md5);
				}
				g_down_info = (ST_DOWNLOAD_INFO_EX *)malloc(pdu_len - sizeof(M2M_PROTOCOL_HDR));
				if(g_down_info)
				{
					pthread_t download_id;
					g_packet_id=ntohl(m2m_req->packet_id);
					memcpy(g_down_info,pdu_ptr + sizeof(M2M_PROTOCOL_HDR),pdu_len - sizeof(M2M_PROTOCOL_HDR));
					if(g_down_info->type == M2M_UDP)
					{
						if (pthread_create(&download_id, NULL, (void *)download_thread_ex, 1) != 0)
						{
							syslog(LOG_ERR, "!!M2M Failed to Create Download Thread Ex");
						}
						else
						{
							pthread_detach(download_id);
							syslog(LOG_NOTICE, "M2M Download Thread Ex %d", download_id);
							break;
						}
					}
					else if(g_down_info->type == M2M_TCP)
					{
						if (pthread_create(&download_id, NULL, (void *)download_thread_ex_tcp, 1) != 0)
						{
							syslog(LOG_ERR, "!!M2M Failed to Create Download Thread Ex");
						}
						else
						{
							pthread_detach(download_id);
							syslog(LOG_NOTICE, "M2M Download Thread Ex %d", download_id);
							break;
						}
					}
				}
			}

			m2m_res->cmd_id = htons(DOWNLOAD_INFO_EX_ACK);
			*(m2m_res_buf + sizeof(M2M_PROTOCOL_HDR)) = 1;
			res_buf_len = sizeof(M2M_PROTOCOL_HDR) + 1;
			m2m_res->len = htons(res_buf_len);
			udp_socket_send(m2m_res_buf, res_buf_len);

			break;
		case FILE_REQ_ACK:
			if((*(pdu_ptr + sizeof(M2M_PROTOCOL_HDR))==0) &&(g_recv_file_fd != NULL))
			{
				fwrite(pdu_ptr + sizeof(M2M_PROTOCOL_HDR) +1,1,pdu_len - sizeof(M2M_PROTOCOL_HDR) -1,g_recv_file_fd);
				g_get_file_req_ack=1;
			}
			break;
#if 0
		case FILE_LIST_GET:
			syslog(LOG_NOTICE, "M2M Command(%02x) FILE_LIST_GET!!!", ntohs(m2m_req->cmd_id));
			m2m_res->cmd_id = htons(FILE_LIST_GET_ACK);
			*(m2m_res_buf + sizeof(M2M_PROTOCOL_HDR)) = 0;
			res_buf_len = sizeof(M2M_PROTOCOL_HDR) + 1;
			m2m_res->len = htons(res_buf_len);
			udp_socket_send(m2m_res_buf, res_buf_len);

			if(	!send_file_list())
				*(m2m_res_buf + sizeof(M2M_PROTOCOL_HDR)) = 1; //error

			udp_socket_send(m2m_res_buf, res_buf_len);
			break;
		case REPORT_FILE_LIST_ACK:
			syslog(LOG_NOTICE, "M2M Command(%02x) REPORT_FILE_LIST_ACK!!!", ntohs(m2m_req->cmd_id));
			break;
#endif
		case DELETE_FILE_ACK:
			syslog(LOG_NOTICE, "M2M Command(%02x) DELETE_FILE_ACK!!!", ntohs(m2m_req->cmd_id));
			break;
		case DELETE_FILE:
			syslog(LOG_NOTICE, "M2M Command(%02x) DELETE_FILE!!!", ntohs(m2m_req->cmd_id));
			m2m_res->cmd_id = htons(DELETE_FILE_ACK);
			*(m2m_res_buf + sizeof(M2M_PROTOCOL_HDR)) = delete_files(pdu_ptr + sizeof(M2M_PROTOCOL_HDR), pdu_len - sizeof(M2M_PROTOCOL_HDR));
			res_buf_len = sizeof(M2M_PROTOCOL_HDR) + 1;
			m2m_res->len = htons(res_buf_len);
			udp_socket_send(m2m_res_buf, res_buf_len);
			break;
		case DOWNLOAD_CFG_FILE:
			fuc_ret=1;
			syslog(LOG_NOTICE, "M2M Command(%02x) DOWNLOAD_CFG_FILE!!!", ntohs(m2m_req->cmd_id));
			m2m_res->cmd_id = htons(DOWNLOAD_CFG_FILE_ACK);
			m2m_tlv = (M2M_PROTOCOL_TLV*)(pdu_ptr + sizeof(M2M_PROTOCOL_HDR));
			syslog(LOG_NOTICE, "DOWNLOAD_CFG_FILE %d:%s", ntohs(m2m_tlv->tlv_len), m2m_tlv->tlv_value);
			fuc_ret=parse_router_config(m2m_tlv->tlv_value, ntohs(m2m_tlv->tlv_len));
			res_buf_len = sizeof(M2M_PROTOCOL_HDR) + 1;
			m2m_res->len = htons(res_buf_len);
			try_count=nvram_get_int("m2m_down_try")>0?:10;
			while((fuc_ret == 0) &&(try_count--))
			{
				AD_UPGRADE_flag = 1;
				N_ACK = 0;
				system("rm -rf /tmp/config_m2m.cfg");
				sprintf(ctrl_cmd, "wget -t 2 -c ftp://%s:%s@%s:%d/%s -O /tmp/config_m2m.cfg &",
					nvram_safe_get("username"), nvram_safe_get("password"),
					nvram_safe_get("ip"), nvram_get_int("port")>0?nvram_get_int("port"):21,nvram_safe_get("filename"));
				syslog(LOG_NOTICE, "M2M download command: %s", ctrl_cmd);
				system(ctrl_cmd);
				sleep(2);
				sprintf(ctrl_cmd,"/tmp/config_m2m.cfg");
				idel_count=0;
				tmp_size=0;
				while (pidof("wget")>0)
				{
					N_ACK = 0;
					if(stat(ctrl_cmd,&st)==0)
					{
						send_download_report(0,ntohl(m2m_req->packet_id),nvram_safe_get("filename"),st.st_size);
						if(tmp_size==st.st_size)
						{
							if(idel_count++>=30)
							{
								syslog(LOG_ERR,"M2M Idel time out");
								system("killall -9 wget");
							}
						}
						else
						{
							idel_count=0;
						}
						tmp_size=st.st_size;
					}
					sleep(1);
				}

				if((stat(ctrl_cmd,&st)==0)&&(st.st_size==nvram_get_int("size")))
				{
					send_download_report(0,ntohl(m2m_req->packet_id),nvram_safe_get("filename"),st.st_size);
					break;
				}
			}

			static char *args[] = {"nvram", "restore", "/tmp/config_m2m.cfg", NULL};

			if((stat(ctrl_cmd,&st)==0)&&(st.st_size==nvram_get_int("size")))
			{
				if (_eval(args, ">/tmp/config_m2m.cfg.msg", 0, NULL) != 0)
					*(m2m_res_buf + sizeof(M2M_PROTOCOL_HDR)) = 1;
				else
					*(m2m_res_buf + sizeof(M2M_PROTOCOL_HDR)) = 0;
			}
			else
			{
				syslog(LOG_ERR,"Download error");
				*(m2m_res_buf + sizeof(M2M_PROTOCOL_HDR)) = 1;
			}
			udp_socket_send(m2m_res_buf, res_buf_len);

			break;
		case M2M_CONFIG_TRAP_ACK:
			syslog(LOG_NOTICE, "M2M Command(%02x) M2M_CONFIG_TRAP_ACK!!!", ntohs(m2m_req->cmd_id));
			break;
		case M2M_REGISTER_ACK:
			syslog(LOG_NOTICE, "M2M Command(%02x) M2M_REGISTER_ACK!!!", ntohs(m2m_req->cmd_id));
			break;
		case M2M_CONFIG_REQ:
			syslog(LOG_NOTICE, "M2M Command(%02x) M2M_CONFIG_REQ!!!", ntohs(m2m_req->cmd_id));
			break;
		case REMOTE_CTRL:
			syslog(LOG_NOTICE, "M2M Command(%02x) REMOTE_CTRL!!!", ntohs(m2m_req->cmd_id));
			m2m_res->cmd_id = htons(REMOTE_CTRL_ACK);
			res_buf_len = sizeof(M2M_PROTOCOL_HDR) + 1;
			m2m_res->len = htons(res_buf_len);
			ctrl_cmd_flag = *(pdu_ptr + sizeof(M2M_PROTOCOL_HDR));
			if (ctrl_cmd_flag == 0x01)
			{
				*(m2m_res_buf + sizeof(M2M_PROTOCOL_HDR)) = 0;
				udp_socket_send(m2m_res_buf, res_buf_len);
				m2m_send_cmd(M2M_LOGOUT);
				syslog(LOG_NOTICE, "M2M Reboot System Command!!");
				reboot(RB_AUTOBOOT);
			}
            else if (ctrl_cmd_flag == 0x05)
            {
				*(m2m_res_buf + sizeof(M2M_PROTOCOL_HDR)) = 0;
				udp_socket_send(m2m_res_buf, res_buf_len);
                #ifdef TCONFIG_N2N
                m2m_send_cmd(M2M_VT_IP_REQ);
                #endif
            }
            else if (ctrl_cmd_flag == 0x06)
            {
				*(m2m_res_buf + sizeof(M2M_PROTOCOL_HDR)) = 0;
				udp_socket_send(m2m_res_buf, res_buf_len);
                #ifdef TCONFIG_N2N
                stop_n2n(  );
                m2m_send_cmd(M2M_VT_CH_REPORT);
                #endif
            }
			else
			{
				syslog(LOG_NOTICE, "M2M Unknown Command!!");
				*(m2m_res_buf + sizeof(M2M_PROTOCOL_HDR)) = 1;
				udp_socket_send(m2m_res_buf, res_buf_len);
			}
			break;
        case M2M_VT_IP_ACK:
			syslog(LOG_NOTICE, "M2M Command(%02x) VT_IP_ACK!!!", ntohs(m2m_req->cmd_id));
            #ifdef TCONFIG_N2N
            struct in_addr ip_buf;
            char n2n_ip_str[16];

			char ack_status = *(pdu_ptr + sizeof(M2M_PROTOCOL_HDR));
            if (ack_status != 0)
            {
                break;
            }

            memcpy(&ip_buf.s_addr, pdu_ptr + sizeof(M2M_PROTOCOL_HDR) + 1, 4);
            syslog(LOG_NOTICE, "n2n ip addr is %02x", ip_buf.s_addr);
            strncpy(n2n_ip_str, (char *)inet_ntoa(ip_buf), sizeof(n2n_ip_str));
            syslog(LOG_NOTICE, "n2n ip addr string is %s", n2n_ip_str);
            start_n2n(n2n_ip_str); 
            #endif
            break;
        case M2M_VT_CH_REPORT_ACK:
			syslog(LOG_NOTICE, "M2M Command(%02x) VT Channel REPORT ACK!!!", ntohs(m2m_req->cmd_id));
            break;
		case DOWNLOAD_INFO:
			syslog(LOG_NOTICE, "M2M Command(%02x) DOWNLOAD_INFO!!!", ntohs(m2m_req->cmd_id));
			m2m_res->cmd_id = htons(DOWNLOAD_INFO_ACK);
			m2m_tlv = (M2M_PROTOCOL_TLV*)(pdu_ptr + sizeof(M2M_PROTOCOL_HDR));
			syslog(LOG_NOTICE, "M2M_CONIFG_SET %d:%s", ntohs(m2m_tlv->tlv_len), m2m_tlv->tlv_value);
			nvram_unset("type");
			fuc_ret = parse_router_config(m2m_tlv->tlv_value, ntohs(m2m_tlv->tlv_len));
			if(!nvram_match("type","hk_camera") && (fuc_ret != 0))
			{
				syslog(LOG_ERR,"parse config error");
				*(m2m_res_buf + sizeof(M2M_PROTOCOL_HDR))=1;
				res_buf_len = sizeof(M2M_PROTOCOL_HDR) + 1;
				m2m_res->len = htons(res_buf_len);
				udp_socket_send(m2m_res_buf, res_buf_len);
				break;
			}
			try_count=nvram_get_int("m2m_down_try")>0?:10;
			while(try_count--)
			{
				AD_UPGRADE_flag = 1;	
				sprintf(ctrl_cmd, "wget -t 2 -c ftp://%s:%s@%s:%d/%s -O /tmp/%s &",
					nvram_safe_get("username"), nvram_safe_get("password"),
					nvram_safe_get("ip"), nvram_get_int("port")>0?nvram_get_int("port"):21,nvram_safe_get("filename"), FTP_FILE_TMP);
				syslog(LOG_NOTICE, "M2M Upgrade command: %s", ctrl_cmd);
				N_ACK = 0;
				system(ctrl_cmd);
				sleep(2);
				sprintf(ctrl_cmd,"/tmp/%s",FTP_FILE_TMP);
				idel_count=0;
				tmp_size=0;
				while (pidof("wget")>0)
				{
					N_ACK = 0;
					if(stat(ctrl_cmd,&st)==0)
					{
						send_download_report(0,ntohl(m2m_req->packet_id),nvram_safe_get("filename"),st.st_size);
						if(tmp_size==st.st_size)
						{
							if(idel_count++>=30)
							{
								syslog(LOG_ERR,"M2M Idel time out");
								system("killall -9 wget");
							}
						}
						else
						{
							idel_count=0;
						}
						tmp_size=st.st_size;
					}
					sleep(1);
				}

				if((stat(ctrl_cmd,&st)==0)&&(st.st_size==nvram_get_int("size")))
				{
					send_download_report(0,ntohl(m2m_req->packet_id),nvram_safe_get("filename"),st.st_size);
					break;
				}
			}

			if(!((stat(ctrl_cmd,&st)==0)&&(st.st_size==nvram_get_int("size"))))
			{
				syslog(LOG_ERR,"Download error");
				m2m_res->cmd_id = htons(DOWNLOAD_INFO_ACK);
				*(m2m_res_buf + sizeof(M2M_PROTOCOL_HDR))=1;
				res_buf_len = sizeof(M2M_PROTOCOL_HDR) + 1;
				m2m_res->len = htons(res_buf_len);
				udp_socket_send(m2m_res_buf, res_buf_len);
				break;
			}
			else
			{
				syslog(LOG_ERR,"Download ok");
				m2m_res->cmd_id = htons(DOWNLOAD_INFO_ACK);
				*(m2m_res_buf + sizeof(M2M_PROTOCOL_HDR))=0;
				res_buf_len = sizeof(M2M_PROTOCOL_HDR) + 1;
				m2m_res->len = htons(res_buf_len);
				udp_socket_send(m2m_res_buf, res_buf_len);
			}
			if(nvram_match("type","hk_camera"))
			{
				syslog(LOG_NOTICE, "M2M Command(%02x) OEM UPGRADE!!!", ntohs(m2m_req->cmd_id));
				if((!g_exdev_running))
				{
					nvram_set("oem_op","upgrade");
					pthread_t exdev_handle_id;
					if (pthread_create(&exdev_handle_id, NULL, (void *)exdev_handle_thread, ntohl(m2m_req->packet_id)) != 0)
					{
						syslog(LOG_ERR, "!!M2M Failed to Create EXDEV Thread");
					}
					else
					{
						pthread_detach(exdev_handle_id);
						syslog(LOG_NOTICE, "M2M EXDEV Thread %d", exdev_handle_id);
						break;
					}
				}

				m2m_res->cmd_id = htons(DOWNLOAD_INFO_ACK);
				*(m2m_res_buf + sizeof(M2M_PROTOCOL_HDR))=1;
				res_buf_len = sizeof(M2M_PROTOCOL_HDR) + 1;
				m2m_res->len = htons(res_buf_len);
				udp_socket_send(m2m_res_buf, res_buf_len);

				break;
			}
			
			if(strstr(nvram_safe_get("filename"),".patch"))
			{
				syslog(LOG_ERR,"mod upgrade");
				if(!mod_upgrade("/tmp/tmp.trx"))
				{
					set_action(ACT_IDLE);
					m2m_send_ack(DOWNLOAD_INFO_ACK,g_packet_id,1);
					m2m_send_cmd(M2M_LOGOUT);
					sleep(2);
					reboot(RB_AUTOBOOT);
				}
				if(nvram_match("mod_upgrade_test","1"))
					exit(1);
			}
			eval("service", "upgrade", "start");
			set_action(ACT_IDLE);
			char *wargv[] = { "mtd-write", "-w", "-i", "/tmp/tmp.trx", "-d", "linux", NULL };
			if (_eval(wargv, ">/tmp/mtd-write-m2m", 0, &pid) != 0) {
				system("rm -rf /tmp/tmp.trx");
				set_action(ACT_IDLE);
				break;
			}
			if (pid != -1) waitpid(pid, &n, 0);
			AD_UPGRADE_flag = 0;
			N_ACK = 0;
			set_action(ACT_REBOOT);
			syslog(LOG_NOTICE, "M2M Reboot System");
			m2m_send_cmd(M2M_LOGOUT);
			sleep(2);
			reboot(RB_AUTOBOOT);
			break;
		case DOWNLOAD_AD:
			syslog(LOG_NOTICE, "M2M Command(%02x) DOWNLOAD_AD!!!", ntohs(m2m_req->cmd_id));
			m2m_res->cmd_id = htons(DOWNLOAD_AD_ACK);
			m2m_tlv = (M2M_PROTOCOL_TLV*)(pdu_ptr + sizeof(M2M_PROTOCOL_HDR));
			syslog(LOG_NOTICE, "M2M_CONIFG_SET %d:%s", ntohs(m2m_tlv->tlv_len), m2m_tlv->tlv_value);
			if(!g_downloading)
			{
				*(m2m_res_buf + sizeof(M2M_PROTOCOL_HDR)) = parse_router_config(m2m_tlv->tlv_value, ntohs(m2m_tlv->tlv_len));
			}
			else
			{
				*(m2m_res_buf + sizeof(M2M_PROTOCOL_HDR)) = 1;
			}
			res_buf_len = sizeof(M2M_PROTOCOL_HDR) + 1;
			m2m_res->len = htons(res_buf_len);
			udp_socket_send(m2m_res_buf, res_buf_len);
			if(!g_downloading)
			{
				pthread_t download_id;
				g_packet_id=ntohl(m2m_req->packet_id);
				if (pthread_create(&download_id, NULL, (void *)download_thread, NULL) != 0)
				{
					syslog(LOG_ERR, "!!M2M Failed to Create Download Thread");
				}
				else
				{
					pthread_detach(download_id);
					syslog(LOG_NOTICE, "M2M Download Thread %d", download_id);
				}
			}
			AD_UPGRADE_flag = 0;
			N_ACK = 0;
			break;
		case DOWNLOAD_REPORT_ACK:
			syslog(LOG_NOTICE, "M2M Command(%02x) DOWNLOAD_REPORT_ACK!!!", ntohs(m2m_req->cmd_id));
			break;
	//	case REPORT_DEVICE_ACK:
	//		syslog(LOG_NOTICE, "M2M Command(%02x) REPORT_DEVICE_ACK!!!", ntohs(m2m_req->cmd_id));
			break;
		case QUERY_DEVICE_ACK:
			syslog(LOG_NOTICE, "M2M Command(%02x) QUERY_DEVICE_ACK!!!", ntohs(m2m_req->cmd_id));
			{
				char *res= pdu_ptr + sizeof(M2M_PROTOCOL_HDR);
				char value[10];

				if(strncmp(res,"value=",6) == 0)
				{
					sprintf(value,"%c",*(res + 6));
					g_query_ack = atoi(value);
					syslog(LOG_ERR,"query res=%d",g_query_ack);
				}
			}
			break;
		case SYNC_TIME_ACK:
			syslog(LOG_NOTICE, "M2M Command(%02x) SYNC_TIME_ACK!!!", ntohs(m2m_req->cmd_id));
			unsigned int data=0;
			struct timeval tv;
			memcpy(&data,pdu_ptr + sizeof(M2M_PROTOCOL_HDR),4);
			tv.tv_sec = ntohl(data);
			tv.tv_usec = 0;
			if(settimeofday(&tv,NULL) == -1)
			{
				syslog(LOG_ERR,"set time error %s",strerror(errno));
			}
			else
			{
				g_sync_time_ack = 1;
			}

			break;
		case SEND_SMS_ACK:
		{
			char *ret=pdu_ptr + sizeof(M2M_PROTOCOL_HDR);
			syslog(LOG_NOTICE, "M2M Command(%02x) SEND_SMS_ACK!!!-------%d", ntohs(m2m_req->cmd_id),*ret);
			g_m2m_sms_ack = *ret;
			break;
		}
		case REPORT_URL_ACK:
			syslog(LOG_NOTICE, "M2M Command(%02x) REPORT_URL_ACK!!!", ntohs(m2m_req->cmd_id));
			break;
		case REMOTE_DEVICE_CTRL:
			syslog(LOG_NOTICE, "M2M Command(%02x) REMOTE_DEVICE_CTRL!!!", ntohs(m2m_req->cmd_id));
			m2m_res->cmd_id = htons(REMOTE_DEVICE_CTRL_ACK);
			*(m2m_res_buf + sizeof(M2M_PROTOCOL_HDR)) = execute_remote_ctrl(pdu_ptr + sizeof(M2M_PROTOCOL_HDR));
			res_buf_len = sizeof(M2M_PROTOCOL_HDR) + 1;
			m2m_res->len = htons(res_buf_len);
			udp_socket_send(m2m_res_buf, res_buf_len);
			break;
		case PACKET_CAP:
			syslog(LOG_NOTICE, "M2M Command(%02x) PACKET_CAP!!!", ntohs(m2m_req->cmd_id));
			if(!g_pcap_working)
			{
				pthread_t pcap_id;
				ST_PACKET_CAP *tmp;
				struct tm *ps;

				tmp = (ST_PACKET_CAP *)(pdu_ptr + sizeof(M2M_PROTOCOL_HDR));
				g_pcap_info.id = ntohl(tmp->id);
				g_pcap_info.start = ntohl(tmp->start);
				g_pcap_info.end = ntohl(tmp->end);
				g_pcap_info.type = tmp->type;

				ps=localtime(&g_pcap_info.start);
				syslog(LOG_ERR,"%u:%d===%d-%d-%d %d:%d:%d -> %u",g_pcap_info.id,g_pcap_info.type,1900+ps->tm_year,1+ps->tm_mon,ps->tm_mday,ps->tm_hour,ps->tm_min,ps->tm_sec,g_pcap_info.end-g_pcap_info.start);
				if (pthread_create(&pcap_id, NULL, (void *)pcap_thread, ntohl(m2m_req->packet_id)) != 0)
				{
					syslog(LOG_ERR, "!!M2M Failed to Create cap Thread");
				}
				else
				{
					pthread_detach(pcap_id);
					syslog(LOG_NOTICE, "M2M cap Thread Ex %d", pcap_id);
				}
			}
			else
			{
				syslog(LOG_NOTICE, "PCAP is running !!!");
				m2m_send_ack(PACKET_CAP_ACK,ntohl(m2m_req->packet_id),1);
			}
			break;
		case CAP_FILE_UPLOAD_ACK:
			if(*(pdu_ptr + sizeof(M2M_PROTOCOL_HDR))==0)
			{
				g_get_cap_upload_ack=1;
			}
			break;
		case DOWNLOAD_CFG_UDP:
			syslog(LOG_NOTICE, "M2M Command(%02x) DOWNLOAD_CFG_UDP!!!", ntohs(m2m_req->cmd_id));
			g_down_info = (ST_DOWNLOAD_INFO_EX *)(pdu_ptr + sizeof(M2M_PROTOCOL_HDR));
			if((!g_downloading) && ((pdu_len - sizeof(M2M_PROTOCOL_HDR)) == (g_down_info->filecount * sizeof(FILE_INFO) + 4)))
			{
				int jjj=0;
				char tmp_md5[35];
				syslog(LOG_ERR,"Filecount %d",g_down_info->filecount);
				for(jjj=0;jjj<g_down_info->filecount;jjj++)
				{
					memset(tmp_md5,0,sizeof(tmp_md5));
					strncpy(tmp_md5,g_down_info->filelist[jjj].md5,32);
					syslog(LOG_ERR,"id:%u---size:%u---name:%s---md5:%s",ntohl(g_down_info->filelist[jjj].id),ntohl(g_down_info->filelist[jjj].size),g_down_info->filelist[jjj].filename,tmp_md5);
				}
				g_down_info = (ST_DOWNLOAD_INFO_EX *)malloc(pdu_len - sizeof(M2M_PROTOCOL_HDR));
				if(g_down_info)
				{
					pthread_t download_id;
					g_packet_id=ntohl(m2m_req->packet_id);
					memcpy(g_down_info,pdu_ptr + sizeof(M2M_PROTOCOL_HDR),pdu_len - sizeof(M2M_PROTOCOL_HDR));
					if (pthread_create(&download_id, NULL, (void *)download_thread_ex, 2) != 0)
					{
						syslog(LOG_ERR, "!!M2M Failed to Create Download Thread Ex");
					}
					else
					{
						pthread_detach(download_id);
						syslog(LOG_NOTICE, "M2M Download Thread Ex %d", download_id);
						break;
					}
				}
			}

			m2m_res->cmd_id = htons(DOWNLOAD_CFG_UDP_ACK);
			*(m2m_res_buf + sizeof(M2M_PROTOCOL_HDR)) = 1;
			res_buf_len = sizeof(M2M_PROTOCOL_HDR) + 1;
			m2m_res->len = htons(res_buf_len);
			udp_socket_send(m2m_res_buf, res_buf_len);

			break;
		case CFG_FILE_REQ_ACK:
			if((*(pdu_ptr + sizeof(M2M_PROTOCOL_HDR))==0) &&(g_recv_file_fd != NULL))
			{
				fwrite(pdu_ptr + sizeof(M2M_PROTOCOL_HDR) +1,1,pdu_len - sizeof(M2M_PROTOCOL_HDR) -1,g_recv_file_fd);
				g_get_file_req_ack=1;
			}
			break;
		case RTU_PUB_ACK:
			syslog(LOG_NOTICE, "M2M Command(%02x) RTU_PUB_ACK!!!", ntohs(m2m_req->cmd_id));
			if (pdu_ptr[sizeof(M2M_PROTOCOL_HDR_T)] == 0x00)
			{
				syslog(LOG_NOTICE, "M2M Command(%02x): success!!!", ntohs(m2m_req->cmd_id));
			}
			else
			{
				syslog(LOG_ERR, "M2M Command(%02x): TLV error!!!", ntohs(m2m_req->cmd_id));
			}
			break;
		case RTU_SCRIPT_GET_CMD:
			syslog(LOG_NOTICE, "M2M Command(%02x) RTU_SCRIPT_GET_CMD!!!", ntohs(m2m_req->cmd_id));
			m2m_res->cmd_id = htons(RTU_SCRIPT_GET_ACK);
		 	m2m_buf = nvram_safe_get("rtu_scripts");
			if ((m2m_buf == NULL) || (strlen(m2m_buf) <= 1))
			{
				*(m2m_res_buf + sizeof(M2M_PROTOCOL_HDR_T)) = 0x01;		//获取脚本失败
				syslog(LOG_NOTICE, "M2M Command(%02x) Get scripts fail!!!", ntohs(m2m_req->cmd_id));
				res_buf_len = sizeof(M2M_PROTOCOL_HDR_T) + 1;
				m2m_res->len = htons(res_buf_len);
				udp_socket_send(m2m_res_buf, res_buf_len);
			}
			else
			{
				*(m2m_res_buf + sizeof(M2M_PROTOCOL_HDR_T)) = 0x00;		//获取脚本成功
				syslog(LOG_NOTICE, "M2M Command(%02x) Get scripts success!!!", ntohs(m2m_req->cmd_id));
				len = strlen(m2m_buf);
				memcpy(m2m_res_buf + sizeof(M2M_PROTOCOL_HDR_T) + 1, m2m_buf, len);
				res_buf_len = sizeof(M2M_PROTOCOL_HDR_T) + 1 + len;
				m2m_res->len = htons(res_buf_len);

				memset(str, 0, 1024);
				HexToStr(m2m_res_buf, str, res_buf_len);
				syslog(LOG_NOTICE, "RTU_SCRIPT_GET_ACK:%s", str);

				udp_socket_send(m2m_res_buf, res_buf_len);
			}
			break;
		case RTU_SCRIPT_SET_CMD:
			syslog(LOG_NOTICE, "M2M Command(%02x) RTU_SCRIPT_SET_CMD!!!", ntohs(m2m_req->cmd_id));
			m2m_res->cmd_id = htons(RTU_SCRIPT_SET_ACK);
			memcpy(tmp_buf, pdu_ptr + sizeof(M2M_PROTOCOL_HDR_T), pdu_len - sizeof(M2M_PROTOCOL_HDR_T));	
			nvram_set("rtu_scripts", tmp_buf);
			system("nvram commit");	
			*(m2m_res_buf + sizeof(M2M_PROTOCOL_HDR_T)) = 0x00;		//设置脚本成功
			res_buf_len = sizeof(M2M_PROTOCOL_HDR_T) + 1;
			m2m_res->len = htons(res_buf_len);

			memset(str, 0, 1024);
			HexToStr(m2m_res_buf, str, res_buf_len);
			syslog(LOG_NOTICE, "RTU_SCRIPT_SET_ACK:%s", str);

			udp_socket_send(m2m_res_buf, res_buf_len);
			m2m_send_cmd(M2M_LOGOUT);
			syslog(LOG_NOTICE, "RTU scripts set reboot!!");
			reboot(RB_AUTOBOOT);
			break;
		default:
			syslog(LOG_NOTICE, "M2M Command(%02x) Unsupport!!!", ntohs(m2m_req->cmd_id));
			break;
	}
}

static int process_m2m_Req( )
{
	int		 iRcv;
	int		 fromlen;
	char		*hdr;
	char		pdubuf[M2M_REQ_PDU_BUF];
	struct sockaddr_in  from_addr;

	memset(pdubuf, 0, sizeof(pdubuf));

	if ( wait_sock(socket_fd , 1 , 0) == 0)
	{
		return (-1);
	}

	fromlen = sizeof(from_addr);

	//Receive the complete PDU
	iRcv = udp_socket_recv(pdubuf , sizeof(pdubuf));

	if (iRcv < sizeof(M2M_PROTOCOL_HDR_T))
	{
		syslog(LOG_ERR, "iRcv: %d != m2mHDR: %d", iRcv, sizeof(M2M_PROTOCOL_HDR_T));
		close_socket(socket_fd);
		return (-1);
	}

	hdr = pdubuf;

	process_packet( hdr, iRcv);
}

static int process_report_Req(int socketfd, unsigned long svrip )
{
	int		 iRcv;
	int		 fromlen;
	char		*hdr;
	char		pdubuf[M2M_REQ_PDU_BUF];
	struct sockaddr_in  from_addr;

	memset(pdubuf, 0, sizeof(pdubuf));

	if ( wait_sock(socketfd , 1 , 0) == 0)
	{
		return (-1);
	}

	fromlen = sizeof(from_addr);

	//Receive the complete PDU
	iRcv = report_udp_socket_recv(socketfd, pdubuf , sizeof(pdubuf), svrip);

	if (iRcv < sizeof(M2M_PROTOCOL_HDR_T))
	{
		syslog(LOG_ERR, "iRcv: %d != m2mHDR: %d", iRcv, sizeof(M2M_PROTOCOL_HDR_T));
		close_socket(socketfd);
		return (-1);
	}

	hdr = pdubuf;

	process_report_packet( hdr, iRcv, socketfd);
}

static int connect_to_server(char *sock_name)
{
	int sock;
	struct sockaddr_un	sa_un;
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	memset(&sa_un, 0, sizeof(sa_un));
	sa_un.sun_family = AF_UNIX;
	strncpy(sa_un.sun_path, sock_name, (sizeof(sa_un.sun_path) - 1));
	if (connect(sock, (struct sockaddr *)&sa_un, strlen(sa_un.sun_path) + sizeof(sa_un.sun_family)))
	{
		syslog(LOG_ERR,"M2M: nd probably not started (Error: %s)\n", strerror(errno));
		return -1;
	}
	return sock;
}

static int send_data(int sock, char *request)
{
	ssize_t len,written;

	len = 0;
	while (len != strlen(request))
	{
		written = write(sock, (request + len), strlen(request) - len);
		if (written == -1)
		{
			syslog(LOG_ERR,"Write to nodogsplash failed: %s\n",strerror(errno));
			return -1;
		}
		len += written;
	}
	return((int)len);
}

int m2m_2_nd(char * cmd)
{
	int	sock;
	int	len;

	sock = connect_to_server("/tmp/.xcgi.sock");
	if(sock<0)
	{
		return 0;
	}

	len = send_data(sock, cmd);
	shutdown(sock, 2);
	close(sock);

	return len;
}

struct _cops{
	unsigned char value;
	char *keyword;
}g_cops[]={
	{1,"GSM"},
	{2,"GPRS"},
	{2,"EDGE"},
	{3,"Auto"},
	{3,"CDMA&EVDO"},
	{5,"EVDO"},
	{5,"HYB"},
	{5,"Hy"},
	{6,"WCDMA"},
	{6,"3G"},
	{7,"HSDPA"},
	{8,"HSUPA"},
	{9,"HSPA+"},
	{6,"HSPA"},
	{9,"HS"},
	{10,"TDSCDMA"},
	{10,"TD-SCDMA"},
	{11,"FDD LTE"},
	{11,"FDD"},
	{12,"TDD LTE"},
	{12,"TDD"},
	{11,"LTE"},
	{10,"TD"},
	{4,"CDMA 1x"},
	{4,"CDMA"},
	{255,NULL}
};

unsigned char get_cops()
{
	struct _cops *tmp=g_cops;
	unsigned char buf[32];

	while(tmp->keyword)
	{
		if(strstr(nvram_safe_get("cell_network"),tmp->keyword))
			return tmp->value;
		/*if(strchr(nvram_safe_get("cell_network"),'"'))
		{
			sprintf(buf,"\"%s\"",tmp->keyword);
			if(!strcmp(nvram_safe_get("cell_network"),buf))
				return tmp->value;
		}*/
		tmp++;
	}

	return 0;
}

int json_init(json *js,int len)
{
	if((js->buf=calloc(len,1)) == NULL)
	{
		return 0;
	}
	js->elm_count=0;
	return 1;
}

int json_destroy(json *js)
{
	if(js->buf)
	{
		free(js->buf);
	}
	return 1;
}

void json_start(json *js)
{
	strcpy(js->buf,"{\n");
}

void json_end(json *js)
{
	strcat(js->buf,"\n}");
}

int json_add_elm(json *js,char *name,char *value)
{
	if(js->elm_count!=0)
	{
		strcat(js->buf,",\n");
	}
	sprintf(js->buf,"%s\t\"%s\": \"%s\"",js->buf,name,value);
	js->elm_count++;
	return 1;
}

int json_add_num(json *js,char *name,unsigned long value)
{
	if(js->elm_count!=0)
	{
		strcat(js->buf,",\n");
	}
	sprintf(js->buf,"%s\t\"%s\": %lu",js->buf,name,value);
	js->elm_count++;
	return 1;
}

char *json_get_elm_value(json_elm *elm,char *name)
{
	int i=0;
	for(i=0;i<SF_JSON_ELM_COUNT;i++)
	{
		if(strcmp(elm[i].name,name) == 0)
		{
			return elm[i].value;
		}
	}
	return "";
}

void format_sf_time(char *buf)
{
	time_t timep;
	struct tm *p;
	struct timeval tv;
	struct timezone tz;

	gettimeofday (&tv ,&tz);
	timep=tv.tv_sec;
	p=localtime(&timep);
	sprintf(buf,"%04d%02d%02d%02d%02d%02d%03ld",(1900+p->tm_year), (1+p->tm_mon),p->tm_mday,p->tm_hour, p->tm_min, p->tm_sec,tv.tv_usec/1000);
}

unsigned long sf_get_traffic()
{
	FILE *f;
	char buf[256];
	char *ifname;
	char *p;
	unsigned long counter[3] = {0};
	static unsigned long sf_pre_trafic = 0;
	unsigned long trafic = 0;

	if ((f = fopen("/proc/net/dev", "r")) == NULL) return 0;
	fgets(buf, sizeof(buf), f);	// header
	fgets(buf, sizeof(buf), f);	// "
	while (fgets(buf, sizeof(buf), f))
	{
		if ((p = strchr(buf, ':')) == NULL) continue;
		*p = 0;
		if ((ifname = strrchr(buf, ' ')) == NULL) ifname = buf;
			else ++ifname;

		if(is_lte()?(strcmp(ifname, "usb0") == 0):(nvram_match("wan_proto","dhcp")?strcmp(ifname, "vlan1") == 0:strcmp(ifname, "ppp0") == 0))
		{
			if (sscanf(p + 1, "%lu%*u%*u%*u%*u%*u%*u%*u%lu", &counter[0], &counter[1]) == 2)
			{
				counter[2] = counter[0] + counter[1];
				memset(buf,0,sizeof(buf));
				if(f_read_string("/tmp/.strafic", buf, sizeof(buf)) > 0)
				{
					sf_pre_trafic = atoi(buf);
				}
				else
				{
					sf_pre_trafic = 0;
				}
				if(counter[2] < sf_pre_trafic)
				{
					trafic = counter[2];
				}
				else
				{
					trafic = counter[2] - sf_pre_trafic;
				}
				if (1)
				{
					trafic_flag = 1;
					sf_pre_trafic = counter[2];
					sprintf(buf,"%lu",sf_pre_trafic);
					f_write_string("/tmp/.strafic", buf, 0, 0);
				}
				break;
			}
		}
	}
	fclose(f);

	return trafic;
}

void handle_sf_request(int fd)
{
	json_elm jelm[SF_JSON_ELM_COUNT];
	json js;
	char buf[JSON_BUF_LEN];
	char *p,time_buf[20];
	char *start,*end,*before,*name,*middle,*middle1,*value,*after;
	int count,pack_len,i,ret;

	count=JSON_BUF_LEN;
	p=buf;
	while(1)
	{
		ret=wait_sock(fd,1,0);
		if(ret>0)
		{
			if((pack_len=recv(fd,p,count,0))>0)
			{
				p += pack_len;
				count -= pack_len;

				if(((start=strchr(buf,'{')) == NULL) || ((end=strchr(start,'}')) == NULL))
				{
					continue;
				}

				start++;
				*end='\0';

				if(!start)
				{
					syslog(LOG_ERR,"Empty JSON data");
					count=JSON_BUF_LEN;
					p=buf;
					continue;;
				}
				count=0;
				while ((p = strsep(&start, ",")) != NULL)
				{
					ret = vstrsep(p, ":\"",&before,&name,&middle,&middle1,&value,&after);
					if(ret == 4)
					{
						value = middle1;
					}
					if((ret != 6) && (ret != 4))
					{
						syslog(LOG_ERR,"Invalid JSON format");
						continue;
					}
					if(strlen(name) && strlen(value))
					{
						jelm[count].name=strdup(name);
						jelm[count].value=strdup(value);
						count++;
					}
					if(count == SF_JSON_ELM_COUNT)
					{
						syslog(LOG_ERR,"ELM list is full");
						break;
					}
				}
				if(count == 3)
				{
					if(strcmp(json_get_elm_value(jelm,"action"),"GET_TRAFFIC_REQ") == 0)
					{
						if(json_init(&js,JSON_BUF_LEN))
						{
							json_start(&js);
							json_add_elm(&js,"action","GET_TRAFFIC_RESP");
							json_add_elm(&js,"version",json_get_elm_value(jelm,"version"));
							memset(time_buf,0,sizeof(time_buf));
							format_sf_time(time_buf);
							json_add_elm(&js,"time",time_buf);
							json_add_num(&js,"traffic",sf_get_traffic());
							json_end(&js);

							count=strlen(js.buf);
							p=js.buf;
							while((pack_len=send(fd,p,count,0))>0)
							{
								p += pack_len;
								count -= pack_len;
								if(count == 0)
								{
									break;
								}
							}
							json_destroy(&js);
							syslog(LOG_ERR,"Have Send RESP to SF BOX");
						}
					}
				}
				else if(count == 4)
				{
					if(strcmp(json_get_elm_value(jelm,"action"),"SWAP_INFO_REQ") == 0)
					{
						syslog(LOG_ERR,"SF BOX ID:%s",json_get_elm_value(jelm,"fcboxAssetId"));
						nvram_set("psn",json_get_elm_value(jelm,"fcboxAssetId"));
						g_report_status_ack=0;
						while(g_report_status_ack == 0)
						{
							syslog(LOG_ERR,"SF box report status");
							m2m_send_cmd(REPORT_STATUS);
							sleep(1);
						}

						if(json_init(&js,JSON_BUF_LEN))
						{
							json_start(&js);
							json_add_elm(&js,"action","SWAP_INFO_RESP");
							json_add_elm(&js,"version",json_get_elm_value(jelm,"version"));
							memset(time_buf,0,sizeof(time_buf));
							format_sf_time(time_buf);
							json_add_elm(&js,"time",time_buf);
							json_add_elm(&js,"routerVendor","dechuan");
							json_add_elm(&js,"iccid",nvram_safe_get("sim_ccid"));
							json_end(&js);

							count=strlen(js.buf);
							p=js.buf;
							while((pack_len=send(fd,p,count,0))>0)
							{
								p += pack_len;
								count -= pack_len;
								if(count == 0)
								{
									break;
								}
							}
							json_destroy(&js);
							syslog(LOG_ERR,"Have Send RESP to SF BOX");
						}
					}
					else if(strcmp(json_get_elm_value(jelm,"action"),"REBOOT_REQ") == 0)
					{
						int delay=atoi(json_get_elm_value(jelm,"delay"));
						if(json_init(&js,JSON_BUF_LEN))
						{
							json_start(&js);
							json_add_elm(&js,"action","REBOOT_RESP");
							json_add_elm(&js,"version",json_get_elm_value(jelm,"version"));
							memset(time_buf,0,sizeof(time_buf));
							format_sf_time(time_buf);
							json_add_elm(&js,"time",time_buf);
							json_end(&js);

							count=strlen(js.buf);
							p=js.buf;
							while((pack_len=send(fd,p,count,0))>0)
							{
								p += pack_len;
								count -= pack_len;
								if(count == 0)
								{
									break;
								}
							}
							json_destroy(&js);
							syslog(LOG_ERR,"Have Send RESP to SF BOX");
						}
						usleep(delay * 1000);
						for(i=0;i < 40;i++)
						{
							if(check_action() != ACT_WEB_UPGRADE)
							{
								break;
							}
							sleep(1);
						}
						set_action(ACT_REBOOT);
						syslog(LOG_NOTICE, "SF Reboot System");
						m2m_send_cmd(M2M_LOGOUT);
						sleep(2);
						reboot(RB_AUTOBOOT);
					}
					count=4;
				}
				for(i=0;i<count;i++)
				{
					if(jelm[i].name)
					{
						free(jelm[i].name);
					}
					if(jelm[i].value)
					{
						free(jelm[i].value);
					}
				}
				count=JSON_BUF_LEN;
				p=buf;
			}
			else if(pack_len == 0)
			{
				syslog(LOG_ERR,"client disconnect,close fd");
				close(fd);
				return;
			}
		}
		else if(ret < 0)
		{
			if (errno != EINTR && errno != EAGAIN)
			{
				syslog(LOG_ERR,"%s:close fd",strerror(errno));
				close(fd);
				return;
			}
		}
	}
}

void sfbox_thread(void *param)
{
	int sock_fd = -1,accept_fd = -1,n = 1;
	struct sockaddr_in svr_addr,client_addr;
	int sin_size = sizeof(struct sockaddr_in);

	while(1)
	{
		sleep(1);
		sock_fd = socket(AF_INET, SOCK_STREAM, 0);
		if(sock_fd < 0)
		{
		    syslog(LOG_ERR, "Create socket error");
		    continue;
		}

		if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&n, sizeof(n)) < 0)
		{
		    syslog(LOG_ERR, "Setsockopt error");
		    close( sock_fd);
		    continue;
		}

		bzero(&svr_addr, sizeof(struct sockaddr_in));
		svr_addr.sin_family = AF_INET;
		svr_addr.sin_port = htons(SF_BOX_PORT);
		if(strlen(nvram_safe_get("lan_ipaddr")))
		{
			svr_addr.sin_addr.s_addr = inet_addr(nvram_safe_get("lan_ipaddr"));
		}
		else
		{
			svr_addr.sin_addr.s_addr = htonl(INADDR_ANY);
		}

		if(bind(sock_fd,(struct sockaddr *)&svr_addr,sizeof(struct sockaddr)) < 0)
		{
		    syslog(LOG_ERR, "Bind error");
		    close(sock_fd);
		    continue;
		}

		if(listen(sock_fd, 5) < 0)
		{
		    syslog(LOG_ERR, "Listen error");
		    close(sock_fd);
		    continue;
		}

		while(1)
		{
			bzero(&client_addr,sizeof(struct sockaddr_in));
			if((accept_fd = accept(sock_fd, (struct sockaddr *)&client_addr, &sin_size)) >= 0)
			{
				handle_sf_request(accept_fd);
			}
		}
	}
}

int create_report_status_socket(unsigned long *svrip)
{
	int socket_status = -1;
	unsigned long svr_addr;
	char domain[128] = "detran.xicp.net";
	int svr_port = 8000;
	char ibuf[64] = {0};

	while ( socket_status < 0 )
	{
		// check ppp online
		if( !check_online() )
		{
			syslog(LOG_NOTICE, "Report status : Cellular Offline" );
			sleep( 3 );
			continue;
		}      

		syslog(LOG_NOTICE, "Report status : Cellular Online" );

		if ((strlen(domain) > 0) && (m2m_get_host(domain, ibuf)))
		{
			svr_addr = m2m_inet_addr(ibuf, strlen(ibuf));
		}
		else
		{
			syslog(LOG_NOTICE, "Report status : Unknown M2M Server Address" );
			sleep( 3 );
			continue;
		}        
		syslog(LOG_NOTICE, "Report status Server Address: 0x%x", svr_addr);

		if ( ( socket_status = report_udp_socket_create( 0, 9993, svr_addr, svr_port) ) < 0 )
		{
			sleep( 2 );
			syslog(LOG_ERR, "Report status UDP Socket Create Error, Sleep 2s ...");
			continue;
		}
	}
	*svrip = svr_addr;
	return socket_status;
}

void heartbeat_report_thread(void *param)
{
	char hb_buf[512] = {0};
	int hb_len = 0;
	int intval = 43200;//12 hours
	int csq = 0;
	int retry=10;
	M2M_PROTOCOL_HDR* hb = (M2M_PROTOCOL_HDR*)hb_buf;
	int fd;

	fd = *((int *)param);
	syslog(LOG_INFO,"[Report] socket fd is :%d",fd);
	while(fd  >= 0)
	{		
		if(r_login_ack)
		{
			memset(hb_buf, 0, 512);
			hb_len = 0;
			hb->cmd_id = htons(M2M_HEARTBEAT);
			hb->packet_id = htonl(report_packet_id+1);
			hb->version = htons(0x0100);
			memcpy(hb->product_id, product_report_id, sizeof(hb->product_id));
			if (nvram_get_int("csq")>0)
				csq = nvram_get_int("csq");
			if (csq>100)
				csq = (csq - 100)/3;
			*(hb_buf + sizeof(M2M_PROTOCOL_HDR)) = csq;

			*(unsigned int*)(hb_buf + sizeof(M2M_PROTOCOL_HDR)+1) = htonl(trafic_calc());
			*(hb_buf + sizeof(M2M_PROTOCOL_HDR)+1+4) = get_cops();
			hb_len = sizeof(M2M_PROTOCOL_HDR)+1+4+1;
			hb->len = htons(hb_len);
			report_udp_socket_send(fd,hb_buf, hb_len);

			if((!(nvram_match("cell_cid",nvram_safe_get("cellg_cid")) && nvram_match("cell_lac",nvram_safe_get("cellg_lac"))))
					&&(!(nvram_match("cell_cid",nvram_safe_get("celle_cid")) && nvram_match("cell_lac",nvram_safe_get("celle_lac")))))
			{
				m2m_report_status_send_cmd(fd,REPORT_STATUS);
			}
			if(!r_report_status_ack)
			{
				syslog(LOG_ERR,"[Report] report status again");
				m2m_report_status_send_cmd(fd,REPORT_STATUS);
			}			
		}
		sleep(intval);
		if(!r_login_ack)
		{
			syslog(LOG_ERR,"[Report] login again");
			m2m_report_status_send_cmd(fd,M2M_LOGIN);
		}
	}
}
void report_status_alone(void *param)
{
	int fd;
	pthread_t r_heartbeat_id;
	unsigned long svrip;

	fd = create_report_status_socket(&svrip);
	m2m_report_status_send_cmd(fd, M2M_LOGIN);
	if (pthread_create(&r_heartbeat_id, NULL, (void *)heartbeat_report_thread, (void *)&fd) != 0)
	{
		syslog(LOG_ERR, "[Report]!!M2M Failed to Create Heartbeat Thread");
	}
	else
	{
		pthread_detach(r_heartbeat_id);
		syslog(LOG_NOTICE, "[Report] M2M Heartbeat Thread %d", r_heartbeat_id);
	}
	while(1)
	{
		int     res;
		fd_set  fdvar;
		struct timeval  tv;

		// check ppp online
		if( !check_online() )
		{
			syslog(LOG_NOTICE, "Report status : Cellular Offline" );
			sleep( 3 );
			continue;
		}     

		FD_ZERO(&fdvar);
		FD_SET(fd, &fdvar);

		tv.tv_sec  = 2;
		tv.tv_usec = 0; 
		res = select( fd + 1 , &fdvar , NULL , NULL , &tv);
		if (res == 1)
		{
			process_report_Req(fd,svrip);
		}
	}  
}

int encode_rtu_pub_pack(unsigned char *buf, int buf_len)
{
	M2M_PROTOCOL_HDR_T *cmd = (M2M_PROTOCOL_HDR_T *)buf;
	char *nv, *nvp, *b;
    int n;
    char slaveid_nv_name[32] = {0};
    char regAddr_nv_name[32] = {0};
    char val_nv_name[32] = {0};
    char valtype_nv_name[32] = {0};
	M2M_PROTOCOL_TLV *tlv = NULL;
	unsigned int length, tlv_len;
	unsigned short regAddr = 0;
	char outBuf[12] = {0};
    int valueType = 0;
    unsigned short startAddr = 0;
    unsigned short naddr = 0;
	int i;

    memset(buf, 0, buf_len);
	cmd->cmd_id = htons(RTU_PUB_CMD);
	cmd->packet_id = htonl(packet_id++);
	cmd->version = htons(0x0300);
	cmd->safe_flag = 0;		//安全标识:1启用, 0不启用
	cmd->type = 0;	//0: M2M指令，1: Lora指令
	memcpy(cmd->product_id, product_id, sizeof(cmd->product_id)); 
	length = sizeof(M2M_PROTOCOL_HDR_T);

	nvp = nv = strdup(nvram_safe_get("rtu_signalinfo_list"));
    if (!nv)
    {
        return -1;
    }

	//encode tlvs
    while ((b = strsep(&nvp, ">")) != NULL)
    {
        char *signalid = NULL, *signalname = NULL, *valtype = NULL, *maxval = NULL, *minval = NULL, *ctrlable = NULL, *oper = NULL;
       	char *slvid_value = NULL, *regAddr_value = NULL, *val_value = NULL;
       	
        n = vstrsep(b, "<", &signalid, &signalname, &valtype, &maxval, &minval, &ctrlable, &oper);
        if (n < 7)
        {
            continue ;
        }

        snprintf(slaveid_nv_name, sizeof(slaveid_nv_name) - 1, "slaveid_%s", signalid);		//设备地址
        snprintf(regAddr_nv_name, sizeof(regAddr_nv_name) - 1, "regAddr_%s", signalid);		//寄存器地址
        snprintf(val_nv_name, sizeof(val_nv_name) - 1, "rtuval_%s", signalid);				//传感器的值
        snprintf(valtype_nv_name, sizeof(valtype_nv_name) - 1, "valueType_%s", signalid);

		slvid_value = nvram_safe_get(slaveid_nv_name);
		regAddr_value = nvram_safe_get(regAddr_nv_name);
		val_value = nvram_safe_get(val_nv_name);
        valueType = nvram_get_int(valtype_nv_name);

		memset(outBuf, 0, sizeof(outBuf));
		
        if (slvid_value == NULL || regAddr_value == NULL || val_value  == NULL)
        {
            continue ;
        }

        startAddr = (unsigned short)atoi(nvram_safe_get(regAddr_nv_name));
        naddr = htons(startAddr);

        n = String2Bytes(val_value, outBuf, strlen(val_value));
        if (n != 4 && n != 2)
        {
            syslog(LOG_NOTICE, "----RTU Pub Function, get reg value failed ,skipped ----");
            continue ;
        }
        
		tlv = (M2M_PROTOCOL_TLV *)(buf + length);

		memset(tlv, 0, sizeof(tlv));
		tlv_len = 0;

		tlv->tlv_tag = htons(TAG_COLL_DATA);
		*(tlv->tlv_value + tlv_len) = 0x01;	//数据采集
		tlv_len += 1;
		*(tlv->tlv_value + tlv_len) = (unsigned char)atoi(slvid_value);
		tlv_len += 1;
		memcpy(tlv->tlv_value + tlv_len, &naddr, 2);
		tlv_len += 2;
		memcpy(tlv->tlv_value + tlv_len, outBuf, n);
		tlv_len += n;
		
		tlv->tlv_len = htons(tlv_len);
		//print_hex(buf + length, tlv_len, 1);
        length += (tlv_len + 4);
    }
    free(nv);

	cmd->len = htons(length);
	//print_hex(buf, length, 1);

    syslog(LOG_NOTICE, "Publish Packet data ok!");
	//unsigned char str[1024] = {0};
	//HexToStr(buf, str, length);
    //syslog(LOG_NOTICE, "Publish Data:%s, len:%d", str, length);

	return length;
}

void *rtu_pub_thread_routine(void *arg)
{
	unsigned char buf[MAX_RTU_PACKET_LENGTH] = {0};
	int pkt_length;
	int ret;
	unsigned int pub_interval = nvram_get_int("rtu_pub_interval");

	
	if (pub_interval < 5)
	{
		pub_interval = 5;	
	}
	
	while (1)
	{
		sleep(pub_interval);

		if (socket_fd < 0)
		{
			continue ;
		}
		pkt_length = encode_rtu_pub_pack(buf, sizeof(buf));
		ret = udp_socket_send(buf, pkt_length);
		if (ret == -1)
		{
			close(socket_fd);
			socket_fd = -1;
		}
	}

    return NULL;
}

void *detran_rtu_routine(void *arg)
{
#define MAX_LOST_PACKET_NUM		5
	char ibuf[21] = {0};
	unsigned char mac[6] = {0};
	unsigned long ip = 0;
	struct timeval  tv;
	char *remote_host = NULL;
	unsigned int remote_port;
	unsigned char buf[MAX_RTU_PACKET_LENGTH] = {0};
	int pkt_length;
	int ret;
	int testIndex = 0;
	int heartbeat_interval = nvram_get_int("m2m_heartbeat_intval");
	char *heartbeat_mode = nvram_safe_get("rtu_heartbeat_mode");
	
	if (heartbeat_interval < 3)
	{
		heartbeat_interval = 3;
	}
	
	remote_host = nvram_safe_get("rtu_svr_host");
	remote_port = nvram_get_int("rtu_svr_port");

	pthread_t pub_tid, sub_tid;
    pthread_attr_t attr;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    ret = pthread_create(&pub_tid, &attr, &rtu_pub_thread_routine, NULL);
    if (ret < 0)
    {
        syslog(LOG_ERR, "Create rtu_pub_thread_routine report thread failed");
        return NULL;
    }
}

void heartbeat_thread(void *param)
{
	char hb_buf[512] = {0};
	int hb_len = 0;
	int intval = 2;
	int csq = 0;
	int retry=nvram_get_int("m2m_heartbeat_retry")?:10;
	M2M_PROTOCOL_HDR_T *hb = (M2M_PROTOCOL_HDR_T*)hb_buf;
	
	if( (intval = m2m_config.heartbeat_intval) < 2 )
		intval = 2;

	syslog(LOG_INFO,"Retry:%d",retry);
	while(socket_fd >= 0)
	{
		if (N_ACK++ > retry && !AD_UPGRADE_flag)
		{
			int action=nvram_get_int("m2m_error_action");
			if(action==1)
			{
				syslog(LOG_ERR,"M2M down, reconnect network");
				system("service modem_checkdial restart&");
				exit(0);
			}
			else if(action==2)
			{
				syslog(LOG_ERR,"M2M down, reboot");
				system("killall -9 modem_watchdog&");
				system("reboot&");
				exit(0);
			}
			else
			{
				syslog(LOG_NOTICE, "M2M Server Dumping....Restart & Resolve DTU&M2M Server DDNS...");
				killall("m2m", SIGTERM);
				killall("dtu", SIGTERM);
				exit(0);
			}
		}
		if(g_login_ack)
		{
			memset(hb_buf, 0, 512);
			hb_len = 0;
			hb->cmd_id = htons(M2M_HEARTBEAT);
			hb->packet_id = htonl(packet_id+1);
			hb->version = htons(0x0300);
			hb->safe_flag = 0;
			hb->type = 0;
			memcpy(hb->product_id, product_id, sizeof(hb->product_id));
			if (nvram_get_int("csq")>0)
				csq = nvram_get_int("csq");
			if (csq>100)
				csq = (csq - 100)/3;
			*(hb_buf + sizeof(M2M_PROTOCOL_HDR_T)) = csq;

			*(unsigned int*)(hb_buf + sizeof(M2M_PROTOCOL_HDR_T)+1) = htonl(trafic_calc());
			*(hb_buf + sizeof(M2M_PROTOCOL_HDR_T)+1+4) = get_cops();
			*(hb_buf + sizeof(M2M_PROTOCOL_HDR_T)+1+4+1) = 0x01;
			hb_len = sizeof(M2M_PROTOCOL_HDR_T)+1+4+1+1;
			hb->len = htons(hb_len);
			udp_socket_send(hb_buf, hb_len);

			if((!(nvram_match("cell_cid",nvram_safe_get("cellg_cid")) && nvram_match("cell_lac",nvram_safe_get("cellg_lac"))))
				&&(!(nvram_match("cell_cid",nvram_safe_get("celle_cid")) && nvram_match("cell_lac",nvram_safe_get("celle_lac")))))
				m2m_send_cmd(REPORT_STATUS);
			if(!g_report_status_ack)
			{
				syslog(LOG_ERR,"report status again");
				m2m_send_cmd(REPORT_STATUS);
			}
			if(!g_sync_time_ack)
			{
				syslog(LOG_ERR,"report sync time again");
				m2m_send_cmd(SYNC_TIME);
			}
		}
		sleep(intval);
		if(!g_login_ack)
		{
			syslog(LOG_ERR,"login again");
			m2m_send_cmd(M2M_LOGIN);
		}
	}
}

int get_mac_format(char *possiblemac,char *mac)
{
	return sscanf(possiblemac,"%2[A-Fa-f0-9]:%2[A-Fa-f0-9]:%2[A-Fa-f0-9]:%2[A-Fa-f0-9]:%2[A-Fa-f0-9]:%2[A-Fa-f0-9]",
	   mac,&mac[2],&mac[4],&mac[6],&mac[8],&mac[10]) == 6;
}

int send_sta_sms(int argc,char *argv[])
{
	unsigned char mac[12];
	char pdu_buf[1024];
	int pdu_len = 0;
	M2M_PROTOCOL_HDR* pdu=NULL;
	int i=0,ret=0,error=0;
	char *cmd_id,*cmd_val;

	if((argc != 2) && (argc != 3))
	{
		return ret;
	}
	if(socket_fd >= 0)
	{
		pdu = (M2M_PROTOCOL_HDR*)pdu_buf;

		pdu->cmd_id = htons(SEND_SMS);
		pdu->packet_id = htonl(packet_id++);
		pdu->version = htons(0x0100);
		memcpy(pdu->product_id, product_id, sizeof(pdu->product_id));

		pdu_len = sizeof(M2M_PROTOCOL_HDR);
		for(i=0;i<argc && !error;i++)
		{
			cmd_id = argv[i];
			if(((cmd_val = strchr(argv[i],':')) == NULL))
			{
				error=1;
				break;
			}

			*cmd_val = '\0';
			cmd_val++;
			if(strcmp(cmd_id,"mobile") == 0)
			{
				sprintf(pdu_buf+pdu_len,"mobile=%s",cmd_val);
				pdu_len += strlen(pdu_buf+pdu_len);
			}
			else if(strcmp(cmd_id,"content") == 0)
			{
				sprintf(pdu_buf+pdu_len,"&content=%s",cmd_val);
				pdu_len += strlen(pdu_buf+pdu_len);
			}
			else if(strcmp(cmd_id,"send_time") == 0)
			{
				sprintf(pdu_buf+pdu_len,"&send_time=%s",cmd_val);
				pdu_len += strlen(pdu_buf+pdu_len);
			}
		}
		if(!error)
		{
			pdu->len = htons(pdu_len);
			udp_socket_send(pdu_buf, pdu_len);
			ret = 1;
		}
		else
		{
			ret = 0;
		}
	}
	return ret;
}

int send_query_device(int argc,char *argv[])
{
	unsigned char mac[12];
	char pdu_buf[1024];
	int pdu_len = 0;
	M2M_PROTOCOL_HDR* pdu=NULL;
	int i=0,ret=0,error=0;
	char *cmd_id,*cmd_val;

	if(argc != 2)
	{
		return ret;
	}

	if(socket_fd >= 0)
	{
		pdu = (M2M_PROTOCOL_HDR*)pdu_buf;

		pdu->cmd_id = htons(QUERY_DEVICE);
		pdu->packet_id = htonl(packet_id++);
		pdu->version = htons(0x0100);
		memcpy(pdu->product_id, product_id, sizeof(pdu->product_id));

		pdu_len = sizeof(M2M_PROTOCOL_HDR);

		for(i=0;i<argc && !error;i++)
		{
			cmd_id = argv[i];
			if(((cmd_val = strchr(argv[i],':')) == NULL))
			{
				error=1;
				break;
			}

			*cmd_val = '\0';
			cmd_val++;
			if(cmd_val == NULL)
			{
				syslog(LOG_ERR,"val error");
				error=1;
				break;
			}
			if(strcmp(cmd_id,"query") == 0)
			{
				sprintf(pdu_buf+pdu_len,"item=%s",cmd_val);
				pdu_len += strlen(pdu_buf+pdu_len);
			}
			else if(strcmp(cmd_id,"mac") == 0)
			{
				sprintf(pdu_buf+pdu_len,"&mac=");
				pdu_len += strlen(pdu_buf+pdu_len);
				if(!get_mac_format(cmd_val,pdu_buf+pdu_len))
				{
					error=1;
					break;
				}
				pdu_len += CLIENT_MAC_LEN;
			}
		}

		if(!error)
		{
			pdu->len = htons(pdu_len);
			udp_socket_send(pdu_buf, pdu_len);
			ret = 1;
		}
		else
		{
			ret = 0;
		}
	}
	return ret;
}

int send_report_device(int argc,char *argv[])
{
	char *pdu_buf=NULL,*cmd_val=NULL;
	int pdu_len = 0;
	M2M_PROTOCOL_HDR* pdu=NULL;
	M2M_PROTOCOL_TLV *m2m_tlv;
	int i=0,cur_pos=0,cmd_id=0,error=0,ret=0;

	if(argc < 2)
		return ret;

	for(i=0;i<argc;i++)
	{
		cmd_id = atoi(argv[i]);

		if(((cmd_val = strchr(argv[i],':')) == NULL))
		{
			return ret;
		}
		if(!(++cmd_val)) cmd_val="";

		switch (cmd_id)
		{
			case CLIENT_MAC:
				pdu_len += (CLIENT_MAC_LEN + 4);
			break;
			case CLINET_TRAFIC:
				pdu_len += (CLIENT_TRAFIC_LEN + 4);
			break;
			case CLIENT_STATUS:
				pdu_len += (CLIENT_STATUS_LEN + 4);
			break;
			case CLIENT_MAIL:
			case CLIENT_AUTH_CODE:
			case ID_CARD:
			case CLIENT_NAME:
				pdu_len += (strlen(cmd_val) + 4);
			break;
			default:
				syslog(LOG_ERR,"%s:%d",__FUNCTION__,__LINE__);
				return ret;
		}
	}

	pdu_len += sizeof(M2M_PROTOCOL_HDR);

	if((socket_fd >= 0) && ((pdu_buf=calloc(pdu_len,sizeof(char))) != NULL))
	{
		pdu = (M2M_PROTOCOL_HDR*)pdu_buf;

		pdu->cmd_id = htons(REPORT_DEVICE);
		pdu->packet_id = htonl(packet_id++);
		pdu->version = htons(0x0100);
		memcpy(pdu->product_id, product_id, sizeof(pdu->product_id));

		cur_pos=sizeof(M2M_PROTOCOL_HDR);

		for(i=0;i<argc && !error;i++)
		{
			m2m_tlv = (M2M_PROTOCOL_TLV*)(pdu_buf + cur_pos);
			cmd_id = atoi(argv[i]);

			if(((cmd_val = strchr(argv[i],':')) == NULL))
			{
				error=1;
				break;
			}
			if(!(++cmd_val)) cmd_val="";
			switch (cmd_id)
			{
				case CLIENT_MAC://Client MAC
					m2m_tlv->tlv_tag = htons(CLIENT_MAC);
					m2m_tlv->tlv_len = htons(CLIENT_MAC_LEN);
					if(!get_mac_format(cmd_val,m2m_tlv->tlv_value))
					{
						error=1;
						break;
					}
					cur_pos += (CLIENT_MAC_LEN + 4);

				break;
				case CLINET_TRAFIC:
					m2m_tlv->tlv_tag = htons(CLINET_TRAFIC);
					m2m_tlv->tlv_len = htons(CLIENT_TRAFIC_LEN);
					*(unsigned int*)(m2m_tlv->tlv_value) = htonl(atol(cmd_val));
					cur_pos += (CLIENT_TRAFIC_LEN + 4);

				break;
				case CLIENT_STATUS:
					m2m_tlv->tlv_tag = htons(CLIENT_STATUS);
					m2m_tlv->tlv_len = htons(CLIENT_STATUS_LEN);
					*(unsigned char*)(m2m_tlv->tlv_value) = (unsigned char *)atoi(cmd_val);
					cur_pos += (CLIENT_STATUS_LEN + 4);

				break;
				case CLIENT_MAIL:
					m2m_tlv->tlv_tag = htons(CLIENT_MAIL);
					m2m_tlv->tlv_len = htons(strlen(cmd_val));
					memcpy(m2m_tlv->tlv_value,cmd_val,strlen(cmd_val));
					cur_pos += (strlen(cmd_val) + 4);

				break;
				case CLIENT_AUTH_CODE:
					m2m_tlv->tlv_tag = htons(CLIENT_AUTH_CODE);
					m2m_tlv->tlv_len = htons(strlen(cmd_val));
					memcpy(m2m_tlv->tlv_value,cmd_val,strlen(cmd_val));
					cur_pos += (strlen(cmd_val) + 4);

				break;
				case ID_CARD:
					m2m_tlv->tlv_tag = htons(ID_CARD);
					m2m_tlv->tlv_len = htons(strlen(cmd_val));
					memcpy(m2m_tlv->tlv_value,cmd_val,strlen(cmd_val));
					cur_pos += (strlen(cmd_val) + 4);

				break;
				case CLIENT_NAME:
					m2m_tlv->tlv_tag = htons(CLIENT_NAME);
					m2m_tlv->tlv_len = htons(strlen(cmd_val));
					memcpy(m2m_tlv->tlv_value,cmd_val,strlen(cmd_val));
					cur_pos += (strlen(cmd_val) + 4);
				break;
				default:
					syslog(LOG_ERR,"Unknown msg id %d",cmd_id);
					error=1;
					break;
			}
		}

		if(!error)
		{
			pdu->len = htons(pdu_len);
			udp_socket_send(pdu_buf, pdu_len);
			ret = 1;
		}
		else
		{
			ret = 0;
		}

		free(pdu_buf);
	}

	return ret;
}

#define ARGV_SIZE 100

static void *external_handler(int fd)
{
	int done,i=0;
	char request[4096];
	ssize_t	read_bytes,len;
	int argc=0;
	char *argv[ARGV_SIZE],*q=NULL,*p=NULL;

	read_bytes = 0;
	done = 0;
	memset(request, 0, sizeof(request));
	while (!done && read_bytes < (sizeof(request) - 1))
	{
		len = read(fd, request + read_bytes,sizeof(request) - read_bytes);

		/* Have we gotten a command yet? */
		for (i = read_bytes; i < (read_bytes + len); i++)
		{
			if (request[i] == '\r' || request[i] == '\n')
			{
				request[i] = '\0';
				done = 1;
			}
		}
		read_bytes += len;
	}

	argc=0;
	p=request;
	while ((q = strsep(&p, ",")) != NULL)
	{
		if(argc < ARGV_SIZE)
			argv[argc++]=q;
		else
		{
			syslog(LOG_ERR,"too many params");
			break;
		}
	}

	if(done)
	{
		if(strncmp(request,"query",5) == 0)
		{
			g_query_ack = -1;
			if(send_query_device(argc,argv))
			{
				int wait=200;

				while((g_query_ack == -1) && (--wait > 0))
				{
					usleep(10000);
				}
				if(g_query_ack == 1)
					send_data(fd, "ok");
				else
					send_data(fd, "nk");
			}
		}
		else if(strncmp(request,"mobile",6) == 0)
		{
			g_m2m_sms_ack = -1;
			if(send_sta_sms(argc,argv))
			{
				int wait=200;

				while((g_m2m_sms_ack == -1) && (--wait > 0))
				{
					usleep(10000);
				}
				if(g_m2m_sms_ack == 0)
					send_data(fd, "ok");
				else
					send_data(fd, "nk");
			}
		}
		else
		{
			send_report_device(argc,argv);
		}
	}
	else
		syslog(LOG_ERR,"%s:%d---------i=%d,argc=%d,done=%d",__FUNCTION__,__LINE__,i,argc,done);

	shutdown(fd, 2);
	close(fd);

	return NULL;
}

void thread_external(void *arg)
{
	int	sock,fd;
	char *sock_name;
	struct 	sockaddr_un	sa_un;
	socklen_t len;

	memset(&sa_un, 0, sizeof(sa_un));
	sock_name = "/tmp/.m2m.sock";

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	unlink(sock_name); /* If it exists, delete... Not the cleanest way to deal. */
	strcpy(sa_un.sun_path, sock_name); /* XXX No size check because we check a few lines before. */
	sa_un.sun_family = AF_UNIX;

	/* Which to use, AF_UNIX, PF_UNIX, AF_LOCAL, PF_LOCAL? */
	if (bind(sock, (struct sockaddr *)&sa_un, strlen(sock_name) + sizeof(sa_un.sun_family)))
	{
		syslog(LOG_ERR, "Bind failed on control socket: %s",strerror(errno));
		pthread_exit(NULL);
	}

	if (listen(sock, 5))
	{
		syslog(LOG_ERR, "Listen failed on control socket: %s",strerror(errno));
		pthread_exit(NULL);
	}

	while(1)
	{
		memset(&sa_un, 0, sizeof(sa_un));
		len = (socklen_t) sizeof(sa_un); /* <<< ADDED BY DPLACKO */
		if ((fd = accept(sock, (struct sockaddr *)&sa_un, &len)) == -1)
		{
			syslog(LOG_ERR, "Accept failed on control socket: %s",strerror(errno));
		}
		else
		{
			external_handler(fd);
		}
	}
}

typedef struct _domain_node{
	struct _domain_node *next;
	char *domain;
}domain_node;

typedef struct _url_report_node{
	struct _url_report_node *next;
	char *ip;
	domain_node *domain_list;
}url_report_node;

url_report_node *node_find_by_ip(url_report_node *first_node,char *ip)
{
	url_report_node *ptr;

	ptr = first_node;
	while (NULL != ptr)
	{
		if (!strcmp(ptr->ip, ip))
			return ptr;
		ptr = ptr->next;
	}

	return NULL;
}

#define LIST_APPNED(head,node) ({\
	if(head != NULL) {\
		for(;head->next != NULL; head=head->next);\
		head->next=node;\
	}\
})

int arp_get(char *req_ip,char *mac)
{
	FILE *proc;
	char ip[16];
	int ret=0,i=0,j=0;

	if (!(proc = fopen("/proc/net/arp", "r")))
		return 0;

	while (!feof(proc) && fgetc(proc) != '\n');
	ret=0;
	while (!feof(proc) && (fscanf(proc, " %15[0-9.] %*s %*s %17[A-Fa-f0-9:] %*s %*s", ip, mac) == 2))
	{
		if (strcmp(ip, req_ip) == 0)
		{
			ret=1;
			break;
		}
	}
	fclose(proc);

	memset(ip,0,sizeof(ip));
	for(i=0,j=0;i<17;i++)
	{
		if(mac[i]==':')
			continue;
		ip[j]=mac[i];
		j++;
	}
	strcpy(mac,ip);
	return ret;
}

void send_url_report(url_report_node *url_node)
{
	char cmac[20],*url_report_buf;
	url_report_node *tmp_unode;
	domain_node *tmp_domain;
	unsigned int total_len=0,url_cont=0,url_len=0,cur_pos=0;

	for(tmp_unode=url_node;tmp_unode != NULL && tmp_unode->ip != NULL;tmp_unode=tmp_unode->next)
	{
		total_len=0;
		url_cont=0;
		url_len=0;

		if(!arp_get(tmp_unode->ip,cmac))
			continue;

		for(tmp_domain=tmp_unode->domain_list;tmp_domain != NULL && tmp_domain->domain != NULL;tmp_domain=tmp_domain->next)
		{
			url_cont++;
			url_len += strlen(tmp_domain->domain);
		}

		total_len = sizeof(M2M_PROTOCOL_HDR) + (url_cont+1) *4 + url_len + CLIENT_MAC_LEN;

		if((url_report_buf=calloc(total_len,sizeof(char))) == NULL)
			continue;

		cur_pos = sizeof(M2M_PROTOCOL_HDR);

		pack_sub_elem(url_report_buf,&cur_pos,CLIENT_MAC,CLIENT_MAC_LEN,cmac);
		for(tmp_domain=tmp_unode->domain_list;tmp_domain != NULL && tmp_domain->domain != NULL;tmp_domain=tmp_domain->next)
		{
			pack_sub_elem(url_report_buf,&cur_pos,CLIENT_VISITED_URL,strlen(tmp_domain->domain),tmp_domain->domain);
		}

		M2M_PROTOCOL_HDR* url = (M2M_PROTOCOL_HDR*)url_report_buf;
		if(socket_fd >= 0)
		{
			url->cmd_id = htons(REPORT_URL);
			url->packet_id = htonl(packet_id++);
			url->version = htons(0x0100);
			memcpy(url->product_id, product_id, sizeof(url->product_id));
			url->len = htons(total_len);
			udp_socket_send(url_report_buf,total_len);
		}

		if(url_report_buf)
			free(url_report_buf);
	}
}

void destroy_unode(url_report_node *tmp_unode)
{
	if (tmp_unode->ip != NULL)
		free(tmp_unode->ip);

	if (tmp_unode->domain_list != NULL)
	{
		domain_node *tmp,*tmp1;
		for(tmp=tmp_unode->domain_list;tmp != NULL;tmp=tmp1)
		{
			tmp1 = tmp->next;
			if(tmp->domain != NULL)
				free(tmp->domain);
			free(tmp);
		}
	}
	free(tmp_unode);
}

void thread_report_url(void *arg)
{
	FILE *fp=NULL;
	char buf[1500];
	char *ip,*domain,*time,*tmp_domain;
	long prev=0,cur=0;
	int save_time=0;
	url_report_node *first_unode=NULL,*tmp_unode,*last_unode;
	domain_node *tmp_dnode,*last_dnode;
	time_t cut_time;

	while(1)
	{
		if((fp=fopen("/proc/webmon_recent_domains","r")) != NULL)
		{
			save_time=0;
			prev=atol(nvram_safe_get("wm_pre_time"));
			while((fgets(buf, sizeof(buf), fp))&&(atol(buf) > prev))
			{
				if (vstrsep(buf, "\t", &time, &ip, &domain) == 3)
				{
					if(save_time==0)
					{
						nvram_set("wm_pre_time",time);
						save_time=1;
					}
					if((last_unode=node_find_by_ip(first_unode,ip)) == NULL)
					{
						if((last_unode=calloc(1,sizeof(url_report_node))) == NULL)
							continue;

						if((last_unode->ip=strdup(ip)) == NULL)
						{
							free(last_unode);
							continue;
						}

						if(first_unode != NULL)
						{
							tmp_unode=first_unode;
							LIST_APPNED(tmp_unode,last_unode);
						}
						else
						{
							first_unode=last_unode;
						}
					}

					if((last_dnode=calloc(1,sizeof(domain_node))) == NULL)
						continue;
					if((last_dnode->domain=strdup(domain)) == NULL)
					{
						free(last_dnode);
						continue;
					}

					if(last_unode->domain_list != NULL)
					{
						tmp_dnode=last_unode->domain_list;
						LIST_APPNED(tmp_dnode,last_dnode);
					}
					else
					{
						last_unode->domain_list=last_dnode;
					}
				}
			}
			fclose(fp);

			while(first_unode != NULL)
			{
				tmp_unode=first_unode;
				send_url_report(first_unode);
				first_unode=first_unode->next;
				destroy_unode(tmp_unode);
			}
		}
		sleep(1);
	}
}

int m2m_main(int argc, char *argv[])
{
	char ibuf[21] = {0};
	unsigned char mac[6] = {0};
	unsigned long ip = 0;
	struct timeval  tv;
	pthread_t pub_tid, heart_beat_id,external_id,report_url_id,report_status_alone_id;
	pthread_t sf_box;
    pthread_attr_t attr;
    size_t stacksize;
	int rc;
	
	m2m_deamon();
	m2m_config_init();
	ether_atoe(nvram_safe_get("et0macaddr"), mac);
	sprintf(product_id, "%s", nvram_safe_get("router_sn"));
	sprintf(product_report_id, "%02x%02x%02x%02x%02x%02x_R%02x%02x%02x%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],mac[2], mac[3], mac[4], mac[5]);
#ifdef TCONFIG_N2N 
	modprobe("tun");
	nvram_set("n2n_ipaddr", "0.0.0.0");
	nvram_set("n2n_online", "0");
#endif

#ifdef TCONFIG_CN
	if (!strcmp(nvram_safe_get("m2m_mode"), "disable"))
	{
		syslog( LOG_NOTICE, "M2M Disabled, Pause!!" );
		if (!strcmp(nvram_safe_get("m2m_background_mode"), "enable"))
		{
			if (pthread_create(&report_status_alone_id, NULL, (void *)report_status_alone, NULL) != 0)
			{
				syslog(LOG_ERR, "!!M2M Failed to Create report_status_alone_id Thread");
			}
			else
			{
				pthread_detach(report_status_alone_id);
				syslog(LOG_NOTICE, "M2M report_status_alone_id Thread %d", report_status_alone_id);
			}
		}
		while (1)
		{
			pause();
		}
	}
	else
	{
		if (!strcmp(nvram_safe_get("m2m_background_mode"), "enable"))
		{
			if(strcmp(nvram_safe_get("m2m_server_domain"),"detran.xicp.net") && strcmp(nvram_safe_get("m2m_server_domain"),"120.78.189.220"))
			{
				syslog(LOG_INFO,"Start report modual");
				if (pthread_create(&report_status_alone_id, NULL, (void *)report_status_alone, NULL) != 0)
				{
					syslog(LOG_ERR, "!!M2M Failed to Create report_status_alone_id Thread");
				}
				else
				{
					pthread_detach(report_status_alone_id);
					syslog(LOG_NOTICE, "M2M report_status_alone_id Thread %d", report_status_alone_id);
				}
			}
		}
	}
#else
	if (!strcmp(nvram_safe_get("m2m_mode"), "disable"))
	{
   	    	syslog( LOG_NOTICE, "M2M Disabled, Pause!!" );
		while (1)
		{
			pause();
		}
	}

#endif
	while ( socket_fd < 0 )
	{
		// check ppp online
		if( !check_online() )
		{
			syslog(LOG_NOTICE, "M2M : Cellular Offline" );
			sleep( 3 );
			continue;
		}      

		syslog(LOG_NOTICE, "M2M : Cellular Online" );

		if ((strlen(m2m_config.svr_domain) > 0) &&
			(m2m_get_host(m2m_config.svr_domain, ibuf)))
		{
			m2m_config.svr_domain_ip = m2m_inet_addr(ibuf, strlen(ibuf));
			ip = m2m_config.svr_domain_ip;
		}
		else if((strlen(m2m_config.svr_ip_str) > 0) && 
			((m2m_config.svr_ip = m2m_inet_addr(m2m_config.svr_ip_str, strlen(m2m_config.svr_ip_str))) != 0))
		{
			ip = m2m_config.svr_ip;
		}
		else
		{
			syslog(LOG_NOTICE, "M2M : Unknown M2M Server Address" );
			sleep( 3 );
			continue;
		}
		
		g_m2m_server_ip=ip;
		syslog(LOG_NOTICE, "M2M Server Address: 0x%x", ip);
		
		if ( ( socket_fd = udp_socket_create( 0, m2m_config.bind_port, ip, m2m_config.svr_port) ) < 0 )
		{
			sleep( 2 );
			syslog(LOG_ERR, "M2M UDP Socket Create Error, Sleep 2s ...");
			continue;
		}
	}

	m2m_send_cmd(M2M_LOGIN);


	if (pthread_create(&heart_beat_id, NULL, (void *)heartbeat_thread, NULL) != 0)
	{
		syslog(LOG_ERR, "!!M2M Failed to Create Heartbeat Thread");
	}
	else
	{
		pthread_detach(heart_beat_id);
		syslog(LOG_NOTICE, "M2M Heartbeat Thread %d", heart_beat_id);
	}
	if (pthread_create(&sf_box, NULL, (void *)sfbox_thread, NULL) != 0)
	{
		syslog(LOG_ERR, "!!M2M Failed to Create SF Box Thread");
	}
	else
	{
		pthread_detach(heart_beat_id);
		syslog(LOG_NOTICE, "M2M SF Box Thread %d", heart_beat_id);
	}
	if (pthread_create(&external_id, NULL, (void *)thread_external, NULL) != 0)
	{
		syslog(LOG_ERR, "!!M2M Failed to Create External Thread");
	}
	else
	{
		pthread_detach(external_id);
		syslog(LOG_NOTICE, "M2M External Thread %d", external_id);
	}
	if(nvram_get_int("url_report_enable")>0)
	{
		if (pthread_create(&report_url_id, NULL, (void *)thread_report_url, NULL) != 0)
		{
			syslog(LOG_ERR, "!!M2M Failed to Create URL Thread");
		}
		else
		{
			pthread_detach(report_url_id);
			syslog(LOG_NOTICE, "M2M URL Thread %d", report_url_id);
		}
	}

    if (strcmp("enable", nvram_safe_get("m2m_mode")) == 0)
    {
        pthread_attr_init(&attr);
        pthread_attr_getstacksize(&attr, &stacksize);
        pthread_attr_setstacksize(&attr, stacksize << 4);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        rc = pthread_create(&pub_tid, &attr, &detran_rtu_routine, NULL);
        if (rc < 0)
        {
            syslog(LOG_ERR, "Create pub report thread failed");
            return -1;
        }
    }

    #ifdef TCONFIG_N2N
	if (nvram_get_int("n2n_bootmode") == 0)
	{
		stop_n2n( );	
	}
    #endif
	
	while(1)
	{
		int     res;
		fd_set  fdvar;

		// check ppp online
		if( !check_online() )
		{
			syslog(LOG_NOTICE, "M2M : Cellular Offline" );
			sleep( 3 );
			continue;
		}     
        #ifdef TCONFIG_N2N
		if (nvram_get_int("n2n_bootmode") == 1 && nvram_get_int("n2n_online") != 1)
		{
			m2m_send_cmd(M2M_VT_IP_REQ);
		}
        #endif
		
		FD_ZERO(&fdvar);
		FD_SET(socket_fd, &fdvar);
 
		tv.tv_sec  = 2;
		tv.tv_usec = 0; 
		res = select( socket_fd + 1 , &fdvar , NULL , NULL , &tv);
    
		if (res == 1)
		{
			process_m2m_Req();
			memset(m2m_res_buf, 0, sizeof(m2m_res_buf));
		}
		if(m2m_gotuser == 1)
		{
			m2m_send_cmd(REPORT_STATUS);
			m2m_gotuser = 0;
		}
	}
	return 0;
}
