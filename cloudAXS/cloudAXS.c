#include "cloudAXS.h"
#include "rc.h"
#include <wlutils.h>

#define CLIENT_IF_START 10
#define BUFF_SIZE 4096
CLOUDAXS_CONFIG cloud_config;
int socket_fd = -1;
int wifi_client = 0;

CLOUD_CHECKBOX_NVRAM sysInfo[] =
{
    {0, "router_name", NULL},
    {0, "router_hw", NULL},
    {1, "", router_firmwire},//router os_version
    {1, "", router_time},//router time
    {1, "", router_uptime},//uptime
    {1, "", router_memory}//total/free memory
};
CLOUD_CHECKBOX_NVRAM netInfo[] =
{
    {1, "wan_iface", connect_status},
    {0, "wan_hwaddr", NULL},
    {0, "modem_type", NULL},
    {1, "modem_state", modem_status},
    {1, "sim_flag", sim_select},
    {0, "cops", NULL},
    {0, "cell_network", NULL},
    {1, "sim_state", sim_status},
    {0, "csq", NULL},
    {0, "wan_ipaddr", NULL},
    {0, "wan_netmask", NULL},
    {0, "wan_gateway_get", NULL},
    {1, "", router_dns},//DNS
    {1, "wan_up", wan_status},
    {1, "", router_connection_uptime}//Connection uptime
};
CLOUD_CHECKBOX_NVRAM gpsInfo[] = 
{
	{0, "gps_valid", NULL},
	{0, "gps_bds", NULL},
	{0, "gps_use", NULL},
	{1, "", gps_time},
	{1, "", gps_position}
};
CLOUD_CHECKBOX_NVRAM dataUsage[] =
{
    {1, "", router_access_lan_device},
    {0, "wifi_client_num", NULL},
    {1, "", get_all_vpn_connect},
    {1, "", router_total_data_translate}
};

int gps_time(unsigned char *buff, int length)
{
	int len = 0;

	if(buff == NULL)
	{
		return len;
	}

	snprintf(buff, length, "%s - %s", nvram_safe_get("gps_date"), nvram_safe_get("gps_time"));

	len = strlen(buff);

	return len;
}

int gps_position(unsigned char *buff, int length)
{
	int len = 0;
	char latitude[64] = {0}, longitude[64] = {0};
	
	if(buff == NULL)
	{
		return len;
	}

	snprintf(latitude, length, "%s%s", nvram_safe_get("gps_latitude"), nvram_safe_get("gps_NS"));
	snprintf(longitude, length, "%s%s", nvram_safe_get("gps_longitude"), nvram_safe_get("gps_EW"));
	
	snprintf(buff, length, "%s - %s", latitude, longitude);

	len = strlen(buff);

	return len;
}

int connect_status(unsigned char *buff, int length)
{
    int len = 0;

    if(buff == NULL)
    {
        return len;
    }
    if(nvram_match("wan_iface", "usb0"))
    {
        snprintf(buff, length, "Cellular Network");
    }
    else if(nvram_match("wan_iface", "ppp0"))
    {
        snprintf(buff, length, "Cellular Network");
    }
	else if(nvram_match("wan_iface", "VLAN1"))
	{
		snprintf(buff, length, "WAN");
	}
	else if(nvram_match("wan_iface", "eth1"))
	{
		snprintf(buff, length, "WiFi");
	}
    else
    {
        snprintf(buff, length, "Searching...");
    }
    len = strlen(buff);

    return len;
}

int sim_status(unsigned char *buff, int length)
{
    int len = 0;

    if(buff == NULL)
    {
        return len;
    }
    if(nvram_match("sim_state", "1"))
    {
        snprintf(buff, length, "Ready");
    }
    else if(nvram_match("sim_state", "0"))
    {
        snprintf(buff, length, "Unknown");
    }
    else
    {
        snprintf(buff, length, "Searching...");
    }
    len = strlen(buff);

    return len;
}

int modem_status(unsigned char *buff, int length)
{
    int len = 0;

    if(buff == NULL)
    {
        return len;
    }
    if(nvram_match("modem_state", "1"))
    {
        snprintf(buff, length, "Ready");
    }
    else if(nvram_match("modem_state", "0"))
    {
        snprintf(buff, length, "Unknown");
    }
    else
    {
        snprintf(buff, length, "Searching...");
    }
    len = strlen(buff);

    return len;
}

int sim_select(unsigned char *buff, int length)
{
    int len = 0;

    if(buff == NULL)
    {
        return len;
    }
    if(nvram_match("wan_ifnameX", "vlan1"))
    {
        snprintf(buff, length, "WAN Running");
    }
    else
    {
        snprintf(buff, length, "USIM %s Running", nvram_safe_get("sim_flag"));
    }
    len = strlen(buff);

    return len;
}

int wan_status(unsigned char *buff, int length)
{
    int len = 0;

    if(buff == NULL)
    {
        return len;
    }
    if(nvram_match("wan_up", "1"))
    {
        snprintf(buff, length, "Connected");
    }
    else
    {
        snprintf(buff, length, "Disconnected");
    }
    len = strlen(buff);

    return len;
}

int router_firmwire(unsigned char *buff, int length)
{
    int len = 0;

    if(buff == NULL)
    {
        return len;
    }
    snprintf(buff, length, "router_%s", nvram_safe_get("os_version"));
    len = strlen(buff);

    syslog(LOG_INFO,"Router_firmwire:%s, len:%d", buff, len);
    return len;
}
int router_time(unsigned char *buff, int length)
{
    int len = 0;
    time_t t;

    if(buff == NULL)
    {
        return len;
    }
    t = time(NULL);
    if (t < Y2K)
    {
        return len;
    }
    else
    {
        strftime(buff, length, "%a, %d %b %Y %H:%M:%S %z", localtime(&t));
        // strftime(s, sizeof(s), "%a, %d %b %Y %H:%M:%S %z", localtime(&t));
    }
    len = strlen(buff);
    syslog(LOG_INFO,"router_time:%s, len:%d", buff, len);
    return len;
}
int router_uptime(unsigned char *buff, int length)
{
    int len = 0;
    struct sysinfo si;

    if(buff == NULL)
    {
        return len;
    }
    sysinfo(&si);
    reltime(buff, si.uptime);

    len = strlen(buff);
    syslog(LOG_INFO,"router_uptime:%s, len:%d", buff, len);

    return len;
}

int router_memory(unsigned char *buff, int length)
{
    int len = 0;
    meminfo_t mem;
    float percent, fmb, tmb;
    char buf[32] = {0};
    float tmp;

    if(buff == NULL)
    {
        return len;
    }

    get_memory(&mem);
    fmb = (float)(mem.free + mem.buffers + mem.cached) / 1024 / 1024;
    tmb = (float)mem.total / 1024 / 1024;
    percent = (float)(mem.free + mem.buffers + mem.cached) / mem.total;
    tmp = percent * 100;
    snprintf(buff, length, "%.2fMB/%.2fMB(%.2f%s)", fmb, tmb, tmp, "%");
    len = strlen(buff);
    syslog(LOG_INFO,"router_memory:%s, len:%d", buff, len);

    return len;

}

int router_dns(unsigned char *buff, int length)
{
    int len = 0;
    const dns_list_t *cdns;
    int i;

    if(buff == NULL)
    {
        return len;
    }
    cdns = get_dns();        // static buffer
    for (i = 0 ; i < cdns->count; ++i)
    {
        if(i == (cdns->count - 1))
        {
            snprintf(buff + strlen(buff), length, "%s:%u", inet_ntoa(cdns->dns[i].addr), cdns->dns[i].port);
        }
        else
        {
            snprintf(buff + strlen(buff), length, "%s:%u,", inet_ntoa(cdns->dns[i].addr), cdns->dns[i].port);
        }
    }
    syslog(LOG_INFO,"router_dns:%s, len:%d", buff, len);

    return len;
}


int router_connection_uptime(unsigned char *buff, int length)
{
    int len = 0;
    struct sysinfo si;
    long uptime;

    if(buff == NULL)
    {
        return len;
    }

    if (check_wanup())
    {
        sysinfo(&si);
        if (f_read("/var/lib/misc/wantime", &uptime, sizeof(uptime)) == sizeof(uptime))
        {
            reltime(buff, si.uptime - uptime);
        }
    }
    syslog(LOG_INFO,"router_uptime:%s, len:%d", buff, len);

    return len;

}
//include send data and recv data
int router_total_data_translate(unsigned char *buff, int length)
{
    int len = 0;
    FILE *f;
    char buf[256];
    char *ifname;
    char *p;
    unsigned long counter[3] = {0};

    if(buff == NULL)
    {
        return len;
    }

    if ((f = fopen("/proc/net/dev", "r")) == NULL) return 0;
    fgets(buf, sizeof(buf), f); // header
    fgets(buf, sizeof(buf), f); // "
    while (fgets(buf, sizeof(buf), f))
    {
        if ((p = strchr(buf, ':')) == NULL) continue;
        *p = 0;
        if ((ifname = strrchr(buf, ' ')) == NULL)
        {
            ifname = buf;
        }
        else
        {
            ++ifname;
        }
        if(is_lte()?(strcmp(ifname, "usb0") == 0):((nvram_match("wan_proto","dhcp") || nvram_match("wan_proto","static"))?strcmp(ifname, "vlan1") == 0:strcmp(ifname, "ppp0") == 0))
        {
            // <rx bytes, packets, errors, dropped, fifo errors, frame errors, compressed, multicast><tx ...>
            if (sscanf(p + 1, "%lu%*u%*u%*u%*u%*u%*u%*u%lu", &counter[0], &counter[1]) == 2)
            {
                snprintf(buff, length, "%ld,%ld", counter[0], counter[1]);
                break;
            }
        }
    }
    fclose(f);

    len = strlen(buff);
    nvram_set("total_package_num", buff);
    syslog(LOG_INFO,"router_total_data_translate:%s, len:%d", buff, len);
    return len;
}

static int get_wl_clients(int idx, int unit, int subunit, void *param)
{
    char *comma = param;
    int i;
    char *p;
    char buf[32];
    char *wlif;
    scb_val_t rssi;
    sta_info_t sti;
    int cmd;
    struct maclist *mlist;
    int mlsize;
    char ifname[16];

    mlsize = sizeof(struct maclist) + (255 * sizeof(struct ether_addr));
    if ((mlist = malloc(mlsize)) != NULL)
    {
        wlif = nvram_safe_get(wl_nvname("ifname", unit, subunit)); // AB multiSSID
        cmd = WLC_GET_ASSOCLIST;
        while (1)
        {
            mlist->count = 255;
            if (wl_ioctl(wlif, cmd, mlist, mlsize) == 0)
            {
                for (i = 0; i < mlist->count; ++i)
                {
                    rssi.ea = mlist->ea[i];
                    rssi.val = 0;
                    if (wl_ioctl(wlif, WLC_GET_RSSI, &rssi, sizeof(rssi)) != 0) continue;

                    // sta_info0<mac>
                    memset(&sti, 0, sizeof(sti));
                    strcpy((char *)&sti, "sta_info");
                    memcpy((char *)&sti + 9, rssi.ea.octet, 6);
                    if (wl_ioctl(wlif, WLC_GET_VAR, &sti, sizeof(sti)) != 0) continue;

                    p = wlif;
                    if (sti.flags & WL_STA_WDS)
                    {
                        if (cmd != WLC_GET_WDSLIST) continue;
                        if ((sti.flags & WL_WDS_LINKUP) == 0) continue;
                        //  if (get_wds_ifname(&rssi.ea, ifname)) p = ifname;
                    }
                    wifi_client++;
                }
            }
            if (cmd == WLC_GET_WDSLIST) break;
            cmd = WLC_GET_WDSLIST;
        }
        free(mlist);
    }
    
    return 0;
}

void get_wifi_client(void)
{
    char comma = ' ';
    char buf[32] = {0};
    
    wifi_client = 0;
    foreach_wif(1, &comma, get_wl_clients);
    snprintf(buf, sizeof(buf), "%d", wifi_client);
    nvram_set("wifi_client_num", buf);
}

int if_interface_exsit_up(char *interface)
{
    char *path = "/proc/sys/net/ipv4/conf/";
    char buf[128] = {0};
    int f;
    struct ifreq ifr;
    struct sockaddr_in *addr = NULL;

    if(interface == NULL)
    {
        return -1;
    }
    addr = (struct sockaddr_in *)&ifr.ifr_addr;
    snprintf(buf, sizeof(buf), "%s%s", path, interface);
    if (!access(buf, F_OK))
    {
        if ((f = socket(AF_INET, SOCK_DGRAM, 0)) >= 0)
        {
            strlcpy(ifr.ifr_name, interface, sizeof(ifr.ifr_name));
            if (ioctl(f, SIOCGIFFLAGS, &ifr) == 0)
            {
                if ((ifr.ifr_flags & IFF_UP) == 1)//interface exsit
                {
                    close(f);
                    return 1;
                }
            }
        }
    }
    close(f);
    return 0;
}

int get_openvpn_connect(void)
{
    char nvram_buf[128] = {0};
    char intf_buf[128] = {0};
    int count = 0;
    int i;

    for(i = 0; i < 2; i++)
    {
        snprintf(nvram_buf, sizeof(nvram_buf), "nvram_client%d_if", i + 1);
        snprintf(intf_buf, sizeof(intf_buf), "%s%d", nvram_safe_get(nvram_buf), i + 1 + CLIENT_IF_START);
        if(if_interface_exsit_up(intf_buf) == 1)
        {
            count++;
        }
    }

    return count;
}
int get_gre_interface_connect(void)
{
    char *nv, *nvp, *b;
    char *on,*index,*tun_addr,*remote,*local,*keep,*intervel,*retries,*desc;
    int n;
    char buf[32] = {0};
    int count = 0;

    nvp = nv = strdup(nvram_safe_get("greparam"));
    if (!nv) return 0;

    while ((b = strsep(&nvp, ">")) != NULL)
    {

        n = vstrsep(b,"<",&on,&index,&tun_addr,&local,&remote,&keep,&intervel,&retries,&desc);
        if ((n != 9) || (*on != '1') ) continue;

        if((*on == '1'))
        {
            snprintf(buf, sizeof(buf), "gre%s", index);
            if(if_interface_exsit_up(buf) == 1)
            {
                count++;
            }
        }
    }
    free(nv);

    return count;
}
int ipsec_l2tp_pptp_connect(void)
{
    FILE *fp=NULL;
    DIR *dir;
    struct dirent *dp;
    char line[128],proto[11],local[17],remote[17];
    char file[1025];
    int count = 0;

    if ((dir = opendir("/etc/xtp/status")))
    {
        while ((dp = readdir(dir)))
        {
            if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0)
                continue;

            snprintf(file,sizeof(file)-1,"/etc/xtp/status/%s",dp->d_name);
            if((fp = fopen(file, "r")) != NULL)
            {
                fclose(fp);
                count++;
            }
        }
        closedir(dir);
    }

    return count;
}

int get_all_vpn_connect(unsigned char *buff, int length)
{
    int vpn = 0, openvpn = 0, gre = 0;
    int total = 0, len;
    if(buff == NULL)
    {
        return len;
    }
    vpn = ipsec_l2tp_pptp_connect();
    gre = get_gre_interface_connect();
    openvpn = get_openvpn_connect();
    total = vpn + gre + openvpn;
    snprintf(buff, length, "%d", total);
    len = strlen(buff);
    nvram_set("total_vpn", buff);
    syslog(LOG_INFO,"vpn:%s, len:%d", buff, len);
    return len;
}

int router_access_lan_device(unsigned char *buff, int length)
{
    int len = 0, count = 0;
    char dev[17];
    FILE *f;
    char s[512];
    int wifi_num = 0;

    if(buff == NULL)
    {
        return len;
    }

    if ((f = fopen("/proc/net/arp", "r")) != NULL)
    {
        while (fgets(s, sizeof(s), f))
        {
            if (sscanf(s, "%*s %*s %*X %*s %*s %16s", dev) != 1) continue;
            if(strcmp(dev,"br0") == 0)
            {
                count++;
            }
        }
        fclose(f);
    }
    wifi_num = nvram_get_int("wifi_client_num");//lan clients include wifi clients;
    count = count - wifi_num;
    snprintf(buff, length, "%d", count);
    len = strlen(buff);
    nvram_set("lan_device_num", buff);
    syslog(LOG_INFO,"router_access_lan_device:%s, len:%d", buff, len);
    return len;
}

char *reltime(char *buf, time_t t)
{
    int days;
    int m;

    if (t < 0) t = 0;
    days = t / 86400;
    m = t / 60;
    if (days == 0)
    {
        sprintf(buf, "%02d:%02d:%02d", ((m / 60) % 24), (m % 60), (int)(t % 60));
    }
    else
    {
        sprintf(buf, "%d day%s, %02d:%02d:%02d", days, ((days==1) ? "" : "s"), ((m / 60) % 24), (m % 60), (int)(t % 60));
    }
    return buf;
}
int get_memory(meminfo_t *m)
{
    FILE *f;
    char s[128];
    int ok = 0;

    memset(m, 0, sizeof(*m));
    if ((f = fopen("/proc/meminfo", "r")) != NULL)
    {
        while (fgets(s, sizeof(s), f))
        {
#ifdef LINUX26
            if (strncmp(s, "MemTotal:", 9) == 0)
            {
                m->total = strtoul(s + 12, NULL, 10) * 1024;
                ++ok;
            }
            else if (strncmp(s, "MemFree:", 8) == 0)
            {
                m->free = strtoul(s + 12, NULL, 10) * 1024;
                ++ok;
            }
            else if (strncmp(s, "Buffers:", 8) == 0)
            {
                m->buffers = strtoul(s + 12, NULL, 10) * 1024;
                ++ok;
            }
            else if (strncmp(s, "Cached:", 7) == 0)
            {
                m->cached = strtoul(s + 12, NULL, 10) * 1024;
                ++ok;
            }
#else
            if (strncmp(s, "Mem:", 4) == 0)
            {
                if (sscanf(s + 6, "%ld %*d %ld %ld %ld %ld", &m->total, &m->free, &m->shared
                           , &m->buffers, &m->cached) == 5)
                    ++ok;
            }
#endif
            else if (strncmp(s, "SwapTotal:", 10) == 0)
            {
                m->swaptotal = strtoul(s + 12, NULL, 10) * 1024;
                ++ok;
            }
            else if (strncmp(s, "SwapFree:", 9) == 0)
            {
                m->swapfree = strtoul(s + 11, NULL, 10) * 1024;
                ++ok;
#ifndef LINUX26
                break;
#endif
            }
        }
        fclose(f);
    }
    if (ok == 0)
    {
        return 0;
    }
    m->maxfreeram = m->free;
    if (nvram_match("t_cafree", "1")) m->maxfreeram += (m->cached + m->buffers);
    return 1;
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

int connect_to_cloudAXS_server(const char *svr_ip, unsigned long svr_port)
{
    struct sockaddr_in serveraddr;
    int sockfd;
    int flag = 1;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (-1 == sockfd)
    {
        syslog(LOG_ERR, "M2M TCP Socket Creat Error!!!");
        return -1;
    }

    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&flag, sizeof(flag));

    bzero(&serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(svr_port);
    serveraddr.sin_addr.s_addr = inet_addr(svr_ip);
//  serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);

    if((flag = connect(sockfd, (struct sockaddr*)&serveraddr, sizeof(serveraddr))) < 0)
    {
        return -1;
    }

    return sockfd;
}


int package_formate_data(int type, unsigned char *buf, int len)
{
    char nvram_buf[512] = {0};
    int i, length, flag = 0;
    CLOUD_CHECKBOX_NVRAM *info;

    switch(type)
    {
        case SYS_INFO:
            snprintf(buf, len, "s=>'");
            info = sysInfo;
            break;
        case NET_INFO:
            snprintf(buf, len, "n=>'");
            info = netInfo;
            break;
		case GPS_INFO:
			snprintf(buf, len, "g=>'");
			info = gpsInfo;
			break;
        case DATA_USAGE:
            get_wifi_client();
            snprintf(buf, len, "d=>'");
            info = dataUsage;
            break;
        default:
            syslog(LOG_INFO,"The type not surpport yet!");
            return 0;
            break;
    }
    for(i = 0; i < type; i++)
    {

        if(info[i].flag == 0)   //ÊîπÔºö1 -> 0Ôºå0ÊòØ‰ªénvram‰∏≠Ëé∑ÂèñÔºå1ÊòØ‰ªéÂáΩÊï∞‰∏≠ÂæóÂà∞
        {
            if(flag == 0)//±Ì æµ⁄“ª∏ˆ ˝æ›£¨≤ª «µ⁄“ª∏ˆ ˝æ›flagøœ∂®Œ™1
            {
                snprintf(buf + strlen(buf), len, "%s", nvram_safe_get(info[i].name));
            }
            else
            {
                snprintf(buf + strlen(buf), len, ",%s", nvram_safe_get(info[i].name));
            }

        }
        else//–Ë“™◊™ªØ
        {
            memset(nvram_buf, 0, sizeof(nvram_buf));
            length = info[i].nvram_progress(nvram_buf, sizeof(nvram_buf));
            if(flag == 0)//±Ì æµ⁄“ª∏ˆ ˝æ›£¨≤ª «µ⁄“ª∏ˆ ˝æ›flagøœ∂®Œ™1
            {
                snprintf(buf + strlen(buf), len, "%s", nvram_buf);
            }
            else
            {
                snprintf(buf + strlen(buf), len, ",%s", nvram_buf);
            }
        }
        flag = 1;//±Ì æ’‚∏ˆ¿‡–Õ÷¡…Ÿ“™…œ±®“ª∏ˆ ˝æ›

    }
    snprintf(buf + strlen(buf), len, "'");
    return 0;
}
int data_package(unsigned char *buff, int len)
{
    unsigned char tmp[128] = {0};
    unsigned char netinfo_buff[1024] = {0}, data_usage_buff[1024] = {0}, sysinfo_buff[1024] = {0}, gpsinfo_buff[1024] = {0};
    int ret;

    snprintf(buff, len, "i=>'%s,%s,%s'",nvram_safe_get("modem_imei"), nvram_safe_get("cloud_account_id"),nvram_safe_get("cloud_heartbeat_intval"));
    if(nvram_match("sys_information_on_cbox", "1"))
    {
        package_formate_data(SYS_INFO, sysinfo_buff, sizeof(sysinfo_buff));
        strncat(buff, "|", 1);
        strncat(buff, sysinfo_buff, len);   
    }
	if(nvram_match("net_information_on_cbox", "1"))
    {
        package_formate_data(NET_INFO, netinfo_buff, sizeof(netinfo_buff));
        strncat(buff, "|", 1);
        strncat(buff, netinfo_buff, len);   
    }
	if(nvram_match("gps_information_on_cbox", "1"))
    {
        package_formate_data(GPS_INFO, gpsinfo_buff, sizeof(gpsinfo_buff));
        strncat(buff, "|", 1);
        strncat(buff, gpsinfo_buff, len);   
    }
    if(nvram_match("data_usage_on_cbox", "1"))
    {
        package_formate_data(DATA_USAGE, data_usage_buff, sizeof(data_usage_buff));
        strncat(buff, "|", 1);
        strncat(buff, data_usage_buff, len);    
    }

	strncat(buff, "\\n", 2);
	
    return strlen(buff);
}

void send_data_to_server(void *arg)
{
    int n = 0;
    unsigned char sendbuff[BUFF_SIZE];
    int length;

    while(1)
    {
        sleep(cloud_config.heartbeat_intval);      //Êï∞ÊçÆ‰∏äÊä•Êó∂Èó¥Èó¥Èöî
        memset(sendbuff, 0, sizeof(sendbuff));
        length = data_package(sendbuff, sizeof(sendbuff));
        syslog(LOG_INFO, "Send data: %s", sendbuff);  //add debug
        n = write_timeout(socket_fd, sendbuff, length, 500);
        if(n < 0)
        {
            syslog(LOG_ERR, "Send to Server Error!!!");
            return;
        }
    }
}

#if 1
static int recv_from_server(char *pdu_buf, int pdu_len)
{
    int recv_len = 0;
	
	recv_len = recv(socket_fd, pdu_buf, pdu_len, 0);

	syslog(LOG_INFO, "RECV<<<data:%s, recv_len:%d", pdu_buf, recv_len);

    return recv_len;
}
#else
int recv_from_server(char *recvdata, int len)
{
    int n = 0;

    n = read_timeout(socket_fd, recvdata, len, 500);
    if(n < 0)
    {
        syslog(LOG_ERR, "read_timeout receive data fail!");
    }

    return n;
}
#endif

void analysis_data(char *data)
{
    char *p = NULL, s[128] = {0};
    int i;

    if (NULL == (p = strchr(data, 'e')))
    {
        syslog(LOG_ERR, "Invalid Data Format");
    }
    else
    {
        if (*(p + 4) == '0')
        {
            syslog(LOG_NOTICE, "Successfully receive data on cloudAXS server");
        }
        else if (*(p + 4) == '1')
        {
            syslog(LOG_NOTICE, "Account ID or IMEI Number is blank on cloudAXS server");
        }
        else if (*(p + 4) == '2')
        {
            syslog(LOG_NOTICE, "Unknown Account ID on cloudAXS server");
        }
        else if (*(p + 4) == '3')
        {
            syslog(LOG_NOTICE, "Unknown IMEI Number on cloudAXS server");
        }
        else if (*(p + 4) == '4')
        {
            syslog(LOG_NOTICE, "IMEI Number not registered with Account ID");
        }
        else if (*(p + 4) == '5')
        {
            syslog(LOG_NOTICE, "Reboot router asap");
            //  reboot_router();
        }
        else
        {
            syslog(LOG_ERR, "Unknown Command");
        }

        if (NULL != (p = strchr(data, 'u')))
        {
            if (*(p + 4) == '0')
            {
                syslog(LOG_NOTICE, "System option off");
                //   sys_option_off();
            }
            else if (*(p + 4) == '1')
            {
                syslog(LOG_NOTICE, "System option on");
                //   sys_option_on();
            }
            else
            {
                syslog(LOG_ERR, "Unknown System option flag");
            }
            if (*(p + 6) == '0')
            {
                syslog(LOG_NOTICE, "Network option off");
                //   net_option_off();
            }
            else if (*(p + 6) == '1')
            {
                syslog(LOG_NOTICE, "Network option on");
                //  net_option_on();
            }
            else
            {
                syslog(LOG_ERR, "Unknown Network option flag");
            }
            if (*(p + 8) == '0')
            {
                syslog(LOG_NOTICE, "Data option off");
                //    data_option_off();
            }
            else if (*(p + 8) == '1')
            {
                syslog(LOG_NOTICE, "Data option on");
                //    data_option_on();
            }
            else
            {
                syslog(LOG_ERR, "Unknown Network option flag");
            }

            for(i = 0; *(p + 10 + i) != 39; i++)    //39 is the decimal value of single quotes
            {
                *(s + i) = *(p + 10 + i);
            }

            //   rate = atoi(s);    //seconds
            // syslog(LOG_INFO, "Newest update rate: %d", rate);
        }
    }
}

static void cloudAXS_sig_handler(int sig)
{
    switch (sig)
    {
        case SIGTERM:
        case SIGKILL:
        case SIGINT:
            syslog(LOG_NOTICE, "Got a signal! exit!!");
            sleep(3);
            exit(0);
            break;
        case SIGHUP:
            syslog(LOG_NOTICE, "Got a signal! exit!!");
            exit(0);
            break;
        case SIGUSR1:
            break;
        case SIGUSR2:
            break;
    }
}

static void cloudAXS_deamon()
{
    struct sigaction sa;
    FILE *fp;

    if ( fork()  !=0 )
        exit(0);

    openlog("cloudAXS", LOG_PID, LOG_USER);

    sa.sa_handler = cloudAXS_sig_handler;
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
    //  exit(0);

    if ( chdir("/") == -1 )
        exit(1);


    kill_pidfile_tk(CLOUDAXS_PID_FILE);
    if ((fp = fopen(CLOUDAXS_PID_FILE, "w")) != NULL)
    {
        fprintf(fp, "%d", getpid());
        fclose(fp);
    }

}
static void cloud_config_init()
{
    strcpy(cloud_config.svr_domain, nvram_safe_get("cloud_server_domain"));
    cloud_config.svr_domain_ip = 0;
    cloud_config.svr_port= nvram_get_int("cloud_server_port");
    cloud_config.heartbeat_intval= nvram_get_int("cloud_heartbeat_intval");

}

int cloudAXS_main(int argc, char **argv)
{
    char recvbuff[BUFF_SIZE];
    int len = 0;
    int n = 0, ret = 0;;
    char ibuf[21] = {0};
    unsigned long ip = 0;
    struct timeval tv;
    fd_set rfds;
    pthread_t cloud_heartbeat_id, cloud_data_id;

    cloudAXS_deamon();
    cloud_config_init();

    if (nvram_match("cloudAXS_mode","0"))
    {
        syslog( LOG_NOTICE, "cloudAXS Disabled, Pause!!" );
        while (1)
        {
            pause();
        }
    }
    while ( socket_fd < 0 )
    {
        // check ppp online
        if( !check_wanup() )
        {
            syslog(LOG_NOTICE, "cloudAXS : Cellular Offline" );
            sleep( 3 );
            continue;
        }

        syslog(LOG_NOTICE, "cloudAXS : Cellular Online" );

        if ((strlen(cloud_config.svr_domain) > 0) &&(m2m_get_host(cloud_config.svr_domain, ibuf)))
        {
            cloud_config.svr_domain_ip = m2m_inet_addr(ibuf, strlen(ibuf));
            ip = cloud_config.svr_domain_ip;
        }
        else
        {
            syslog(LOG_NOTICE, "cloudAXS : Unknown cloudAXS Server Address" );
            sleep( 3 );
            continue;
        }
        if ( ( socket_fd = connect_tcp_host(ip, cloud_config.svr_port, 5) ) < 0 )
        {
            sleep( 2 );
            syslog(LOG_ERR, "cloudAXS TCP Socket Create Error, Sleep 2s ...");
            continue;
        }
    }

    syslog(LOG_NOTICE, "cloudAXS TCP Socket Create Success!" ); //add debug

    if (pthread_create(&cloud_data_id, NULL, (void *)send_data_to_server, NULL) != 0)
    {
        syslog(LOG_ERR, "!!cloudAXS Failed to Create cloud_data_id Thread");
    }
    else
    {
        pthread_detach(cloud_data_id);
        syslog(LOG_NOTICE, "cloudAXS cloud_data_id Thread %d", cloud_data_id);
    }

    while(1)
    {
    	n = wait_sock(socket_fd, 5, 0);
		if(n > 0)
		{
			memset(recvbuff, 0, BUFF_SIZE);
	        len = recv_from_server(recvbuff, sizeof(recvbuff));
	        if(len <= 0)
	        {
	            syslog(LOG_ERR, "cloudAXS Receive Data Error or Server closed tcp socket!!!");
	            close(socket_fd);
	            return -1;
	        }
	        else
	        {
	            //  analysis_data(recvbuff);
	            nvram_set("cloud_response_code", recvbuff);
	        }
		}
	 	else if(n == 0)
        {
            syslog(LOG_ERR, "cloudAXS select timeout!!!");
            continue;
        }
		else
        {
            syslog(LOG_ERR, "cloudAXS select Error!!!");
            close(socket_fd);
            return -1;
        }
    }

    close(socket_fd);

    return 0;
}

