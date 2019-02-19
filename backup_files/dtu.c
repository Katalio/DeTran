/*************************************************************************
	> File Name: dtu_new.c
	> Author: zhangguocheng
	> Mail: gczhang@detran.com.cn
	> Created Time: Mon 09 May 2016 03:42:09 PM CST
 ************************************************************************/

#include "rc.h"
#include "dtu.h"

#include <netdb.h>
#include <sys/types.h>
#include <signal.h>
#include <linux/tcp.h>
#include <time.h>
#include <sys/time.h>
#include <math.h>
#include <libemqtt.h>

#define CONSOLE "/dev/ttyUSB0"
#define SERIAL  "/dev/ttyS0"

static volatile int dtu_gothup = 0;
static volatile int dtu_gotuser = 0;
static volatile int dtu_gotterm = 0;
static int sys_time_flag = 1; //µÚÒ»´Î¶Áµ½gpsÊý¾Ý»ñÈ¡µÄÊ±¼äÐ´ÈëÏµÍ³Ê±¼ä
static int is_valid = 0;
static char gps_date[16] = {0};
static char gps_time[16] = {0};
static char gps_latitude[16] = {0};
static char gps_NS[3] = {0};
static char gps_longitude[16] = {0};
static char gps_EW[3] = {0};
static char gps_use[3] = {0};
static char gps_speed[16] = {0};
static char gps_degrees[16] = {0};
static char gps_FS[3] = {0};
static char gps_HDOP[16] = {0};
static char gps_MSL[16] = {0};
static int GP_BD = 0; // 0 -- GPS 1 -- BDS 2 -- GPS/BDS


int dtu_data_process(int serialFd, DTU_CONFIG_T *dtuConf, SERIAL_CONFIG_T *seConf, MQTT_CONFIG_T *mqttConf);
int newbei_data_process(int serialFd, DTU_CONFIG_T *dtuConf, SERIAL_CONFIG_T *seConf, MQTT_CONFIG_T *mqttConf);
int relay_process(int serialFd, DTU_CONFIG_T *dtuConf, SERIAL_CONFIG_T *seConf, MQTT_CONFIG_T *mqttConf);
int gps_nmea_process(int serialFd, DTU_CONFIG_T *dtuConf, SERIAL_CONFIG_T *seConf, MQTT_CONFIG_T *mqttConf);
int gps_m2m_fmt_process(int serialFd, DTU_CONFIG_T *dtuConf, SERIAL_CONFIG_T *seConf, MQTT_CONFIG_T *mqttConf);
int double_gps_nmea_process(int serialFd,DTU_CONFIG_T * dtuConfig,SERIAL_CONFIG_T * serConf, MQTT_CONFIG_T *mqttConf);
int double_gps_m2m_fmt_process(int serialFd, DTU_CONFIG_T *dtuConf, SERIAL_CONFIG_T *seConf, MQTT_CONFIG_T *mqttConf);

static int init_dtu_config(DTU_CONFIG_T *dtuConf, SERIAL_CONFIG_T *seConf, MQTT_CONFIG_T *mqttConf);
static int init_gps_config(DTU_CONFIG_T *gpsConf, SERIAL_CONFIG_T *seConf, MQTT_CONFIG_T *mqttConf);
static int init_newbei_config(DTU_CONFIG_T *dtuConf, SERIAL_CONFIG_T *seConf, MQTT_CONFIG_T *mqttConf);
static void gps_process(char* buf, int len);
static void string_to_hex(char *str,char buf[]);
static char valueToHexCh(const int value);
static unsigned char *str_to_hex(char *str_in,unsigned char *hex_out);
static int write_serial_nb(int fd, char *buf, ssize_t len, int msec, DTU_CONFIG_T *dtuConf);

int String2Bytes(const char* src, unsigned char* dst, int len);
extern int send_to_gpctl(int fd, const char *sms_trigger_content, int cont_len, const char *send_num, int num_len);
extern int create_unix_socket(const char *path);

int switch_data(int serialFd, int sockFd, DTU_CONFIG_T *dtuConf, MQTT_CONFIG_T *mqttConf);

int set_nonblock(int fd);
static int create_tcp_socket(DTU_CONFIG_T *dtu_config);
static int create_udp_socket(DTU_CONFIG_T *dtu_config);
static int which_serial(char *port_name);

mqtt_broker_handle_t broker;
char packet_buffer[RCVBUFSIZE];
int keepalive = 30;

static struct sockaddr_in m_udp_recv_addr;
static int m_recv_addr_len;
static int m_newbei_multsvr_socketFd[MAX_SVR_CENTER];

const DATA_PROCESS_HOOT_T dtu_hook = {"IPoC", "/dev/ttyS0", init_dtu_config, dtu_data_process};
const DATA_PROCESS_HOOT_T newbei_hook = {"CUST_M2M", "/dev/ttyS0", init_newbei_config, newbei_data_process};
const DATA_PROCESS_HOOT_T gps_m2m_hook = {"GPS_M2M_FMT", "/dev/ttyS0", init_gps_config, gps_m2m_fmt_process};
const DATA_PROCESS_HOOT_T gps_nmea_hook = {"GPS_NMEA", "/dev/ttyS0", init_gps_config, gps_nmea_process};
const DATA_PROCESS_HOOT_T relay_hook = {"RELAY", "/dev/ttyS0", init_dtu_config, relay_process};

const DATA_PROCESS_HOOT_T double_gps_nmea_hook = {"DOUBLE_GPS_NMEA", "/dev/ttyS0", init_gps_config, double_gps_nmea_process};
const DATA_PROCESS_HOOT_T double_gps_m2m_hook = {"DOUBLE_GPS_M2M_FMT", "/dev/ttyS0", init_gps_config, double_gps_m2m_fmt_process};

static baudmap_t baudtable_st[] =
{
    { 300, B300 },
    { 600, B600 },
    { 1200, B1200 },
    { 2400, B2400 },
    { 4800, B4800 },
    { 9600, B9600 },
    { 19200, B19200 },
    { 38400, B38400 },
    { 57600, B57600 },
    { 115200, B115200 }
};
MODEM_TO_PORT_TABLE r21_modem_table[] = 
{
	{"F5521gw", "/dev/ttyUSB10"},
	{"MU609",   "/dev/ttyUSB4"},
	{"EC20",    "/dev/ttyUSB2"},
	{"EC25",    "/dev/ttyUSB2"},
	{"UC20",    "/dev/ttyUSB1"},
	{"MC73xx",  "/dev/ttyUSB1"},
	{"ME90X",   "/dev/ttyUSB4"},
	{"SLM630",  "/dev/ttyUSB4"},
	{"SLM7XX",  "/dev/ttyUSB4"},
	{"SIM72",   "/dev/ttyUSB2"},
	{NULL,    NULL}
};
MODEM_TO_PORT_TABLE modem_table[] = 
{
	{"F5521gw", "/dev/ttyUSB9"},
	{"MU609",   "/dev/ttyUSB3"},
	{"EC20",    "/dev/ttyUSB1"},
	{"EC25",    "/dev/ttyUSB1"},
	{"UC20",    "/dev/ttyUSB0"},
	{"MC73xx",  "/dev/ttyUSB0"},
	{"ME90X",   "/dev/ttyUSB3"},
	{"SLM630",  "/dev/ttyUSB3"},
	{"SLM7XX",  "/dev/ttyUSB3"},
	{"SIM72",   "/dev/ttyUSB1"},
	{NULL,    NULL}
};
static int m_pl2303_com_sockfd = 0;

static volatile int m_send_nb_heartbeat_flag = 0;
#define NB_RELLAY_ADD_PREFIX 0
#define NB_RELLAY_DEL_PREFIX 1
#define NB_RELLAY_HONGKONG_CUST 2
#define DTU_SOCK		"/tmp/dtu"
#define REDIAL_TIMES 3
static volatile int m_recv_flag[MAX_SVR_CENTER];


void *memmem(const void *l, size_t l_len, const void *s, size_t s_len)
{
    register char *cur, *last;
    const char *cl = (const char *)l;
    const char *cs = (const char *)s;

    /* we need something to compare */
    if (l_len == 0 || s_len == 0)
        return NULL;

    /* "s" must be smaller or equal to "l" */
    if (l_len < s_len)
        return NULL;

    /* special case where s_len == 1 */
    if (s_len == 1)
        return memchr(l, (int)*cs, l_len);

    /* the last position where its possible to find "s" in "l" */
    last = (char *)cl + l_len - s_len;

    for (cur = (char *)cl; cur <= last; cur++)
        if (cur[0] == cs[0] && memcmp(cur, cs, s_len) == 0)
            return cur;

    return NULL;
}
static char valueToHexCh(const int value)

{

	char result = '\0';

	if(value >= 0 && value <= 9){

		result = (char)(value + 48); //48为ascii编码的‘0’字符编码值

	}

	else if(value >= 10 && value <= 15){

		result = (char)(value - 10 + 65); //减去10则找出其在16进制的偏移量，65为ascii的'A'的字符编码值

	}

	return result;

}

static unsigned char *str_to_hex(char *str_in,unsigned char *hex_out)
{
	int high,low;
	int tmp = 0;
	if(str_in == NULL || hex_out == NULL){
		return NULL;
	}
	if(strlen(str_in) == 0){
		return NULL;
	}
	while(*str_in){
		tmp = (int)*str_in;
		high = tmp >> 4;
		low = tmp & 15;
		*hex_out++ = valueToHexCh(high); //先写高字节
		*hex_out++ = valueToHexCh(low); //其次写低字节
		str_in++;
	}
	*hex_out = '\0';
	return hex_out;
}
void string_to_hex(char *str,char buf[])
{
        int i,k = 0,j = 0;
        char trim_buf[2048];
        char *data;
        //int hex_buf[512];
        char high_byte;
  		  char low_byte;
  		  int num_h,num_l;
        unsigned char num;

        memset(trim_buf,0,sizeof(trim_buf));

        if(str == NULL)
                {
                        return;
        }
            
        while(*str != '\0')
                {
                        if(*str == ' ')
                                {
                                        str++;
                                        continue;
                        }
                        trim_buf[j++] = *str++;
        }
        trim_buf[j] = '\0';
        data = trim_buf;

         for(i = 0; i < strlen(data)/2; i++)
        {


                high_byte = *(data+ 2*i);
                low_byte = *(data + 2*i +1);

                if(high_byte >= '0' && high_byte <= '9')
                {
                        num_h = high_byte - '0';
                }
                else if(high_byte >= 'a' && high_byte <= 'z')
                {
                        num_h = high_byte - 'a' + 10;
                }
                else if(high_byte >= 'A' && high_byte <= 'Z')
                {
                        num_h = high_byte - 'A' + 10;
                }


                if(low_byte >= '0' && low_byte <= '9')
                {
                        num_l = low_byte - '0';
                }
                else if(low_byte >= 'a' && low_byte <= 'z')
                {
                        num_l = low_byte - 'a' + 10;
                }
                else if(low_byte >= 'A' && low_byte <= 'Z')
                {
                        num_l = low_byte - 'A' + 10;
                }

                num = (unsigned char)(num_h << 4 | num_l);

                                buf[i] = num;

                        //      sprintf(&buf[i*3],"%02x ",num);

        }

}

static void kill_pidfile_tk(const char *pidfile)
{
	FILE *fp;
	char buf[256];
	pid_t pid = 0;
	int n;

	if ((fp = fopen(pidfile, "r")) != NULL)
	{
		if (fgets(buf, sizeof(buf), fp) != NULL)
			pid = strtoul(buf, NULL, 0);
		fclose(fp);
	}

	if (pid > 1 && kill(pid, SIGTERM) == 0)
	{
		n = 10;
	    while ((kill(pid, 0) == 0) && (n-- > 0))
	   	{
			printf("%s: waiting pid=%d n=%d\n", __FUNCTION__, pid, n);
	   	    usleep(100 * 1000);
	    }
	   	if (n < 0)
	   	{
			n = 10;
	   	    while ((kill(pid, SIGKILL) == 0) && (n-- > 0))
			{
				printf("%s: SIGKILL pid=%d n=%d\n", __FUNCTION__, pid, n);
                usleep(100 * 1000);
            }
        }
	}
}

static void dtu_signal_handler(int sig)
{
    switch (sig)
    {
    case SIGTERM:
    case SIGKILL:
    case SIGINT:
        dtu_gotterm = 1;
        syslog(LOG_INFO, "Got a signal! exit!!");
        sleep(3);
        exit(0);
        break;
    case SIGHUP:
        syslog(LOG_INFO, "Got a signal! exit!!");
        exit(0);
        dtu_gothup = 1;
        break;
    case SIGUSR1:
        dtu_gotuser = 1;
        break;
    case SIGUSR2:
        dtu_gotuser = 2;
        break;
    }
}


static void init_deamon( )
{
    struct sigaction sa;
    FILE *fp;

    if (fork() !=0)
    {
        exit(0);
    }

    sa.sa_handler = dtu_signal_handler;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGKILL, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    if (setsid() < 0)
    {
        exit(1);
    }

    if (chdir("/") == -1)
    {
        exit(1);
    }

    kill_pidfile_tk(DTU_PID_FILE);
    if ((fp = fopen(DTU_PID_FILE, "w")) != NULL)
    {
        fprintf(fp, "%d", getpid());
        fclose(fp);
    }
}

int String2Bytes(const char* str, unsigned char* buf, int len)
{
	int i;
    char *data;
    char high_byte;
    char low_byte;
    int num_h,num_l;
    unsigned char num;

    if(str == NULL)
    {
		return -1;
	}

	data = str;
	for(i = 0; i < len/2; i++)
	{
		high_byte = *(data+ 2*i);
		low_byte = *(data + 2*i +1);

		if(high_byte >= '0' && high_byte <= '9')
		{
			num_h = high_byte - '0';
		}
		else if(high_byte >= 'a' && high_byte <= 'z')
		{
			num_h = high_byte - 'a' + 10;
		}
		else if(high_byte >= 'A' && high_byte <= 'Z')
		{
			num_h = high_byte - 'A' + 10;
		}

		if(low_byte >= '0' && low_byte <= '9')
		{
			num_l = low_byte - '0';
		}
		else if(low_byte >= 'a' && low_byte <= 'z')
		{
			num_l = low_byte - 'a' + 10;
		}
		else if(low_byte >= 'A' && low_byte <= 'Z')
		{
			num_l = low_byte - 'A' + 10;
		}

		num = (unsigned char)(num_h << 4 | num_l);

		buf[i] = num;
	}

	return len / 2;
}

static int init_newbei_config(DTU_CONFIG_T *dtuConf, SERIAL_CONFIG_T *seConf, MQTT_CONFIG_T *mqttConf)
{
    unsigned char mac[6] = {0};


    syslog(LOG_INFO, "----IPoC Parameters Init. Start----");

    memset(dtuConf, 0, sizeof(DTU_CONFIG_T));
    memset(&dtuConf->data, 0, sizeof(DATA_FRAME_T));
    memset(&dtuConf->server[0], 0, sizeof(SERVER_PARAM_T));
    memset(&dtuConf->local, 0, sizeof(SERVER_PARAM_T));
    memset(&dtuConf->heartbeat, 0, sizeof(HEARTBEAT_PARAM_T));
    memset(seConf, 0, sizeof(SERIAL_CONFIG_T));


    dtuConf->data.max_len = nvram_get_int("packet_len") ? : DEFAULT_MAX_LEN;
    dtuConf->reconnect_interval = 3;

    syslog(LOG_INFO, "IPoC Payload Data Max Length %d !", dtuConf->data.max_len );

    seConf->rate = nvram_get_int("serial_rate");

    seConf->parity = *nvram_safe_get("serial_parity");

    seConf->databits = *nvram_safe_get("serial_databits");

    seConf->stopbits = *nvram_safe_get("serial_stopbits");

    seConf->streamcontrol = '0';

    syslog(LOG_INFO, "serial config: %d, parity: %c, databits: %c, stopbits: %c",
           seConf->rate,
           seConf->parity,
           seConf->databits,
           seConf->stopbits );

    dtuConf->data.timeout = nvram_get_int("socket_timeout");

    dtuConf->data.serial_timeout = nvram_get_int("serial_timeout");

    dtuConf->protocol = (nvram_match("socket_type", "tcp"))? DTU_SOCKET_TCP : DTU_SOCKET_UDP;

    strncpy( dtuConf->local.svr_port,  nvram_safe_get("local_port"), sizeof(dtuConf->local.svr_port ) );

    if (nvram_match("dtu_mode", "client"))
    {
        dtuConf->mode = DTU_MODE_CLIENT;

        strcpy(dtuConf->server[0].svr_addr, nvram_safe_get("server_ip"));
        dtuConf->server[0].svr_ip = inet_addr(dtuConf->server[0].svr_addr);

        strcpy(dtuConf->server[0].svr_port, nvram_safe_get("server_port"));

        strcpy( dtuConf->server[1].svr_addr, nvram_safe_get("server2_ip"));
        dtuConf->server[1].svr_ip = inet_addr(dtuConf->server[1].svr_addr);

        strcpy( dtuConf->server[1].svr_port, nvram_safe_get("server2_port"));
#if 0
        strcpy( dtuConf->server[2].svr_addr, nvram_safe_get("server3_ip"));
        dtuConf->server[2].svr_ip = inet_addr(dtuConf->server[1].svr_addr);

        strcpy( dtuConf->server[2].svr_port, nvram_safe_get("server3_port"));

        strcpy( dtuConf->server[3].svr_addr, nvram_safe_get("server4_ip"));
        dtuConf->server[3].svr_ip = inet_addr(dtuConf->server[1].svr_addr);

        strcpy( dtuConf->server[3].svr_port, nvram_safe_get("server4_port"));
#endif
        dtuConf->server[0].svr_connect_interval = nvram_get_int("server_connect_intval") ? : 5;

        dtuConf->server[0].svr_connect_times    = nvram_get_int("server_connect_intval") ? : 3;

        dtuConf->server[0].svr_connect_timeout = 10;

        dtuConf->heartbeat.heartbeat_interval = nvram_get_int("heartbeat_intval") ? nvram_get_int("heartbeat_intval") : 1;

        if (!nvram_match("m2m_product_id", ""))
        {
            //strncpy( dtu.heartbeat.content, nvram_safe_get("heartbeat_data"), sizeof(dtu.heartbeat.content)-1);
            ether_atoe(nvram_safe_get("et0macaddr"), mac);
            sprintf(dtuConf->heartbeat.content, "%s_R%02x%02x%02x%02x", nvram_safe_get("m2m_product_id"), mac[2], mac[3], mac[4], mac[5]);
        }
        else
        {
            memset(dtuConf->heartbeat.content, 0, sizeof(dtuConf->heartbeat.content));
        }
        strncpy(dtuConf->heartbeat.router_id, nvram_safe_get("router_id"), sizeof(dtuConf->heartbeat.router_id)-1);

        syslog(LOG_INFO, "mode: %s, local_port: %s, server addr:<1>[%s:%s], <2>[%s:%s], socket_timeout: %d, serial_timeout: %d, packet_len: %d",
               "client",
               dtuConf->local.svr_port,
               dtuConf->server[0].svr_addr,
               dtuConf->server[0].svr_port,
               dtuConf->server[1].svr_addr,
               dtuConf->server[1].svr_port,
               dtuConf->data.timeout,
               dtuConf->data.serial_timeout,
               dtuConf->data.max_len);
        syslog(LOG_INFO, "IPoC [hearbeat for client[%s] payload: %s, interval: %d]",
               dtuConf->heartbeat.router_id,
               dtuConf->heartbeat.content,
               dtuConf->heartbeat.heartbeat_interval);

    }
    else
    {
        dtuConf->mode = DTU_MODE_SERVER;
        syslog(LOG_INFO, "mode: %s, local_port: %s, addr: [%s:%s], socket_timeout: %d, serial_timeout: %d, packet_len: %d",
               "server",
               dtuConf->local.svr_port,
               dtuConf->server[0].svr_addr,
               dtuConf->server[0].svr_port,
               dtuConf->data.timeout,
               dtuConf->data.serial_timeout,
               dtuConf->data.max_len);
    }

    char *tmp = nvram_safe_get("nb_router_id");
    dtuConf->nb_router_id_len = String2Bytes(tmp, dtuConf->nb_router_id, strlen(tmp));
    syslog(LOG_INFO, "Router ID: %s,%d", dtuConf->nb_router_id, dtuConf->nb_router_id_len);

    tmp = nvram_safe_get("nb_prefix_content");
    dtuConf->prefix_content_len = String2Bytes(tmp, dtuConf->prefix_content, strlen(tmp));
    syslog(LOG_INFO, "Prefix Content: %s,%d", dtuConf->prefix_content, dtuConf->prefix_content_len);

    strncpy(dtuConf->relay_proto, nvram_safe_get("relay_proto"), sizeof(dtuConf->relay_proto) - 1);
    strcpy(dtuConf->nb_ht_content, nvram_safe_get("nb_ht_content"));
    dtuConf->nb_ht_length = strlen(dtuConf->nb_ht_content);

    dtuConf->prefix_type = nvram_get_int("nb_prefix_type");
    syslog(LOG_INFO, "Prefix type: %d", dtuConf->prefix_type);
    dtuConf->del_prefix_index = nvram_get_int("nb_del_prefix_index");

    syslog(LOG_NOTICE, "----IPoC  Parameters Init. End----");
    return (1);
}

static int init_dtu_config(DTU_CONFIG_T *dtuConf, SERIAL_CONFIG_T *seConf, MQTT_CONFIG_T *mqttConf)
{
    unsigned char mac[6] = {0};


    syslog(LOG_INFO, "----IPoC Parameters Init. Start----");

    memset(dtuConf, 0, sizeof(DTU_CONFIG_T));
    memset(&dtuConf->data, 0, sizeof(DATA_FRAME_T));
    memset(&dtuConf->server[0], 0, sizeof(SERVER_PARAM_T));
    memset(&dtuConf->local, 0, sizeof(SERVER_PARAM_T));
    memset(&dtuConf->heartbeat, 0, sizeof(HEARTBEAT_PARAM_T));
    memset(seConf, 0, sizeof(SERIAL_CONFIG_T));
	memset(mqttConf, 0, sizeof(MQTT_CONFIG_T));

    dtuConf->data.max_len = nvram_get_int("packet_len") ? : DEFAULT_MAX_LEN;
    dtuConf->reconnect_interval = 3;

    syslog(LOG_INFO, "IPoC Payload Data Max Length %d !", dtuConf->data.max_len );

    seConf->rate = nvram_get_int("serial_rate");

    seConf->parity = *nvram_safe_get("serial_parity");

    seConf->databits = *nvram_safe_get("serial_databits");

    seConf->stopbits = *nvram_safe_get("serial_stopbits");

    seConf->streamcontrol = '0';

    syslog(LOG_INFO, "Serial config: %d, parity: %c, databits: %c, stopbits: %c",
           seConf->rate,
           seConf->parity,
           seConf->databits,
           seConf->stopbits );

    dtuConf->data.timeout = nvram_get_int("socket_timeout");

    dtuConf->data.serial_timeout = nvram_get_int("serial_timeout");

    dtuConf->protocol = (nvram_match("socket_type", "tcp"))? DTU_SOCKET_TCP : DTU_SOCKET_UDP;

    strncpy( dtuConf->local.svr_port,  nvram_safe_get("local_port"), sizeof(dtuConf->local.svr_port ) );

    if (nvram_match("dtu_mode", "client"))
    {
        dtuConf->mode = DTU_MODE_CLIENT;

        strcpy(dtuConf->server[0].svr_addr, nvram_safe_get("server_ip"));
        dtuConf->server[0].svr_ip = inet_addr(dtuConf->server[0].svr_addr);

        strcpy(dtuConf->server[0].svr_port, nvram_safe_get("server_port"));

        strcpy( dtuConf->server[1].svr_addr, nvram_safe_get("server2_ip"));
        dtuConf->server[1].svr_ip = inet_addr(dtuConf->server[1].svr_addr);

        strcpy( dtuConf->server[1].svr_port, nvram_safe_get("server2_port"));

        dtuConf->server[0].svr_connect_interval = nvram_get_int("server_connect_intval") ? : 5;

        dtuConf->server[0].svr_connect_times    = nvram_get_int("server_connect_intval") ? : 3;

        dtuConf->server[0].svr_connect_timeout = 3;

        dtuConf->heartbeat.heartbeat_interval = nvram_get_int("heartbeat_intval") ? nvram_get_int("heartbeat_intval") : 1;

        if (!nvram_match("m2m_product_id", ""))
        {
            //strncpy( dtu.heartbeat.content, nvram_safe_get("heartbeat_data"), sizeof(dtu.heartbeat.content)-1);
            ether_atoe(nvram_safe_get("et0macaddr"), mac);
            sprintf(dtuConf->heartbeat.content, "%s_R%02x%02x%02x%02x", nvram_safe_get("m2m_product_id"), mac[2], mac[3], mac[4], mac[5]);
        }
        else
        {
            memset(dtuConf->heartbeat.content, 0, sizeof(dtuConf->heartbeat.content));
        }
        strncpy(dtuConf->heartbeat.router_id, nvram_safe_get("router_id"), sizeof(dtuConf->heartbeat.router_id)-1);

        syslog(LOG_INFO, "mode: %s, local_port: %s, server addr:<1>[%s:%s], <2>[%s:%s], socket_timeout: %d, serial_timeout: %d, packet_len: %d",
               "client",
               dtuConf->local.svr_port,
               dtuConf->server[0].svr_addr,
               dtuConf->server[0].svr_port,
               dtuConf->server[1].svr_addr,
               dtuConf->server[1].svr_port,
               dtuConf->data.timeout,
               dtuConf->data.serial_timeout,
               dtuConf->data.max_len);
        syslog(LOG_INFO, "IPoC [hearbeat for client[%s] payload: %s, interval: %d]",
               dtuConf->heartbeat.router_id,
               dtuConf->heartbeat.content,
               dtuConf->heartbeat.heartbeat_interval);

    }
    else
    {
        dtuConf->mode = DTU_MODE_SERVER;
        syslog(LOG_INFO, "mode: %s, local_port: %s, addr: [%s:%s], socket_timeout: %d, serial_timeout: %d, packet_len: %d",
               "server",
               dtuConf->local.svr_port,
               dtuConf->server[0].svr_addr,
               dtuConf->server[0].svr_port,
               dtuConf->data.timeout,
               dtuConf->data.serial_timeout,
               dtuConf->data.max_len);
    }


	if(nvram_match("ipoc_mqtt_mode", "1") && (dtuConf->mode == DTU_MODE_CLIENT))
	{
		strncpy( mqttConf->usrname,  nvram_safe_get("ipoc_mqtt_usrname"), sizeof(mqttConf->usrname) );
    	strncpy( mqttConf->passwd,  nvram_safe_get("ipoc_mqtt_passwd"), sizeof(mqttConf->passwd) );
    	strncpy( mqttConf->pub_topic,  nvram_safe_get("ipoc_mqtt_pubtopic"), sizeof(mqttConf->pub_topic) );
    	strncpy( mqttConf->sub_topic,  nvram_safe_get("ipoc_mqtt_subtopic"), sizeof(mqttConf->sub_topic) );

    	syslog(LOG_INFO, "MQTT config--->usrname: %s, passwd: %s, publish topic: %s, subscribe topic: %s",
    	       mqttConf->usrname,
    	       mqttConf->passwd,
    	       mqttConf->pub_topic,
			   mqttConf->sub_topic);
	}

    syslog(LOG_NOTICE, "----IPoC Parameters Init. End----");

    return (1);
}



static int init_gps_config(DTU_CONFIG_T *gpsConf, SERIAL_CONFIG_T *seConf, MQTT_CONFIG_T *mqttConf)
{
    unsigned char mac[6] = {0};
    syslog(LOG_NOTICE, "----GPS Parameters Init. Start----");

    memset(gpsConf, 0, sizeof(DTU_CONFIG_T));
    memset(&gpsConf->data, 0, sizeof(DATA_FRAME_T));
    memset(&gpsConf->server[0], 0, sizeof(SERVER_PARAM_T));
    memset(&gpsConf->local, 0, sizeof(SERVER_PARAM_T));
    memset(&gpsConf->heartbeat, 0, sizeof(HEARTBEAT_PARAM_T));
    memset(seConf, 0, sizeof(SERIAL_CONFIG_T));

    gpsConf->data.max_len = nvram_get_int("packet_len1") ? : DEFAULT_MAX_LEN;
    gpsConf->reconnect_interval = 3;

    syslog(LOG_NOTICE, "GPS Payload Data Max Length %d !", gpsConf->data.max_len );

    seConf->rate = nvram_get_int("serial_rate1");

    seConf->parity = *nvram_safe_get("serial_parity1");

    seConf->databits = *nvram_safe_get("serial_databits1");

    seConf->stopbits = *nvram_safe_get("serial_stopbits1");

    seConf->streamcontrol = '0';

    gpsConf->data.timeout = nvram_get_int("socket_timeout1");

    gpsConf->data.serial_timeout = nvram_get_int("serial_timeout1");

    gpsConf->protocol = (nvram_match("socket_type1", "tcp"))? DTU_SOCKET_TCP : DTU_SOCKET_UDP;

    strncpy(gpsConf->local.svr_port,  nvram_safe_get("local_port1"), sizeof(gpsConf->local.svr_port ) );

    gpsConf->heartbeat.heartbeat_interval = nvram_get_int("heartbeat_intval1") ? nvram_get_int("heartbeat_intval1") : 1;
    if (nvram_match("dtu_mode1", "client"))
    {
        gpsConf->mode = DTU_MODE_CLIENT;

        char *ptr = nvram_get("server_ip1");
        if (ptr == NULL || (unsigned char)ptr[0] == 0x0)
        {
            strcpy(gpsConf->server[0].svr_addr, nvram_safe_get("lan_ipaddr"));
        }
        else
        {
            strcpy(gpsConf->server[0].svr_addr, nvram_safe_get("server_ip1"));
        }
        gpsConf->server[0].svr_ip = inet_addr(gpsConf->server[0].svr_addr);

        strcpy(gpsConf->server[0].svr_port, nvram_safe_get("server_port1"));

        strcpy(gpsConf->server[1].svr_addr, nvram_safe_get("server2_ip1"));
        gpsConf->server[1].svr_ip = inet_addr(gpsConf->server[1].svr_addr);

        strcpy(gpsConf->server[1].svr_port, nvram_safe_get("server2_port1"));

        gpsConf->server[0].svr_connect_interval = nvram_get_int("server_connect_intval1") ? : 5;

        gpsConf->server[0].svr_connect_times    = nvram_get_int("server_connect_intval1") ? : 3;

        gpsConf->server[0].svr_connect_timeout = 3;

        //   gpsConf->heartbeat.heartbeat_interval = nvram_get_int("heartbeat_intval1") ? : 1;

        if (!nvram_match("m2m_product_id", ""))
        {
            //strncpy( dtu.heartbeat.content, nvram_safe_get("heartbeat_data"), sizeof(dtu.heartbeat.content)-1);
            ether_atoe(nvram_safe_get("et0macaddr"), mac);
            sprintf(gpsConf->heartbeat.content, "%s_R%02x%02x%02x%02x", nvram_safe_get("m2m_product_id"), mac[2], mac[3], mac[4], mac[5]);
        }
        else
        {
            memset(gpsConf->heartbeat.content, 0, sizeof(gpsConf->heartbeat.content));
        }
        strncpy(gpsConf->heartbeat.router_id, nvram_safe_get("router_id1"), sizeof(gpsConf->heartbeat.router_id) - 1);

        syslog(LOG_NOTICE, "GPS [mode: %s, local_port: %s, server for client mode: [1]%s:%s, [2]%s:%s, socket_timeout: %d, serial_timeout: %d, packet_len: %d]",
               "client",
               gpsConf->local.svr_port,
               gpsConf->server[0].svr_addr,
               gpsConf->server[0].svr_port,
               gpsConf->server[1].svr_addr,
               gpsConf->server[1].svr_port,
               gpsConf->data.timeout,
               gpsConf->data.serial_timeout,
               gpsConf->data.max_len);
        syslog(LOG_NOTICE, "GPS [hearbeat for client[%s] payload: %s, interval: %d]",
               gpsConf->heartbeat.router_id,
               gpsConf->heartbeat.content,
               gpsConf->heartbeat.heartbeat_interval);

    }
    else
    {
        gpsConf->mode = DTU_MODE_SERVER;
        syslog(LOG_NOTICE, "GPS [mode: %s, local_port: %s, server for client mode: %s:%s, socket_timeout: %d, serial_timeout: %d, packet_len: %d]",
               "server",
               gpsConf->local.svr_port,
               gpsConf->server[0].svr_addr,
               gpsConf->server[0].svr_port,
               gpsConf->data.timeout,
               gpsConf->data.serial_timeout,
               gpsConf->data.max_len);
    }


    syslog(LOG_NOTICE, "GPS [serial: %d, parity: %c, databits: %c, stopbits: %c",
           seConf->rate, seConf->parity, seConf->databits, seConf->stopbits );

    syslog(LOG_NOTICE, "----GPS Parameters Init. End----");

    return (1);
}


/* Serial Function define ........................... */

static int baud_flag(unsigned int speed)
{
    int i = 0;

    for (i = 0; i < (sizeof(baudtable_st) / sizeof(baudmap_t)); i++ )
    {
        if (speed == baudtable_st[i].baud )
            return (baudtable_st[i].flag );
    }
    return (-1);
}


static void save_term_ios(int serial_fd, struct termios *old_term )
{
    if (tcgetattr(serial_fd, old_term ) < 0)
    {
        exit(0);
    }
}

static void restore_term_ios(int serial_fd, struct termios *old_term )
{
    if (tcsetattr(serial_fd, TCSAFLUSH, old_term ) < 0 )
    {
        exit(0);
    }
}


static int init_serial( int serial_fd,  SERIAL_CONFIG_T *serial_config)
{
    struct termios tio;

    memset(&tio, 0, sizeof(tio));

    tio.c_cflag = CREAD | HUPCL | baud_flag(serial_config->rate);

    switch (serial_config->streamcontrol)
    {
    case '1':
        tio.c_cflag |= CRTSCTS;
        break;
    case '2':
        tio.c_iflag |= IXON | IXOFF;
        break;
    default:
        break;
    }

    switch (serial_config->parity )
    {
    case 'e':
        tio.c_cflag |= PARENB;
        break;
    case 'o':
        tio.c_cflag |= PARENB | PARODD;
        break;
    default:
        break;
    }

    switch (serial_config->databits)
    {
    case '5':
        tio.c_cflag |= CS5;
        break;
    case '6':
        tio.c_cflag |= CS6;
        break;
    case '7':
        tio.c_cflag |= CS7;
        break;
    default:
        tio.c_cflag |= CS8;
        break;
    }

    tio.c_cc[VMIN] = 1;
    tio.c_cc[VTIME] = 0;

    if ( tcsetattr(serial_fd, TCSAFLUSH, &tio) < 0 )
    {
        return (-1);
    }
    return (0);
}


static int open_serial(const char *dev, struct termios *old_term)
{
    int fd = open(dev, (O_RDWR | O_NDELAY | O_NONBLOCK) ) ;
    if (fd < 0 )
    {
        return (-1);
    }

    save_term_ios(fd, old_term);

    return ( fd );
}

static int close_serial(int fd, struct termios *old_term )
{
    if(fd < 0 )
    {
        return (-1);
    }

    restore_term_ios(fd, old_term );

    close (fd);
    fd = -1;

    return (0);
}



/* socket Function Define ....................... */

static int domain_to_ip(const char *domain, int *ip)
{
    struct hostent *host = NULL;
    struct in_addr sin_addr;

    if (NULL == domain || NULL == ip)
    {
        return -1;
    }
    *ip = 0;
    if (1 == inet_pton(AF_INET, domain, &sin_addr))
    {
        *ip = sin_addr.s_addr;
        return 0;
    }

    host = gethostbyname(domain);
    if (NULL == host)
    {
        return -1;
    }

    bcopy(host->h_addr_list[0], ip, sizeof(int));
    return (0);
}


static int wait_rsock(int fd, int sec, int usec)
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


static int wait_wsock(int fd, int sec, int usec)
{
    struct timeval tv;
    fd_set fdvar;
    int res;

    FD_ZERO(&fdvar);
    FD_SET(fd, &fdvar);
    tv.tv_sec = sec;
    tv.tv_usec = usec;
    res = select(fd+1, NULL, &fdvar, NULL, &tv);

    return res;
}

static int create_tcp_listen_socket(unsigned short bind_port)
{
    int sock_fd = -1;
    struct sockaddr_in svr_addr;

    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0)
    {
        syslog(LOG_ERR, "Create TCP socket error");
        return -1;
    }

    bzero(&svr_addr, sizeof(struct sockaddr_in));
    svr_addr.sin_family = AF_INET;
    svr_addr.sin_port = htons(bind_port);
    svr_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    int n = 1;
    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&n, sizeof(n)) < 0)
    {
        close(sock_fd);
        return (-1);
    }

    if (bind(sock_fd, (struct sockaddr *)&svr_addr, sizeof(struct sockaddr)) < 0)
    {
        close(sock_fd);
        return (-1);
    }

    if (listen(sock_fd, 2) < 0)
    {
        close(sock_fd);
        return (-1);
    }

    return sock_fd;
}

static int create_tcp_socket(DTU_CONFIG_T *dtuConfig)
{
    int sock_fd = -1, accept_fd = -1;
    struct sockaddr_in svr_addr, accept_addr;
    int sin_size = sizeof(struct sockaddr_in);
    fd_set rset;
    struct timeval  time_out = {5, 0};
    int ret = -1 ;


    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0)
    {
        syslog(LOG_ERR, "Create TCP socket error");
        return -1;
    }

    bzero(&svr_addr, sizeof(struct sockaddr_in));
    bzero(&accept_addr, sizeof(struct sockaddr_in));
    svr_addr.sin_family = AF_INET;
    svr_addr.sin_port = htons((unsigned short)atoi(dtuConfig->local.svr_port));
    svr_addr.sin_addr.s_addr = htonl(INADDR_ANY);


    int n = 1;
    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&n, sizeof(n)) < 0)
    {
        close(sock_fd);
        return (-1);
    }

    if (bind(sock_fd, (struct sockaddr *)&svr_addr, sizeof(struct sockaddr)) < 0)
    {
        close(sock_fd);
        return (-1);
    }

    if (listen(sock_fd, 2) < 0)
    {
        close(sock_fd);
        return (-1);
    }

    while (1)
    {
        FD_ZERO(&rset);
        FD_SET(sock_fd, &rset);

        ret = select(sock_fd + 1, &rset, NULL, NULL, &time_out);
        if (ret < 0)
        {
            if (errno != EINTR)
            {
                close(sock_fd);
                return (-1);
            }
            continue;
        }
        else if(0 == ret)
        {
            continue;
        }

        if (FD_ISSET(sock_fd, &rset))
        {
            accept_fd = accept(sock_fd, (struct sockaddr *)&accept_addr, &sin_size);
            if (accept_fd < 0)
            {
                if (EWOULDBLOCK == errno)
                {
                    continue;
                }

                close(sock_fd);
                return (-1);
            }
            else
            {
                close(sock_fd);
                break;
            }
        }
    }

    int on = 1;
    if ( 0 != setsockopt(accept_fd, SOL_SOCKET, SO_KEEPALIVE, (char *)&on, sizeof(int)) )
    {
        return (-1);
    }

    int idle = 300;
    if ( 0 != setsockopt(accept_fd, IPPROTO_TCP, TCP_KEEPIDLE, (void *)&idle, sizeof(int)) )
    {
        return (-1);
    }

    int intvl = 60;
    if ( 0 != setsockopt(accept_fd, IPPROTO_TCP, TCP_KEEPINTVL, (char *)&intvl, sizeof(int)) )
    {
        return (-1);
    }

    int cnt = 3;
    if ( 0 != setsockopt(accept_fd, IPPROTO_TCP, TCP_KEEPCNT, (char *)&cnt, sizeof(int)) )
    {
        return (-1);
    }

    return (accept_fd);
}


static int create_udp_socket(DTU_CONFIG_T *dtuConfig)
{
    int sock_fd;
    int ret = 0;
    char flag;
    struct sockaddr_in svr_addr;


    sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0)
    {
        return -1;
    }

    bzero(&svr_addr, sizeof(struct sockaddr_in));
    svr_addr.sin_family = AF_INET;
    svr_addr.sin_port = htons((unsigned short)atoi(dtuConfig->local.svr_port));
    svr_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    flag = 1;
    setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&flag, sizeof(flag));

    ret = bind(sock_fd, (struct sockaddr*)&svr_addr, sizeof(svr_addr));
    if (ret < 0)
    {
        close(sock_fd);
        return -1;
    }

    return sock_fd;
}



int set_nonblock(int fd)
{
    int val;

    if ((val = fcntl(fd, F_GETFL, 0)) < 0)
    {
        syslog(LOG_ERR, "Get fd(%d) Flag Failed !", fd);
        return (-1);
    }

    val |= O_NONBLOCK;
    if(fcntl(fd, F_SETFL, val) < 0)
    {
        syslog(LOG_ERR, "Set fd(%d) Flag NON_BLOCK Failed !", fd);
        return (-1);
    }

    return (0);
}


static int handle_async_connect(int sock_fd, int nsec)
{
    struct timeval tv;
    fd_set	wfds;
    int	ret = -1;
    int	error = 0;
    int	len = sizeof(error);;

    FD_ZERO( &wfds );
    FD_SET( sock_fd, &wfds );

    tv.tv_sec = nsec;
    tv.tv_usec = 0;

    ret = select(sock_fd + 1, NULL, &wfds, NULL, &tv);
    if(ret > 0)
    {
        getsockopt(sock_fd, SOL_SOCKET, SO_ERROR, &error, &len);
        if(error == 0)
        {
            return 0;
        }
    }

    return -1;
}


static int connect_tcp_host(int ip, int port, int conn_timeout)
{
    int	ret = -1;
    int	sock_fd = -1;
    struct	sockaddr_in svr_addr;


    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0)
    {
        return -1;
    }

    if (set_nonblock(sock_fd) < 0)
    {
        close(sock_fd);
        return -1;
    }

	int flag = 1;
    if ( 0 != setsockopt(sock_fd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int)) )
    {
        return (-1);
    }

    int on = 1;
    if ( 0 != setsockopt(sock_fd, SOL_SOCKET, SO_KEEPALIVE, (char *)&on, sizeof(int)) )
    {
        return (-1);
    }

    int idle = 300;
    if ( 0 != setsockopt(sock_fd, IPPROTO_TCP, TCP_KEEPIDLE, (void *)&idle, sizeof(int)) )
    {
        return (-1);
    }

    int intvl = 60;
    if ( 0 != setsockopt(sock_fd, IPPROTO_TCP, TCP_KEEPINTVL, (char *)&intvl, sizeof(int)) )
    {
        return (-1);
    }

    int cnt = 3;
    if ( 0 != setsockopt(sock_fd, IPPROTO_TCP, TCP_KEEPCNT, (char *)&cnt, sizeof(int)) )
    {
        return (-1);
    }

    bzero( &svr_addr, sizeof(svr_addr) );
    svr_addr.sin_family = AF_INET;
    svr_addr.sin_port = htons(port);
    svr_addr.sin_addr.s_addr = ip;

    ret = connect(sock_fd, (struct sockaddr *)&svr_addr, sizeof(struct sockaddr_in));
    if (ret < 0)
    {
        if (errno != EINPROGRESS)
        {
            syslog(LOG_ERR, "TCP Socket connect Failed <%s> !", strerror(errno));
            close(sock_fd);
            return -2;
        }
    }
    else
    {
        return sock_fd;
    }

    if (0 == handle_async_connect(sock_fd, conn_timeout))
    {
        syslog(LOG_INFO, "connect_tcp_host-->sock_fd is %d ", sock_fd);
        return (sock_fd);
    }

    syslog(LOG_ERR, "handle_async_connect Failed <%s> !", strerror(errno));
    close(sock_fd);
    return -1;
}



static int connect_udp_host(int ip, int port , unsigned short  local_port)
{
    int sock_fd = -1;
    int flag;
    struct sockaddr_in svr_addr,local_addr;


    sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0)
    {
        return (-1);
    }

    bzero( &svr_addr, sizeof(svr_addr) );
    svr_addr.sin_family = AF_INET;
    svr_addr.sin_port = htons(port);
    svr_addr.sin_addr.s_addr = ip;

    bzero( &local_addr, sizeof(local_addr) );
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(local_port);
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    // bind the socket to an address and port.
    flag = 1;
    setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&flag, sizeof(flag));

    if (bind(sock_fd, (struct sockaddr *)&local_addr, sizeof(local_addr)) < 0)
    {
        syslog(LOG_ERR, "UDP Socket Bind(port:%d) Failed !", local_port);
        close(sock_fd);
        return -1;
    }

    if (connect(sock_fd, (struct sockaddr *)&svr_addr, sizeof(svr_addr)) < 0)
    {
        syslog(LOG_ERR, "UDP Socket connect Failed <%s> !", strerror(errno));
        close( sock_fd );
        return -1;
    }

    if (set_nonblock(sock_fd) < 0)
    {
        close( sock_fd );
        return (-1);
    }

    syslog(LOG_INFO, "connect_udp_host-->sock_fd is %d ", sock_fd);
    return (sock_fd);
}

static int connect_server(DTU_CONFIG_T *dtu_config)
{
    int	i, svr_index = 0;
    int	sock_fd = -1;
    int  ip = 0;
    char server_ip[16+1] = {0};
    char *svr_addr_ptr = dtu_config->server[svr_index].svr_addr;
    char *svr_port_ptr = dtu_config->server[svr_index].svr_port;
    int svr_con_times = dtu_config->server[svr_index].svr_connect_times;
    int svr_con_itv = dtu_config->server[svr_index].svr_connect_interval;
    int svr_con_timeout = dtu_config->server[svr_index].svr_connect_timeout ;

    if((0 == *svr_addr_ptr) || (0 == *svr_port_ptr))
    {
        return (-1);
    }

    for(i = 0; i < svr_con_times; i++)
    {
        for(svr_index = 0; svr_index < 2; svr_index++)
        {
            svr_addr_ptr = dtu_config->server[svr_index].svr_addr;
            svr_port_ptr = dtu_config->server[svr_index].svr_port;
            if((0 == *svr_addr_ptr) || (0 == *svr_port_ptr))
            {
                continue;
            }

            if ((strlen(svr_addr_ptr) < 7) || (strlen(svr_addr_ptr) > 15))
            {
                syslog(LOG_ERR,  "Resolve Server Domain:%.15s (%d).", svr_addr_ptr, i + 1);
            }

            ip = 0;
            if (domain_to_ip(svr_addr_ptr, &ip) < 0)
            {
                syslog(LOG_ERR, "Can't Resolver Server Domain:%.15s (%d)\n" , svr_addr_ptr, errno);
            }

            memset(server_ip, 0, sizeof(server_ip));
            inet_ntop(AF_INET, &ip, server_ip, sizeof(server_ip));

			if(nvram_match("ipoc_mqtt_mode", "1"))
			{
				dtu_config->protocol = DTU_SOCKET_TCP;
			}

			if (DTU_SOCKET_UDP == dtu_config->protocol)
            {
                syslog(LOG_INFO,  "UDP Connect the (%s:%s) %d.", server_ip, svr_port_ptr, i+1 );
                sock_fd = connect_udp_host(ip , atoi(svr_port_ptr), atoi(dtu_config->local.svr_port));
                if (sock_fd < 0)
                {
                    syslog(LOG_ERR,  "UDP Failed to connect(%s:%s)", server_ip, svr_port_ptr);
                    sleep(svr_con_itv);
                    continue;
                }
                else
                {
                    syslog(LOG_INFO,  "UDP Succeed to connect(%s:%s)", server_ip, svr_port_ptr );
                    return (sock_fd);
                }
            }
            else
            {
                syslog(LOG_INFO,  "TCP connect the (%s:%s) %d.", server_ip, svr_port_ptr, i+1 );
                sock_fd = connect_tcp_host(ip, atoi(svr_port_ptr), svr_con_timeout);
                if (sock_fd < 0)
                {
                    syslog(LOG_ERR,  "TCP Failed to connect(%s:%s)", server_ip, svr_port_ptr );
                    sleep( svr_con_itv );
                    continue;
                }
                else
                {
                    syslog(LOG_INFO,  "TCP Succeed to connect(%s:%s)", server_ip, svr_port_ptr );
                    return (sock_fd);
                }
            }
		
        }
    }

    return (-1);
}

static int connect2_server(DTU_CONFIG_T *dtu_config)
{
    int	i, svr_index = 1;
    int	sock_fd = -1;
    int  ip = 0;
    char server_ip[16+1] = {0};
    char *svr_addr_ptr = dtu_config->server[svr_index].svr_addr;
    char *svr_port_ptr = dtu_config->server[svr_index].svr_port;
    int svr_con_times = dtu_config->server[0].svr_connect_times;
    int svr_con_itv = dtu_config->server[0].svr_connect_interval;
    int svr_con_timeout = dtu_config->server[0].svr_connect_timeout ;

    if((0 == *svr_addr_ptr) || (0 == *svr_port_ptr))
    {
        return (-1);
    }

    for(i = 0; i < svr_con_times; i++)
    {   
            svr_addr_ptr = dtu_config->server[svr_index].svr_addr;
            svr_port_ptr = dtu_config->server[svr_index].svr_port;
            if((0 == *svr_addr_ptr) || (0 == *svr_port_ptr))
            {
                continue;
            }

            if ((strlen(svr_addr_ptr) < 7) || (strlen(svr_addr_ptr) > 15))
            {
                syslog(LOG_ERR,  "Resolve Server Domain:%.15s (%d).", svr_addr_ptr, i + 1);
            }

            ip = 0;
            if (domain_to_ip(svr_addr_ptr, &ip) < 0)
            {
                syslog(LOG_ERR, "Can't Resolver Server Domain:%.15s (%d)\n" , svr_addr_ptr, errno);
            }

            memset(server_ip, 0, sizeof(server_ip));
            inet_ntop(AF_INET, &ip, server_ip, sizeof(server_ip));

            if (DTU_SOCKET_UDP == dtu_config->protocol)
            {
                syslog(LOG_ERR,  "UDP Connect the (%s:%s) %d.", server_ip, svr_port_ptr, i+1 );
                sock_fd = connect_udp_host(ip , atoi(svr_port_ptr), atoi(dtu_config->local.svr_port));
                if (sock_fd < 0)
                {
                    syslog(LOG_ERR,  "UDP Failed to connect(%s:%s)", server_ip, svr_port_ptr);
                    sleep(svr_con_itv);
                    continue;
                }
                else
                {
                    syslog(LOG_ERR,  "UDP Succeed to connect(%s:%s)", server_ip, svr_port_ptr );
                    return (sock_fd);
                }
            }
            else
            {
                syslog(LOG_ERR,  "TCP connect the (%s:%s) %d.", server_ip, svr_port_ptr, i+1 );
                sock_fd = connect_tcp_host(ip, atoi(svr_port_ptr), svr_con_timeout);
                if (sock_fd < 0)
                {
                    syslog(LOG_ERR,  "TCP Failed to connect(%s:%s)", server_ip, svr_port_ptr );
                    sleep( svr_con_itv );
                    continue;
                }
                else
                {
                    syslog(LOG_ERR,  "TCP Succeed to connect(%s:%s)", server_ip, svr_port_ptr );
                    return (sock_fd);
                }
            }
    }

    return (-1);
}


static int double_connect_multi_server(DTU_CONFIG_T *dtu_config,int *socketFd)
{
    int	i, svr_index = 0;
    int	sock_fd = -1;
    int  ip = 0;
    char server_ip[16+1] = {0};
    char *svr_addr_ptr = dtu_config->server[svr_index].svr_addr;
    char *svr_port_ptr = dtu_config->server[svr_index].svr_port;
    int svr_con_times = dtu_config->server[svr_index].svr_connect_times;
    int svr_con_itv = dtu_config->server[svr_index].svr_connect_interval;
    int svr_con_timeout = dtu_config->server[svr_index].svr_connect_timeout ;

    if((0 == *svr_addr_ptr) || (0 == *svr_port_ptr))
    {
        return (-1);
    }

    for(i = 0; i < svr_con_times; i++)
    {
        for(svr_index = 0; svr_index < 2; svr_index++)
        {
            svr_addr_ptr = dtu_config->server[svr_index].svr_addr;
            svr_port_ptr = dtu_config->server[svr_index].svr_port;
            if((0 == *svr_addr_ptr) || (0 == *svr_port_ptr))
            {
                continue;
            }

            if ((strlen(svr_addr_ptr) < 7) || (strlen(svr_addr_ptr) > 15))
            {
                syslog(LOG_ERR,  "Resolve Server Domain:%.15s (%d).", svr_addr_ptr, i + 1);
            }

            ip = 0;
            if (domain_to_ip(svr_addr_ptr, &ip) < 0)
            {
                syslog(LOG_ERR, "Can't Resolver Server Domain:%.15s (%d)\n" , svr_addr_ptr, errno);
            }

            memset(server_ip, 0, sizeof(server_ip));
            inet_ntop(AF_INET, &ip, server_ip, sizeof(server_ip));

            if (DTU_SOCKET_UDP == dtu_config->protocol)
            {
                syslog(LOG_ERR,  "UDP Connect the (%s:%s) %d.", server_ip, svr_port_ptr, i+1 );
                sock_fd = connect_udp_host(ip , atoi(svr_port_ptr), atoi(dtu_config->local.svr_port));
                if (sock_fd < 0)
                {
                    syslog(LOG_ERR,  "UDP Failed to connect(%s:%s)", server_ip, svr_port_ptr);
                    sleep(svr_con_itv);
                    continue;
                }
                else
                {
                    syslog(LOG_ERR,  "UDP Succeed to connect(%s:%s)", server_ip, svr_port_ptr );
                    socketFd[svr_index] = sock_fd;
                }
            }
            else
            {
                syslog(LOG_ERR,  "TCP connect the (%s:%s) %d.", server_ip, svr_port_ptr, i+1 );
                sock_fd = connect_tcp_host(ip, atoi(svr_port_ptr), svr_con_timeout);
                if (sock_fd < 0)
                {
                    syslog(LOG_ERR,  "TCP Failed to connect(%s:%s)", server_ip, svr_port_ptr );
                    sleep( svr_con_itv );
                    continue;
                }
                else
                {
                    syslog(LOG_ERR,  "TCP Succeed to connect(%s:%s)", server_ip, svr_port_ptr );
                    socketFd[svr_index] = sock_fd;
                }
            }
        }

        return 0;
    }

    return (-1);
}





/* Cyclequeue function  .... */

int init_queue(CIRCLEQUEUE_T **queue, int size)
{
    CIRCLEQUEUE_T *tmp;

    tmp = (CIRCLEQUEUE_T *)malloc(sizeof(CIRCLEQUEUE_T));
    if (tmp == NULL)
    {
        return -1;
    }

    tmp->data = (char *)malloc(size * sizeof(char));
    if (tmp->data == NULL)
    {
        free(tmp);
        return -1;
    }

    tmp->rear = 0;
    tmp->front = 0;
    tmp->count = 0;
    tmp->maxItem = size;
    *queue = tmp;
    return 0;
}


int is_queue_empty(CIRCLEQUEUE_T *queue)
{
    if(queue->count == 0)
        return 1;
    else
        return 0;
}


int is_queue_full(CIRCLEQUEUE_T *queue)
{
    if(queue->count == queue->maxItem)
        return 1;
    else
        return 0;
}


int en_queue(CIRCLEQUEUE_T *queue, char *inBuf, int inLen)
{
    if(queue->count == queue->maxItem)
    {
        return 0;
    }

    if (queue->maxItem - queue->count >= inLen)
    {
        // enough space to save inbuf data
        if (queue->maxItem - queue->rear >= inLen)
        {
            memcpy(&queue->data[queue->rear], inBuf, inLen);
        }
        else
        {
            syslog(LOG_INFO, "rear = %d, front = %d, count = %d, inLen = %d", queue->rear, queue->front, queue->count, inLen);
            memcpy(&queue->data[queue->rear], inBuf, queue->maxItem - queue->rear);
            memcpy(queue->data, inBuf + (queue->maxItem - queue->rear), inLen - (queue->maxItem - queue->rear));
        }


        queue->rear = (queue->rear + inLen) % queue->maxItem;
        queue->count += inLen;
    }
    else
    {
        // not enough space to save inbuf data
        if (queue->rear > queue->front)
        {
            memcpy(&queue->data[queue->rear], inBuf, queue->maxItem - queue->rear);
            if (queue->front > 0)
            {
                memcpy(queue->data, inBuf + (queue->maxItem - queue->rear), queue->front - (queue->maxItem - queue->rear));
            }

            queue->rear = (queue->rear + (queue->maxItem - queue->count)) % queue->maxItem;
            queue->count = queue->maxItem;
        }
        else
        {
            memcpy(&queue->data[queue->rear], inBuf, queue->front - queue->rear);
            queue->rear = (queue->rear + (queue->front - queue->rear)) % queue->maxItem;
            queue->count = queue->maxItem;
        }
    }


    return 0;
}


int de_queue_start(CIRCLEQUEUE_T *queue, char *outBuf, int outLen)
{
    if(queue->count == 0)
    {
        return 0;
    }

    if (queue->count >= outLen)
    {
        if (queue->front < queue->rear)
        {
            memcpy(outBuf, &queue->data[queue->front], outLen);
        }
        else
        {
            int len = queue->maxItem - queue->front;
            if (len >= outLen)
            {
                memcpy(outBuf, &queue->data[queue->front], outLen);
            }
            else
            {
                memcpy(outBuf, &queue->data[queue->front], len);
                memcpy(outBuf + len, queue->data, outLen - len);
            }

        }
        return outLen;
    }
    else
    {
        if (queue->front < queue->rear)
        {
            memcpy(outBuf, &queue->data[queue->front], queue->count);
        }
        else
        {
            memcpy(outBuf, &queue->data[queue->front], queue->maxItem - queue->front);
            if (queue->rear > 0)
            {
                memcpy(outBuf + queue->maxItem - queue->front, queue->data, queue->rear);
            }
        }

        return queue->count;
    }


}

int de_queue_done(CIRCLEQUEUE_T *queue, int outLen)
{
    queue->front = (queue->front + outLen) % queue->maxItem;
    queue->count -= outLen;
    return 0;
}


int show_queue_element(CIRCLEQUEUE_T *queue)
{
    int index = 0;
    char str[8192];

    if (strcmp(nvram_safe_get("dtu_debug"), "en") == 0)
    {
        memset(str, 0, sizeof(str));
        while (index < queue->count)
        {
            str[index] = queue->data[(queue->front + index) % queue->maxItem];
            index++;
        }

        syslog(LOG_INFO, "BUF:[%s]", str);
    }
    return 0;
}

int clear_queue(CIRCLEQUEUE_T *queue)
{
    queue->front = queue->rear = 0;
    queue->count = 0;
    return 0;
}

int destroy_queue(CIRCLEQUEUE_T **queue)
{
    (*queue)->front = (*queue)->rear = 0;
    (*queue)->count = 0;

    free((*queue)->data);
    free(*queue);
    return 0;
}

int get_queue_length(CIRCLEQUEUE_T *queue)
{
    return queue->count;
}

int get_queue_empty_length(CIRCLEQUEUE_T *queue)
{
    return queue->maxItem - queue->count;
}


/* IO Function .... */


static int write_socket_nb(int fd, char* buf, int len, int msec, DTU_CONFIG_T *dtuConf)
{
    int nwrite = 0;
    char* data = buf;
    int ret = -1;
    int n;

    while (nwrite < len + dtuConf->nb_router_id_len)
    {
        char buff[1500] = {0};

        memcpy(buff, dtuConf->nb_router_id, dtuConf->nb_router_id_len);
        memcpy(buff + dtuConf->nb_router_id_len, data, len);

        if (msec > 0)
        {
            ret = wait_wsock(fd, 0, msec * 1000);
            if (-1 == ret)
            {
                return -2;
            }
            else if (0 == ret)
            {
                break;
            }
        }

        if ((DTU_SOCKET_UDP == dtuConf->protocol) && (DTU_MODE_SERVER == dtuConf->mode))
        {
            if ( m_udp_recv_addr.sin_addr.s_addr == 0 )
            {
                n = len + dtuConf->nb_router_id_len - nwrite ;
            }
            else
            {
                n = sendto(fd , buff + nwrite, len + dtuConf->nb_router_id_len - nwrite, 0, (struct sockaddr *)&m_udp_recv_addr, sizeof(struct sockaddr_in));
                if(n < 0)
                {
                    syslog(LOG_ERR, "UDP: Send Error");
                }
            }

        }
        else
        {
            n = write(fd, buff + nwrite, len + dtuConf->nb_router_id_len - nwrite);
        }

        if (n < 0)
        {
            if (errno != EWOULDBLOCK)
            {
                syslog(LOG_ERR, "Socket write(%p,%d)", data + nwrite, len + dtuConf->nb_router_id_len - nwrite);
                return (-1);
            }
            break;
        }
        else
        {
            nwrite += n;
        }

        if ((nwrite == len + dtuConf->nb_router_id_len) || (0 == msec))
        {
            break;
        }
    }


    return (nwrite - dtuConf->nb_router_id_len);

}

static int get_index_by_fd(int fd)
{
    int index;

    for (index = 0; index < MAX_SVR_CENTER; index++)
    {
        if (fd == m_newbei_multsvr_socketFd[index])
        {
            return index;
        }
    }

    return -1;
}

static int read_socket_nb(int fd, char* buf, int len, int msec, DTU_CONFIG_T *dtuConf)
{
    int nread = 0;
    char *data = buf;
    int ret = -1;
    int n;

    while (nread < len)
    {
        if (msec > 0)
        {
            ret = wait_rsock(fd, 0, msec * 1000);
            if (-1 == ret)
            {
                return -2;
            }
            else if (0 == ret)
            {
                break;
            }
        }

        if ((DTU_SOCKET_UDP == dtuConf->protocol) && (DTU_MODE_SERVER == dtuConf->mode))
        {
            m_recv_addr_len = sizeof(struct sockaddr_in);
            n = recvfrom(fd, data + nread, len - nread, 0, (struct sockaddr *)&m_udp_recv_addr, &m_recv_addr_len);
        }
        else
        {
            n = read(fd, data + nread, len - nread);
        }

        if (n < 0)
        {
            if (errno != EWOULDBLOCK)
            {
                syslog(LOG_ERR, "Socket read(%p,%d)", data + nread, len - nread);
                return -1;
            }
            break;
        }
        else if (0 == n)
        {
            syslog(LOG_INFO, "Socket read(%p,%d) be Closed", data + nread, len - nread);
            return -1;
        }
        else
        {
            char iocmd[6] = {0xdb, 0xbd, 0x02, 0x03, 0x00};
            char *str = memmem(data + nread, n, iocmd, 5);
            if (str != NULL)
            {
                syslog(LOG_INFO, "Get IOCMD(0xDB, 0xBD, 0x02, 0x03, 0x00), and req IO Output High");
                if (n == sizeof(iocmd) - 1 || (n - (str - (data + nread)) == sizeof(iocmd) - 1))
                {
                    /* 0xDB, 0xBD, 0x02, 0x03, 0x00*/ /* 0x01 0x31 0xDB, 0xBD, 0x02, 0x03, 0x00*/
                    memset(str, 0, 5);
                }
                else
                {
                    /* 0x01, 0x30, 0x31, 0xdb, 0xbd, 0x02, 0x03, 0x00, 0x01, 0x30*/
                    memmove(str, str + 5, n - sizeof(iocmd) + 1 - (str - (data + nread)));
                    memset(str + n - sizeof(iocmd) + 1 - (str - (data + nread)), 0, sizeof(iocmd) - 1);
                }
                char num[12] = "13800138000";

                send_to_gpctl(m_pl2303_com_sockfd, iocmd, sizeof(iocmd) - 1, num, strlen(num));
                n -= 5;
            }
            else
            {
                char ht_resp[2] = {0x00};
                str = memmem(data + nread, n, ht_resp, 1);
                if (str != NULL && n == sizeof(ht_resp) - 1)
                {
                    n -= 1;
                }
            }

            *(data + nread + n) = '\0';
            syslog(LOG_INFO,  "Read: Socket read(%s,%d)", data + nread, n);
            int index = get_index_by_fd(fd);
            if (index > 0)
                m_recv_flag[index] = 0;

            nread += n;
        }

        if (nread == len || 0 == msec)
        {
            break;
        }
    }


    return nread;
}

static int write_serial_nb(int fd, char *buf, ssize_t len, int msec, DTU_CONFIG_T *dtuConf)
{
    int nwrite = 0;
    char* data = buf;
    int ret = -1;
    int n;
    char buff[1500] = {0};
    int orig_len = len;

    if (dtuConf->prefix_type == NB_RELLAY_ADD_PREFIX)
    {
        memcpy(buff, dtuConf->prefix_content, dtuConf->prefix_content_len);
        memcpy(buff + dtuConf->prefix_content_len, buf, len);
        len += dtuConf->prefix_content_len;
        data = buff;
    }
    else if (dtuConf->prefix_type == NB_RELLAY_DEL_PREFIX)
    {
        if (len > dtuConf->del_prefix_index)
        {
            data += dtuConf->del_prefix_index;
            len -= dtuConf->del_prefix_index;
        }
    }
    else
    {
        //hongkong custom
        if (buf[0] == 0x01)
        {
            data += 1;
            len -= 1;
        }
    }

    while (nwrite < len)
    {
        if (msec > 0)
        {
            ret = wait_wsock(fd, 0, msec * 1000);
            if (-1 == ret)
            {
                return -2;
            }
            else if (0 == ret)
            {
                break;
            }
        }

        n = write(fd, data + nwrite, len - nwrite);
        if (n < 0)
        {
            if (errno != EWOULDBLOCK)
            {
                syslog(LOG_ERR, "Write(%p,%d) error", data + nwrite, len - nwrite);
                return (-1);
            }
            break;
        }
        else
        {
            nwrite += n;
        }
        if (nwrite == len || n > 0)
        {
            break;
        }
    }



    if (dtuConf->prefix_type == NB_RELLAY_DEL_PREFIX && orig_len <= dtuConf->del_prefix_index)
    {
        return nwrite;
    }
    else if (dtuConf->prefix_type == NB_RELLAY_HONGKONG_CUST)
    {
        if (buf[0] == 0x01)
        {
            syslog(LOG_INFO,  "Write Serial: [%s,%d] --> orig length is [%d]", data, nwrite, orig_len);
            return nwrite + 1;
        }
        else
        {
            return nwrite;
        }
    }
    else
    {
        syslog(LOG_INFO,  "Write Serial: [%s,%d] --> orig length is [%d]", data, nwrite, (dtuConf->prefix_type == NB_RELLAY_ADD_PREFIX) ?
               nwrite - strlen(dtuConf->prefix_content) :
               nwrite + dtuConf->del_prefix_index);
        return (dtuConf->prefix_type == NB_RELLAY_ADD_PREFIX) ?
               nwrite - strlen(dtuConf->prefix_content) :
               nwrite + dtuConf->del_prefix_index;
    }
}

static int write_timeout(int fd, char *buf, ssize_t len, int msec)
{
    int nwrite = 0;
    char *data = buf;
    int ret = -1;
    int n;

    while (nwrite < len)
    {
        if (msec > 0)
        {
            ret = wait_wsock(fd, 0, msec * 1000);
            if (-1 == ret)
            {
                return -2;
            }
            else if (0 == ret)
            {
                break;
            }
        }

        n = write(fd, data + nwrite, len - nwrite);
        if (n < 0)
        {
            if (errno != EWOULDBLOCK)
            {
                syslog(LOG_ERR,  "Serial Write(%p,%d) error", data + nwrite, len - nwrite);
                return (-1);
            }
            break;
        }
        else
        {
            nwrite += n;
        }

        if (nwrite == len || n > 0)
        {
            break;
        }
    }


    return nwrite;
}


static int read_timeout( int fd, char* buf, int len, int msec)
{
    int nread = 0;
    int ret = -1;
    char* data = buf;
    int n;


    while (nread < len)
    {
        if (msec > 0)
        {
            ret = wait_rsock(fd, 0, msec * 1000);
            if (-1 == ret)
            {
                return -2;
            }
            else if (0 == ret)
            {
                break;
            }
        }

        n = read(fd, data + nread, len - nread);
        if (n < 0)
        {
			syslog(LOG_ERR, "Error code: %d", errno);
            if (errno != EWOULDBLOCK)
            {
                syslog(LOG_ERR,  "Error: Serial Read(%p,%d)", data + nread, len - nread);
                return (-1);
            }
            break;
        }
        else if (0 == n)
        {
			syslog(LOG_ERR,  "Serial Read(%p,%d) be Closed", data + nread, len - nread);
            return (-1);
        }
        else
        {
            nread += n;
        }

        if (nread == len || 0 == msec)
        {
            break;
        }
    }


    return nread;
}



static int socket_read_udp_svr(int fd, char* buf, int len, int msec)
{
    int nread = 0;
    char* data = buf;
    int ret = -1;
    int n;

    while (nread < len)
    {
        if (msec > 0)
        {
            ret = wait_rsock(fd, 0, msec * 1000);
            if (-1 == ret)
            {
                return -2;
            }
            else if (0 == ret)
            {
                break;
            }
        }

        m_recv_addr_len = sizeof(struct sockaddr_in);
        n = recvfrom(fd, data + nread, len - nread, 0, (struct sockaddr *)&m_udp_recv_addr, &m_recv_addr_len);
        if (n < 0)
        {
            if (errno != EWOULDBLOCK)
            {
                syslog(LOG_ERR,  "Socket read(%p,%d)", data + nread, len - nread);
                return (-1);
            }
            break;
        }
        else if (0 == n)
        {
            syslog(LOG_INFO, "Warning : Socket read(%p,%d) be Closed", data + nread, len - nread);
            return (-1);
        }
        else
        {
            nread += n;
        }

        if (nread == len || 0 == msec)
            break;

    }


    return (nread);
}



static int socket_write_udp_svr(int fd, char* buf, int len, int msec)
{
    int nwrite = 0;
    char* data = buf;
    int ret = -1;
    int n;


    while (nwrite < len)
    {
        if (msec > 0)
        {
            ret = wait_wsock(fd, 0, msec * 1000);
            if (-1 == ret)
            {
                return -2;
            }
            else if (0 == ret)
            {
                break;
            }
        }

        if (m_udp_recv_addr.sin_addr.s_addr == 0)
        {
            n = len - nwrite ;
        }
        else
        {
            n = sendto(fd , data + nwrite, len - nwrite, 0, (struct sockaddr *)&m_udp_recv_addr, sizeof(struct sockaddr_in));
        }

        if (n < 0)
        {
            if (errno != EWOULDBLOCK)
            {
                syslog(LOG_ERR,  "Error: Socket write(%p,%d)", data + nwrite, len - nwrite);
                return (-1);
            }
            break;
        }
        else
        {
            nwrite += n;
        }

        if (nwrite == len || 0 == msec)
            break;
    }


    return nwrite;
}


static int get_max_fd(int *socketFd)
{
    int i;
    int max;

    max = socketFd[0];
    for (i = 1; i < MAX_SVR_CENTER; i++)
    {
        if (socketFd[i] > max)
        {
            max = socketFd[i];
        }
    }

    return max;
}



int relay_process(int serialFd, DTU_CONFIG_T *dtuConfig, SERIAL_CONFIG_T *serConf, MQTT_CONFIG_T *mqttConf)
{
#define RELAY_CMD_LEN 9
    unsigned char set_all_off_cmd[ ] = {0xcc, 0xdd, 0xa0, 0x00, 0x00, 0x00, 0x0d, 0xad, 0x5a};
    unsigned char set_2on1off_cmd[ ] = {0xcc, 0xdd, 0xa0, 0x00, 0x01, 0x00, 0x0d, 0xae, 0x5c};
    unsigned char set_2off1on_cmd[ ] = {0xcc, 0xdd, 0xa0, 0x00, 0x02, 0x00, 0x0d, 0xaf, 0x5e};
    unsigned char set_all_on_cmd[ ] = {0xcc, 0xdd, 0xa0, 0x00, 0x03, 0x00, 0x0d, 0xb0, 0x60};
    unsigned char read_status_cmd[ ] = {0xcc, 0xdd, 0xb0, 0x00, 0x00, 0x00, 0x0d, 0xbd, 0x7a};
    char * relay_cmd1 = NULL;
    char * relay_cmd2 = NULL;
    unsigned char relay_buf[9] = {0};
    char *relay_status1 = NULL;
    char *relay_status2 = NULL;
    char relay_set_len = 0;
    int relay_flag = 0;

    while (serialFd > 0)
    {
        memset(relay_buf, 0, 9);
        if (9 == write_timeout(serialFd, read_status_cmd, 9, 1000))
        {
            if(9 == read_timeout(serialFd, relay_buf, 9, 2000))
            {
                syslog(LOG_NOTICE, "[Serial App]-->: serial_read_relay_status:%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x",
                       relay_buf[0], relay_buf[1], relay_buf[2], relay_buf[3], relay_buf[4], relay_buf[5], relay_buf[6], relay_buf[7], relay_buf[8]);
                if (relay_buf[0] == 0xAA && relay_buf[1] == 0xBB)
                {
                    if (relay_buf[5] == 0x00)
                    {
                        nvram_set("relay_status_1", "0");
                        nvram_set("relay_status_2", "0");
                    }
                    else if (relay_buf[5] == 0x01)
                    {
                        nvram_set("relay_status_1", "1");
                        nvram_set("relay_status_2", "0");
                    }
                    else if (relay_buf[5] == 0x02)
                    {
                        nvram_set("relay_status_1", "0");
                        nvram_set("relay_status_2", "1");
                    }
                    else if (relay_buf[5] == 0x03)
                    {
                        nvram_set("relay_status_1", "1");
                        nvram_set("relay_status_2", "1");
                    }
                }
            }
        }

        if (((relay_status1 = nvram_safe_get("relay_status_1")) && (*relay_status1 == 0))
                || ((relay_status2 = nvram_safe_get("relay_status_2")) && (*relay_status2 == 0)))
        {
            sleep(2);
            continue;
        }

        relay_flag = 0;
        if ((relay_cmd1 = nvram_safe_get("relay_cmd_1")) && (*relay_cmd1 == 0))
        {
            relay_flag++;
            relay_cmd1 = relay_status1;
        }
        if ((relay_cmd2 = nvram_safe_get("relay_cmd_2")) && (*relay_cmd2 == 0))
        {
            relay_flag++;
            relay_cmd2 = relay_status2;
        }
        if (relay_flag == 2)
        {
            sleep(2);
            continue;
        }

        if (*relay_cmd1 == '0' && *relay_cmd2 == '0' )
        {
            relay_set_len = write_timeout(serialFd, set_all_off_cmd, 9, 1000);
        }
        else if (*relay_cmd1 == '1' && *relay_cmd2 == '1' )
        {
            relay_set_len = write_timeout(serialFd, set_all_on_cmd, 9, 1000);
        }
        else if (*relay_cmd1 == '0' && *relay_cmd2 == '1' )
        {
            relay_set_len = write_timeout(serialFd, set_2off1on_cmd, 9, 1000);
        }
        else if (*relay_cmd1 == '1' && *relay_cmd2 == '0' )
        {
            relay_set_len = write_timeout(serialFd, set_2on1off_cmd, 9, 1000);
        }

        memset(relay_buf, 0, 9);

        if (9 == relay_set_len)
        {

            if(9 == read_timeout(serialFd, relay_buf, 9, 2000))
            {

                if ((relay_buf[0] == 0x4f) && (relay_buf[1] == 0x4b) && (relay_buf[2] == 0x21))
                {
                    nvram_unset("relay_cmd_1");
                    nvram_unset("relay_cmd_2");
                }
            }
        }
    }

    return 0;
}

int read_durty_data(int fd)
{
    char buf[1024] = {0};
    int ret = 0;

    syslog(LOG_INFO, "get durty data: start ... ");
    while ((ret = read_timeout(fd, buf, sizeof(buf) - 1, 100)) > 0 && ret == (sizeof(buf) - 1))
    {
        syslog(LOG_INFO, "get durty data: %d, %s", ret, buf);
    }
    syslog(LOG_INFO, "get durty data: end ... ret = %d", ret);

	return ret;
}

void gps_data_to_web(void)
{
	if (is_valid)
        {
            char* p = NULL;
            double fl, gl;
            unsigned int i;
            char google_gps_lat[16] = {0};
            char google_gps_lon[16] = {0};
            char google_map[32] = {0};
            nvram_set("gps_valid", "OK");
            nvram_set("gps_use", gps_use);
            nvram_set("gps_date", gps_date);
            nvram_set("gps_time", gps_time);
            nvram_set("gps_latitude", gps_latitude);
            nvram_set("gps_NS", gps_NS);
            nvram_set("gps_longitude", gps_longitude);
            nvram_set("gps_EW", gps_EW);
            nvram_set("gps_speed", gps_speed);
            nvram_set("gps_degrees", gps_degrees);
            nvram_set("gps_FS", gps_FS);
            nvram_set("gps_HDOP", gps_HDOP);
            nvram_set("gps_MSL", gps_MSL);
            if (0 == GP_BD)
                nvram_set("gps_bds", "GPS");
            else if (1 == GP_BD)
                nvram_set("gps_bds", "BDS");
            else
                nvram_set("gps_bds", "GPS/BDS");

            p = strchr(gps_latitude, '.');
            if (p)
            {
                fl = atof(gps_latitude);
                i = (unsigned int)fl/100;
                gl = i + (fl - (unsigned int)(fl/100)*100)/60.0;
                //gl = pixelToLat((unsigned int)(latToPixel(gl, 18)+1193), 18);
                sprintf(google_gps_lat, "%s%.6f",(strchr(gps_NS, 'N'))?"+":"-",  gl);

                syslog(LOG_NOTICE, "########latitude<%s>", google_gps_lat);
            }
            p = strchr(gps_longitude, '.');
            if (p)
            {
                fl = atof(gps_longitude);
                i = (unsigned int)fl/100;
                gl = i + (fl - (unsigned int)(fl/100)*100)/60.0;
                //gl = pixelToLng((unsigned int)(lngToPixel(gl, 18)-270), 18);
                sprintf(google_gps_lon, "%s%.6f",(strchr(gps_EW, 'E'))?"+":"-", gl);

                syslog(LOG_NOTICE, "########longitude<%s>", google_gps_lon);
            }
            sprintf(google_map, "%s,%s", google_gps_lat, google_gps_lon);
            nvram_set("google_map", google_map);
        }
        else
        {
            nvram_set("gps_valid", "N/A");
            nvram_set("gps_use", gps_use);
            nvram_set("gps_date", gps_date);
            nvram_set("gps_time", gps_time);
        }
	
	
}

int send_serial_data(int serialFd, int sockFd, DTU_CONFIG_T *dtuConf)
{
    int ret = -1, n;
    int maxfd = -1;
    fd_set rset, wset;
    struct timeval tv;
    CIRCLEQUEUE_T *serial_buf_queue = NULL;
    char *dataBuf;

    dataBuf = (char *)malloc(dtuConf->data.max_len * sizeof(char));
    if (dataBuf == NULL)
    {
        goto err_quit;
    }

    ret = init_queue(&serial_buf_queue, MAX_CIRCLE_QUEUE_SIZE);
    if (ret < 0)
    {
        goto err_quit;
    }


    maxfd = serialFd > sockFd ? serialFd : sockFd;
    syslog(LOG_INFO, "Serial APP: switch_data");
    (void)read_durty_data(serialFd);
    while (1)
    {
        FD_ZERO(&rset);
        FD_ZERO(&wset);

        FD_SET(serialFd, &rset);
        FD_SET(sockFd, &rset);

        if (is_queue_empty(serial_buf_queue) == 0)
        {
            FD_SET(sockFd, &wset);
        }


        tv.tv_sec = dtuConf->heartbeat.heartbeat_interval;
        tv.tv_usec = 0;

        ret = select(maxfd + 1, &rset, &wset, NULL, &tv);
        if (ret < 0)
        {
            if (errno != EINTR && errno != EAGAIN)
            {
                syslog(LOG_ERR,  "Error : Select Error( return:%d errno:%d )", ret , errno );
                goto err_quit;
            }
        }
        else if (ret == 0)
        {
            if (is_queue_empty(serial_buf_queue) == 1)
            {
                en_queue(serial_buf_queue, dtuConf->heartbeat.content, strlen(dtuConf->heartbeat.content));
            }
        }

        if (FD_ISSET(sockFd, &wset))
        {
            if (is_queue_empty(serial_buf_queue) == 0)
            {
                //not empty
                memset(dataBuf, 0, dtuConf->data.max_len);
                n = de_queue_start(serial_buf_queue, dataBuf, dtuConf->data.max_len);
                if (dtuConf->mode == DTU_MODE_SERVER && dtuConf->protocol == DTU_SOCKET_UDP)
                {
                    n = socket_write_udp_svr(sockFd, dataBuf, n, 0);
                    if (n < 0)
                    {
                        break;
                    }
                }
                else
                {
                    n = write_timeout(sockFd, dataBuf, n, 0);
                    if (n < 0)
                    {
                        break;
                    }
                }
		gps_process(dataBuf, n);
		gps_data_to_web();
                if(sys_time_flag == 1 && is_valid == 1 && nvram_match("gps_clock","1"))
                {
                    char time_buf[64];
                    char date_buf[16];
                    char result_buf[64];
                    int len;
                    int k = 0,j = 0;
                    int m = 0,n = 0;
                    memset(time_buf,0,sizeof(time_buf));
                    memset(date_buf,0,sizeof(date_buf));
                    memset(result_buf,0,sizeof(result_buf));
                    len = strlen(gps_time);
                    while(j < len)
                    {
                        if(*(gps_time+j) == '.')
                        {
                            break;
                        }
                        if((k + 1)%3 == 0)
                        {
                            time_buf[k++] = ':';
                            continue;
                        }
                        time_buf[k++] = *(gps_time+j);
                        j++;
                    }
                    len = strlen(gps_date);
                    while(m < len)
                    {
                        if((n + 1)%3 == 0)
                        {
                            date_buf[n++] = '-';
                            continue;
                        }
                        date_buf[n++] = *(gps_date+m);
                        m++;
                    }
                    sprintf(result_buf,"date '20%s %s'",date_buf,time_buf);
                    syslog(LOG_INFO,"the time is :%s",result_buf);
                    system(result_buf);
                    sys_time_flag = 0;
                }
                de_queue_done(serial_buf_queue, n);
            }
        }

	if (FD_ISSET(sockFd, &rset))
	{
			if (dtuConf->mode == DTU_MODE_SERVER && dtuConf->protocol == DTU_SOCKET_UDP)
			{
				n = socket_read_udp_svr(sockFd, dataBuf, sizeof(dataBuf), dtuConf->data.timeout);
				if (n < 0)
				{
					break;
				}
			}
			else
			{
				n = read_timeout(sockFd, dataBuf, sizeof(dataBuf), dtuConf->data.timeout);
				if (n < 0)
				{
					break;
				}
			}
			
	}

        if (FD_ISSET(serialFd, &rset))
        {
            if (is_queue_full(serial_buf_queue) == 0)
            {
                memset(dataBuf, 0, dtuConf->data.max_len);

                n = get_queue_empty_length(serial_buf_queue);
                int req_len = dtuConf->data.max_len > n ? n : dtuConf->data.max_len;
                n = read_timeout(serialFd, dataBuf, req_len, dtuConf->data.serial_timeout);
                if (n < 0)
                {
                    break;
                }
                en_queue(serial_buf_queue, dataBuf, n);
                show_queue_element(serial_buf_queue);
            }
        }
    }

err_quit:
    if (serial_buf_queue != NULL)
    {
        destroy_queue(&serial_buf_queue);
    }

    if (dataBuf != NULL)
    {
        free(dataBuf);
    }

    if (serialFd > 0)
    {
        close(serialFd);
    }

    if (sockFd > 0)
    {
        close(sockFd);
    }

    return (ret);
}

int double_send_serial_data(int serialFd, int *sockFd, DTU_CONFIG_T *dtuConf)
{
    int ret = -1, n,i;
    int maxfd = -1;
    fd_set rset, wset;
    struct timeval tv;
    CIRCLEQUEUE_T *serial_buf_queue[MAX_SVR_CENTER];
    char *dataBuf;

    dataBuf = (char *)malloc(dtuConf->data.max_len * sizeof(char));
    if (dataBuf == NULL)
    {
        goto err_quit;
    }
    for(i = 0;i < MAX_SVR_CENTER;i++)
    {
        ret = init_queue(&serial_buf_queue[i], MAX_CIRCLE_QUEUE_SIZE);
        if (ret < 0)
        {
            goto err_quit;
        }
    }

    maxfd = get_max_fd(sockFd);
    maxfd = maxfd > serialFd ? maxfd : serialFd;
    syslog(LOG_INFO, "Serial APP: switch_data");
    while (1)
    {
        FD_ZERO(&rset);
        FD_ZERO(&wset);

        FD_SET(serialFd, &rset);
        
        for(i = 0;i < MAX_SVR_CENTER;i++)
        {
            if (is_queue_empty(serial_buf_queue[i]) == 0)
            {              
                if(sockFd[i] > 0)
                {
                    FD_SET(sockFd[i], &wset);
                }
                
            }
        }

        tv.tv_sec = dtuConf->heartbeat.heartbeat_interval;
        tv.tv_usec = 0;

        ret = select(maxfd + 1, &rset, &wset, NULL, &tv);
        if (ret < 0)
        {
            if (errno != EINTR && errno != EAGAIN)
            {
                syslog(LOG_ERR,  "Error : Select Error( return:%d errno:%d )", ret , errno );
                goto err_quit;
            }
        }
        else if (ret == 0)
        {
            for(i = 0;i < MAX_SVR_CENTER;i++)
            {
                if (is_queue_empty(serial_buf_queue[i]) == 1)
                {
                    en_queue(serial_buf_queue[i], dtuConf->heartbeat.content, strlen(dtuConf->heartbeat.content));
                }
            }
        }
        for(i = 0;i < MAX_SVR_CENTER;i++)
        {
            if (sockFd[i] > 0 && FD_ISSET(sockFd[i], &wset))
            {
                if (is_queue_empty(serial_buf_queue[i]) == 0)
                {
                    //not empty
                    memset(dataBuf, 0, dtuConf->data.max_len);
                    n = de_queue_start(serial_buf_queue[i], dataBuf, dtuConf->data.max_len);
                    if (dtuConf->mode == DTU_MODE_SERVER && dtuConf->protocol == DTU_SOCKET_UDP)
                    {
                       
                            n = socket_write_udp_svr(sockFd[i], dataBuf, n, dtuConf->data.timeout);
                            if (n < 0)
                            {
                                goto err_quit;
                            }
                         
                    }
                    else
                    {
                        n = write_timeout(sockFd[i], dataBuf, n, dtuConf->data.timeout);
                        if (n < 0)
                        {
                           goto err_quit;
                        }
                    }
		    
		    gps_process(dataBuf, n);
		    gps_data_to_web();
                    de_queue_done(serial_buf_queue[i], n);
                }
	    }
	    if (sockFd[i] > 0 && FD_ISSET(sockFd[i], &rset))
	    {
			    if (dtuConf->mode == DTU_MODE_SERVER && dtuConf->protocol == DTU_SOCKET_UDP)
			    {
				    n = socket_read_udp_svr(sockFd[i], dataBuf, sizeof(dataBuf), dtuConf->data.timeout);
				    if (n < 0)
				    {
					    goto err_quit;
				    }
			    }
			    else
			    {
				    n = read_timeout(sockFd[i], dataBuf, sizeof(dataBuf), dtuConf->data.timeout);
				    if (n < 0)
				    {
					    goto err_quit;
				    }
			    }
	    
	    }
        }

        if (FD_ISSET(serialFd, &rset))
        {
            memset(dataBuf, 0, dtuConf->data.max_len);

            n = read_timeout(serialFd, dataBuf, dtuConf->data.max_len, dtuConf->data.serial_timeout);
            if (n < 0)
            {
                ret = -1;
                break;
            }
            for(i = 0;i < MAX_SVR_CENTER;i++)
            {
            
                if (is_queue_full(serial_buf_queue[i]) == 0)
                {                 
                    en_queue(serial_buf_queue[i], dataBuf, n);
                    show_queue_element(serial_buf_queue[i]);
                }
            }
        }
    }

err_quit:   
    for(i = 0;i < MAX_SVR_CENTER;i++)
    {
        if (serial_buf_queue[i] != NULL)
        {
            destroy_queue(&serial_buf_queue[i]);
        }
    }
    if (dataBuf != NULL)
    {
        free(dataBuf);
    }

    if (serialFd > 0)
    {
        close(serialFd);
    }
    for(i = 0;i < MAX_SVR_CENTER;i++)
    {
        if (sockFd[i] > 0)
        {
            close(sockFd[i]);
        }
    }
    return ret;
}


int double_gps_nmea_process(int serialFd, DTU_CONFIG_T *dtuConfig, SERIAL_CONFIG_T *serConf, MQTT_CONFIG_T *mqttConf)
{
    //int count = 0;
    int socketFd[MAX_SVR_CENTER];
    int i;

    while (1)
    {

        for(i = 0; i < MAX_SVR_CENTER; i++)
        {
            socketFd[i] = -1;
        }
        if (DTU_MODE_SERVER == dtuConfig->mode)
        {
            syslog(LOG_INFO,  "Serial APP: Client Mode" );
            if (DTU_SOCKET_TCP == dtuConfig->protocol)
            {
                syslog(LOG_INFO,  "TCP Server Mode" );
                if ((socketFd[0] = create_tcp_socket(dtuConfig)) < 0)
                {
                    sleep(5);
                    continue;
                }
            }
            else
            {
                syslog(LOG_INFO, "Serial APP: UDP Server Mode" );
                if ((socketFd[0] = create_udp_socket(dtuConfig)) < 0)
                {
                    sleep(5);
                    continue;
                }
            }
        }
        else
        {
            syslog(LOG_INFO,  "Serial APP: Client Mode" );
            if ((double_connect_multi_server(dtuConfig,socketFd)) < 0)
            {
                sleep(dtuConfig->reconnect_interval);
                continue;
            }
        }

       double_send_serial_data(serialFd, socketFd, dtuConfig); 
        
        struct termios old_term;
        char dev_port[24] = {0};
        int ret;
        
        serialFd = -1;
        
        while (serialFd < 0)
        {
            ret = which_serial(dev_port);
            if(ret < 0)
            {
                serialFd = open_serial(double_gps_nmea_hook.portName, &old_term);
                if (serialFd < 0)
                {
                    syslog(LOG_ERR, "[%s]-->: Open serial %s Failed", double_gps_nmea_hook.name, double_gps_nmea_hook.portName);
                    sleep(1);
                    continue;
                }
            }
            else
            {
                serialFd = open_serial(dev_port, &old_term);
                if (serialFd < 0)
                {
                    syslog(LOG_ERR, "[%s]-->: Open serial %s Failed", double_gps_nmea_hook.name, double_gps_nmea_hook.portName);
                    sleep(1);
                    continue;
                }
            }

            if (init_serial(serialFd, serConf) < 0)
            {
                syslog(LOG_ERR, "[%s]-->: Init serial %s Failed", double_gps_nmea_hook.name, double_gps_nmea_hook.portName);
                close_serial(serialFd, &old_term);
                return (-1);
            }

            syslog(LOG_INFO, "[%s]-->: Open serial %s succ, fd = %d", double_gps_nmea_hook.name, double_gps_nmea_hook.portName, serialFd);
        }
#if 0
            count++;
            sleep(3);
        
        if (count > 3)
            break;
#endif
    }

    return 0;
}

#if 1
int gps_nmea_process(int serialFd, DTU_CONFIG_T *dtuConfig, SERIAL_CONFIG_T *serConf, MQTT_CONFIG_T *mqttConf)
{
//    int count = 0;
    int socketFd;
    struct termios old_term;
    //int  serialFd = -1;
    int Sfd = -1;
    char dev_port[24] = {0};
    int ret;
    while (1)
    {
        if (DTU_MODE_SERVER == dtuConfig->mode)
        {
            syslog(LOG_INFO,  "Serial APP: Server Mode" );
            if (DTU_SOCKET_TCP == dtuConfig->protocol)
            {
                syslog(LOG_INFO,  "TCP Server Mode" );
                if ((socketFd = create_tcp_socket(dtuConfig)) < 0)
                {
                    sleep(5);
                    continue;
                }
            }
            else
            {
                syslog(LOG_INFO, "Serial APP: UDP Server Mode" );
                if ((socketFd = create_udp_socket(dtuConfig)) < 0)
                {
                    sleep(5);
                    continue;
                }
            }
        }
        else
        {
            syslog(LOG_INFO,  "Serial APP: Client Mode" );
            if ((socketFd = connect_server(dtuConfig)) < 0)
            {
                sleep(dtuConfig->reconnect_interval);
                continue;
            }
        }

        while (Sfd < 0)
        {
            ret = which_serial(dev_port);
            if(ret < 0)
            {
                Sfd = open_serial(gps_nmea_hook.portName, &old_term);
                if (Sfd < 0)
                {
                    syslog(LOG_ERR, "[%s]-->: Open serial %s Failed", gps_nmea_hook.name, gps_nmea_hook.portName);
                    sleep(1);
                    continue;
                }
            }
            else
            {
                Sfd = open_serial(dev_port, &old_term);
                if (Sfd < 0)
                {
                    syslog(LOG_ERR, "[%s]-->: Open serial %s Failed", gps_nmea_hook.name, gps_nmea_hook.portName);
                    sleep(1);
                    continue;
                }
            }
            /*serialFd = open_serial(gps_nmea_hook.portName, &old_term);
            if (serialFd < 0)
            {
                syslog(LOG_ERR, "[%s]-->: Open serial %s Failed", gps_nmea_hook.name, gps_nmea_hook.portName);
                return (-1);
            }*/

            if (init_serial(Sfd, serConf) < 0)
            {
                syslog(LOG_ERR, "[%s]-->: Init serial %s Failed", gps_nmea_hook.name, gps_nmea_hook.portName);
                close_serial(Sfd, &old_term);
                return (-1);
            }

            syslog(LOG_INFO, "[%s]-->: Open serial %s succ, fd = %d", gps_nmea_hook.name, gps_nmea_hook.portName, Sfd);
        }
        send_serial_data(Sfd, socketFd, dtuConfig);
        
        Sfd = -1;
        socketFd = -1;
#if 0
        count++;
        sleep(3);


        if (count > 3)
            break;
#endif
    }

    return 0;
}
#endif

#if 0
#define PI 	(3.1415926)
#define E   (2.718281828)

static double lngToPixel(double lng, int zoom)
{
    return (lng + 180) * (256L << zoom) / 360;
}

static double pixelToLng(double pixelX, int zoom)
{

    return pixelX * 360 / (256L << zoom) - 180;

}

static double latToPixel(double lat, int zoom)
{

    double siny = sin(lat * PI / 180);

    double y = log((1 + siny) / (1 - siny));

    return (128 << zoom) * (1 - y / (2 * PI));

}

static double pixelToLat(double pixelY, int zoom)
{

    double y = 2 * PI * (1 - pixelY / (128 << zoom));

    double z = pow(E, y);

    double siny = (z - 1) / (z + 1);

    return asin(siny) * 180 / PI;

}
#endif

static void gps_process(char* buf, int len)
{
    char* GPRMC_ptr = NULL;
    char* GPGGA_ptr = NULL;
    char word[512]= {0}, *next_word;
    int count, l;

    if ((GPGGA_ptr = strstr(buf, "GGA")) && (strstr(GPGGA_ptr, "\r\n")))
    {
        count = 0;
        foreach_44(word, GPGGA_ptr, next_word)
        {
            switch(count)
            {
			case 0:
                break;
            case 2: //is GPS data valid
                l = strlen(word);
                if ((1 == l) && (0 == atoi(word)))
                    is_valid = 0;
                else
                    is_valid = 1;
                break;
            case 3:
                l = strlen(word);
                if(!is_valid && (3>l) && (l>0))
                {
                    bzero(gps_use, sizeof(gps_use));
                    strncpy(gps_use, word, sizeof(gps_use));
                }
                break;
            case 6:
                l = strlen(word);
                if(is_valid && (3>l) && (l>0))
                {
                    bzero(gps_FS, sizeof(gps_FS));
                    strncpy(gps_FS, word, sizeof(gps_FS));
                }
                break;
            case 7:
                l = strlen(word);
                if(is_valid && (3>l) && (l>0))
                {
                    bzero(gps_use, sizeof(gps_use));
                    strncpy(gps_use, word, sizeof(gps_use));
                }
                break;
            case 8:
                l = strlen(word);
                if(is_valid && (8>l) && (l>0))
                {
                    bzero(gps_HDOP, sizeof(gps_HDOP));
                    strncpy(gps_HDOP, word, sizeof(gps_HDOP));
                }
                break;
            case 9:
                l = strlen(word);
                if(is_valid && (8>l) && (l>0))
                {
                    bzero(gps_MSL, sizeof(gps_MSL));
                    strncpy(gps_MSL, word, sizeof(gps_MSL));
                }
                break;
            }
            ++count;
        }
    }
    if ((GPRMC_ptr = strstr(buf, "RMC")) && (strstr(GPRMC_ptr, "\r\n")))
    {
        if (strstr(buf, "GPRMC"))
            GP_BD = 0;
        else if (strstr(buf, "BDRMC"))
            GP_BD = 1;
        else
            GP_BD = 2;
        count = 0;
        bzero(word, sizeof(word));
        next_word = NULL;
        is_valid = 0;
        foreach_44(word, GPRMC_ptr, next_word)
        {
            switch(count)
            {
            case 0:
                break;
            case 1: //hhmmss.xx
                bzero(gps_time, sizeof(gps_time));
                strncpy(gps_time, word, sizeof(gps_time));
                break;
            case 2: //is GPS data valid
                if (strchr(word, 'A'))
                    is_valid = 1;
                else
                    is_valid = 0;
                break;
            case 3: //
                if (is_valid)
                {
                    bzero(gps_latitude, sizeof(gps_latitude));
                    strncpy(gps_latitude, word, sizeof(gps_latitude));
                }
                else if(6 == strlen(word))
                {
                    bzero(gps_date, sizeof(gps_date));
                    strncpy(&gps_date[0], &word[4], 2);
                    strncpy(&gps_date[2], &word[2], 2);
                    strncpy(&gps_date[4], &word[0], 2);
                    //strncpy(gps_date, word, sizeof(gps_date));
                }
                break;
            case 4: //N /S
                bzero(gps_NS, sizeof(gps_NS));
                strncpy(gps_NS, word, sizeof(gps_NS));
                break;
            case 5: //
                bzero(gps_longitude, sizeof(gps_longitude));
                strncpy(gps_longitude, word, sizeof(gps_longitude));
                break;
            case 6: //E | W
                bzero(gps_EW, sizeof(gps_EW));
                strncpy(gps_EW, word, sizeof(gps_EW));
                break;
            case 7: //Speed
                bzero(gps_speed, sizeof(gps_speed));
                strncpy(gps_speed, word, sizeof(gps_speed));
                break;
            case 8://yymmdd or degrees
                if (!strchr(word, '.') && (6 == strlen(word)))
                {
                    bzero(gps_date, sizeof(gps_date));
                    strncpy(&gps_date[0], &word[4], 2);
                    strncpy(&gps_date[2], &word[2], 2);
                    strncpy(&gps_date[4], &word[0], 2);
                }
                else
                {
                    bzero(gps_degrees, sizeof(gps_degrees));
                    strncpy(gps_degrees, word, sizeof(gps_degrees));
                }
                break;
            case 9://yymmdd
                if (!strchr(word, '*') && (6 == strlen(word)))
                {
                    bzero(gps_date, sizeof(gps_date));
                    strncpy(&gps_date[0], &word[4], 2);
                    strncpy(&gps_date[2], &word[2], 2);
                    strncpy(&gps_date[4], &word[0], 2);
                }
                break;

            }
            if (count > 2 && !is_valid)
                break;

            ++count;
        }
    }
}

int fmt_data(int serialFd, DTU_CONFIG_T *dtuConf)
{
    int ret = -1, n;
    int maxfd = -1;
    fd_set rset, wset;
    struct timeval tv;
    CIRCLEQUEUE_T *serial_buf_queue = NULL;
    char *dataBuf;

    dataBuf = (char *)malloc(dtuConf->data.max_len * sizeof(char));
    if (dataBuf == NULL)
    {
        goto err_quit;
    }

    ret = init_queue(&serial_buf_queue, MAX_CIRCLE_QUEUE_SIZE);
    if (ret < 0)
    {
        goto err_quit;
    }


    maxfd = serialFd;
    syslog(LOG_INFO, "Serial APP: fmt_data");
    while (1)
    {
        FD_ZERO(&rset);
        FD_ZERO(&wset);

        FD_SET(serialFd, &rset);


        tv.tv_sec = dtuConf->heartbeat.heartbeat_interval;
        tv.tv_usec = 0;

        ret = select(maxfd + 1, &rset, &wset, NULL, &tv);
        if (ret < 0)
        {
            if (errno != EINTR && errno != EAGAIN)
            {
                syslog(LOG_ERR,  "Select Error( return:%d errno:%d )", ret , errno );
                goto err_quit;
            }
        }
        else if (ret == 0)
        {
            if (is_queue_empty(serial_buf_queue) == 1)
            {
                en_queue(serial_buf_queue, dtuConf->heartbeat.content, strlen(dtuConf->heartbeat.content));
            }
        }

        if (FD_ISSET(serialFd, &rset))
        {
            if (is_queue_full(serial_buf_queue) == 0)
            {
                memset(dataBuf, 0, dtuConf->data.max_len);

                n = get_queue_empty_length(serial_buf_queue);
                int req_len = dtuConf->data.max_len > n ? n : dtuConf->data.max_len;
                n = read_timeout(serialFd, dataBuf, req_len, dtuConf->data.serial_timeout);
                if (n < 0)
                {
                    break;
                }
                en_queue(serial_buf_queue, dataBuf, n);
                show_queue_element(serial_buf_queue);
            }
        }

        if (is_queue_empty(serial_buf_queue) == 0)
        {
            //not empty
            memset(dataBuf, 0, dtuConf->data.max_len);
            n = de_queue_start(serial_buf_queue, dataBuf, dtuConf->data.max_len);
            gps_process(dataBuf, n);
            de_queue_done(serial_buf_queue, n);
        }
    }

err_quit:
    if (serial_buf_queue != NULL)
    {
        destroy_queue(&serial_buf_queue);
    }

    if (dataBuf != NULL)
    {
        free(dataBuf);
    }

    if (serialFd > 0)
    {
        close(serialFd);
    }

    return (ret);
}

void *gps_data_heartbeat_rtn(void *arg)
{
    char hb_buf[512] = {0};
    char rd_buf[256] = {0};
    int hb_len = 0;
    int socket_fd = -1;
    fd_set rset, wset;
    struct timeval tv;
    DTU_CONFIG_T *dtuConfig = (DTU_CONFIG_T *)arg;

    pthread_detach(pthread_self( ));


    while(1)
    {
        while (socket_fd < 0)
        {
            if (DTU_MODE_SERVER == dtuConfig->mode)
            {
                syslog(LOG_INFO,  "Serial APP: Client Mode" );
                if (DTU_SOCKET_TCP == dtuConfig->protocol)
                {
                    syslog(LOG_INFO,  "TCP Server Mode" );
                    if ((socket_fd = create_tcp_socket(dtuConfig)) < 0)
                    {
                        sleep(5);
                        continue;
                    }
                }
                else
                {
                    syslog(LOG_INFO, "Serial APP: UDP Server Mode" );
                    if ((socket_fd = create_udp_socket(dtuConfig)) < 0)
                    {
                        sleep(5);
                        continue;
                    }
                }
            }
            else
            {
                syslog(LOG_INFO,  "Serial APP: Client Mode" );
                if ((socket_fd = connect_server(dtuConfig)) < 0)
                {
                    sleep(dtuConfig->reconnect_interval);
                    continue;
                }
            }
        }

        while(1)
        {
            int ret;
            int n;

            FD_ZERO(&rset);
            FD_ZERO(&wset);

            FD_SET(socket_fd, &rset);
            FD_SET(socket_fd, &wset);

            tv.tv_sec = 5;
            tv.tv_usec = 0;

            memset(hb_buf, 0, 512);
            if (is_valid)
            {
                char* p = NULL;
                double fl, gl;
                unsigned int i;
                char google_gps_lat[16] = {0};
                char google_gps_lon[16] = {0};
                char google_map[32] = {0};
                nvram_set("gps_valid", "OK");
                nvram_set("gps_use", gps_use);
                nvram_set("gps_date", gps_date);
                nvram_set("gps_time", gps_time);
                nvram_set("gps_latitude", gps_latitude);
                nvram_set("gps_NS", gps_NS);
                nvram_set("gps_longitude", gps_longitude);
                nvram_set("gps_EW", gps_EW);
                nvram_set("gps_speed", gps_speed);
                nvram_set("gps_degrees", gps_degrees);
                nvram_set("gps_FS", gps_FS);
                nvram_set("gps_HDOP", gps_HDOP);
                nvram_set("gps_MSL", gps_MSL);
                if (0 == GP_BD)
                    nvram_set("gps_bds", "GPS");
                else if (1 == GP_BD)
                    nvram_set("gps_bds", "BDS");
                else
                    nvram_set("gps_bds", "GPS/BDS");

            p = strchr(gps_latitude, '.');
            if (p)
            {
                fl = atof(gps_latitude);
                i = (unsigned int)fl/100;
                gl = i + (fl - (unsigned int)(fl/100)*100)/60.0;
                //gl = pixelToLat((unsigned int)(latToPixel(gl, 18)+1193), 18);
                sprintf(google_gps_lat, "%s%.6f",(strchr(gps_NS, 'N'))?"+":"-",  gl);

                syslog(LOG_NOTICE, "########latitude<%s>", google_gps_lat);
            }
            p = strchr(gps_longitude, '.');
            if (p)
            {
                fl = atof(gps_longitude);
                i = (unsigned int)fl/100;
                gl = i + (fl - (unsigned int)(fl/100)*100)/60.0;
                //gl = pixelToLng((unsigned int)(lngToPixel(gl, 18)-270), 18);
                sprintf(google_gps_lon, "%s%.6f",(strchr(gps_EW, 'E'))?"+":"-", gl);

                    syslog(LOG_NOTICE, "########longitude<%s>", google_gps_lon);
                }
                sprintf(google_map, "%s,%s", google_gps_lat, google_gps_lon);
                nvram_set("google_map", google_map);
                if(sys_time_flag == 1 && nvram_match("gps_clock","1"))
                {
                    char time_buf[64];
                    char date_buf[16];
                    char result_buf[64];
                    int len;
                    int k = 0,j = 0;
                    int m = 0,n = 0;
                    memset(time_buf,0,sizeof(time_buf));
                    memset(date_buf,0,sizeof(date_buf));
                    memset(result_buf,0,sizeof(result_buf));
                    len = strlen(gps_time);
                    while(j < len)
                    {
                        if(*(gps_time + j) == '.')
                        {
                            break;
                        }
                        if((k+1)%3 == 0)
                        {
                            time_buf[k++] = ':';
                            continue;
                        }
                        time_buf[k++] = *(gps_time+j);
                        j++;
                    }
                    len = strlen(gps_date);
                    while(m < len)
                    {
                        if((n + 1)%3 == 0)
                        {
                            date_buf[n++] = '-';
                            continue;
                        }
                        date_buf[n++] = *(gps_date+m);
                        m++;
                    }
                    sprintf(result_buf,"date '20%s %s'",date_buf,time_buf);
                    syslog(LOG_INFO,"the time is :%s",result_buf);
                    system(result_buf);
                    sys_time_flag = 0;
                }
            }
            else
            {
                nvram_set("gps_valid", "N/A");
                nvram_set("gps_use", gps_use);
                nvram_set("gps_date", gps_date);
                nvram_set("gps_time", gps_time);
            }
            /*
                    syslog(LOG_NOTICE, "----GPS (%s:%s), (%s-%s), (%s%s), (%s%s)----",
                        nvram_safe_get("gps_valid"),
                        nvram_safe_get("gps_use"),
                        nvram_safe_get("gps_date"),
                        nvram_safe_get("gps_time"),
                        nvram_safe_get("gps_latitude"),
                        nvram_safe_get("gps_NS"),
                        nvram_safe_get("gps_longitude"),
                        nvram_safe_get("gps_EW")
                        );
            */
            hb_len = sprintf(hb_buf, "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s",
                             dtuConfig->heartbeat.content, gps_date, gps_time, gps_use, gps_latitude, gps_NS, gps_longitude, gps_EW, gps_speed, gps_degrees, gps_FS, gps_HDOP, gps_MSL );
            if (!nvram_match("gps_data", "relay"))
            {

                ret = select(socket_fd + 1, &rset, &wset, NULL, &tv);
                if(ret < 0)
                {
                    close(socket_fd);
                    socket_fd = -1;
                    syslog(LOG_INFO,"Select error!");
                    break;
                }
                else if(ret == 0)
                {
                    continue;
                }
                if(socket_fd > 0 && FD_ISSET(socket_fd,&wset))
                {
                    if (dtuConfig->mode == DTU_MODE_SERVER && dtuConfig->protocol == DTU_SOCKET_UDP)
                    {
                        n = socket_write_udp_svr(socket_fd, hb_buf, hb_len, dtuConfig->data.timeout);
                        if (n < 0)
                        {

                            close(socket_fd);
                            socket_fd= -1;
                            break;
                        }
                    }
                    else
                    {
                        n = write_timeout(socket_fd, hb_buf, hb_len, dtuConfig->data.timeout);
                        if (n < 0)
                        {
                            close(socket_fd);
                            socket_fd= -1;
                            break;
                        }
                    }
                }
                if(socket_fd > 0 && FD_ISSET(socket_fd,&rset))
                {
                    if (dtuConfig->mode == DTU_MODE_SERVER && dtuConfig->protocol == DTU_SOCKET_UDP)
                    {
                        n = socket_read_udp_svr(socket_fd, rd_buf, sizeof(rd_buf), dtuConfig->data.timeout);
                        if (n < 0)
                        {

                            close(socket_fd);
                            socket_fd= -1;
                            break;
                        }
                    }
                    else
                    {
                        n = read_timeout(socket_fd, rd_buf, sizeof(rd_buf), dtuConfig->data.timeout);
                        if (n < 0)
                        {
                            close(socket_fd);
                            socket_fd= -1;
                            break;
                        }
                    }
                }

#if 0
                int ret = write(socket_fd, hb_buf, hb_len);
                if(ret < 0)
                {
                    syslog(LOG_NOTICE, "Write data error!");
                    close(socket_fd);
                    socket_fd = -1;
                    break;
                }
#endif
                syslog(LOG_NOTICE, ">>>>>hb write %d fd=%d, hb_buf=%s", ret, socket_fd, hb_buf);
            }
            sleep(dtuConfig->heartbeat.heartbeat_interval);
        }
    }

    return NULL;
}

void *gps2_data_heartbeat_rtn(void *arg)
{
    char hb_buf[512] = {0};
    int hb_len = 0;
    int socket_fd = -1;
    DTU_CONFIG_T *dtuConfig = (DTU_CONFIG_T *)arg;

    pthread_detach(pthread_self());


    while(1)
    {
        while (socket_fd < 0)
        {
            if (DTU_MODE_SERVER == dtuConfig->mode)
            {
                syslog(LOG_INFO,  "Server Mode has not two GPS!" );
                return NULL;
            }
            else
            {
                syslog(LOG_INFO,  "Serial APP: Client Mode" );
                if ((socket_fd = connect2_server(dtuConfig)) < 0)
                {
                    sleep(dtuConfig->reconnect_interval);
                    continue;
                }
            }
        }

        memset(hb_buf, 0, 512);
	
        if (is_valid)
        {
            char* p = NULL;
            double fl, gl;
            unsigned int i;
            char google_gps_lat[16] = {0};
            char google_gps_lon[16] = {0};
            char google_map[32] = {0};       
	        nvram_set("gps_valid", "OK");
            nvram_set("gps_use", gps_use);
            nvram_set("gps_date", gps_date);
            nvram_set("gps_time", gps_time);
            nvram_set("gps_latitude", gps_latitude);
            nvram_set("gps_NS", gps_NS);
            nvram_set("gps_longitude", gps_longitude);
            nvram_set("gps_EW", gps_EW);
            nvram_set("gps_speed", gps_speed);
            nvram_set("gps_degrees", gps_degrees);
            nvram_set("gps_FS", gps_FS);
            nvram_set("gps_HDOP", gps_HDOP);
            nvram_set("gps_MSL", gps_MSL);
            if (0 == GP_BD)
                nvram_set("gps_bds", "GPS");
            else if (1 == GP_BD)
                nvram_set("gps_bds", "BDS");
            else
                nvram_set("gps_bds", "GPS/BDS");


            p = strchr(gps_latitude, '.');
            if (p)
            {
                fl = atof(gps_latitude);
                i = (unsigned int)fl/100;
                gl = i + (fl - (unsigned int)(fl/100)*100)/60.0;
                //gl = pixelToLat((unsigned int)(latToPixel(gl, 18)+1193), 18);
                sprintf(google_gps_lat, "%s%.6f",(strchr(gps_NS, 'N'))?"+":"-",  gl);

                syslog(LOG_NOTICE, "########latitude<%s>", google_gps_lat);
            }
            p = strchr(gps_longitude, '.');
            if (p)
            {
                fl = atof(gps_longitude);
                i = (unsigned int)fl/100;
                gl = i + (fl - (unsigned int)(fl/100)*100)/60.0;
                //gl = pixelToLng((unsigned int)(lngToPixel(gl, 18)-270), 18);
                sprintf(google_gps_lon, "%s%.6f",(strchr(gps_EW, 'E'))?"+":"-", gl);

                syslog(LOG_NOTICE, "########longitude<%s>", google_gps_lon);
            }
            sprintf(google_map, "%s,%s", google_gps_lat, google_gps_lon);
            
        }
       
      
        hb_len = sprintf(hb_buf, "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s",
                         dtuConfig->heartbeat.content, gps_date, gps_time, gps_use, gps_latitude, gps_NS, gps_longitude, gps_EW, gps_speed, gps_degrees, gps_FS, gps_HDOP, gps_MSL );
        if (!nvram_match("gps_data", "relay"))
        {
            int ret = write(socket_fd, hb_buf, hb_len);
            syslog(LOG_NOTICE, ">>>>>hb write %d fd=%d, hb_buf=%s", ret, socket_fd, hb_buf);
        }

        sleep(dtuConfig->heartbeat.heartbeat_interval);
    }

    return NULL;
}

#if 1
int gps_m2m_fmt_process(int serialFd, DTU_CONFIG_T *dtuConfig, SERIAL_CONFIG_T *serConf, MQTT_CONFIG_T *mqttConf)
{
//    int count = 0;
    pthread_t gps_ht_id;
    char dev_port[24] = {0};
    int ret;

    if (pthread_create(&gps_ht_id, NULL, (void *)gps_data_heartbeat_rtn, dtuConfig) != 0)
    {
        syslog(LOG_ERR, "Failed to Create Heartbeat Thread");
        return -1;
    }   
    while (1)
    {
        fmt_data(serialFd, dtuConfig);

        struct termios old_term;

        serialFd = -1;
        while (serialFd < 0)
        {
    		ret = which_serial(dev_port);
    		if(ret < 0)
    		{   
    			serialFd = open_serial(gps_m2m_hook.portName, &old_term);
    			if (serialFd < 0)
    			{   
    				syslog(LOG_ERR, "[%s]-->: Open serial %s Failed", gps_m2m_hook.name, gps_m2m_hook.portName);
    			//	sleep(1);
    			//	continue;
    			    break;
    			}
    		}
    		else
    		{   
    			serialFd = open_serial(dev_port, &old_term);
    			if (serialFd < 0)
    			{
    				syslog(LOG_ERR, "[%s]-->: Open serial %s Failed",gps_m2m_hook.name, gps_m2m_hook.portName);
    			//	sleep(1);
    			//	continue;
    			    break;
    			}
    		}
            /*serialFd = open_serial(gps_m2m_hook.portName, &old_term);
            if (serialFd < 0)
            {
                syslog(LOG_ERR, "[%s]-->: Open serial %s Failed", gps_m2m_hook.name, gps_m2m_hook.portName);
                return (-1);
            }*/

            if (init_serial(serialFd, serConf) < 0)
            {
                syslog(LOG_ERR, "[%s]-->: Init serial %s Failed", gps_m2m_hook.name, gps_m2m_hook.portName);
                close_serial(serialFd, &old_term);
                return (-1);
            }

            syslog(LOG_INFO, "[%s]-->: Open serial %s succ, fd = %d", gps_m2m_hook.name, gps_m2m_hook.portName, serialFd);
        }
#if 0
        count++;
        sleep(3);


        if (count > 3)
            break;
#endif
    }

    return 0;
}
int double_gps_m2m_fmt_process(int serialFd, DTU_CONFIG_T *dtuConfig, SERIAL_CONFIG_T *serConf, MQTT_CONFIG_T *mqttConf)
{
    //int count = 0;
    pthread_t gps_ht_id;
    pthread_t gps2_ht_id;

    if (pthread_create(&gps_ht_id, NULL, (void *)gps_data_heartbeat_rtn, dtuConfig) != 0)
    {
        syslog(LOG_ERR, "Failed to Create Heartbeat Thread");
        return -1;
    }

    if (pthread_create(&gps2_ht_id, NULL, (void *)gps2_data_heartbeat_rtn, dtuConfig) != 0)
    {
        syslog(LOG_ERR, "Failed to Create Heartbeat2 Thread");
        return -1;
    }
    
    while (1)
    {
        fmt_data(serialFd, dtuConfig);

        struct termios old_term;

        serialFd = -1;
        char dev_port[24] = {0};
        int ret;
        
        while (serialFd < 0)
	{
		ret = which_serial(dev_port);
		if(ret < 0)
		{
			serialFd = open_serial(double_gps_m2m_hook.portName, &old_term);
			if (serialFd < 0)
			{
				syslog(LOG_ERR, "[%s]-->: Open serial %s Failed", double_gps_m2m_hook.name, double_gps_m2m_hook.portName);
	//			sleep(1);
		//		continue;
		        break;
			}
		}
		else
		{
			serialFd = open_serial(dev_port, &old_term);
			if (serialFd < 0)
			{
				syslog(LOG_ERR, "[%s]-->: Open serial %s Failed",double_gps_m2m_hook.name, double_gps_m2m_hook.portName);
//				sleep(1);
//				continue;
                break;
			}
		}
            /*serialFd = open_serial(gps_m2m_hook.portName, &old_term);
            if (serialFd < 0)
            {
                syslog(LOG_ERR, "[%s]-->: Open serial %s Failed", gps_m2m_hook.name, gps_m2m_hook.portName);
                return (-1);
            }*/

            if (init_serial(serialFd, serConf) < 0)
            {
                syslog(LOG_ERR, "[%s]-->: Init serial %s Failed", double_gps_m2m_hook.name, double_gps_m2m_hook.portName);
                close_serial(serialFd, &old_term);
                return (-1);
            }

            syslog(LOG_INFO, "[%s]-->: Open serial %s succ, fd = %d", double_gps_m2m_hook.name, double_gps_m2m_hook.portName, serialFd);
        }
#if 0
        count++;
        sleep(3);


        if (count > 3)
            break;
#endif
    }

    return 0;
}
#endif

static int send_packet(void* socket_info, const void* buf, unsigned int count)
{
	int fd = *((int*)socket_info);
	return send(fd, buf, count, 0);
}

static void init_socket(mqtt_broker_handle_t* broker, int sockFd)
{
	// MQTT stuffs
	mqtt_set_alive(broker, keepalive);
	broker->socket_info = (void*)&sockFd;
	broker->send = send_packet;

	return;
}

static int close_socket(mqtt_broker_handle_t* broker)
{
	int fd = *((int*)broker->socket_info);
	return close(fd);
}

static int read_packet(int sockFd, int timeout)
{
	if(timeout > 0)
	{
		fd_set readfds;
		struct timeval tmv;

		// Initialize the file descriptor set
		FD_ZERO (&readfds);
		FD_SET (sockFd, &readfds);

		// Initialize the timeout data structure
		tmv.tv_sec = timeout;
		tmv.tv_usec = 0;

		// select returns 0 if timeout, 1 if input available, -1 if error
		if(select(1, &readfds, NULL, NULL, &tmv))
			return -2;
	}

	int total_bytes = 0, bytes_rcvd, packet_length;
	memset(packet_buffer, 0, sizeof(packet_buffer));
	
	if((bytes_rcvd = recv(sockFd, (packet_buffer+total_bytes), RCVBUFSIZE, 0)) <= 0) {
		syslog(LOG_ERR, "%s----------%d", __FUNCTION__, __LINE__);
		syslog(LOG_ERR, "errno = %d", errno);
		return -1;
	}

	total_bytes += bytes_rcvd; // Keep tally of total bytes
	if (total_bytes < 2)
	{
		syslog(LOG_ERR, "%s----------%d", __FUNCTION__, __LINE__);
		syslog(LOG_ERR, "errno = %d", errno);
		return -1;
	}
	// now we have the full fixed header in packet_buffer
	// parse it for remaining length and number of bytes
	uint16_t rem_len = mqtt_parse_rem_len(packet_buffer);
	uint8_t rem_len_bytes = mqtt_num_rem_len_bytes(packet_buffer);
	
	//packet_length = packet_buffer[1] + 2; // Remaining length + fixed header length
	// total packet length = remaining length + byte 1 of fixed header + remaning length part of fixed header
	packet_length = rem_len + rem_len_bytes + 1;

	while(total_bytes < packet_length) // Reading the packet
	{
		if((bytes_rcvd = recv(sockFd, (packet_buffer+total_bytes), RCVBUFSIZE, 0)) <= 0)
		{
			syslog(LOG_ERR, "%s---------%d", __FUNCTION__, __LINE__);
			syslog(LOG_ERR, "errno = %d", errno);
			return -1;
		}
		total_bytes += bytes_rcvd; // Keep tally of total bytes
	}

	return packet_length;
}

void alive(int sig)
{
	syslog(LOG_NOTICE, "Timeout! Sending ping...");
	mqtt_ping(&broker);

	alarm(keepalive);
}

void term(int sig)
{
	// >>>>> DISCONNECT
	mqtt_disconnect(&broker);
	close_socket(&broker);

	exit(0);
}

static int mqtt_connect_server(int sockFd, MQTT_CONFIG_T *mqttConf)
{
	int packet_length;
	uint16_t msg_id, msg_id_rcv;

	//initial MQTT
	mqtt_init(&broker, "detran_client000000");
	mqtt_init_auth(&broker, mqttConf->usrname, mqttConf->passwd);
	init_socket(&broker, sockFd);

	// >>>>> CONNECT
	if(mqtt_connect(&broker) < 0)
	{
		syslog(LOG_INFO,"Mqtt connect error!");
		return -1;
	}

	// <<<<< CONNACK
	packet_length = read_packet(sockFd, 1);
	if(packet_length < 0)
	{
		syslog(LOG_INFO,"Error(%d) on read packet!\n",packet_length);
		return -1;
	}

	if(MQTTParseMessageType(packet_buffer) != MQTT_MSG_CONNACK)
	{
		syslog(LOG_INFO,"CONNACK expected!");
		return -2;
	}

	if(packet_buffer[3] != 0x00)
	{
		syslog(LOG_INFO,"CONNACK failed!!");
		return -2;
	}

	// Signals after connect MQTT
	signal(SIGALRM, alive);
	alarm(keepalive);
	signal(SIGINT, term);

	if(strlen(mqttConf->sub_topic) != 0)
	{
		// >>>>> SUBSCRIBE
		mqtt_subscribe(&broker, mqttConf->sub_topic, &msg_id);
		// <<<<< SUBACK
		packet_length = read_packet(sockFd, 1);
		if(packet_length < 0)
		{
			syslog(LOG_INFO, "Error(%d) on read packet!", packet_length);
			
			return -1;
		}

		if(MQTTParseMessageType(packet_buffer) != MQTT_MSG_SUBACK)
		{
			syslog(LOG_INFO, "SUBACK expected!");
			return -2;
		}

		msg_id_rcv = mqtt_parse_msg_id(packet_buffer);
		if(msg_id != msg_id_rcv)
		{
			syslog(LOG_INFO, "%d message id was expected, but %d message id was found!", msg_id, msg_id_rcv);
			return -3;
		}

		syslog(LOG_NOTICE, "Subscribe topic '%s' success.", mqttConf->sub_topic);
	}

	return 0;
}

static int socket_read_mqtt_svr(int sockFd, char *outBuf, int timeout)
{
	int packet_length = 0;
	
	packet_length = read_packet(sockFd, timeout);
	if(packet_length == -1)
	{
		syslog(LOG_INFO, "Error(%d) on read packet!", packet_length);
		return -1;
	}
	else if(packet_length > 0)
	{
		syslog(LOG_INFO,"Packet Header: 0x%x...", packet_buffer[0]);
		if(MQTTParseMessageType(packet_buffer) == MQTT_MSG_PUBLISH)
		{
			uint8_t topic[255], msg[1000];
			uint16_t len;
			len = mqtt_parse_pub_topic(packet_buffer, topic);
			topic[len] = '\0'; // for printf
			len = mqtt_parse_publish_msg(packet_buffer, msg);
			msg[len] = '\0'; // for printf
			syslog(LOG_INFO, "Recv from MQTT:%s %s", topic, msg);

			memcpy(outBuf, msg, len);
			return len;
		}
		else if(MQTTParseMessageType(packet_buffer) == MQTT_MSG_PINGRESP)
		{
			memcpy(outBuf, packet_buffer, packet_length);	
			return packet_length;
		}
	}
}

int switch_data(int serialFd, int sockFd, DTU_CONFIG_T *dtuConf, MQTT_CONFIG_T *mqttConf)
{
    int ret = -1, n;
    int maxfd = -1;
    fd_set rset, wset;
    struct timeval tv;
    CIRCLEQUEUE_T *svr_buf_queue = NULL, *serial_buf_queue = NULL;
    char *dataBuf;
    char *strhex[2048];
	char debug_buf[1024];
	char out_buf[4096];
	int i,outlen;

    dataBuf = (char *)malloc(dtuConf->data.max_len * sizeof(char));
    if (dataBuf == NULL)
    {
        goto err_quit;
    }

    ret = init_queue(&serial_buf_queue, MAX_CIRCLE_QUEUE_SIZE);
    if (ret < 0)
    {
        goto err_quit;
    }

    ret = init_queue(&svr_buf_queue, MAX_CIRCLE_QUEUE_SIZE);
    if (ret < 0)
    {
        goto err_quit;
    }

    maxfd = serialFd > sockFd ? serialFd : sockFd;
    syslog(LOG_INFO, "Serial APP: switch_data");
    while (1)
    {
        FD_ZERO(&rset);
        FD_ZERO(&wset);

        FD_SET(serialFd, &rset);
        FD_SET(sockFd, &rset);

        if (is_queue_empty(serial_buf_queue) == 0)
        {
            FD_SET(sockFd, &wset);
        }

        if (is_queue_empty(svr_buf_queue) == 0)
        {
            FD_SET(serialFd, &wset);
        }

        tv.tv_sec = dtuConf->heartbeat.heartbeat_interval;
        tv.tv_usec = 0;

        ret = select(maxfd + 1, &rset, &wset, NULL, &tv);
        if (ret < 0)
        {
            if (errno != EINTR && errno != EAGAIN)
            {
                syslog(LOG_ERR,  "Error : Select Error( return:%d errno:%d )", ret , errno );
                goto err_quit;
            }
        }
        else if (ret == 0)
        {
            if (is_queue_empty(serial_buf_queue) == 1)
            {
                en_queue(serial_buf_queue, dtuConf->heartbeat.content, strlen(dtuConf->heartbeat.content));
            }
        }

        if (FD_ISSET(sockFd, &wset))
        {
            if (is_queue_empty(serial_buf_queue) == 0)
            {
                //not empty
                memset(dataBuf, 0, dtuConf->data.max_len);
                n = de_queue_start(serial_buf_queue, dataBuf, dtuConf->data.max_len);
				if(dtuConf->mode == DTU_MODE_CLIENT && nvram_match("ipoc_mqtt_mode", "1"))	// send data with mqtt
				{
					mqtt_publish(&broker, mqttConf->pub_topic, dataBuf, 0);
				}
				else //send data with tcp/udp
				{
					if (dtuConf->mode == DTU_MODE_SERVER && dtuConf->protocol == DTU_SOCKET_UDP)
                	{
                	    n = socket_write_udp_svr(sockFd, dataBuf, n, dtuConf->data.timeout);
                	    if (n < 0)
                	    {
							return -1;
                	        //break;
                	    }
                	}
                	else
                	{
                	    n = write_timeout(sockFd, dataBuf, n, dtuConf->data.timeout);
                	    if (n < 0)
                	    {
							return -1;
                	        //break;
                	    }
                	}
				}
				if(nvram_match("debug_enable","1"))
					{
						memset(debug_buf,0,sizeof(debug_buf));
						memset(out_buf,0,sizeof(out_buf));
					//	outlen = String2Bytes(dataBuf,debug_buf,n);
						if(str_to_hex(dataBuf,strhex) == NULL)
						{
							syslog(LOG_NOTICE, "Write sockFd");
							syslog(LOG_ERR,"The strhex is NULL");
							break;
						}
						string_to_hex(strhex,debug_buf);
					//	string_to_hex(dataBuf,debug_buf);
						for(i = 0; i < atoi(nvram_safe_get("debug_num")); i++)
						{
							sprintf(&out_buf[i*3],"%02x ",debug_buf[i]);
						}
						syslog(LOG_INFO,"Write Socket-->%s",out_buf);
				}
                de_queue_done(serial_buf_queue, n);
            }
        }

        if (FD_ISSET(serialFd, &wset))
        {
            if (is_queue_empty(svr_buf_queue) == 0)
            {
                //not empty
                memset(dataBuf, 0, dtuConf->data.max_len);

                n = de_queue_start(svr_buf_queue, dataBuf, dtuConf->data.max_len);
                n = write_timeout(serialFd, dataBuf, n, dtuConf->data.serial_timeout);
                if (n < 0)
                {
                    break;
                }
				if(nvram_match("debug_enable","1"))
					{
						memset(debug_buf,0,sizeof(debug_buf));
						memset(out_buf,0,sizeof(out_buf));
					//	outlen = String2Bytes(dataBuf,debug_buf,n);
						if(str_to_hex(dataBuf,strhex) == NULL)
						{
							syslog(LOG_NOTICE, "Write seiralFd");
							syslog(LOG_ERR,"The strhex is NULL");
							break;
						}
						string_to_hex(strhex,debug_buf);
						for(i = 0; i < atoi(nvram_safe_get("debug_num")); i++)
						{
							sprintf(&out_buf[i*3],"%02x ",debug_buf[i]);
						}
						syslog(LOG_INFO,"Write Serial-->%s ",out_buf);
						
				}
                de_queue_done(svr_buf_queue, n);
            }
        }

        if (FD_ISSET(sockFd, &rset))
        {
            if (is_queue_full(svr_buf_queue) == 0)
            {
                memset(dataBuf, 0, dtuConf->data.max_len);

                n = get_queue_empty_length(svr_buf_queue);
                int req_len = dtuConf->data.max_len > n ? n : dtuConf->data.max_len;

				if (dtuConf->mode == DTU_MODE_SERVER && dtuConf->protocol == DTU_SOCKET_UDP)
                {
                    n = socket_read_udp_svr(sockFd, dataBuf, req_len, dtuConf->data.timeout);
                    if (n < 0)
                    {
						return -1;
                        //break;
                    }
                }
                else
                {
                    n = read_timeout(sockFd, dataBuf, req_len, dtuConf->data.timeout);
                    if (n < 0)
                    {
						syslog(LOG_ERR, "Read sockFd fail");
						return -1;
                        //break;
                    }
                }

				if((dtuConf->mode == DTU_MODE_CLIENT) && nvram_match("ipoc_mqtt_mode", "1"))
				{
					if(MQTTParseMessageType(dataBuf) == MQTT_MSG_PINGRESP)
					{
						syslog(LOG_NOTICE, "Ping response...");
						continue;
					}
					if(strlen(mqttConf->sub_topic) != 0)
					{
						uint16_t rem_len = mqtt_parse_rem_len(dataBuf);
						uint8_t rem_len_bytes = mqtt_num_rem_len_bytes(dataBuf);
						
						int packet_length = rem_len + rem_len_bytes + 1;
						if(dataBuf[1] != (packet_length - 2))
						{
							syslog(LOG_ERR, "Remain Length(%02x) != Payload Length(%02x)", dataBuf[1], packet_length - 2);
							return -1;
						}

						syslog(LOG_INFO,"Packet Header: 0x%x...", dataBuf[0]);
						if(MQTTParseMessageType(dataBuf) == MQTT_MSG_PUBLISH)
						{
							uint8_t topic[255], msg[1000];
							uint16_t len;
							len = mqtt_parse_pub_topic(dataBuf, topic);
							topic[len] = '\0'; // for printf
							len = mqtt_parse_publish_msg(dataBuf, msg);
							msg[len] = '\0'; // for printf
							syslog(LOG_INFO, "Recv from MQTT:%s %s", topic, msg);

							memset(dataBuf, 0, dtuConf->data.max_len);
							memcpy(dataBuf, msg, len);
						}
					}
				}

				if(nvram_match("debug_enable","1"))
				{
						memset(debug_buf,0,sizeof(debug_buf));
						memset(out_buf,0,sizeof(out_buf));
						//outlen = String2Bytes(dataBuf,debug_buf,n);
						if(str_to_hex(dataBuf,strhex) == NULL)
						{
							syslog(LOG_NOTICE, "Read sockFd");
							syslog(LOG_ERR,"The strhex is NULL");
							break;
						}
						string_to_hex(strhex,debug_buf);
						//string_to_hex(dataBuf,debug_buf);
						for(i = 0; i < atoi(nvram_safe_get("debug_num")); i++)
						{
							sprintf(&out_buf[i*3],"%02x ",debug_buf[i]);
						}
						syslog(LOG_INFO,"Read Socket-->%s",out_buf);
				}
                en_queue(svr_buf_queue, dataBuf, n);
                show_queue_element(svr_buf_queue);
            }
        }

        if (FD_ISSET(serialFd, &rset))
        {
            if (is_queue_full(serial_buf_queue) == 0)
            {
                memset(dataBuf, 0, dtuConf->data.max_len);

                n = get_queue_empty_length(serial_buf_queue);
                int req_len = dtuConf->data.max_len > n ? n : dtuConf->data.max_len;
                n = read_timeout(serialFd, dataBuf, req_len, dtuConf->data.serial_timeout);
                if (n < 0)
                {
                    break;
                }
                en_queue(serial_buf_queue, dataBuf, n);

				if(nvram_match("debug_enable","1"))
					{
						memset(debug_buf,0,sizeof(debug_buf));
						memset(out_buf,0,sizeof(out_buf));
					//	outlen = String2Bytes(dataBuf,debug_buf,n);
						if(str_to_hex(dataBuf,strhex) == NULL)
						{
							syslog(LOG_NOTICE, "Read serialFd");
							syslog(LOG_ERR,"The strhex is NULL");
							break;
						}
						string_to_hex(strhex,debug_buf);
					//	string_to_hex(dataBuf,debug_buf);
						for(i = 0; i < atoi(nvram_safe_get("debug_num")); i++)
						{
							sprintf(&out_buf[i*3],"%02x ",debug_buf[i]);
						}
						syslog(LOG_INFO,"Read Serial-->%s",out_buf);
				}
                show_queue_element(serial_buf_queue);
            }
        }
	}

err_quit:
    if (serial_buf_queue != NULL)
    {
        destroy_queue(&serial_buf_queue);
    }

    if (svr_buf_queue != NULL)
    {
        destroy_queue(&svr_buf_queue);
    }

    if (dataBuf != NULL)
    {
        free(dataBuf);
    }

    if (serialFd > 0)
    {
        close(serialFd);
    }

	if(nvram_match("ipoc_mqtt_mode", 1) && (dtuConf->mode == DTU_MODE_CLIENT))
	{
		mqtt_disconnect(&broker);
	}

    if (sockFd > 0)
    {
        close(sockFd);
    }

    return (ret);
}

/*
int switch_multiSvr_data(int serialFd, DTU_CONFIG_T *dtuConf)
{
    int ret = -1;
    int maxfd = -1;
    fd_set rset, wset;
    struct timeval tv;
    CIRCLEQUEUE_T *svr_buf_queue[MAX_SVR_CENTER], *serial_buf_queue[MAX_SVR_CENTER];
    int index;
    char *dataBuf;
    int n;

    dataBuf = (char *)malloc(dtuConf->data.max_len * sizeof(char));
    if (dataBuf == NULL)
    {
        goto err_quit;
    }

    for (index = 0; index < MAX_SVR_CENTER; index++)
    {
        ret = init_queue(&svr_buf_queue[index], MAX_CIRCLE_QUEUE_SIZE);
        if (ret < 0)
        {
            goto err_quit;
        }
    }

    for (index = 0; index < MAX_SVR_CENTER; index++)
    {
        ret = init_queue(&serial_buf_queue[index], MAX_CIRCLE_QUEUE_SIZE);
        if (ret < 0)
        {
            goto err_quit;
        }
    }

    maxfd = get_max_fd(m_newbei_multsvr_socketFd);
    maxfd = maxfd > serialFd ? maxfd : serialFd;

    while ( 1 )
    {
        FD_ZERO(&rset);
        FD_ZERO(&wset);

        FD_SET(serialFd, &rset);
        for (index = 0; index < MAX_SVR_CENTER; index++)
        {
            if (m_newbei_multsvr_socketFd[index] > 0)
            {
                FD_SET(m_newbei_multsvr_socketFd[index], &rset);
            }
        }


        for (index = 0; index < MAX_SVR_CENTER; index++)
        {
            if (is_queue_empty(serial_buf_queue[index]) == 0)
            {
                if (m_newbei_multsvr_socketFd[index] > 0)
                {
                    FD_SET(m_newbei_multsvr_socketFd[index], &wset);
                }
            }
        }

        for (index = 0; index < MAX_SVR_CENTER; index++)
        {
            if (is_queue_empty(svr_buf_queue[index]) == 0)
            {
                FD_SET(serialFd, &wset);
            }
        }
        tv.tv_sec = dtuConf->heartbeat.heartbeat_interval;
        tv.tv_usec = 0;
        //syslog(LOG_INFO, "1110");

        ret = select(maxfd + 1, &rset, &wset, NULL, &tv);
        if (ret < 0)
        {
            if (errno != EINTR && errno != EAGAIN)
            {
                syslog(LOG_ERR, "Select Error( return:%d errno:%d )", ret , errno );
                goto err_quit;
            }
        }

        //syslog(LOG_INFO, "1111");
        if (m_send_nb_heartbeat_flag)
        {
            m_send_nb_heartbeat_flag = 0;
            for (index = 0; index < MAX_SVR_CENTER; index++)
            {
            	if (m_newbei_multsvr_socketFd[index] > 0)
            	{
	                if (m_recv_flag[index] >= REDIAL_TIMES)
	                {
	                    syslog(LOG_ERR, "Can not recv ack from server over %d times ", m_recv_flag[index]);
	                    close(m_newbei_multsvr_socketFd[index]);
	                    m_newbei_multsvr_socketFd[index] = -1;
	                    m_recv_flag[index] = 0;
	                }
	                else
	                {
	                	en_queue(serial_buf_queue[index], dtuConf->nb_ht_content, dtuConf->nb_ht_length);
	                	m_recv_flag[index]++;
	                }
                }
            }
        }

        if (serialFd > 0 && FD_ISSET(serialFd, &wset))
        {
            for (index = 0; index < MAX_SVR_CENTER; index++)
            {
                if (is_queue_empty(svr_buf_queue[index]) == 0)
                {
                    //not empty
                    memset(dataBuf, 0, dtuConf->data.max_len);

                    n = de_queue_start(svr_buf_queue[index], dataBuf, dtuConf->data.max_len);
                    n = write_serial_nb(serialFd, dataBuf, n, dtuConf->data.serial_timeout, dtuConf);
                    if (n < 0)
                    {
                        ret = -1;
                        goto err_quit;
                    }
                    de_queue_done(svr_buf_queue[index], n);
                }
            }
        }

        for (index = 0; index < MAX_SVR_CENTER; index++)
        {
            if (m_newbei_multsvr_socketFd[index] > 0 && FD_ISSET(m_newbei_multsvr_socketFd[index], &wset))
            {
                if (is_queue_empty(serial_buf_queue[index]) == 0)
                {
                    //not empty
                    memset(dataBuf, 0, dtuConf->data.max_len);
                    n = de_queue_start(serial_buf_queue[index], dataBuf, dtuConf->data.max_len);
                    n = write_socket_nb(m_newbei_multsvr_socketFd[index], dataBuf, n, dtuConf->data.timeout, dtuConf);
                    if (n < 0)
                    {
                        close(m_newbei_multsvr_socketFd[index]);
                        m_newbei_multsvr_socketFd[index] = -1;
                        continue ;
                    }
                    de_queue_done(serial_buf_queue[index], n);
                }
            }
        }


        //syslog(LOG_INFO, "1114");
        if (serialFd > 0 && FD_ISSET(serialFd, &rset))
        {
            memset(dataBuf, 0, dtuConf->data.max_len);

            n = read_timeout(serialFd, dataBuf, dtuConf->data.max_len, dtuConf->data.serial_timeout);
            if (n < 0)
            {
                ret = -1;
                break;
            }

            for (index = 0; index < MAX_SVR_CENTER; index++)
            {
                if (is_queue_full(serial_buf_queue[index]) == 0)
                {
                    en_queue(serial_buf_queue[index], dataBuf, n);
                    show_queue_element(serial_buf_queue[index]);
                }
            }
        }

        //syslog(LOG_INFO, "1115");

        for (index = 0; index < MAX_SVR_CENTER; index++)
        {
            if (m_newbei_multsvr_socketFd[index] > 0 && FD_ISSET(m_newbei_multsvr_socketFd[index], &rset))
            {
                if (is_queue_full(svr_buf_queue[index]) == 0)
                {
                    memset(dataBuf, 0, dtuConf->data.max_len);
                    n = get_queue_empty_length(svr_buf_queue[index]);
                    int req_len = dtuConf->data.max_len > n ? n : dtuConf->data.max_len;

                    n = read_socket_nb(m_newbei_multsvr_socketFd[index], dataBuf, req_len, dtuConf->data.timeout, dtuConf);
                    if (n < 0)
                    {
                        close(m_newbei_multsvr_socketFd[index]);
                        m_newbei_multsvr_socketFd[index] = -1;
                        continue;
                    }

                    en_queue(svr_buf_queue[index], dataBuf, n);
                    show_queue_element(svr_buf_queue[index]);
                }
            }
        }

    }

err_quit:
    for (index = 0; index < MAX_SVR_CENTER; index++)
    {
        if (svr_buf_queue[index] != NULL)
        {
            destroy_queue(&svr_buf_queue[index]);
        }
    }

    for (index = 0; index < MAX_SVR_CENTER; index++)
    {
        if (serial_buf_queue[index] != NULL)
        {
            destroy_queue(&serial_buf_queue[index]);
        }
    }

    for (index = 0; index < MAX_SVR_CENTER; index++)
    {
        if (m_newbei_multsvr_socketFd[index] > 0)
        {
            close(m_newbei_multsvr_socketFd[index]);
            m_newbei_multsvr_socketFd[index] = -1;
        }
    }

    if (dataBuf)
    {
        free(dataBuf);
    }

    return (ret);
}
*/

void sigroutine(int signo)
{
    m_send_nb_heartbeat_flag = 1;
}


void *connect_multi_svr_rtn(void *arg)
{
    int index = 0, ret, len;
    int lis_fd = -1, acc_fd, sock_fd;
    DTU_CONFIG_T *dtuConfig = (DTU_CONFIG_T *)arg;
    struct sockaddr_in acc_addr;
    int ip;
    char *svr_addr_ptr, *svr_port_ptr;
    int svr_con_timeout;


    pthread_detach(pthread_self( ));

    while (1)
    {
        switch (dtuConfig->mode)
        {
        case DTU_MODE_SERVER:
            if (DTU_SOCKET_UDP == dtuConfig->protocol)
            {
                syslog(LOG_INFO,  "UDP Server Mode, no need connect thread, quit");
                return NULL;
            }

            syslog(LOG_INFO,  "TCP Server Mode, the max connection = %d", MAX_SVR_CENTER);
            if (lis_fd < 0)
            {
                lis_fd = create_tcp_listen_socket((unsigned short)atoi(dtuConfig->local.svr_port));
                if (lis_fd < 0)
                {
                    sleep(5);
                    continue;
                }
            }

            ret = wait_rsock(lis_fd, 5, 0);
            if (ret > 0)
            {
                bzero(&acc_addr, sizeof(struct sockaddr_in));
                len = sizeof(struct sockaddr_in);
                acc_fd = accept(lis_fd, (struct sockaddr *)&acc_addr, &len);
                if (acc_fd < 0)
                {
                    close(lis_fd);
                    lis_fd = -1;
                    continue ;
                }
                else
                {
                    for (index = 0; index < MAX_SVR_CENTER; index++)
                    {
                        if (m_newbei_multsvr_socketFd[index] < 0)
                        {
                            m_newbei_multsvr_socketFd[index] = acc_fd;
                        }
                    }

                    if (index == MAX_SVR_CENTER)
                    {
                        syslog(LOG_INFO, "TCP Server reaches the max connection");
                    }
                    continue ;
                }
            }
            else if (ret < 0)
            {
                sleep(5);
            }
            break;

        case DTU_MODE_CLIENT:
            for (index = 0; index < MAX_SVR_CENTER; index++)
            {
                if (m_newbei_multsvr_socketFd[index] < 0)
                {
                    svr_addr_ptr = dtuConfig->server[index].svr_addr;
                    svr_port_ptr = dtuConfig->server[index].svr_port;
                    svr_con_timeout = dtuConfig->server[0].svr_connect_timeout ;

                    if((0 == *svr_addr_ptr) || (0 == *svr_port_ptr))
                    {
                        continue;
                    }

                    (void)domain_to_ip(svr_addr_ptr, &ip);
                    if (DTU_SOCKET_UDP == dtuConfig->protocol)
                    {
                        sock_fd = connect_udp_host(ip , atoi(svr_port_ptr), atoi(dtuConfig->local.svr_port));
                        if (sock_fd < 0)
                        {
                            syslog(LOG_ERR, "UDP Failed to connect(%s:%s)", svr_addr_ptr, svr_port_ptr);
                            //sleep(svr_con_itv);
                            continue;
                        }

                        syslog(LOG_ERR, "UDP Connected the (%s:%s)--->svr[%d]", svr_addr_ptr, svr_port_ptr, index);
                        m_newbei_multsvr_socketFd[index] = sock_fd;
                        m_recv_flag[index] = 0;
                        (void)write_socket_nb(m_newbei_multsvr_socketFd[index], dtuConfig->nb_ht_content, dtuConfig->nb_ht_length, dtuConfig->data.timeout, dtuConfig);
                		m_recv_flag[index]++;
                    }
                    else
                    {
                        sock_fd = connect_tcp_host(ip, atoi(svr_port_ptr), svr_con_timeout);
                        if (sock_fd < 0)
                        {
                            syslog(LOG_ERR, "TCP Failed to connect(%s:%s)", svr_addr_ptr, svr_port_ptr );
                            //sleep( svr_con_itv );
                            continue;
                        }

                        syslog(LOG_ERR, "TCP connected the (%s:%s)--->svr[%d]", svr_addr_ptr, svr_port_ptr, index);
                        m_newbei_multsvr_socketFd[index] = sock_fd;
                        m_recv_flag[index] = 0;
                        (void)write_socket_nb(m_newbei_multsvr_socketFd[index], dtuConfig->nb_ht_content, dtuConfig->nb_ht_length, dtuConfig->data.timeout, dtuConfig);
                		m_recv_flag[index]++;
                    }
                }
            }

            sleep(5);
            break;

        default:
            syslog(LOG_ERR, "Illegal mode, unsupport.");
            return NULL;
        }
    }

    return NULL;
}

#if 0
int newbei_data_process(int serialFd, DTU_CONFIG_T *dtuConfig, SERIAL_CONFIG_T *serConf, MQTT_CONFIG_T *mqttConf)
{
    int index = 0, errCount = 0, connFlag = 0;

    pthread_t conn_thread_id;

    for (index = 0; index < MAX_SVR_CENTER; index++)
    {
        m_newbei_multsvr_socketFd[index] = -1;
    }

    if (pthread_create(&conn_thread_id, NULL, connect_multi_svr_rtn, (void *)dtuConfig) < 0)
    {
        syslog(LOG_ERR, "create connect multi svr thread failed");
        return -1;
    }

    if (strcmp(dtuConfig->relay_proto, "newbei") == 0)
    {
        m_pl2303_com_sockfd = create_unix_socket(DTU_SOCK);
    }

    if (strcmp(dtuConfig->relay_proto, "newbei") == 0)
    {
        struct itimerval val, old_val;

        val.it_value.tv_sec = dtuConfig->heartbeat.heartbeat_interval;
        val.it_value.tv_usec = 0;

        val.it_interval.tv_sec = dtuConfig->heartbeat.heartbeat_interval;
        val.it_interval.tv_usec = 0;

        signal(SIGALRM, sigroutine);
        setitimer(ITIMER_REAL, &val, &old_val);
    }

    while (1)
    {
        for (index = 0; index < MAX_SVR_CENTER; index++)
            m_recv_flag[index] = 0;

        if (DTU_MODE_SERVER == dtuConfig->mode && DTU_SOCKET_UDP == dtuConfig->protocol)
        {
            syslog(LOG_INFO, "Serial APP: UDP Server Mode" );
            m_newbei_multsvr_socketFd[0] = create_udp_socket(dtuConfig);
            if (m_newbei_multsvr_socketFd[0] < 0)
            {
                sleep(5);
                continue;
            }
        }

        connFlag = 0;
        for (index = 0; index < MAX_SVR_CENTER; index++)
        {
            if (m_newbei_multsvr_socketFd[index] > 0)
            {
                connFlag = 1;
                break;
            }
        }

        if (connFlag == 1)
        {
            switch_multiSvr_data(serialFd, dtuConfig);
        }
        else
        {
            sleep(2);
            continue;
        }

        struct termios old_term;
        serialFd = -1;
        while (serialFd < 0)
        {
		if(nvram_match("port_type","1"))    //RS485/RS232
		{
			serialFd = open_serial(SERIAL, &old_term);
			if (serialFd < 0)
    		{
    			syslog(LOG_ERR, "[%s]-->: Open serial %s Failed", newbei_hook.name, SERIAL);
    		//	return (-1);
				break;
    		}
		}
		else
		{       
			serialFd = open_serial(CONSOLE, &old_term);
			if (serialFd < 0)
    		{
    			syslog(LOG_ERR, "[%s]-->: Open serial %s Failed", newbei_hook.name, CONSOLE);
    		//	return (-1);
				break;
    		}
		}
		

		if (init_serial(serialFd, serConf) < 0)
		{
			syslog(LOG_ERR, "[%s]-->: Init serial %s Failed", newbei_hook.name, newbei_hook.portName);
			close_serial(serialFd, &old_term);
			return (-1);
			
		}
        if(nvram_match("port_type","1"))    //RS485/RS232
        {
            syslog(LOG_INFO, "[%s]-->: Open serial %s succ, fd = %d", newbei_hook.name, SERIAL, serialFd);
        }
        else
        {

            syslog(LOG_INFO, "[%s]-->: Open serial %s succ, fd = %d", newbei_hook.name, CONSOLE, serialFd);
        }
		
        }
        errCount++;
        sleep(3);

        if (errCount > 3)
        {
            break;
        }
    }

    return 0;
}
#endif

int dtu_data_process(int serialFd, DTU_CONFIG_T *dtuConfig, SERIAL_CONFIG_T *serConf, MQTT_CONFIG_T *mqttConf)
{
    int count = 0;
    int socketFd;

    while (1)
    {
        if (DTU_MODE_SERVER == dtuConfig->mode)
        {
            syslog(LOG_INFO,  "Serial APP: Server Mode" );
            if (DTU_SOCKET_TCP == dtuConfig->protocol)
            {
                syslog(LOG_INFO,  "TCP Server Mode" );
                if ((socketFd = create_tcp_socket(dtuConfig)) < 0)
                {
                    sleep(5);
                    continue;
                }
            }
            else
            {
                syslog(LOG_INFO, "Serial APP: UDP Server Mode" );
                if ((socketFd = create_udp_socket(dtuConfig)) < 0)
                {
                    sleep(5);
                    continue;
                }
            }
        }
        else
        {
            syslog(LOG_INFO, "Serial APP: Client Mode");
            if ((socketFd = connect_server(dtuConfig)) < 0)
            {
                sleep(dtuConfig->reconnect_interval);
                continue;
			}
			//if enable MQTT
			if(nvram_match("ipoc_mqtt_mode", "1"))
			{
				if(mqtt_connect_server(socketFd, mqttConf) < 0)
				{
					syslog(LOG_ERR, "Connect to MQTT Server Fail");

        	        sleep(5);
        	        continue;
				}
				syslog(LOG_INFO, "Connect to mqtt server success.");
			}
		}
		
		//add by jerry,clean dtu serial cache
		if(nvram_match("cache_enable","0"))
		{
			tcflush(serialFd, TCIOFLUSH);
			syslog(LOG_INFO,"Clean serial cache!");
		}

		switch_data(serialFd, socketFd, dtuConfig, mqttConf);

		syslog(LOG_NOTICE, "socket disconnect, restarting");

    	struct termios old_term;
    	serialFd = -1;
    	socketFd = -1;

		while (serialFd < 0)
		{
			if(nvram_match("port_type","1"))    //RS485/RS232
			{
				serialFd = open_serial(SERIAL, &old_term);
    			if (serialFd < 0)
    			{
    				syslog(LOG_ERR, "[%s]-->: Open serial %s Failed", dtu_hook.name, SERIAL);
    			//	return (-1);
					break;
    			}
			}
			else
			{       
				serialFd = open_serial(CONSOLE, &old_term);
				if (serialFd < 0)
    			{
    				syslog(LOG_ERR, "[%s]-->: Open serial %s Failed", dtu_hook.name, CONSOLE);
    			//	return (-1);
					break;
    			}
			}		

    	    if (init_serial(serialFd, serConf) < 0)
    	    {
    	        syslog(LOG_ERR, "[%s]-->: Init serial %s Failed", dtu_hook.name, dtu_hook.portName);
    	        close_serial(serialFd, &old_term);
    	        return (-1);
    	    }

			if(nvram_match("port_type","1"))    //RS485/RS232
			{
    	        syslog(LOG_INFO, "[%s]-->: Open serial %s succ, fd = %d", dtu_hook.name, SERIAL, serialFd);
			}
			else
			{
    	        syslog(LOG_INFO, "[%s]-->: Open serial %s succ, fd = %d", dtu_hook.name, CONSOLE, serialFd);
			}
		}
        count++;
        sleep(3);

        if (count > 3)
            break;
    }

    return 0;
}


static int which_serial(char *port_name)
{
    char tmp[128];
    MODEM_TO_PORT_TABLE *table;
    int exsit_flag = 0;

#ifdef TCONFIG_OUTERGPS
    strcpy(port_name, "/dev/ttyS0");
    return 0;
#endif

    strncpy(tmp, nvram_safe_get("modem_type"),sizeof(tmp));
    syslog(LOG_INFO, "the modem_type is :%s",tmp);
#ifdef TCONFIG_R21_HW
    for(table = &r21_modem_table[0]; table->modem_name; table++)
#else
    for(table = &modem_table[0]; table->modem_name; table++)
#endif
    {
    	if(strstr(tmp,table->modem_name) != NULL)
	{
		
		strcpy(port_name, table->port_name);
		exsit_flag = 1;
		syslog(LOG_INFO, "find the match port:%s",table->port_name);
		break;
	}
    
    }

    if(exsit_flag == 0)
    {
        syslog(LOG_INFO, "Can not find the match port!");
        return -1;
    }
    return 0;
}

void *process_gps_data_rtn(void *arg)
{
    DTU_CONFIG_T dtuConf;
    SERIAL_CONFIG_T serConf;
	MQTT_CONFIG_T mqttConf;
    int serialFd = -1;
    struct termios old_term;
    char dev_port[24] = {0};
    int ret;


    pthread_detach(pthread_self( ));

    nvram_set("gps_valid", "N/A");
    if (strcmp(nvram_safe_get("dtu_mode1"), "disable") == 0)
    {
        while (1)
        {
            syslog(LOG_ERR, "[IPoC]-->: GPS disabled");
            pause( );
        }
    }

    if (nvram_match("gps_data", "relay"))
    {
        if (gps_nmea_hook.init_config)
        {
            gps_nmea_hook.init_config(&dtuConf, &serConf, &mqttConf);
        }
#if 0
        while (serialFd < 0)
        {
            memset(dev_port, 0, sizeof(dev_port));
            ret = which_serial(dev_port);
            if (ret < 0)
            {
                serialFd = open_serial(gps_nmea_hook.portName, &old_term);
                if (serialFd < 0)
                {
                    syslog(LOG_ERR, "[%s]-->: Open serial %s Failed", gps_nmea_hook.name, gps_nmea_hook.portName);
                    return NULL;
                }
		syslog(LOG_INFO, "[%s]-->: Open serial %s succ, fd = %d", gps_nmea_hook.name,gps_nmea_hook.portName, serialFd);
            }
            else
            {
                serialFd = open_serial(dev_port, &old_term);
                if (serialFd < 0)
                {
                    syslog(LOG_ERR, "[%s]-->: Open serial %s Failed", gps_nmea_hook.name, dev_port);
                    return NULL;
                }
		syslog(LOG_INFO, "[%s]-->: Open serial %s succ, fd = %d", gps_nmea_hook.name,dev_port, serialFd);
            }


            if (init_serial(serialFd, &serConf) < 0)
            {
                syslog(LOG_ERR, "[%s]-->: Init serial %s Failed", gps_nmea_hook.name, gps_nmea_hook.portName);
                close_serial(serialFd, &old_term);
                return NULL;
            }

        }
#endif
        gps_nmea_hook.data_process(serialFd, &dtuConf, &serConf, &mqttConf);
    }
    else
    {
        if (gps_m2m_hook.init_config)
        {
            gps_m2m_hook.init_config(&dtuConf, &serConf, &mqttConf);
        }

        while (serialFd < 0)
        {
            memset(dev_port, 0, sizeof(dev_port));
            ret = which_serial(dev_port);
            if (ret < 0)
            {
                serialFd = open_serial(gps_m2m_hook.portName, &old_term);
                if (serialFd < 0)
                {
                    syslog(LOG_ERR, "[%s]-->: Open serial %s Failed", gps_m2m_hook.name, gps_m2m_hook.portName);
                    return NULL;
                }
		syslog(LOG_INFO, "[%s]-->: Open serial %s succ, fd = %d", gps_m2m_hook.name, gps_m2m_hook.portName, serialFd);
            }
            else
            {
                serialFd = open_serial(dev_port, &old_term);
                if (serialFd < 0)
                {
                    syslog(LOG_ERR, "[%s]-->: Open serial %s Failed", gps_m2m_hook.name, dev_port);
                    return NULL;
                }
		syslog(LOG_INFO, "[%s]-->: Open serial %s succ, fd = %d", gps_m2m_hook.name, dev_port, serialFd);
            }

            if (init_serial(serialFd, &serConf) < 0)
            {
                syslog(LOG_ERR, "[%s]-->: Init serial %s Failed", gps_m2m_hook.name, gps_m2m_hook.portName);
                close_serial(serialFd, &old_term);
                return NULL;
            }

        }

        gps_m2m_hook.data_process(serialFd, &dtuConf, &serConf, &mqttConf);
    }

    return NULL;
}
void *double_process_gps_data_rtn(void *arg)
{
    DTU_CONFIG_T dtuConf;
    SERIAL_CONFIG_T serConf;
	MQTT_CONFIG_T mqttConf;
    int serialFd = -1;
    struct termios old_term;
    char dev_port[24] = {0};
    int ret;


    pthread_detach(pthread_self( ));

    if (strcmp(nvram_safe_get("dtu_mode1"), "disable") == 0)
    {
        while (1)
        {
            syslog(LOG_ERR, "[IPoC]-->: GPS disabled");
            pause( );
        }
    }

    if (nvram_match("gps_data", "relay"))
    {
        if (double_gps_nmea_hook.init_config)
        {
            double_gps_nmea_hook.init_config(&dtuConf, &serConf, &mqttConf);
        }
        while (serialFd < 0)
        {
        	memset(dev_port, 0, sizeof(dev_port));
        	ret = which_serial(dev_port);
        	if (ret < 0)
        	{
            	serialFd = open_serial(double_gps_nmea_hook.portName, &old_term);
            	if (serialFd < 0)
	            {
	                syslog(LOG_ERR, "[%s]-->: Open serial %s Failed", double_gps_nmea_hook.name, double_gps_nmea_hook.portName);
	                return NULL;
	            }
            }
            else
            {
            	serialFd = open_serial(dev_port, &old_term);
            	if (serialFd < 0)
	            {
	                syslog(LOG_ERR, "[%s]-->: Open serial %s Failed", double_gps_nmea_hook.name, dev_port);
	                return NULL;
	            }
            }
           

            if (init_serial(serialFd, &serConf) < 0)
            {
                syslog(LOG_ERR, "[%s]-->: Init serial %s Failed", double_gps_nmea_hook.name, double_gps_nmea_hook.portName);
                close_serial(serialFd, &old_term);
                return NULL;
            }

            syslog(LOG_INFO, "[%s]-->: Open serial %s succ, fd = %d", double_gps_nmea_hook.name, double_gps_nmea_hook.portName, serialFd);
        }

        double_gps_nmea_hook.data_process(serialFd, &dtuConf, &serConf, &mqttConf);
    }
    else
    {
        if (double_gps_m2m_hook.init_config)
        {
            double_gps_m2m_hook.init_config(&dtuConf, &serConf, &mqttConf);
        }

        while (serialFd < 0)
        {
            memset(dev_port, 0, sizeof(dev_port));
            ret = which_serial(dev_port);
            if (ret < 0)
            {
                serialFd = open_serial(double_gps_m2m_hook.portName, &old_term);
                if (serialFd < 0)
                {
                    syslog(LOG_ERR, "[%s]-->: Open serial %s Failed", double_gps_m2m_hook.name, double_gps_m2m_hook.portName);
                    return NULL;
                }
            }
            else
            {
                serialFd = open_serial(dev_port, &old_term);
                if (serialFd < 0)
                {
                    syslog(LOG_ERR, "[%s]-->: Open serial %s Failed", double_gps_m2m_hook.name, dev_port);
                    return NULL;
                }
            }

            if (init_serial(serialFd, &serConf) < 0)
            {
                syslog(LOG_ERR, "[%s]-->: Init serial %s Failed", double_gps_m2m_hook.name, double_gps_m2m_hook.portName);
                close_serial(serialFd, &old_term);
                return NULL;
            }

           syslog(LOG_INFO, "[%s]-->: Open serial %s succ, fd = %d", double_gps_m2m_hook.name, double_gps_m2m_hook.portName, serialFd);
        }

        double_gps_m2m_hook.data_process(serialFd, &dtuConf, &serConf, &mqttConf);
    }

    return NULL;
}


int dtu_main(int argc, char *argv[])
{
    DTU_CONFIG_T dtuConf;
    SERIAL_CONFIG_T serConf;
	MQTT_CONFIG_T mqttConf;
    int serialFd = -1;
    struct termios old_term;
    pthread_t gps_id;
    //char port_dev[24];
    openlog("dtu", LOG_PID, LOG_USER);

    init_deamon( );

/*
#ifdef TCONFIG_DOUBLE_GPS
    if (pthread_create(&gps_id, NULL, (void *)double_process_gps_data_rtn, NULL) != 0)
    {
        syslog(LOG_ERR, "Failed to Create Heartbeat Thread");
        return -1;
    }
#else
	if (pthread_create(&gps_id, NULL, (void *)process_gps_data_rtn, NULL) != 0)
    {
        syslog(LOG_ERR, "Failed to Create Heartbeat Thread");
        return -1;
    }
#endif
*/
	if(nvram_match("ipoc_mode","modbus"))
	{   
		syslog(LOG_INFO, "Start Modbus Progress!");
		//start_modbus();
	}
	else
	{
		if (strcmp(nvram_safe_get("dtu_mode"), "disable") == 0)
		{
			while (1)
			{
				syslog(LOG_ERR, "[IPoC]-->: IPoC disabled");
				pause( );
			}
		}

#if 0
		if (nvram_match("relay_proto", "newbei"))
		{
			if (newbei_hook.init_config)
			{
				newbei_hook.init_config(&dtuConf, &serConf);
			}

			while (serialFd < 0)
			{
				if(nvram_match("port_type","1"))    //RS485/RS232
				{
					serialFd = open_serial(SERIAL, &old_term);
					if (serialFd < 0)
    				{
    					syslog(LOG_ERR, "[%s]-->: Open serial %s Failed", newbei_hook.name, SERIAL);
    				//	return (-1);
						break;
    				}
				}
				else
				{
					serialFd = open_serial(CONSOLE, &old_term);
					if (serialFd < 0)
    				{
    					syslog(LOG_ERR, "[%s]-->: Open serial %s Failed", newbei_hook.name, CONSOLE);
    			//		return (-1);
						break;
    				}
				}

				if (init_serial(serialFd, &serConf) < 0)
				{
					syslog(LOG_ERR, "[%s]-->: Init serial %s Failed", newbei_hook.name, newbei_hook.portName);
					close_serial(serialFd, &old_term);
					return (-1);
				}
                if(nvram_match("port_type","1"))    //RS485/RS232
				{
                    syslog(LOG_INFO, "[%s]-->: Open serial %s succ, fd = %d", newbei_hook.name, SERIAL, serialFd);
				}
				else
				{
                    syslog(LOG_INFO, "[%s]-->: Open serial %s succ, fd = %d", newbei_hook.name, CONSOLE, serialFd);
				}
			}

			newbei_hook.data_process(serialFd, &dtuConf, &serConf);
		}
#endif
	//	else
    //	{
    	    if (dtu_hook.init_config)
    	    {
    	        dtu_hook.init_config(&dtuConf, &serConf, &mqttConf);
    	    }

			while (serialFd < 0)
			{
				if(nvram_match("port_type","1"))    //RS485/RS232
				{
					serialFd = open_serial(SERIAL, &old_term);
					if (serialFd < 0)
    				{
    					syslog(LOG_ERR, "[%s]-->: Open serial %s Failed", dtu_hook.name, SERIAL);
    				//	return (-1);
						break;
    				}
				}
				else
				{       
					serialFd = open_serial(CONSOLE, &old_term);
					if (serialFd < 0)
    				{
    					syslog(LOG_ERR, "[%s]-->: Open serial %s Failed", dtu_hook.name, CONSOLE);
    				//	return (-1);
						break;
    				}
				}

				if (init_serial(serialFd, &serConf) < 0)
				{
					syslog(LOG_ERR, "[%s]-->: Init serial %s Failed", dtu_hook.name, dtu_hook.portName);
					close_serial(serialFd, &old_term);
					return (-1);
				}
				if(nvram_match("port_type","1"))    //RS485/RS232
				{
                    syslog(LOG_INFO, "[%s]-->: Open serial %s succ, fd = %d", dtu_hook.name, SERIAL, serialFd);
				}
				else
				{
                    syslog(LOG_INFO, "[%s]-->: Open serial %s succ, fd = %d", dtu_hook.name, CONSOLE, serialFd);
				}
			}

			dtu_hook.data_process(serialFd, &dtuConf, &serConf, &mqttConf);
	//	}
	}
	return 0;
}

