#include "rc.h"
#include    "m2m.h"

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
unsigned char product_id[16];
unsigned char product_report_id[24];
unsigned int packet_id = 0;
unsigned int report_packet_id = 0;
int serialFd = -1;
int req_file_finish_flag = 0;
char filename[128] = {0};

char g_query_ack=0;
char g_m2m_sms_ack=0;
int g_login_ack=0,g_report_status_ack=0,g_sync_time_ack=0,r_login_ack = 0, r_report_status_ack = 0;
int g_tcp_serial_num=0;
unsigned long g_m2m_server_ip = 0;
ST_PACKET_CAP g_pcap_info;
int g_pcap_working=0;
int g_get_cap_upload_ack=0;

ST_DOWNLOAD_INFO *g_down_info;

#define tcp_down_def_size 	64000
#define tcp_down_recv_size 	64029
#define udp_down_def_size 	2048	
#define udp_down_recv_size 	2077

FILE *g_recv_file_fd=NULL;
int g_get_file_req_ack=0;
typedef struct _MAC_LIST
{
    char mac[18];
    int rssi;
} MAC_LIST;

baudmap_st baudtable_st[] =
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
static const uint8_t table_crc_hi[] =
{
    0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0,
    0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
    0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0,
    0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40,
    0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1,
    0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41,
    0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1,
    0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
    0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0,
    0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40,
    0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1,
    0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40,
    0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0,
    0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40,
    0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0,
    0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40,
    0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0,
    0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
    0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0,
    0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
    0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0,
    0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40,
    0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1,
    0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
    0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0,
    0x80, 0x41, 0x00, 0xC1, 0x81, 0x40
};
/* Table of CRC values for low-order byte */
static const uint8_t table_crc_lo[] =
{
    0x00, 0xC0, 0xC1, 0x01, 0xC3, 0x03, 0x02, 0xC2, 0xC6, 0x06,
    0x07, 0xC7, 0x05, 0xC5, 0xC4, 0x04, 0xCC, 0x0C, 0x0D, 0xCD,
    0x0F, 0xCF, 0xCE, 0x0E, 0x0A, 0xCA, 0xCB, 0x0B, 0xC9, 0x09,
    0x08, 0xC8, 0xD8, 0x18, 0x19, 0xD9, 0x1B, 0xDB, 0xDA, 0x1A,
    0x1E, 0xDE, 0xDF, 0x1F, 0xDD, 0x1D, 0x1C, 0xDC, 0x14, 0xD4,
    0xD5, 0x15, 0xD7, 0x17, 0x16, 0xD6, 0xD2, 0x12, 0x13, 0xD3,
    0x11, 0xD1, 0xD0, 0x10, 0xF0, 0x30, 0x31, 0xF1, 0x33, 0xF3,
    0xF2, 0x32, 0x36, 0xF6, 0xF7, 0x37, 0xF5, 0x35, 0x34, 0xF4,
    0x3C, 0xFC, 0xFD, 0x3D, 0xFF, 0x3F, 0x3E, 0xFE, 0xFA, 0x3A,
    0x3B, 0xFB, 0x39, 0xF9, 0xF8, 0x38, 0x28, 0xE8, 0xE9, 0x29,
    0xEB, 0x2B, 0x2A, 0xEA, 0xEE, 0x2E, 0x2F, 0xEF, 0x2D, 0xED,
    0xEC, 0x2C, 0xE4, 0x24, 0x25, 0xE5, 0x27, 0xE7, 0xE6, 0x26,
    0x22, 0xE2, 0xE3, 0x23, 0xE1, 0x21, 0x20, 0xE0, 0xA0, 0x60,
    0x61, 0xA1, 0x63, 0xA3, 0xA2, 0x62, 0x66, 0xA6, 0xA7, 0x67,
    0xA5, 0x65, 0x64, 0xA4, 0x6C, 0xAC, 0xAD, 0x6D, 0xAF, 0x6F,
    0x6E, 0xAE, 0xAA, 0x6A, 0x6B, 0xAB, 0x69, 0xA9, 0xA8, 0x68,
    0x78, 0xB8, 0xB9, 0x79, 0xBB, 0x7B, 0x7A, 0xBA, 0xBE, 0x7E,
    0x7F, 0xBF, 0x7D, 0xBD, 0xBC, 0x7C, 0xB4, 0x74, 0x75, 0xB5,
    0x77, 0xB7, 0xB6, 0x76, 0x72, 0xB2, 0xB3, 0x73, 0xB1, 0x71,
    0x70, 0xB0, 0x50, 0x90, 0x91, 0x51, 0x93, 0x53, 0x52, 0x92,
    0x96, 0x56, 0x57, 0x97, 0x55, 0x95, 0x94, 0x54, 0x9C, 0x5C,
    0x5D, 0x9D, 0x5F, 0x9F, 0x9E, 0x5E, 0x5A, 0x9A, 0x9B, 0x5B,
    0x99, 0x59, 0x58, 0x98, 0x88, 0x48, 0x49, 0x89, 0x4B, 0x8B,
    0x8A, 0x4A, 0x4E, 0x8E, 0x8F, 0x4F, 0x8D, 0x4D, 0x4C, 0x8C,
    0x44, 0x84, 0x85, 0x45, 0x87, 0x47, 0x46, 0x86, 0x82, 0x42,
    0x43, 0x83, 0x41, 0x81, 0x80, 0x40
};

char* router_config[] =
{
    "dhcp_start",
    "dhcp_num"
    "iot_report_interval",
    "iot_cycle_interval",
    "sch_rboot",
    "http_username",
    "http_passwd",
    "icmp_keepalive",
    "ND_enable",
    "GatewayName",
    "RedirectURL",
    "ClientForceTimeout",
    "ClientIdleTimeout",
    "TrafficControl",
    "totaldownrate",
    "nd_traffic_limit",
    "normaldownrate",
    "limiteddownrate",
    "ND_ad_time",
    "mtu_enable",
    "wan_mtu",
    "bk_check_type",
    "bk_check_ping_intval",
    "bk_check_ping_timeout",
    "bk_check_ping_retry",
    "bk_check_ping_addr",
    "bk_check_http_intval",
    "bk_check_http_timeout",
    "bk_check_http_retry",
    "bk_check_http_addr",
    "PingEnable",
    "UtmsPingAddr",
    "UtmsPingAddr1",
    "PingInterval",
    "PingMax",
    "icmp_action",
    "rx_tx_enable",
    "rx_tx_mode",
    "rx_tx_check_int",
    "rx_tx_action",
    "dualsim",
    "main_timeout",
    "backup_timeout",
    "cellType",
    "CelldialPincode",
    "CelldialApn",
    "CelldialUser",
    "CelldialPwd",
    "CelldialNum",
    "auth_type",
    "local_ip",
    "cellType2",
    "CelldialPincode2",
    "CelldialApn2",
    "CelldialUser2",
    "CelldialPwd2",
    "CelldialNum2",
    "auth_type2",
    "local_ip2",
    "lan_ipaddr",
    "lan_netmask",
    "lan_ipaddr1",
    "lan_netmask1",
    "lan_ipaddr2",
    "lan_netmask2",
    "lan_ipaddr3",
    "lan_netmask3",
    "lan_gateway",
    "lan_proto",
    "dhcpd_startip",
    "dhcpd_endip",
    "dhcp_lease",
    "dhcpd_dmdns",
    "wan_dns",
    "wl0_radio",
    "wl0_ssid",
    "wl0_closed",
    "wl0_security_mode",
    "wl0_crypto",
    "wl0_wpa_psk",
    "wl0_bcast",
    "wl1_bcast",
    "wl1_radio",
    "wl1_ssid",
    "wl1_closed",
    "wl1_security_mode",
    "wl1_crypto",
    "wl1_wpa_psk",
    "wl_macmode",
    "wl_maclist",
    "port_forwarding",
    "port_redirecting",
    "port_forwarding",
    "xdog_on",
    "xdog_auth",
    "xdog_root",
    "xdog_whost",
    "xdog_phost",
    "xdog_login_timeout",
    "xdog_idle_timeout",
    "xdog_iglan",
    "xdog_redir",
    "xdog_trustmac",
    "xdog_qos_don",
    "xdog_qos_dt",
    "xdog_qos_ds",
    "xdog_qos_dsc",
    "xdog_qos_uon",
    "xdog_qos_ut",
    "xdog_qos_us",
    "xdog_qos_usc",
    "ipoc_mode",
    "dtu_mode",
    "server_ip",
    "server_port",
    "socket_type",
    "socket_timeout",
    "serial_timeout",
    "packet_len",
    "heartbeat_intval",
    "port_type",
    "debug_enable",
    "debug_num",
    "serial_rate",
    "serial_parity",
    "serial_databits",
    "serial_stopbits",
    "dtu_mode1",
    "gps_data",
    "local_port1",
    "socket_type1",
    "socket_timeout1",
    "serial_timeout1",
    "packet_len1",
    "server_ip1",
    "server_port1",
    "server2_ip1",
    "server2_port1",
    "m2m_product_id_gps",
    "heartbeat_intval1",
    "url_filter",
    "domain_filter",
    "portfilterenabled",
    "defaultfirewallpolicy",
    "vpn_gre",
    "router_name",
    "wan_hostname",
    "wan_domain",
    "tm_sel",
    "tm_dst",
    "tm_tz",
    "ntp_updates",
    "ntp_tdod",
    "ntp_server",
    "storage_udisk",
    "m2m_error_action",
    "m2m_product_id",
    "m2m_server_domain",
    "m2m_server_port",
    "m2m_heartbeat_intval",
    "m2m_heartbeat_retry",
    "url_report_enable",
    "remote_management",
    "n2n_bootmode",
    "n2n_server",
    "vpn_mode",
    "pptp_client_enable",
    "pptp_client_srvip",
    "pptp_client_username",
    "pptp_client_passwd",
    "ipsec1_mode",
    "ipsec1_ext",
    "ipsec1_left",
    "ipsec1_leftsubnet",
    "ipsec1_leftfirewall",
    "ipsec1_right",
    "ipsec1_rightsubnet",
    "ipsec1_rightfirewall",
    "ipsec1_authby",
    "ipsec1_ph1_group",
    "ipsec1_ike_enc",
    "ipsec1_ike_auth",
    "ipsec1_ikelifetime",
    "ipsec1_ph2_group",
    "ipsec1_esp_enc",
    "ipsec1_esp_auth",
    "ipsec1_keylife",
    "ipsec1_pskkey",
    "ipsec1_aggressive",
    "ipsec1_compress",
    "ipsec1_dpdaction",
    "ipsec1_icmp_check",
    "ipsec1_custom1",
    "ipsec1_custom2",
    "ipsec1_custom3",
    "ipsec1_custom4",
    "ipsec2_mode",
    "ipsec2_ext",
    "ipsec2_left",
    "ipsec2_leftsubnet",
    "ipsec2_leftfirewall",
    "ipsec2_right",
    "ipsec2_rightsubnet",
    "ipsec2_rightfirewall",
    "ipsec2_authby",
    "ipsec2_ph1_group",
    "ipsec2_ike_enc",
    "ipsec2_ike_auth",
    "ipsec2_ikelifetime",
    "ipsec2_ph2_group",
    "ipsec2_esp_enc",
    "ipsec2_esp_auth",
    "ipsec2_keylife",
    "ipsec2_pskkey",
    "ipsec2_aggressive",
    "ipsec2_compress",
    "ipsec2_dpdaction",
    "ipsec2_icmp_check",
    "ipsec2_custom1",
    "ipsec2_custom2",
    "ipsec2_custom3",
    "ipsec2_custom4",
    "rtu_pub_interval",
    "modbusCmdTable",
    "iot_cycle_interval",
    "slave_id1",
    "slave_id2",
    "slave_id3",
    "slave_id4",
    "serial_rate1",
    "serial_rate2",
    "serial_rate3",
    "serial_rate4",
    "serial_parity1",
    "serial_parity2",
    "serial_parity3",
    "serial_parity4",
    "serial_databits1",
    "serial_databits2",
    "serial_databits3",
    "serial_databits4",
    "serial_stopbits1",
    "serial_stopbits2",
    "serial_stopbits3",
    "serial_stopbits4",
    NULL
};

struct sockaddr_in fromaddr;
struct sockaddr_in fromaddr_r;
struct sockaddr_in serveraddr;
struct sockaddr_in serveraddr_r;

static int socket_fd = -1;
static int tcp_socket = -1;
SNNODE *head = NULL;

SNNODE *add_sn_to_list(SNNODE *list,unsigned char *sn)
{
    SNNODE *node;
    SNNODE *tmp;

    if(sn == NULL)
    {
        return list;
    }
    node = (SNNODE *)malloc(sizeof(SNNODE));
    if(node == NULL)
    {
        syslog(LOG_INFO,"M2M: malloc failed!");
        return NULL;
    }
    node->next = NULL;
    node->report = 1;
    memcpy(node->sn,sn,SN_LENGTH);
    if(list == NULL)
    {
        list = node;
    }
    else
    {
        tmp = list;
        while(tmp->next)
        {
            tmp = tmp->next;
        }
        tmp->next = node;
    }
    return list;
}
SNNODE *list_free(SNNODE *list)
{
    SNNODE *node;
    SNNODE *tmp;
    if(list)
    {
        node = list;
        while(node->next)
        {
            tmp = node;
            free(tmp);
            node = node->next;
        }
        tmp = node;
        free(tmp);
        list = NULL;
    }
    return list;
}

int check_sn_report_flag(SNNODE *list, unsigned char *sn)
{
    SNNODE *node;
    if(list == NULL)
    {
        return 0;
    }
    node = list;
    while(node->next)
    {
        if(strncmp(node->sn,sn,SN_LENGTH) == 0)
        {
            syslog(LOG_INFO,"1----->sn:%s, report:%d",node->sn,node->report);
            return node->report;
        }
        node = node->next;
    }

    if(strncmp(node->sn,sn,SN_LENGTH) == 0)
    {
        syslog(LOG_INFO,"2----->sn:%s, report:%d",node->sn,node->report);
        return node->report;
    }

    return 0;
}
static void save_term_ios(int serial_fd, struct termios *old_term )
{
    if (tcgetattr(serial_fd, old_term ) < 0)
    {
        exit(0);
    }
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
static void restore_term_ios(int serial_fd, struct termios *old_term )
{
    if (tcsetattr(serial_fd, TCSAFLUSH, old_term ) < 0 )
    {
        exit(0);
    }
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
            continue;
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
            if (errno != EWOULDBLOCK)
            {
                syslog(LOG_ERR,  "Error: Serial Read(%p,%d), %s", data + nread, len - nread, strerror(errno));
                return (-1);
            }
            continue;
        }
        else if (0 == n)
        {
            syslog(LOG_INFO,  "Serial Read(%p,%d) be Closed", data + nread, len - nread);
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
static unsigned char checksum(unsigned char *addr, int count)
{
    unsigned char sum = 0;
    int i;

    for(i = 0; i < count; i++)
    {
        sum += *(addr + i);
    }
    return sum;
}
int get_translate_data(char *dataBuf, char *reportData)
{
    unsigned short dataLen = 0;

    if(dataBuf == NULL || reportData == NULL)
    {
        return NULL;
    }
    dataLen = (dataBuf[3] << 8) | dataBuf[2];
    syslog(LOG_INFO,"====[%s: %d]====datalen:%d",__FUNCTION__,__LINE__,dataLen);
    memcpy(reportData,dataBuf + sizeof(SERIALHEAD),dataLen - 6);

    return dataLen - 6;

}
//socket send interface
int udp_socket_send(char *pdu_buf, int pdu_len)
{
    int send_len = -1;
    int count = 0;

    while (count < UDP_MAX_SEND_COUNT)
    {
        if (( send_len = sendto(socket_fd, pdu_buf, pdu_len, 0,(struct sockaddr *)&serveraddr, sizeof(serveraddr))) == -1)
        {
            syslog(LOG_ERR, "M2M UDP Socket Send Error(%d):%s", errno, strerror(errno));
        }
        count ++;
    }

    print_hex(pdu_buf, pdu_len, SEND);

    return send_len;
}

int m2m_send_lora_sn(char *sn)
{
    char hb_buf[BUF_LEN];
    int hb_len = 0;
    M2M_PROTOCOL_HDR* hb = (M2M_PROTOCOL_HDR*)hb_buf;
    M2M_PROTOCOL_TLV *tlv;
    char router_type[64];
    char para_array[1024] = {0};
    unsigned short str_len;
    if(sn == NULL)
    {
        return -1;
    }
    if(socket_fd >= 0)
    {
        memset(hb_buf, 0, sizeof(hb_buf));

        hb->cmd_id = htons(REPORT_STATUS);
        hb->packet_id = htonl(packet_id++);
        hb->version = htons(M2M_VERSION);
        hb->safe_flag = 0;
        hb->data_type = 0;
        memcpy(hb->product_id, product_id, sizeof(hb->product_id));
        hb_len += sizeof(M2M_PROTOCOL_HDR);

        tlv = (M2M_PROTOCOL_TLV *)(hb_buf + hb_len);
        str_len = strlen(sn);
        tlv->tlv_tag = htons(0x025F);
        tlv->tlv_len = htons(str_len);
        strncpy(tlv->tlv_value, sn, 16);
        hb_len += str_len + 4;

        hb->len = htons(hb_len);
        udp_socket_send(hb_buf, hb_len);
        return 1;
    }

    return 0;
}

int handle_serial_data(char *dataBuf, int length)
{
    unsigned char dataSum;
    unsigned char checkSum;
    char sn[16];
    int translate_len = 0;
    char r_data[BUF_LEN] = {0};


    dataSum = dataBuf[length - 2];
    checkSum = checksum(dataBuf,length - 2);
    syslog(LOG_INFO,"====[%s: %d]====dataSum:%d, checkSum:%d",__FUNCTION__,length,dataSum,checkSum);
    if(dataSum != checkSum)
    {
        syslog(LOG_INFO,"Check recv data error!");
        return 0;
    }
    memcpy(sn,dataBuf + sizeof(SERIALHEAD) + 12, 16);
    if(!check_sn_report_flag(head, sn))//sn has reported
    {
        //send sn
        //send data
        g_report_status_ack = 2;
        while(g_report_status_ack == 2)
        {
            m2m_send_lora_sn(sn);
            sleep(1);
        }
        syslog(LOG_INFO,"------->Send lora sn success!");
        head = add_sn_to_list(head, sn);
    }
    //send data
    translate_len = get_translate_data(dataBuf, r_data);
    udp_socket_send(r_data, translate_len);
}

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
    //  exit(0);

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
    syslog(LOG_DEBUG, "%s---%s---", (op==SEND)?"SEND>>":"RECV<<", str);
}


static int report_udp_socket_send(int fd,char *pdu_buf, int pdu_len)
{
    int send_len = -1;
    int count = 0;

    while (count < UDP_MAX_SEND_COUNT)
    {
        if (( send_len = sendto(fd, pdu_buf, pdu_len, 0,(struct sockaddr *)&serveraddr_r, sizeof(serveraddr_r))) == -1)
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

static int tcp_socket_send(char *pdu_buf, int pdu_len)
{
    int send_len = -1;
    int count = 0;

    while (count < UDP_MAX_SEND_COUNT)
    {
        if (( send_len = send(tcp_socket, pdu_buf, pdu_len, 0)) == -1)
        {
            syslog(LOG_ERR, "DOWNLOAD TCP Socket Send Error(%d):%s", errno, strerror(errno));
        }
        count ++;
    }

    print_hex(pdu_buf, pdu_len, SEND);

    return send_len;
}

static int tcp_socket_recv(char *pdu_buf, int pdu_len)
{
    int recv_len = 0;
	int ret = 0;

	while(1)
	{
		if(wait_sock(tcp_socket, 2, 0) > 0) 
		{
			ret = recv(tcp_socket, pdu_buf + recv_len, pdu_len - recv_len, 0);
			
			syslog(LOG_NOTICE, "%s>>>Recv Len:%d", __FUNCTION__, ret);
				
			if(ret == -1)
			{
				syslog(LOG_ERR, "%s>>>Recv() ERROR:%s", __FUNCTION__, strerror(errno));
				if((errno == EINTR) || (errno == EWOULDBLOCK) || (errno == EAGAIN))
					continue;
				else
					return -1;
			}	
			
			recv_len += ret;
			if (recv_len == pdu_len)
			{
				break;
			}
		}
	}
	
	print_hex(pdu_buf, recv_len, RECV);

    return recv_len;
}

static int close_socket(int sockfd)
{
    /* Clear the UDP socket */
    char dummy[1024];
    int  iLen, res;

    res = wait_sock(sockfd, 1, 0);

    if (res == 1)
    {
        iLen  = recvfrom(sockfd, dummy, sizeof(dummy), 0, NULL,0 );
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
        iLen  = recvfrom(sockfd, dummy, sizeof(dummy), 0,NULL,0 );
        res = wait_sock(sockfd, 0, 100);
    }

    return 0;

}

static int udp_socket_nowait_recv(char *pdu_buf, int pdu_len)
{
    int recv_len = -1;
    int fromaddr_len = sizeof(fromaddr);

    recv_len = recvfrom(socket_fd, pdu_buf, pdu_len, 0, (struct sockaddr *)&fromaddr, &fromaddr_len);

    print_hex(pdu_buf, recv_len, RECV);

    if(fromaddr.sin_addr.s_addr != m2m_config.svr_domain_ip)
    {
        syslog(LOG_ERR,"------Ambitious data from :%x------------",fromaddr.sin_addr.s_addr);
        return 0;
    }

    return recv_len;
}

//socket receive interface
static int udp_socket_recv(char *pdu_buf, int pdu_len)
{
    int recv_len = -1;
    int fromaddr_len = sizeof(fromaddr);

    if (wait_sock(socket_fd, 5, 0)<=0)
    {
        syslog(LOG_NOTICE, "M2M UDP Recv Timeout");
        return -1;
    }

    recv_len = recvfrom(socket_fd, pdu_buf, pdu_len, 0, (struct sockaddr *)&fromaddr, &fromaddr_len);

    print_hex(pdu_buf, recv_len, RECV);

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

    recv_len = recvfrom(fd, pdu_buf, pdu_len, 0, (struct sockaddr *)&fromaddr_r, &fromaddr_len);

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

int get_router_nvram(char *conf_buf, char *conf_value, int val_len)
{
    char *nvp, *nv, *b;
    char *p =  NULL;
    int len = 0;

    nvp = nv = strdup(conf_buf);
    while ((b = strsep(&nvp, ",")) != NULL)
    {
        p = nvram_safe_get(b);
        snprintf(conf_value + len, val_len, "%s=%s&", b, p);
        syslog(LOG_INFO,"--------->%s=%s&", b, p);
        len += strlen(b);
        len += strlen(p);
        len += strlen("=&");
    }
    conf_value[len - 1] = 0;

    return len - 1;
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
    fgets(buf, sizeof(buf), f); // header
    fgets(buf, sizeof(buf), f); // "
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

static unsigned char parse_exdev_config(char *param_ptr, int param_len,char *op)
{
    FILE *fp=NULL;
    char word[256]= {0}, *next;
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
    char word[256]= {0}, *next;
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

static void set_non_blocking_mode(int sock)
{
    int flags = 0;
	
	flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
}

static int connect_m2m_tcp_server(unsigned long local_ip, unsigned short local_port, unsigned long dest_ip, unsigned long dest_port)
{
    struct sockaddr_in local_addr;
    int sockfd;
    int flag = -1;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (-1 == sockfd)
    {
        syslog(LOG_ERR, "M2M TCP Socket Creat Error!!!");
        return -1;
    }
	
	set_non_blocking_mode(tcp_socket);
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&flag, sizeof(flag));
	//setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, (const char*)&nRecvBuf, sizeof(int));

    bzero(&local_addr,sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(local_port);
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if(bind(sockfd, (struct sockaddr *)&local_addr, sizeof(local_addr)) < 0)
    {
        syslog(LOG_ERR, "M2M TCP Socket Bind Error!!!");
		close(sockfd);
        return -1;
    }

    bzero(&serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(dest_port);
    serveraddr.sin_addr.s_addr = dest_ip;//INADDR_ANY

    if((flag=connect(sockfd, (struct sockaddr*)&serveraddr, sizeof(serveraddr)))<0)
    {
		close(sockfd);
        return -1;
    }

    return sockfd;
}

int m2m_tcp_send_file_req(unsigned short cmd, unsigned int id, unsigned int off, unsigned int len, unsigned int cmd_sn)
{
    char hb_buf[1024];
    int hb_len = 0;
    M2M_PROTOCOL_HDR* hb = (M2M_PROTOCOL_HDR*)hb_buf;
    ST_FILE_REQ *fr;

    if(tcp_socket >= 0)
    {
        memset(hb_buf, 0, sizeof(hb_buf));

        hb->cmd_id = htons(cmd);
        hb->packet_id = htonl(packet_id++);
        hb->version = htons(M2M_VERSION);
        memcpy(hb->product_id, product_id, sizeof(hb->product_id));
        hb_len += sizeof(M2M_PROTOCOL_HDR);

        fr=(ST_FILE_REQ *)(hb_buf+ sizeof(M2M_PROTOCOL_HDR));
        fr->id = htonl(id);
        fr->off = htonl(off);
        fr->len = htonl(len);
        fr->cmd_sn = htonl(cmd_sn);
        hb_len += 16;

        hb->len = htons(hb_len);
		tcp_socket_send(hb_buf, hb_len);

        return 1;
    }
    return 0;
}

int m2m_udp_send_file_req(unsigned short cmd, unsigned int id, unsigned int off, unsigned int len, unsigned int cmd_sn)
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
        hb->version = htons(M2M_VERSION);
        memcpy(hb->product_id, product_id, sizeof(hb->product_id));
        hb_len += sizeof(M2M_PROTOCOL_HDR);

        fr=(ST_FILE_REQ *)(hb_buf+ sizeof(M2M_PROTOCOL_HDR));
        fr->id = htonl(id);
        fr->off = htonl(off);
        fr->len = htonl(len);
        fr->cmd_sn = htonl(cmd_sn);
        hb_len += 16;

        hb->len = htons(hb_len);
		udp_socket_send(hb_buf, hb_len);

        return 1;
    }
    return 0;
}

char *change_small_to_big_letter(char *src, char *desc, int len)
{
    int i;

    if(src == NULL || desc == NULL)
    {
        return NULL;
    }
    for(i = 0; i < len; i++)
    {
        desc[i] = toupper(src[i]);
    }

    return desc;
}

int get_md5(char *file,char *md5)
{
	char buf[512];
	char arr[128] = {0};
	FILE *fpmd5=NULL;
	sprintf(buf,"md5sum %s > /tmp/.cap.md5",file);
	system(buf);
	if((fpmd5=fopen("/tmp/.cap.md5","r")) != NULL)
	{
		memset(buf,0,sizeof(buf));
		fgets(buf, sizeof(buf), fpmd5);
		fclose(fpmd5);
		syslog(LOG_ERR,"1--->%s",buf);
		change_small_to_big_letter(buf, arr, 32);
		syslog(LOG_ERR,"2--->%s",arr);
		memcpy(md5,arr,32);
		return 1;
	}
	syslog(LOG_ERR,"MD5 get NK");
	return 0;
}

int check_md5(char *file,char *md5)
{
    char buf[512];
    char arr[128] = {0};
    FILE *fpmd5=NULL;
    sprintf(buf,"md5sum %s > /tmp/.trx.md5",file);
    system(buf);
    if((fpmd5=fopen("/tmp/.trx.md5","r")) != NULL)
    {
        memset(buf,0,sizeof(buf));
        fgets(buf, sizeof(buf), fpmd5);
        fclose(fpmd5);
        change_small_to_big_letter(buf, arr, 32);
        syslog(LOG_INFO,"buf:%s, md5:%s, MD5:%s", buf, md5, arr);
        if(!strncasecmp(arr,md5,32))
        {
            syslog(LOG_INFO,"MD5 check OK");
            unlink("/tmp/.trx.md5");
            return 1;
        }
    }
    syslog(LOG_INFO,"MD5 check NK");
    unlink("/tmp/.trx.md5");
    return 0;
}

static int udp_download_process(FILE *file_fd, unsigned int pack_id)
{
	int recv_count, total_count, last_size;
	M2M_PROTOCOL_HDR *udp_hdr;
	int retry = 0;
	char recv_buf[udp_down_recv_size];
	int recv_len = 0;
	char md5[33] = {0};
	int filesize = 0;
	struct stat st;

	total_count = ntohl(g_down_info->filelist[0].size) / udp_down_def_size;
	if((last_size = ntohl(g_down_info->filelist[0].size) % udp_down_def_size) != 0)
		total_count ++;
	else
		last_size = udp_down_def_size;

	syslog(LOG_NOTICE, "total_count:%d, def_size:%d, last_size:%d", total_count, udp_down_def_size, last_size);
	
	recv_count = 0;
	while (recv_count < total_count)
	{
		syslog(LOG_NOTICE, "Downloading:%d", recv_count + 1);
		
		if(recv_count  + 1 == total_count)
			m2m_udp_send_file_req(FILE_REQ, ntohl(g_down_info->filelist[0].id), recv_count * udp_down_def_size, last_size, pack_id);
		else
			m2m_udp_send_file_req(FILE_REQ, ntohl(g_down_info->filelist[0].id), recv_count * udp_down_def_size, udp_down_def_size, pack_id);

		memset(recv_buf, 0, udp_down_recv_size);
		
		recv_len = udp_socket_recv(recv_buf, udp_down_recv_size);
		
		syslog(LOG_NOTICE, "recv_len:%d", recv_len);
		
		if(recv_len > sizeof(M2M_PROTOCOL_HDR))
		{
			udp_hdr = (M2M_PROTOCOL_HDR *)recv_buf;
			
			if(((ntohs(udp_hdr->cmd_id)) == FILE_REQ_ACK) && (*(recv_buf + sizeof(M2M_PROTOCOL_HDR)) == 0))
			{
				syslog(LOG_NOTICE, "FILE_REQ_ACK!!!");
				
				fwrite(recv_buf + sizeof(M2M_PROTOCOL_HDR) + 1, 1, recv_len - sizeof(M2M_PROTOCOL_HDR) - 1, file_fd);
				recv_count ++;
			}
			else
			{
				syslog(LOG_ERR, "Invalid response data for FILE_REQ");
				
				return 0;
			}
		}
		else
		{
			syslog(LOG_ERR, "recv_len: %d != m2mHDR: %d", recv_len, sizeof(M2M_PROTOCOL_HDR));

			return 0;
		}
	}
	
	if(stat(filename, &st) == 0)
	{
		filesize = st.st_size;
	}
	get_md5(filename, md5);
	
	syslog(LOG_NOTICE, "filename md5:%s, size:%d", md5, filesize);
	syslog(LOG_NOTICE, "download file md5:%s, size:%d", g_down_info->filelist[0].md5, g_down_info->filelist[0].size);

	if(check_md5(filename, g_down_info->filelist[0].md5) && (filesize == g_down_info->filelist[0].size))
	{
		syslog(LOG_NOTICE, "Downlaod file is correct!");
		
		return 1;
	}
	else
	{
		syslog(LOG_ERR, "MD5 or Filesize is not correct!");

		return 0;
	}
}

static int download_process(unsigned int pack_id)
{	
	int recv_count, total_count, last_size;
	FILE *file_fd;
	M2M_PROTOCOL_HDR *tcp_hdr;
	int retry = 0;
	char recv_buf[tcp_down_recv_size];
	int recv_len = 0;
	char md5[33] = {0};
	int filesize = 0;
	struct stat st;

	total_count = ntohl(g_down_info->filelist[0].size) / tcp_down_def_size;
	if((last_size = ntohl(g_down_info->filelist[0].size) % tcp_down_def_size) != 0)
		total_count ++;
	else
		last_size = tcp_down_def_size;

	syslog(LOG_NOTICE, "total_count:%d, def_size:%d, last_size:%d", total_count, tcp_down_def_size, last_size);
	
	file_fd = fopen(filename, "wb");
	if(file_fd != NULL)
	{
		while((tcp_socket = connect_m2m_tcp_server(0, 0, g_m2m_server_ip, m2m_config.svr_port)) < 0)
		{
			retry ++;
			if(retry >= 5)
			{
				syslog(LOG_ERR, "Fail to connect download TCP, over retry.Try to use UDP to download!");
				if(udp_download_process(file_fd, pack_id))	//if tcp connect fail, use udp to download
				{
					fclose(file_fd);
					return 1;
				}
			}

			syslog(LOG_ERR, "Fail to connect download TCP, retry %d.", retry);
			sleep(60);
		}	
		
		syslog(LOG_NOTICE, "Success to connect download TCP!!!");
		syslog(LOG_NOTICE, "Start TCP download...");
		
		recv_count = 0;
		while (recv_count < total_count)
		{
			syslog(LOG_NOTICE, "Downloading:%d", recv_count + 1);

			if(recv_count + 1 == total_count)
				m2m_tcp_send_file_req(FILE_REQ, ntohl(g_down_info->filelist[0].id), recv_count * tcp_down_def_size, last_size, pack_id);
			else
				m2m_tcp_send_file_req(FILE_REQ, ntohl(g_down_info->filelist[0].id), recv_count * tcp_down_def_size, tcp_down_def_size, pack_id);

			memset(recv_buf, 0, tcp_down_recv_size);

			if(recv_count + 1 == total_count)
				recv_len = tcp_socket_recv(recv_buf, last_size + 29);
			else
				recv_len = tcp_socket_recv(recv_buf, tcp_down_def_size + 29);
				
			syslog(LOG_NOTICE, "recv_len:%d", recv_len); 
				
			if(recv_len > sizeof(M2M_PROTOCOL_HDR))
			{
				tcp_hdr = (M2M_PROTOCOL_HDR *)recv_buf;
					
				if(((ntohs(tcp_hdr->cmd_id)) == FILE_REQ_ACK) && (*(recv_buf + sizeof(M2M_PROTOCOL_HDR)) == 0))
				{
					syslog(LOG_NOTICE, "FILE_REQ_ACK!!!");
						
					fwrite(recv_buf + sizeof(M2M_PROTOCOL_HDR) + 1, 1, recv_len - sizeof(M2M_PROTOCOL_HDR) - 1, file_fd);
					recv_count ++;
				}
				else
				{
					syslog(LOG_ERR, "Invalid response data for FILE_REQ");
						
					close(tcp_socket);
					fclose(file_fd);
					return 0;
				}
			}
			else
			{
				syslog(LOG_ERR, "recv_len: %d != m2mHDR: %d", recv_len, sizeof(M2M_PROTOCOL_HDR));

				close(tcp_socket);
				fclose(file_fd);
				return 0;
			}
		}
		
		if(stat(filename, &st) == 0)
		{
			filesize = st.st_size;
		}
		get_md5(filename, md5);
			
		syslog(LOG_NOTICE, "filename md5:%s, size:%d", md5, filesize);
		syslog(LOG_NOTICE, "download file md5:%s, size:%d", g_down_info->filelist[0].md5, ntohl(g_down_info->filelist[0].size));

		if(check_md5(filename, g_down_info->filelist[0].md5) && (filesize == ntohl(g_down_info->filelist[0].size)))
		{
			syslog(LOG_NOTICE, "Downlaod file is correct!");
				
			close(tcp_socket);
			fclose(file_fd);
			return 1;
		}
		else
		{
			syslog(LOG_ERR, "MD5 or Filesize is not correct!");

			close(tcp_socket);
			fclose(file_fd);
			return 0;
		}
	}	
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

int send_download_ack(unsigned short cmd,unsigned int pack_id, unsigned char status, int filesize)
{
    char hb_buf[1024] = {0};
    int hb_len = 0;
    M2M_PROTOCOL_HDR* hb = (M2M_PROTOCOL_HDR*)hb_buf;

	syslog(LOG_NOTICE, "%s>>>%d", __FUNCTION__, filesize);
    if(socket_fd >= 0)
    {
        memset(hb_buf, 0, 1024);
        hb_len = 0;

        hb->cmd_id = htons(cmd);
        hb->packet_id = htonl(pack_id);
        hb->version = htons(M2M_VERSION);
        memcpy(hb->product_id, product_id, sizeof(hb->product_id));

        *(hb_buf + sizeof(M2M_PROTOCOL_HDR)) = status;
		hb_len = sizeof(M2M_PROTOCOL_HDR) + 1;
		
		filesize = htonl(filesize);
		memcpy(hb_buf + hb_len, &filesize, 4);
        hb_len += 4;
		
        hb->len = htons(hb_len);
        udp_socket_send(hb_buf, hb_len);

        return 1;
    }

    return 0;
}

int m2m_send_ack(unsigned short cmd,unsigned char status)
{
    char hb_buf[1024] = {0};
    int hb_len = 0;
    M2M_PROTOCOL_HDR* hb = (M2M_PROTOCOL_HDR*)hb_buf;

    if(socket_fd >= 0)
    {
        memset(hb_buf, 0, 512);
        hb_len = 0;

        hb->cmd_id = htons(cmd);
        hb->packet_id = htonl(packet_id++);
        hb->version = htons(M2M_VERSION);
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
    char word[256]= {0};


    sprintf(word,"cmd=3&mac=%s\r\n",param_ptr);
    if(pidof("xdog")>1)
    {
        m2m_2_nd(word);
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
#if 0
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
        fl->cmd_id = htons(REPORT_FILE_LIST);
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
#endif
    return 0;
}

int list_rssi_min(MAC_LIST *maclist,int list_len)
{
    int i;
    int min=1000;
    int ret=0;

    for(i=0; i<list_len; i++)
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
    char hb_buf[BUF_LEN];
    unsigned short hb_len = 0;
    M2M_PROTOCOL_HDR* hb = (M2M_PROTOCOL_HDR*)hb_buf;
    M2M_PROTOCOL_TLV *tlv;
    char router_type[64];
    char para_array[1024] = {0};
    unsigned short str_len = 0;

    if(fd >= 0)
    {
        memset(hb_buf, 0, sizeof(hb_buf));

        hb->cmd_id = htons(cmd);
        hb->packet_id = htonl(packet_id++);
        hb->version = htons(M2M_VERSION);
        hb->safe_flag = 0;
        hb->data_type = 0;
        memcpy(hb->product_id, product_id, sizeof(hb->product_id));
        hb_len += sizeof(M2M_PROTOCOL_HDR);

        if(cmd == M2M_LOGIN)
        {
            //设备型号
            tlv = (M2M_PROTOCOL_TLV *)(hb_buf + hb_len);
            str_len = strlen(nvram_safe_get("router_type"));
            tlv->tlv_tag = htons(MODEM_TYPE_TAG);
            tlv->tlv_len = htons(str_len);
            strncpy(tlv->tlv_value,nvram_safe_get("router_type"),str_len);
            hb_len += str_len + 4;
            //设备别名
            tlv = (M2M_PROTOCOL_TLV *)(hb_buf + hb_len);
            str_len = strlen(nvram_safe_get("m2m_product_id"));
            tlv->tlv_tag = htons(DEVICE_RENAME_TAG);
            tlv->tlv_len = htons(str_len);
            strncpy(tlv->tlv_value,nvram_safe_get("m2m_product_id"),str_len);
            hb_len += str_len + 4;
            //设备条码
            tlv = (M2M_PROTOCOL_TLV *)(hb_buf + hb_len);
            str_len = strlen(nvram_safe_get("router_sn"));
            tlv->tlv_tag = htons(DEVICE_PRODUCT_SN_TAG);
            tlv->tlv_len = htons(str_len);
            strncpy(tlv->tlv_value,nvram_safe_get("router_sn"),str_len);
            hb_len += str_len + 4;
            //软件版本号
            tlv = (M2M_PROTOCOL_TLV *)(hb_buf + hb_len);
            str_len = strlen(nvram_safe_get("os_version"));
            tlv->tlv_tag = htons(FIRMWARE_TAG);
            tlv->tlv_len = htons(str_len);
            strncpy(tlv->tlv_value,nvram_safe_get("os_version"),str_len);
            hb_len += str_len + 4;

        }
        else if (cmd == M2M_VT_CH_REPORT)
        {
            *(hb_buf + hb_len) = 0x0;
            hb_len++;
        }
        else if(cmd == M2M_LOGOUT)
        {
            *(hb_buf + hb_len) = 0x0;
            hb_len++;
        }
        else if(cmd == REPORT_STATUS)
        {
            if(nvram_get_int("cell_cops") == 7)
            {

                tlv = (M2M_PROTOCOL_TLV *)(hb_buf + hb_len);
                str_len = strlen(nvram_safe_get("celle_lac"));
                tlv->tlv_tag = htons(BASE_STATION1_LAC_TAG);
                tlv->tlv_len = htons(str_len);
                strncpy(tlv->tlv_value,nvram_safe_get("celle_lac"),str_len);
                hb_len += str_len + 4;

                tlv = (M2M_PROTOCOL_TLV *)(hb_buf + hb_len);
                str_len = strlen(nvram_safe_get("celle_cid"));
                tlv->tlv_tag = htons(BASE_STATION1_CELLID_TAG);
                tlv->tlv_len = htons(str_len);
                strncpy(tlv->tlv_value,nvram_safe_get("celle_cid"),str_len);
                hb_len += str_len + 4;

                tlv = (M2M_PROTOCOL_TLV *)(hb_buf + hb_len);
                str_len = strlen(nvram_safe_get("cops"));
                tlv->tlv_tag = htons(BASE_STATION1_MNC_TAG);
                tlv->tlv_len = htons(str_len);
                strncpy(tlv->tlv_value,nvram_safe_get("cops"),str_len);
                hb_len += str_len + 4;
            }
            else
            {
                tlv = (M2M_PROTOCOL_TLV *)(hb_buf + hb_len);
                str_len = strlen(nvram_safe_get("cellg_lac"));
                tlv->tlv_tag = htons(BASE_STATION1_LAC_TAG);
                tlv->tlv_len = htons(str_len);
                strncpy(tlv->tlv_value,nvram_safe_get("cellg_lac"),str_len);
                hb_len += str_len + 4;

                tlv = (M2M_PROTOCOL_TLV *)(hb_buf + hb_len);
                str_len = strlen(nvram_safe_get("cellg_cid"));
                tlv->tlv_tag = htons(BASE_STATION1_CELLID_TAG);
                tlv->tlv_len = htons(str_len);
                strncpy(tlv->tlv_value,nvram_safe_get("cellg_cid"),str_len);
                hb_len += str_len + 4;

                tlv = (M2M_PROTOCOL_TLV *)(hb_buf + hb_len);
                str_len = strlen(nvram_safe_get("cops"));
                tlv->tlv_tag = htons(BASE_STATION1_MNC_TAG);
                tlv->tlv_len = htons(str_len);
                strncpy(tlv->tlv_value,nvram_safe_get("cops"),str_len);
                hb_len += str_len + 4;
            }
            tlv = (M2M_PROTOCOL_TLV *)(hb_buf + hb_len);
            str_len = strlen(nvram_safe_get("module_vendor"));
            tlv->tlv_tag = htons(MODEM_PRODUCT_TAG);
            tlv->tlv_len = htons(str_len);
            strncpy(tlv->tlv_value,nvram_safe_get("module_vendor"),str_len);
            hb_len += str_len + 4;

            str_len = get_modem_type(para_array);
            tlv = (M2M_PROTOCOL_TLV *)(hb_buf + hb_len);
            tlv->tlv_tag = htons(MODEM_PRODUCT_TAG);
            tlv->tlv_len = htons(str_len);
            strncpy(tlv->tlv_value,para_array,str_len);
            hb_len += str_len + 4;


            tlv = (M2M_PROTOCOL_TLV *)(hb_buf + hb_len);
            str_len = strlen(nvram_safe_get("modem_mode"));
            tlv->tlv_tag = htons(MODEM_TYPE_TAG);
            tlv->tlv_len = htons(str_len);
            strncpy(tlv->tlv_value,nvram_safe_get("modem_mode"),str_len);
            hb_len += str_len + 4;

            if(strlen(nvram_safe_get("psn")))
            {
                tlv = (M2M_PROTOCOL_TLV *)(hb_buf + hb_len);
                str_len = strlen(nvram_safe_get("psn"));
                tlv->tlv_tag = htons(HOST_SN_TAG);
                tlv->tlv_len = htons(str_len);
                strncpy(tlv->tlv_value,nvram_safe_get("psn"),str_len);
                hb_len += str_len + 4;
            }
            if(strlen(nvram_safe_get("near_apmac")))
            {

                str_len = get_near_apmac(para_array);
                tlv = (M2M_PROTOCOL_TLV *)(hb_buf + hb_len);
                tlv->tlv_tag = htons(WIFI_AP_LIST_TAG);
                tlv->tlv_len = htons(str_len);
                strncpy(tlv->tlv_value,para_array,str_len);
                hb_len += str_len + 4;
            }
        }
        hb->len = htons(hb_len);
        report_udp_socket_send(fd, hb_buf, hb_len);
        return 1;
    }

    return 0;
}

int get_modem_type(char *modem_type, int len)
{
    char *p;

    memcpy(modem_type,nvram_safe_get("modem_type"), len);
    p=modem_type;
    if((p=strchr(p,':')) != NULL)
    {
        *p=0;
    }
    syslog(LOG_ERR,"mtype:%s",modem_type);

    return strlen(modem_type);
}

int get_near_apmac(char *macs)
{
    char *nv, *nvp, *b;
    const char *mac, *rssi;
    MAC_LIST maclist[6];
    char *temp = NULL;
    int i=0;

    nvp = nv = strdup(nvram_safe_get("near_apmac"));
    if (nv)
    {
        memset(maclist,0,sizeof(maclist));
        for(i=0; i<6; i++)
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
        for(i=0; i<6; i++)
        {
            temp = macs;
            if(strlen(maclist[i].mac))
                snprintf(macs,sizeof(macs)-1,"%s%s,",temp,maclist[i].mac);
            syslog(LOG_ERR,"%s",macs);
        }

        if(macs[strlen(macs)-1]==',')
            macs[strlen(macs)-1]='\0';
        syslog(LOG_ERR,"==%s==",macs);
        nvram_set("near_apmac_check",nvram_safe_get("near_apmac"));
    }
    return strlen(macs);
}
int m2m_send_cmd(unsigned short cmd)
{
    char hb_buf[M2M_TLV_VALUE];
    unsigned short hb_len = 0;
    M2M_PROTOCOL_HDR* hb = (M2M_PROTOCOL_HDR*)hb_buf;
    M2M_PROTOCOL_TLV *tlv;
    char router_type[64];
    char para_array[128] = {0};
    unsigned short str_len = 0;
    int config_len = 0;

    if(socket_fd >= 0)
    {
        memset(hb_buf, 0, sizeof(hb_buf));

        hb->cmd_id = htons(cmd);
        hb->packet_id = htonl(packet_id++);
        hb->version = htons(M2M_VERSION);
        hb->safe_flag = 0;
        hb->data_type = 0;
        memcpy(hb->product_id, product_id, sizeof(hb->product_id));
        hb_len += sizeof(M2M_PROTOCOL_HDR);

        if(cmd == M2M_LOGIN)
        {
            //设备型号
            tlv = (M2M_PROTOCOL_TLV *)(hb_buf + hb_len);
            str_len = strlen(nvram_safe_get("router_type"));
            tlv->tlv_tag = htons(DEVICE_NETWORK_TAG);
            tlv->tlv_len = htons(str_len);
            strncpy(tlv->tlv_value,nvram_safe_get("router_type"),str_len);
            hb_len += str_len + 4;
            //设备别名
            tlv = (M2M_PROTOCOL_TLV *)(hb_buf + hb_len);
            str_len = strlen(nvram_safe_get("m2m_product_id"));
            tlv->tlv_tag = htons(DEVICE_RENAME_TAG);
            tlv->tlv_len = htons(str_len);
            strncpy(tlv->tlv_value,nvram_safe_get("m2m_product_id"),str_len);
            hb_len += str_len + 4;
            //设备条码
            tlv = (M2M_PROTOCOL_TLV *)(hb_buf + hb_len);
            str_len = strlen(nvram_safe_get("router_sn"));
            tlv->tlv_tag = htons(DEVICE_PRODUCT_SN_TAG);
            tlv->tlv_len = htons(str_len);
            strncpy(tlv->tlv_value,nvram_safe_get("router_sn"),str_len);
            hb_len += str_len + 4;
            //软件版本号
            tlv = (M2M_PROTOCOL_TLV *)(hb_buf + hb_len);
            str_len = strlen(nvram_safe_get("os_version"));
            tlv->tlv_tag = htons(FIRMWARE_TAG);
            tlv->tlv_len = htons(str_len);
            strncpy(tlv->tlv_value,nvram_safe_get("os_version"),str_len);
            hb_len += str_len + 4;
            //imei
            tlv = (M2M_PROTOCOL_TLV *)(hb_buf + hb_len);
            str_len = strlen(nvram_safe_get("modem_imei"));
            tlv->tlv_tag = htons(MODEM_IMEI_TAG);
            tlv->tlv_len = htons(str_len);
            strncpy(tlv->tlv_value,nvram_safe_get("modem_imei"),str_len);
            hb_len += str_len + 4;
            //imsi
            tlv = (M2M_PROTOCOL_TLV *)(hb_buf + hb_len);
            str_len = strlen(nvram_safe_get("modem_imsi"));
            tlv->tlv_tag = htons(MODEM_IMSI_TAG);
            tlv->tlv_len = htons(str_len);
            strncpy(tlv->tlv_value,nvram_safe_get("modem_imsi"),str_len);
            hb_len += str_len + 4;
            //iccid
            tlv = (M2M_PROTOCOL_TLV *)(hb_buf + hb_len);
            str_len = strlen(nvram_safe_get("sim_ccid"));
            tlv->tlv_tag = htons(MODEM_ICCID_TAG);
            tlv->tlv_len = htons(str_len);
            strncpy(tlv->tlv_value,nvram_safe_get("sim_ccid"),str_len);
            hb_len += str_len + 4;
        }
        else if (cmd == M2M_VT_CH_REPORT)
        {
            *(hb_buf + hb_len) = 0x0;
            hb_len++;
        }
        else if(cmd == M2M_LOGOUT)
        {
            *(hb_buf + hb_len) = 0x0;
            hb_len++;
        }
        else if(cmd == RTU_SCRIPT_TRAP)
        {
            char *p;

            p = nvram_safe_get("rtu_scripts");
            memcpy(hb_buf + hb_len, p, strlen(p));
            hb_len += strlen(p);
        }
        else if(cmd == M2M_CONFIG_TRAP)
        {
            tlv = (M2M_PROTOCOL_TLV *)(hb_buf + hb_len);
            config_len = make_router_config(tlv->tlv_value);   
            tlv->tlv_tag = htons(0x0106);
            tlv->tlv_len = htons(config_len);
            hb_len += config_len + 4;
            syslog(LOG_INFO,"Report all config trap len:%d", config_len);
        }
        else if(cmd == REPORT_STATUS)
        {
            if(nvram_get_int("cell_cops") == 7)
            {

                tlv = (M2M_PROTOCOL_TLV *)(hb_buf + hb_len);
                str_len = strlen(nvram_safe_get("celle_lac"));
                tlv->tlv_tag = htons(BASE_STATION1_LAC_TAG);
                tlv->tlv_len = htons(str_len);
                strncpy(tlv->tlv_value,nvram_safe_get("celle_lac"),str_len);
                hb_len += str_len + 4;

                tlv = (M2M_PROTOCOL_TLV *)(hb_buf + hb_len);
                str_len = strlen(nvram_safe_get("celle_cid"));
                tlv->tlv_tag = htons(BASE_STATION1_CELLID_TAG);
                tlv->tlv_len = htons(str_len);
                strncpy(tlv->tlv_value,nvram_safe_get("celle_cid"),str_len);
                hb_len += str_len + 4;

                tlv = (M2M_PROTOCOL_TLV *)(hb_buf + hb_len);
                str_len = strlen(nvram_safe_get("cops"));
                tlv->tlv_tag = htons(BASE_STATION1_MNC_TAG);
                tlv->tlv_len = htons(str_len);
                strncpy(tlv->tlv_value,nvram_safe_get("cops"),str_len);
                hb_len += str_len + 4;
            }
            else
            {
                tlv = (M2M_PROTOCOL_TLV *)(hb_buf + hb_len);
                str_len = strlen(nvram_safe_get("cellg_lac"));
                tlv->tlv_tag = htons(BASE_STATION1_LAC_TAG);
                tlv->tlv_len = htons(str_len);
                strncpy(tlv->tlv_value,nvram_safe_get("cellg_lac"),str_len);
                hb_len += str_len + 4;

                tlv = (M2M_PROTOCOL_TLV *)(hb_buf + hb_len);
                str_len = strlen(nvram_safe_get("cellg_cid"));
                tlv->tlv_tag = htons(BASE_STATION1_CELLID_TAG);
                tlv->tlv_len = htons(str_len);
                strncpy(tlv->tlv_value,nvram_safe_get("cellg_cid"),str_len);
                hb_len += str_len + 4;

                tlv = (M2M_PROTOCOL_TLV *)(hb_buf + hb_len);
                str_len = strlen(nvram_safe_get("cops"));
                tlv->tlv_tag = htons(BASE_STATION1_MNC_TAG);
                tlv->tlv_len = htons(str_len);
                strncpy(tlv->tlv_value,nvram_safe_get("cops"),str_len);
                hb_len += str_len + 4;
            }
            //生产厂家
            tlv = (M2M_PROTOCOL_TLV *)(hb_buf + hb_len);
            str_len = strlen(nvram_safe_get("module_vendor"));
            tlv->tlv_tag = htons(MODEM_PRODUCT_TAG);
            tlv->tlv_len = htons(str_len);
            strncpy(tlv->tlv_value,nvram_safe_get("module_vendor"),str_len);
            hb_len += str_len + 4;
            //运营商
            tlv = (M2M_PROTOCOL_TLV *)(hb_buf + hb_len);
            str_len = strlen(nvram_safe_get("cell_network"));
            tlv->tlv_tag = htons(OPERATOR_NAME_TAG);
            tlv->tlv_len = htons(str_len);
            strncpy(tlv->tlv_value,nvram_safe_get("cell_network"),str_len);
            hb_len += str_len + 4;
            //模块型号
            str_len = get_modem_type(para_array,sizeof(para_array));
            tlv = (M2M_PROTOCOL_TLV *)(hb_buf + hb_len);
            tlv->tlv_tag = htons(MODEM_TYPE_TAG);
            tlv->tlv_len = htons(str_len);
            strncpy(tlv->tlv_value,para_array,str_len);
            hb_len += str_len + 4;


           /* tlv = (M2M_PROTOCOL_TLV *)(hb_buf + hb_len);
            str_len = strlen(nvram_safe_get("modem_mode"));
            tlv->tlv_tag = htons(MODEM_TYPE_TAG);
            tlv->tlv_len = htons(str_len);
            strncpy(tlv->tlv_value,nvram_safe_get("modem_mode"),str_len);
            hb_len += str_len + 4;*/

            if(strlen(nvram_safe_get("psn")))
            {
                tlv = (M2M_PROTOCOL_TLV *)(hb_buf + hb_len);
                str_len = strlen(nvram_safe_get("psn"));
                tlv->tlv_tag = htons(HOST_SN_TAG);
                tlv->tlv_len = htons(str_len);
                strncpy(tlv->tlv_value,nvram_safe_get("psn"),str_len);
                hb_len += str_len + 4;
            }
            if(strlen(nvram_safe_get("near_apmac")))
            {

                str_len = get_near_apmac(para_array);
                tlv = (M2M_PROTOCOL_TLV *)(hb_buf + hb_len);
                tlv->tlv_tag = htons(WIFI_AP_LIST_TAG);
                tlv->tlv_len = htons(str_len);
                strncpy(tlv->tlv_value,para_array,str_len);
                hb_len += str_len + 4;
            }
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
            m2m_send_ack(OEM_CAMERA_CONFIG_SET_ACK,1);
        else if(nvram_match("oem_op","get"))
            m2m_send_ack(OEM_CAMERA_CONFIG_GET_ACK,1);
        else if(nvram_match("oem_op","upgrade"))
            m2m_send_ack(DOWNLOAD_INFO_ACK,1);
        else
            m2m_send_ack(OEM_CAMERA_RESET_ACK,1);
    }

    g_exdev_running=0;
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

#define YEAR2015 1420041600             //2015-01-01 00:00:00
#define PCAP_FILE "/tmp/m2m_pcap.pcap"


#define TCPDUMP_MAGIC       0xa1b2c3d4
#ifndef PCAP_VERSION_MAJOR
#define PCAP_VERSION_MAJOR 2
#endif
#ifndef PCAP_VERSION_MINOR
#define PCAP_VERSION_MINOR 4
#endif

#define DLT_NULL    0   /* BSD loopback encapsulation */
#define DLT_EN10MB  1   /* Ethernet (10Mb) */
#define DLT_EN3MB   2   /* Experimental Ethernet (3Mb) */
#define DLT_AX25    3   /* Amateur Radio AX.25 */
#define DLT_PRONET  4   /* Proteon ProNET Token Ring */
#define DLT_CHAOS   5   /* Chaos */
#define DLT_IEEE802 6   /* 802.5 Token Ring */
#define DLT_ARCNET  7   /* ARCNET, with BSD-style header */
#define DLT_SLIP    8   /* Serial Line IP */
#define DLT_PPP     9   /* Point-to-point Protocol */
#define DLT_FDDI    10  /* FDDI */

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

struct pcap_file_header
{
    bpf_u_int32 magic;
    u_short version_major;
    u_short version_minor;
    bpf_int32 thiszone;     /* gmt to local correction */
    bpf_int32 sigfigs;    /* accuracy of timestamps */
    bpf_u_int32 snaplen;    /* max length saved portion of each pkt */
    bpf_u_int32 linktype;   /* data link type (LINKTYPE_*) */
};

struct pcap_pkthdr
{
    struct timeval ts;      /* time stamp */
    bpf_u_int32 caplen;     /* length of portion present */
    bpf_u_int32 len;        /* length this packet (off wire) */
};

struct pcap_timeval
{
    bpf_int32 tv_sec;       /* seconds */
    bpf_int32 tv_usec;      /* microseconds */
};

struct pcap_sf_pkthdr
{
    struct pcap_timeval ts; /* time stamp */
    bpf_u_int32 caplen;     /* length of portion present */
    bpf_u_int32 len;        /* length this packet (off wire) */
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

int send_upload_file(ST_PACKET_CAP_UPLOAD cap, char *data, int len)
{
    int sendTime = 0, n;
    int pdu_len = 0;
    M2M_PROTOCOL_HDR *upload_req_head, *m2m_req;
    char pdubuf[M2M_RES_PDU_BUF];
    char resBuf[M2M_RES_PDU_BUF];

    memset(resBuf, 0, 2048);
    upload_req_head = (M2M_PROTOCOL_HDR *)resBuf;
    upload_req_head->cmd_id = htons(UPLOAD_FILE);
    upload_req_head->data_type = 0;
    upload_req_head->packet_id = htonl(packet_id++);
    memcpy(upload_req_head->product_id, product_id, sizeof(upload_req_head->product_id));
    upload_req_head->safe_flag = 0;
    upload_req_head->version = htons(M2M_VERSION);
    upload_req_head->len = htons(sizeof(M2M_PROTOCOL_HDR) + sizeof(ST_PACKET_CAP_UPLOAD) + len);

    memcpy(resBuf + sizeof(M2M_PROTOCOL_HDR), &cap, sizeof(ST_PACKET_CAP_UPLOAD));
    memcpy(resBuf + sizeof(M2M_PROTOCOL_HDR) + sizeof(ST_PACKET_CAP_UPLOAD), data, len);

    syslog(LOG_INFO,"---------->upload send data len:%d, cal_len:%d", strlen(resBuf), sizeof(M2M_PROTOCOL_HDR) + sizeof(ST_PACKET_CAP_UPLOAD) + len);
    udp_socket_send(resBuf, sizeof(M2M_PROTOCOL_HDR) + sizeof(ST_PACKET_CAP_UPLOAD) + len);

    while(socket_fd > 0)
    {
        memset(pdubuf, 0, sizeof(pdubuf));
        n = udp_socket_recv(pdubuf, sizeof(pdubuf));
        if(n < 0)//recv timeout or other error
        {
            sleep(5);
            udp_socket_send(resBuf, sizeof(M2M_PROTOCOL_HDR) + sizeof(ST_PACKET_CAP_UPLOAD) + len);
            sendTime++;
            if(sendTime >= 3)//download failed
            {
                //send failed response packet
                return 0;
            }
        }
        else if(n > 0)//Recv pdu
        {
            if((n < sizeof(M2M_PROTOCOL_HDR)) || (pdubuf[sizeof(M2M_PROTOCOL_HDR)] != 0))
            {
                syslog(LOG_INFO,"Upload cap file error!");
                return 0;
            }
            else
            {
                m2m_req = (M2M_PROTOCOL_HDR *)pdubuf;

                if(ntohs(m2m_req->cmd_id) == UPLOAD_FILE_ACK)
                {
                    syslog(LOG_INFO,"Upload data success!");
                    break;
                }
                else if(ntohs(m2m_req->cmd_id) == M2M_HEARTBEAT_ACK)
                {
                    N_ACK = 0;
                    syslog(LOG_INFO,"Upload process recv heartbeat ack!");
                    continue;
                }
                else
                {
                    syslog(LOG_INFO,"Recv other response!");
                    continue;
                }
            }
        }
        else//Recv from incorrect server
        {
            continue;
        }
    }

    return 1;
}

int start_file_upload(unsigned int id, char *filename)
{
    struct stat st;
    int offset = 0, file_size, read_len, ret;
    FILE *fp;
    char md5[33];
    char rdBuf[M2M_RES_PDU_BUF] = {0};
    ST_PACKET_CAP_UPLOAD pcap_upload;

    memset(md5,0,sizeof(md5));

    if(stat(filename,&st)==0)
    {
        file_size=st.st_size;
    }
    if(!get_md5(filename,md5))
    {
        syslog(LOG_INFO,"File MD5 error: %s",md5);
        return ret;
    }
    if((fp=fopen(filename,"r")) == NULL)
    {
        return ret;
    }
    pcap_upload.id = htonl(id);
    pcap_upload.total = htonl(file_size);
    memcpy(pcap_upload.md5, md5, 32);
    while(offset < file_size)
    {
        memset(rdBuf, 0, sizeof(rdBuf));
        if((read_len = fread(rdBuf,1,UDP_UPLOAD_DOWNLOAD_LEN,fp)) != UDP_UPLOAD_DOWNLOAD_LEN)
        {
            syslog(LOG_ERR,"%s---%d",__FUNCTION__,__LINE__);
            if(ferror(fp))
            {
                syslog(LOG_ERR,"%s---%d",__FUNCTION__,__LINE__);
                ret=0;
                break;
            }
        }
        pcap_upload.offset = htonl(offset);
        if(!send_upload_file(pcap_upload, rdBuf, read_len))
        {
            ret = 0;
            syslog(LOG_INFO,"Upload cap file error, exit!");
            break;
        }
        offset += read_len;
    }
    ret = 1;
    fclose(fp);
    return ret;
}
int pcap_thread(ST_PACKET_CAP cap)
{
    unsigned int now;
    unsigned int cap_size=0;
    int ret = 0;

    now=time(NULL);

    while((cap.start > now) && (now > YEAR2015))
    {
        sleep(1);
        now=time(NULL);
    }

    if(cap.type==1)
        cap_size=68;
    else if(cap.type==2)
        cap_size=500;
    else
        cap_size=0;

    if(start_capture(nvram_safe_get("wan_iface"),cap.end - cap.start,cap_size))
    {
        syslog(LOG_INFO,"---->capid:%d", cap.id);
        ret = start_file_upload(cap.id, PCAP_FILE);
    }
    unlink(PCAP_FILE);
    return ret;
}
#if 0
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
#endif
static int process_report_packet(char* pdu_ptr, int pdu_len, int socketfd)
{
    M2M_PROTOCOL_HDR *m2m_req, *m2m_res;
    M2M_PROTOCOL_TLV *m2m_tlv;
    int try_count=0;
    unsigned int tmp_size,idel_count;
    char *param_buf;
    unsigned char dataType;
    unsigned char saveFlag;
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
    m2m_res->safe_flag = m2m_req->safe_flag;
    m2m_res->data_type = 0;
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
        default:
            syslog(LOG_NOTICE, "[Report] M2M Command(%02x) Unsupport!!!", ntohs(m2m_req->cmd_id));
            break;
    }
}

void get_cap_file_para(char *pdu_ptr, ST_PACKET_CAP *cap)
{

    int tlvLen;
    unsigned int tmp;
    M2M_PROTOCOL_TLV *m2m_tlv;

    tlvLen = sizeof(M2M_PROTOCOL_HDR) + 1;

    m2m_tlv = (M2M_PROTOCOL_TLV *)(pdu_ptr + tlvLen);
    tlvLen += ntohs(m2m_tlv->tlv_len) + 4;
    memcpy(&tmp, m2m_tlv->tlv_value, 4);
    cap->id = ntohl(tmp);

    m2m_tlv = (M2M_PROTOCOL_TLV *)(pdu_ptr + tlvLen);
    tlvLen += ntohs(m2m_tlv->tlv_len) + 4;
    memcpy(&tmp, m2m_tlv->tlv_value, 4);
    cap->start = ntohl(tmp);


    m2m_tlv = (M2M_PROTOCOL_TLV *)(pdu_ptr + tlvLen);
    tlvLen += ntohs(m2m_tlv->tlv_len) + 4;
    memcpy(&tmp, m2m_tlv->tlv_value, 4);
    cap->end = ntohl(tmp);

    m2m_tlv = (M2M_PROTOCOL_TLV *)(pdu_ptr + tlvLen);
    cap->type = m2m_tlv->tlv_value[0];
}

int creat_cfg_file(unsigned char *path)
{
    unsigned char msg[64] = {0};
    static char *args[] = { "nvram", "backup", NULL, NULL };
    unsigned char tmp[64] = {0};

    strcpy(tmp, "/tmp/backupXXXXXX");
	 mktemp(tmp);
    memcpy(path, tmp, strlen(tmp));
	 args[2] = tmp;
    if (_eval(args, msg, 0, NULL) == 0)
    {
        syslog(LOG_INFO,"Nvram backup success!");
        return 1;
    }

    syslog(LOG_INFO,"Nvram backup failed!");
    return 0;
}

int check_report_all_sense(char *tlv)
{
    if(tlv == NULL)
    {
        return 0;
    }
    syslog(LOG_INFO,"[tlv0]:%d, [tlv1]:%d, [tlv2]:%d, [tlv3]:%d,", *tlv, *(tlv + 1), (tlv + 2), *(tlv + 3));
    if(*tlv == 0x01 && *(tlv + 1) == 0x0 && *(tlv + 2) == 0x0 && *(tlv + 3) == 0x0)
    {
        return 1;
    }

    return 0;
}
unsigned short parse_tlv_data(char *tlv, char *tag_value, unsigned short *tag_cmd)
{
    M2M_PROTOCOL_TLV *m2m_tlv;
    int len;

    if(tlv = NULL || tag_value == NULL)
    {
        return 0;
    }

    m2m_tlv = (M2M_PROTOCOL_TLV *)tlv;
    if(htons(m2m_tlv->tlv_tag) == 0x0 || ntohs(m2m_tlv->tlv_len) == 0x0)
    {
        syslog(LOG_INFO,"String has no tlv!");
        return 0;
    }
    *tag_cmd = ntohs(m2m_tlv->tlv_tag);
    len = ntohs(m2m_tlv->tlv_len);
    memcpy(tag_value, m2m_tlv->tlv_value, len);

    return len;
}
static int init_serial( int serial_fd)
{
    struct termios tio;

    memset(&tio, 0, sizeof(tio));

    tio.c_cflag = CREAD | HUPCL | baud_flag(115200);

    switch ('0')
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

    switch ('N')
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

    switch (8)
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
static uint16_t crc16(uint8_t *buffer, uint16_t buffer_length)
{
    uint8_t crc_hi = 0xFF; /* high CRC byte initialized */
    uint8_t crc_lo = 0xFF; /* low CRC byte initialized */
    unsigned int i; /* will index into CRC lookup */

    /* pass through message buffer */
    while (buffer_length--)
    {
        i = crc_hi ^ *buffer++; /* calculate the CRC  */
        crc_hi = crc_lo ^ table_crc_hi[i];
        crc_lo = table_crc_lo[i];
    }

    return (crc_hi << 8 | crc_lo);
}

void serial_upgrade(char *filename)
{
    int n,i,rn,rs;
    int fd,serial_fd;
    struct termios old_term;

    nvram_set("upgrade_serial_use","1");
    system("killall -9 modbus");
    sleep(3);
    serial_fd = open_serial("/dev/ttyS0", &old_term);
    if (serial_fd < 0)
    {
        syslog(LOG_ERR, "Error open ttyS0");
        return;
    }
    init_serial(serial_fd);

    int foffset = 0;
    fd = open(filename, O_RDONLY, 0666);
    if (fd < 0)
    {
        syslog(LOG_ERR, "Open tmp.bin file error!");
        close_serial(serial_fd,&old_term);
        return;
    }

    char mbuf[138] = {0}, mRsp[32];
    memset(mbuf, 0, sizeof(mbuf));
    while ((n = read(fd,mbuf + 7, 128)) != EOF)
    {
        if (n - 128 < 0)
        {
            mbuf[0] = 0x01;
            mbuf[1] = 0x44;
            int nOffset = htonl(foffset);
            memcpy(&mbuf[2], &nOffset, 4);
            mbuf[6] = n;

            unsigned short crc = crc16(mbuf, n + 7);
            mbuf[n + 7] = crc >> 8;
            mbuf[n + 8] = crc & 0x00FF;
            write(serial_fd, mbuf, n + 9);
            usleep(300 * 1000);
#if 1
            char str[3050] = {0};
            char *ptr;

            memset(str, 0, sizeof(str));
            for (i = 0; i < n + 9; i++)
            {
                ptr = &str[i * 3];
                sprintf(ptr,"%02x ",(unsigned char )*(mbuf + i));
            }
            syslog(LOG_INFO, "Send ---> [%s]", str);
#endif
            rn = read(serial_fd, mRsp, 32);

            foffset += n;
            memset(mbuf, 0, sizeof(mbuf));
            mbuf[0] = 0x01;
            mbuf[1] = 0x44;
            nOffset = htonl(foffset);
            memcpy(&mbuf[2], &nOffset, 4);
            mbuf[6] = 0;

            crc = crc16(mbuf, 7);
            mbuf[7] = crc >> 8;
            mbuf[8] = crc & 0x00FF;
            write(serial_fd, mbuf, 9);
#if 1
            usleep(300 * 1000);
            memset(str, 0, sizeof(str));
            for (i = 0; i < 9; i++)
            {
                ptr = &str[i * 3];
                sprintf(ptr,"%02x ",(unsigned char )*(mbuf + i));
            }
            syslog(LOG_INFO, "Send ---> [%s]", str);
#endif
            break;
        }
        else
        {
            mbuf[0] = 0x01;
            mbuf[1] = 0x44;
            int nOffset = htonl(foffset);
            memcpy(&mbuf[2], &nOffset, 4);
            mbuf[6] = 128;

            foffset += 128;

            unsigned short crc = crc16(mbuf, 128 + 7);
            mbuf[128 + 7] = crc >> 8;
            mbuf[128 + 8] = crc & 0x00FF;
            write(serial_fd, mbuf, 128 + 9);
#if 1
            //usleep(300 * 1000);
            char str[3050] = {0};
            char *ptr;

            memset(str, 0, sizeof(str));
            for (i = 0; i < 128 + 9; i++)
            {
                ptr = &str[i * 3];
                sprintf(ptr, "%02x ",(unsigned char )*(mbuf + i));
            }
            syslog(LOG_INFO, "Send ---> [%s]", str);
#endif
            rs = wait_sock(serial_fd, 2, 0);
            if (rs > 0)
            {
                memset(mbuf, 0, sizeof(mbuf));
                rn = read(serial_fd, mRsp, 32);
                if (rn> 0)
                {
#if 0
                    char str[3050] = {0};
                    char *ptr;

                    memset(str, 0, sizeof(str));
                    for (i = 0; i < n; i++)
                    {
                        ptr = &str[i * 3];
                        sprintf(ptr, "%02x ",(unsigned char )*(mRsp + i));
                    }
                    syslog(LOG_INFO, "recv ---> [%s]", str);
#endif
                }
            }
            else
            {
                syslog(LOG_INFO, "recv timeout or error, break upgrade");
                close_serial(serial_fd,&old_term);
                close(fd);
                return;

            }
        }


    }
    syslog(LOG_NOTICE, "<<<<<<<<<<<<< write to stm32 success");
    close_serial(serial_fd,&old_term);
    close(fd);
    nvram_set("upgrade_serial_use","0");
}


static int process_packet(char* pdu_ptr, int pdu_len)
{
    M2M_PROTOCOL_HDR *m2m_req, *m2m_res;
    M2M_PROTOCOL_TLV *m2m_tlv;
    M2M_PROTOCOL_TLV *m2m_tmp;
    M2M_PROTOCOL_DOWNLOAD_PARAM *m2m_dp = NULL;
    M2M_PROTOCOL_DOWNLOAD_FILE *m2m_df = NULL;
    SERIALHEAD *lora_head;
    SERIALTAIL *lora_tail;
    int try_count=0;
    unsigned int tmp_size,idel_count;
    char *param_buf;
    char ctrl_cmd_flag;
    char ctrl_cmd[256] = {0};
    unsigned char dataType;
    unsigned char saveFlag;
    int tlv_len = 0, res_buf_len = 0;
    int pid = -1;
    int n = 0;
    int fuc_ret=1;
    struct stat st;
    char translateBuf[2048] = {0};
    char cmdResult;
    int req_file_offset, downloadNum;//下载进度
    char *p;
    int len;

    m2m_req = (M2M_PROTOCOL_HDR*)pdu_ptr;
    m2m_res = (M2M_PROTOCOL_HDR*)m2m_res_buf;

    syslog(LOG_DEBUG, "M2M Request: len(%02x) cmdid(%02x) pkid(%02x) ver(%02x) saveflag(%02x) datatype(%02x) pid(%s)",
           ntohs(m2m_req->len), ntohs(m2m_req->cmd_id), ntohl(m2m_req->packet_id), ntohs(m2m_req->version), m2m_req->safe_flag,m2m_req->data_type, m2m_req->product_id);

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

    if(m2m_req->data_type == 1)
    {
        lora_head = (SERIALHEAD *)translateBuf;
        lora_tail = (SERIALTAIL *)(translateBuf + pdu_len + sizeof(SERIALHEAD));
        memcpy(translateBuf + sizeof(SERIALHEAD), pdu_ptr, pdu_len);
        lora_head->length = pdu_len + sizeof(SERIALHEAD) + sizeof(SERIALTAIL);
        lora_head->serHead = 0xAA;
        lora_head->type = 0xC1;
        lora_tail->check = checksum(translateBuf,pdu_len + sizeof(SERIALHEAD));
        lora_tail->tail = 0xBB;
        //translate to lora
        n = write_timeout(serialFd, translateBuf, lora_head->length, 500);
        if(n < 0)
        {
            syslog(LOG_INFO,"Translate data to lora failed!");
            close(serialFd);
            serialFd = -1;
        }
        syslog(LOG_INFO,"[%d]->Translate data to lora success!",n);
    }
    else
    {
        m2m_res->packet_id = m2m_req->packet_id;
        m2m_res->version = m2m_req->version;
        m2m_res->safe_flag = m2m_req->safe_flag;
        m2m_res->data_type = 0;
        memcpy(m2m_res->product_id, product_id, sizeof(m2m_res->product_id));


        switch (ntohs(m2m_req->cmd_id))
        {
            case M2M_LOGIN_ACK:
                cmdResult = *(pdu_ptr + sizeof(M2M_PROTOCOL_HDR));
                if(cmdResult == 0)
                {
                    g_login_ack=1;
                    m2m_send_cmd(REPORT_STATUS);
                    m2m_send_cmd(RTU_SCRIPT_TRAP);
                    m2m_send_cmd(M2M_CONFIG_TRAP); 
                }
                syslog(LOG_NOTICE, "M2M Command(%02x) cmdResult(%02x) M2M_LOGIN_ACK!!!", ntohs(m2m_req->cmd_id), cmdResult);
                break;
            case M2M_LOGOUT_ACK:
                syslog(LOG_NOTICE, "M2M Command(%02x) M2M_LOGOUT_ACK!!!", ntohs(m2m_req->cmd_id));
                g_login_ack = 2;
                break;
            case M2M_HEARTBEAT_ACK:
                cmdResult = *(pdu_ptr + sizeof(M2M_PROTOCOL_HDR));
                if(cmdResult == 0)
                {
                    trafic_flag = 0;
                }
                syslog(LOG_NOTICE, "M2M Command(%02x) cmdResult(%02x) M2M_HEARTBEAT_ACK!!!", ntohs(m2m_req->cmd_id), cmdResult);
                break;
            case REPORT_STATUS_ACK:
                cmdResult = *(pdu_ptr + sizeof(M2M_PROTOCOL_HDR));
                if(cmdResult == 0)
                {
                    g_report_status_ack=1;
                    nvram_unset("near_apmac");
                }
                syslog(LOG_NOTICE, "M2M Command(%02x) REPORT_STATUS_ACK!!!", ntohs(m2m_req->cmd_id));
                break;
            case M2M_CONFIG_GET:
                m2m_res->cmd_id = htons(M2M_CONFIG_GET_ACK);
                syslog(LOG_NOTICE, "M2M Command(%02x) M2M_CONFIG_GET!!!", ntohs(m2m_req->cmd_id));
                *(m2m_res_buf + sizeof(M2M_PROTOCOL_HDR)) = 0x00;
                m2m_tlv = (M2M_PROTOCOL_TLV*)(m2m_res_buf + sizeof(M2M_PROTOCOL_HDR) + 1);

                if(pdu_len == sizeof(M2M_PROTOCOL_HDR))//上报所有参数
                {
                    tlv_len = make_router_config(m2m_tlv->tlv_value);
                    syslog(LOG_INFO,"Report all config");
                }
                else//上报指定参数值
                {
                    m2m_tmp = (M2M_PROTOCOL_TLV *)(pdu_ptr + sizeof(M2M_PROTOCOL_HDR));
                    tlv_len = get_router_nvram(m2m_tmp->tlv_value, m2m_tlv->tlv_value, M2M_TLV_VALUE);
                    syslog(LOG_INFO,"Report some config");
                }

                m2m_tlv->tlv_tag = htons(0x0106);
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
                else if(ctrl_cmd_flag == 0x02)
                {
                    f_write_string("/proc/sys/net/ipv4/ip_forward", "0", 0, 0);
                    *(m2m_res_buf + sizeof(M2M_PROTOCOL_HDR)) = 0;
                    udp_socket_send(m2m_res_buf, res_buf_len);
                }
                else if(ctrl_cmd_flag == 0x03)
                {
                    f_write_string("/proc/sys/net/ipv4/ip_forward", "1", 0, 0);
                    *(m2m_res_buf + sizeof(M2M_PROTOCOL_HDR)) = 0;
                    udp_socket_send(m2m_res_buf, res_buf_len);

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
                else if(ctrl_cmd_flag == 0x07)
                {
                    char mac[64];
                    m2m_tlv = (M2M_PROTOCOL_TLV *)(pdu_ptr + sizeof(M2M_PROTOCOL_HDR) + 1);
                    memcpy(mac, m2m_tlv->tlv_value, ntohs(m2m_tlv->tlv_len));

                    *(m2m_res_buf + sizeof(M2M_PROTOCOL_HDR)) = execute_remote_ctrl(mac);
                    udp_socket_send(m2m_res_buf, res_buf_len);

                }
                else if(ctrl_cmd_flag == 0x08)//cap the packet
                {
                    ST_PACKET_CAP capFile;
                    get_cap_file_para(pdu_ptr,&capFile);
                    syslog(LOG_INFO,"---->capid:%d, start:%d, end:%d, type:%02x", capFile.id, capFile.start, capFile.end, capFile.type);
                    AD_UPGRADE_flag = 1;
                    N_ACK = 0;
                    if(pcap_thread(capFile))//success
                    {
                        *(m2m_res_buf + sizeof(M2M_PROTOCOL_HDR)) = 0;
                    }
                    else
                    {
                        *(m2m_res_buf + sizeof(M2M_PROTOCOL_HDR)) = 1;
                    }
                    udp_socket_send(m2m_res_buf, res_buf_len);
                    AD_UPGRADE_flag = 0;
                }
                else if(ctrl_cmd_flag == 0x09)
                {
                    int id;
                    unsigned char path[64] = {0};

                    m2m_tlv = (M2M_PROTOCOL_TLV *)(pdu_ptr + sizeof(M2M_PROTOCOL_HDR) + 1);
                    memcpy(&id, m2m_tlv->tlv_value, 4);
                    creat_cfg_file(path);
                    syslog(LOG_INFO,"--->Get upload id :%d", ntohl(id));
                    AD_UPGRADE_flag = 1;
                    N_ACK = 0;
                    if(start_file_upload(ntohl(id),path))
                    {
                        *(m2m_res_buf + sizeof(M2M_PROTOCOL_HDR)) = 0;
                    }
                    else
                    {
                        *(m2m_res_buf + sizeof(M2M_PROTOCOL_HDR)) = 1;
                    }
                    udp_socket_send(m2m_res_buf, res_buf_len);
                    unlink(path);
                    AD_UPGRADE_flag = 0;
                }
                else if(ctrl_cmd_flag == 0x0A)
                {
#if 0
                    system("mv /jffs_nv/nv.cfg /jffs_nv/nv.cfg.fac");
                    eval("mtd-erase", "-d", "nvram");
                    system("mtd erase /dev/mtd5");

                    *(m2m_res_buf + sizeof(M2M_PROTOCOL_HDR)) = 0;
                    udp_socket_send(m2m_res_buf, res_buf_len);
                    m2m_send_cmd(M2M_LOGOUT);
                    syslog(LOG_NOTICE, "M2M Reboot System Command!!");
                    reboot(RB_AUTOBOOT);
#endif
                    *(m2m_res_buf + sizeof(M2M_PROTOCOL_HDR)) = 1;
                    udp_socket_send(m2m_res_buf, res_buf_len);

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

            case DOWNLOAD_INFO:
                syslog(LOG_NOTICE, "M2M Command(%02x) DOWNLOAD_INFO!!!", ntohs(m2m_req->cmd_id));
				
				unsigned int pack_id = ntohl(m2m_req->packet_id);
				int filesize = 0;
				struct stat st;
				int ret;
				
				g_down_info = (ST_DOWNLOAD_INFO *)(pdu_ptr + sizeof(M2M_PROTOCOL_HDR));
				syslog(LOG_NOTICE, "Filecount:%d", g_down_info->filecount);
				
				if((!g_downloading) && ((pdu_len - sizeof(M2M_PROTOCOL_HDR)) == (g_down_info->filecount * sizeof(FILE_INFO) + 4)))
				{
					g_downloading = 1;
					g_down_info = (ST_DOWNLOAD_INFO *)malloc(pdu_len - sizeof(M2M_PROTOCOL_HDR));
					
					if(g_down_info)
					{
						memcpy(g_down_info, pdu_ptr + sizeof(M2M_PROTOCOL_HDR), pdu_len - sizeof(M2M_PROTOCOL_HDR));
						
                		if(strstr(g_down_info->filelist[0].filename,".trx"))
							strcpy(filename, "/tmp/tmp.trx");
						
                		if(strstr(g_down_info->filelist[0].filename,".cfg"))
							strcpy(filename, "/tmp/tmp.cfg");
						
						if(strstr(g_down_info->filelist[0].filename,".bin"))
							strcpy(filename, "/tmp/tmp.bin");

						ret = download_process(pack_id);

						if(stat(filename, &st) == 0)
						{
							filesize = st.st_size;
						}
						syslog(LOG_NOTICE, "Filesize after downloading:%d", filesize);
						
						if(ret == 1)
						{
							send_download_ack(DOWNLOAD_INFO_ACK, pack_id, 0, filesize);
							syslog(LOG_NOTICE, "All TCP download success.");
							g_downloading = 0;
							free(g_down_info);
						}
						else
						{
							send_download_ack(DOWNLOAD_INFO_ACK, pack_id, 1, filesize);
							syslog(LOG_NOTICE, "All TCP download fial.");
							g_downloading = 0;
							free(g_down_info);
							break;
						}
					}
				}
				else
				{
					syslog(LOG_ERR, "Downloading is running");
					send_download_ack(DOWNLOAD_INFO_ACK, pack_id, 1, filesize);
					break;
				}

#if 1
                //after save file, need to do other thing, such as upgrade...
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

                    break;
                }
                if(strstr(g_down_info->filelist[0].filename,".patch"))
                {
                    syslog(LOG_ERR,"mod upgrade");
                    if(!mod_upgrade(filename))
                    {
                        set_action(ACT_IDLE);
                        m2m_send_cmd(M2M_LOGOUT);
                        sleep(2);
                        reboot(RB_AUTOBOOT);
                    }
                    if(nvram_match("mod_upgrade_test","1"))
                        exit(1);
                }
                else if(strstr(g_down_info->filelist[0].filename,".trx"))
                {
                    eval("service", "upgrade", "start");
                    set_action(ACT_IDLE);
                    char *wargv[] = { "mtd-write", "-w", "-i", filename, "-d", "linux", NULL };
					syslog(LOG_NOTICE, "%s", filename);
                    // wargv[3] = filename;
                    _eval(wargv, ">/tmp/mtd-write-m2m", 0, &pid);
                    if (pid != -1) waitpid(pid, &n, 0);
                }
                else if(strstr(g_down_info->filelist[0].filename,".cfg"))
                {
                    static char *args[] = {"nvram", "restore", filename, NULL};
                    _eval(args, ">/tmp/tmp.cfg.msg", 0, NULL);
                }
                else if(strstr(g_down_info->filelist[0].filename,".bin"))
                {
                    serial_upgrade(filename);
                }
                AD_UPGRADE_flag = 0;
                set_action(ACT_REBOOT);
                syslog(LOG_NOTICE, "M2M Reboot System");
                m2m_send_cmd(M2M_LOGOUT);
                sleep(2);
                unlink(g_down_info->filelist[0].filename);
                reboot(RB_AUTOBOOT);
#endif
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
            case RTU_SCRIPT_GET:
                m2m_res->cmd_id = htons(RTU_SCRIPT_GET_ACK);
                syslog(LOG_NOTICE, "M2M Command(%02x) RTU_SCRIPT_GET!!!", ntohs(m2m_req->cmd_id));
                *(m2m_res_buf + sizeof(M2M_PROTOCOL_HDR)) = 0x0;
                p = nvram_safe_get("rtu_scripts");
                strncpy(m2m_res_buf + sizeof(M2M_PROTOCOL_HDR) + 1, p, strlen(p));
                len = sizeof(M2M_PROTOCOL_HDR) + 1 + strlen(p);
                m2m_res->len = htons(len);
                udp_socket_send(m2m_res_buf, len);
                break;
            case RTU_SCRIPT_SET:

                m2m_res->cmd_id = htons(RTU_SCRIPT_SET_ACK);
                syslog(LOG_NOTICE, "M2M Command(%02x) RTU_SCRIPT_SET!!!", ntohs(m2m_req->cmd_id));
                nvram_set("rtu_scripts", pdu_ptr + sizeof(M2M_PROTOCOL_HDR));
                system("nvram commit");
                syslog(LOG_NOTICE, "Scripts set:%s", pdu_ptr + sizeof(M2M_PROTOCOL_HDR));
                *(m2m_res_buf + sizeof(M2M_PROTOCOL_HDR)) = 0x0;
                m2m_res->len = htons(sizeof(M2M_PROTOCOL_HDR) + 1);
                udp_socket_send(m2m_res_buf, sizeof(M2M_PROTOCOL_HDR) + 1);
                m2m_send_cmd(M2M_LOGOUT);
                system("killall -9 modem_watchdog&");
                syslog(LOG_NOTICE, "M2M config set reboot!!");
                reboot(RB_AUTOBOOT);
                break;
            case RTU_SCRIPT_TRAP_ACK:
                syslog(LOG_NOTICE, "M2M Command(%02x) RTU_SCRIPT_TRAP_ACK!!!", RTU_SCRIPT_TRAP_ACK);
                break;
            case M2M_CONFIG_TRAP_ACK:
                syslog(LOG_NOTICE, "M2M Command(%02x) M2M_CONFIG_TRAP_ACK!!!", M2M_CONFIG_TRAP_ACK);
                break;
            case RTU_SUB:
#if 0
                char tlv_value[M2M_TLV_VALUE];
                unsigned short tcmd, tlen;
                int length;
                m2m_res->cmd_id = htons(RTU_SUB_ACK);
                syslog(LOG_NOTICE, "M2M Command(%02x) RTU_SUB!!!", ntohs(m2m_req->cmd_id));
                length = sizeof(M2M_PROTOCOL_HDR);
                while((tlen = parse_tlv_data(m2m_req + length, tlv_value, &tcmd)) != 0)
                {
                    if(check_report_all_sense(tlv_value))//上报所有传感器的值
                    {

                        break;
                    }
                    else//上报指定传感器的值
                    {

                    }
                    length += tlen + 4;
                }
                udp_socket_send(m2m_res_buf, res_buf_len);
#endif
                break;
            case RTU_PUBLISH_ACK:
                syslog(LOG_NOTICE, "RTU Command(%02x) RTU_PUBLISH_ACK!!!", ntohs(m2m_req->cmd_id));
                break;

            default:
                syslog(LOG_NOTICE, "M2M Command(%02x) Unsupport!!!", ntohs(m2m_req->cmd_id));
                break;
        }
    }
}

static int process_m2m_Req( )
{
    int      iRcv;
    int      fromlen;
    char        *hdr;
    char        pdubuf[M2M_REQ_PDU_BUF];
    struct sockaddr_in  from_addr;

    memset(pdubuf, 0, sizeof(pdubuf));

    if ( wait_sock(socket_fd, 1, 0) == 0)
    {
        return (-1);
    }

    fromlen = sizeof(from_addr);

    //Receive the complete PDU
    iRcv = udp_socket_recv(pdubuf, sizeof(pdubuf));

    if (iRcv < sizeof(M2M_PROTOCOL_HDR))
    {
        syslog(LOG_ERR, "iRcv: %d != m2mHDR: %d", iRcv, sizeof(M2M_PROTOCOL_HDR));
        close_socket(socket_fd);
        return (-1);
    }

    hdr = pdubuf;

    process_packet( hdr, iRcv);
}
static int process_report_Req(int socketfd, unsigned long svrip )
{
    int      iRcv;
    int      fromlen;
    char        *hdr;
    char        pdubuf[M2M_REQ_PDU_BUF];
    struct sockaddr_in  from_addr;

    memset(pdubuf, 0, sizeof(pdubuf));

    if ( wait_sock(socketfd, 1, 0) == 0)
    {
        return (-1);
    }

    fromlen = sizeof(from_addr);

    //Receive the complete PDU
    iRcv = report_udp_socket_recv(socketfd, pdubuf, sizeof(pdubuf), svrip);

    if (iRcv < sizeof(M2M_PROTOCOL_HDR))
    {
        syslog(LOG_ERR, "iRcv: %d != m2mHDR: %d", iRcv, sizeof(M2M_PROTOCOL_HDR));
        close_socket(socketfd);
        return (-1);
    }

    hdr = pdubuf;

    process_report_packet( hdr, iRcv, socketfd);
}

static int connect_to_server(char *sock_name)
{
    int sock;
    struct sockaddr_un  sa_un;
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
    int sock;
    int len;

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

struct _cops
{
    unsigned char value;
    char *keyword;
} g_cops[]=
{
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
    for(i=0; i<SF_JSON_ELM_COUNT; i++)
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

    gettimeofday (&tv,&tz);
    timep=tv.tv_sec;
    p=localtime(&timep);
    sprintf(buf, "%04d%02d%02d%02d%02d%02d%03ld", (1900+p->tm_year), (1+p->tm_mon),p->tm_mday,p->tm_hour, p->tm_min, p->tm_sec,tv.tv_usec/1000);
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
    fgets(buf, sizeof(buf), f); // header
    fgets(buf, sizeof(buf), f); // "
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
                            syslog(LOG_NOTICE,"Have Send RESP to SF BOX");
                        }
                    }
                }
                else if(count == 4)
                {
                    if(strcmp(json_get_elm_value(jelm,"action"),"SWAP_INFO_REQ") == 0)
                    {
                        syslog(LOG_NOTICE, "SF BOX ID:%s",json_get_elm_value(jelm,"fcboxAssetId"));
                        nvram_set("psn",json_get_elm_value(jelm,"fcboxAssetId"));
                        g_report_status_ack=3;
                        while(g_report_status_ack == 3)
                        {
                            syslog(LOG_NOTICE,"SF box report status");
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
                            syslog(LOG_NOTICE,"Have Send RESP to SF BOX");
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
                            syslog(LOG_NOTICE,"Have Send RESP to SF BOX");
                        }
                        usleep(delay * 1000);
                        for(i=0; i < 40; i++)
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
                for(i=0; i<count; i++)
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
            hb->packet_id = htonl(packet_id++);
            hb->version = htons(M2M_VERSION);
            hb->safe_flag = 0;
            hb->data_type = 0;
            memcpy(hb->product_id, product_id, sizeof(hb->product_id));
            if (nvram_get_int("csq")>0)
                csq = nvram_get_int("csq");
            if (csq>100)
                csq = (csq - 100)/3;
            *(hb_buf + sizeof(M2M_PROTOCOL_HDR)) = csq;

            *(unsigned int*)(hb_buf + sizeof(M2M_PROTOCOL_HDR)+1) = htonl(trafic_calc());
            *(hb_buf + sizeof(M2M_PROTOCOL_HDR)+1+4) = get_cops();
            *(hb_buf + sizeof(M2M_PROTOCOL_HDR)+1+4+1) = 1;//nvram_get_int("sim_flag")
            hb_len = sizeof(M2M_PROTOCOL_HDR)+1+4+1+1;
            hb->len = htons(hb_len);
            report_udp_socket_send(fd,hb_buf, hb_len);

            if((!(nvram_match("cell_cid",nvram_safe_get("cellg_cid")) && nvram_match("cell_lac",nvram_safe_get("cellg_lac"))))
               &&(!(nvram_match("cell_cid",nvram_safe_get("celle_cid")) && nvram_match("cell_lac",nvram_safe_get("celle_lac")))))
            {
                //   m2m_report_status_send_cmd(fd,REPORT_STATUS);
            }
            if(!g_report_status_ack)
            {
                syslog(LOG_ERR,"report status again");
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
        res = select( fd + 1, &fdvar, NULL, NULL, &tv);
        if (res == 1)
        {
            process_report_Req(fd,svrip);
        }
    }
}
void heartbeat_thread(void *param)
{
    char hb_buf[512] = {0};
    int hb_len = 0;
    int intval = 2;
    int csq = 0;
    int retry=nvram_get_int("m2m_heartbeat_retry")?:10;
    M2M_PROTOCOL_HDR* hb = (M2M_PROTOCOL_HDR*)hb_buf;

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
            hb->packet_id = htonl(packet_id++);
            hb->version = htons(M2M_VERSION);
            hb->safe_flag = 0;
            hb->data_type = 0;
            memcpy(hb->product_id, product_id, sizeof(hb->product_id));
            if (nvram_get_int("csq")>0)
                csq = nvram_get_int("csq");
            if (csq>100)
                csq = (csq - 100)/3;
            *(hb_buf + sizeof(M2M_PROTOCOL_HDR)) = csq;

            *(unsigned int*)(hb_buf + sizeof(M2M_PROTOCOL_HDR)+1) = htonl(trafic_calc());
            *(hb_buf + sizeof(M2M_PROTOCOL_HDR)+1+4) = get_cops();
            *(hb_buf + sizeof(M2M_PROTOCOL_HDR)+1+4+1) = 1;//nvram_get_int("sim_flag")
            hb_len = sizeof(M2M_PROTOCOL_HDR)+1+4+1+1;
            hb->len = htons(hb_len);
            udp_socket_send(hb_buf, hb_len);

            if((!(nvram_match("cell_cid",nvram_safe_get("cellg_cid")) && nvram_match("cell_lac",nvram_safe_get("cellg_lac"))))
               &&(!(nvram_match("cell_cid",nvram_safe_get("celle_cid")) && nvram_match("cell_lac",nvram_safe_get("celle_lac")))))
            {
                m2m_send_cmd(REPORT_STATUS);
            }
            if(!g_report_status_ack)
            {
                syslog(LOG_ERR,"report status again");
                m2m_send_cmd(REPORT_STATUS);
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
        for(i=0; i<argc && !error; i++)
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

        for(i=0; i<argc && !error; i++)
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
#if 0
    if(argc < 2)
        return ret;

    for(i=0; i<argc; i++)
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

        for(i=0; i<argc && !error; i++)
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
#endif
    return ret;
}

#define ARGV_SIZE 100

static void *external_handler(int fd)
{
    int done,i=0;
    char request[4096];
    ssize_t read_bytes,len;
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
    int sock, fd;
    char *sock_name;
    struct  sockaddr_un sa_un;
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

typedef struct _domain_node
{
    struct _domain_node *next;
    char *domain;
} domain_node;

typedef struct _url_report_node
{
    struct _url_report_node *next;
    char *ip;
    domain_node *domain_list;
} url_report_node;

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
    for(i=0,j=0; i<17; i++)
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
#if 0
    for(tmp_unode=url_node; tmp_unode != NULL && tmp_unode->ip != NULL; tmp_unode=tmp_unode->next)
    {
        total_len=0;
        url_cont=0;
        url_len=0;

        if(!arp_get(tmp_unode->ip,cmac))
            continue;

        for(tmp_domain=tmp_unode->domain_list; tmp_domain != NULL && tmp_domain->domain != NULL; tmp_domain=tmp_domain->next)
        {
            url_cont++;
            url_len += strlen(tmp_domain->domain);
        }

        total_len = sizeof(M2M_PROTOCOL_HDR) + (url_cont+1) *4 + url_len + CLIENT_MAC_LEN;

        if((url_report_buf=calloc(total_len,sizeof(char))) == NULL)
            continue;

        cur_pos = sizeof(M2M_PROTOCOL_HDR);

        pack_sub_elem(url_report_buf,&cur_pos,CLIENT_MAC,CLIENT_MAC_LEN,cmac);
        for(tmp_domain=tmp_unode->domain_list; tmp_domain != NULL && tmp_domain->domain != NULL; tmp_domain=tmp_domain->next)
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
#endif
}

void destroy_unode(url_report_node *tmp_unode)
{
    if (tmp_unode->ip != NULL)
        free(tmp_unode->ip);

    if (tmp_unode->domain_list != NULL)
    {
        domain_node *tmp,*tmp1;
        for(tmp=tmp_unode->domain_list; tmp != NULL; tmp=tmp1)
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
int encode_rtu_pub_pack(unsigned char *buf, int buf_len)
{
    unsigned short hb_len = 0;
    M2M_PROTOCOL_HDR* hb = (M2M_PROTOCOL_HDR*)buf;
    M2M_PROTOCOL_TLV *tlv;
    RTU_PUBLISH_DATA *dtlv;
    unsigned short startAddr;
    char *nv, *nvp, *b;
    int n, valueType;
    char signal_nv_name[32] = {0};
    char addr_nv_name[32] = {0};
    char val_nv_name[32] = {0};
    short val_s;
    int val_i;
    float val_f;
    char val_c;
    char outBuf[12] = {0};

    hb->cmd_id = htons(RTU_PUBLISH);
    hb->packet_id = htonl(packet_id++);
    hb->version = htons(M2M_VERSION);
    hb->safe_flag = 0;
    hb->data_type = 0;
    memcpy(hb->product_id, product_id, sizeof(hb->product_id));
    hb_len += sizeof(M2M_PROTOCOL_HDR);

    nvp = nv = strdup(nvram_safe_get("modbusCmdTable"));
    if (nv == NULL || *nv == 0x0)
    {
        syslog(LOG_NOTICE, "modbusCmdTable is NULL ");
        return -1;
    }
    //encode tlvs
    while ((b = strsep(&nvp, ">")) != NULL)
    {
        char *cmd, *regAddr, *data_type, *sigid, *desc;
        char *regAddr_value = NULL, *val_value = NULL;
        int len;


        n = vstrsep(b, "<", &cmd, &regAddr, &data_type, &sigid, &desc);
        if (n < 5)
        {
            continue ;
        }
        snprintf(addr_nv_name, sizeof(addr_nv_name), "regAddr_%s", sigid);
        snprintf(val_nv_name, sizeof(val_nv_name), "signalval_%s", sigid);

        regAddr_value = nvram_safe_get(addr_nv_name);
        val_value = nvram_safe_get(val_nv_name);

        startAddr = atoi(regAddr_value);
        valueType = atoi(data_type);
        syslog(LOG_INFO,"----->valtype:%d, startAddr:%d, len:%d", valueType, startAddr, hb_len);

        tlv = (M2M_PROTOCOL_HDR *)(buf + hb_len);
        dtlv = (RTU_PUBLISH_DATA *)(tlv->tlv_value);
        syslog(LOG_NOTICE, "PUB Function---> MODBUS get: %s, %s", regAddr_value, val_value);
        tlv->tlv_tag = htons(PUBLISH_DATA_TLV_CMD);
        dtlv->data_type = 0x01;
        dtlv->slave_id = 0x01;
        dtlv->regaddr = htons(startAddr);
        switch(valueType)
        {
            case 1://浮点数
                val_f = atof(val_value);
                memcpy(outBuf, &val_f, 4);
                tlv->tlv_value[sizeof(RTU_PUBLISH_DATA)] = outBuf[0];
                tlv->tlv_value[sizeof(RTU_PUBLISH_DATA) + 1] = outBuf[1];
                tlv->tlv_value[sizeof(RTU_PUBLISH_DATA) + 2] = outBuf[2];
                tlv->tlv_value[sizeof(RTU_PUBLISH_DATA) + 3] = outBuf[3];
                len = 4;
                break;
            case 2://单字节
                val_c = (char)atoi(val_value);
                tlv->tlv_value[sizeof(RTU_PUBLISH_DATA)] = val_c;
                len = 1;
                break;
            case 3://双字节
                val_s = (short)atoi(val_value);
                memcpy(outBuf, &val_s, 2);
                tlv->tlv_value[sizeof(RTU_PUBLISH_DATA)] = outBuf[1];
                tlv->tlv_value[sizeof(RTU_PUBLISH_DATA) + 1] = outBuf[0];
                //memcpy(tlv->tlv_value + sizeof(RTU_PUBLISH_DATA), &val_s, 2);
                len = 2;
                break;
            case 4://四字节
                val_i = atoi(val_value);
                memcpy(outBuf, &val_i, 4);
                tlv->tlv_value[sizeof(RTU_PUBLISH_DATA)] = outBuf[3];
                tlv->tlv_value[sizeof(RTU_PUBLISH_DATA) + 1] = outBuf[2];
                tlv->tlv_value[sizeof(RTU_PUBLISH_DATA) + 2] = outBuf[1];
                tlv->tlv_value[sizeof(RTU_PUBLISH_DATA) + 3] = outBuf[0];
                len = 4;
                break;
            default:
                break;
        }

        tlv->tlv_len = htons(sizeof(RTU_PUBLISH_DATA) + len);
        hb_len += len + 8;
    }
    hb->len = htons(hb_len);
    free(nv);

    print_hex(buf, hb_len, 1);

    return hb_len;
}

void *rtu_pub_thread_routine(void *arg)
{
    unsigned char buf[2048] = {0};
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
        memset(buf, 0, sizeof(buf));
        pkt_length = encode_rtu_pub_pack(buf, sizeof(buf));
        if(pkt_length < 0)
        {
            continue;
        }
        ret = udp_socket_send(buf,pkt_length);
        if (ret == -1)
        {
            close(socket_fd);
            socket_fd = -1;
        }
    }

    return NULL;
}

int m2m_main(int argc, char *argv[])
{
    char ibuf[21] = {0};
    unsigned char mac[6] = {0};
    unsigned long ip = 0;
    struct timeval  tv;
    pthread_t heart_beat_id,external_id,report_url_id,report_status_alone_id, lora_id, rtu_pub_id;
    pthread_t sf_box;
    char *p;

    m2m_deamon();
    m2m_config_init();
    ether_atoe(nvram_safe_get("et0macaddr"), mac);
    p = nvram_safe_get("router_sn");
    memcpy(product_id, p + 2, 15);
    syslog(LOG_INFO,"----->product_id:%s,%s",p, product_id);
    //sprintf(product_id, "%02x%02x%02x%02x", mac[2], mac[3], mac[4], mac[5]);
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
    if (pthread_create(&rtu_pub_id, NULL, (void *)rtu_pub_thread_routine, NULL) != 0)
    {
        syslog(LOG_ERR, "!!M2M Failed to Create Heartbeat Thread");
    }
    else
    {
        pthread_detach(rtu_pub_id);
        syslog(LOG_NOTICE, "M2M rtu_pub_id Thread %d", rtu_pub_id);
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
        res = select( socket_fd + 1, &fdvar, NULL, NULL, &tv);

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
