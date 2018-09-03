
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "modbus.h"
#include "signal.h"
#include <bcmnvram.h>
#include <stdarg.h>
#include <pthread.h>
#include <unistd.h>
#include <pthread.h>
#include <libemqtt.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/tcp.h>
#include <semaphore.h>
#include <sys/sysinfo.h>
#include "des.h"
#include "MD5.h"
#include <cJSON.h>

#include "modbus-private.h"

#include "modbus_main.h"
#include "modbus_signal_data.h"
enum
{
    TCP,
    TCP_PI,
    RTU
};

static volatile int modbus_gothup = 0;
static volatile int modbus_gotuser = 0;
static volatile int modbus_gotterm = 0;

static MODBUS_CONFIG modbus_config;
volatile int m_total_pack = 0;

#define MAX_MESSAGE_LENGTH 260
#define MAX_RTU_PACKET_LENGTH		1024
typedef struct modbus_mbap_t
{
    uint8_t evtCode[2];
    uint8_t proto[2];
    unsigned short length;
    uint8_t addr;
} MODBUS_MBAP_T;

#pragma pack(1)

#if 0
typedef struct _uart_cfg
{
    unsigned char 	endflag[2];
    unsigned long	baudrate;		//²¨ÌØÂÊ
    unsigned char	databit;			//Êý¾ÝÎ»
    unsigned char	stopbit;			//Í£Ö¹Î»
    unsigned char	paritybit;		//Ð£ÑéÎ»
//    char			reserved;
} UART_CFG_T;
#endif

typedef struct _uart_cfg
{
    unsigned char	modbus_slave_count;
    unsigned char	modbus_slave_addr[32];
    unsigned long	baudrate;		//²¨ÌØÂÊ
    unsigned char	databit;			//Êý¾ÝÎ»
    unsigned char	stopbit;			//Í£Ö¹Î»
    unsigned char	paritybit;		//Ð£ÑéÎ»
//    char			reserved;
} UART_CFG_T;

typedef struct _rtu_cmd_head
{
	unsigned short length;
	unsigned short cmdid;
	unsigned int seq;
	unsigned short version;
	unsigned char safe_flag;
	unsigned char type;
	char dev_sn[16];
} RTU_CMD_HEAD;

typedef struct _rtu_cmd_tlv
{
	unsigned short tlv_tag;
	unsigned short tlv_len;
	char tlv_value[1024];
} RTU_CMD_TLV;

#if 1
typedef struct _rtu_cmd_head_t
{
	unsigned char head;
	unsigned short length;
	char ver[2];
	unsigned int seq;
	char dev_sn[16];
	unsigned short cmdid;
} RTU_CMD_HEAD_T;

typedef struct _rtu_cmd_tlv_t
{
	unsigned char tag[4];
	unsigned short len;
} RTU_CMD_TLV_T;

#endif
#pragma pack()

unsigned char m_detrantech[ ] = {0xe5, 0xbe, 0xb7, 0xe4, 0xbc, 0xa0, 0xe6, 0x8a, 0x80, 0xe6, 0x9c, 0xaf, 0x0};
unsigned char m_deviceRep[ ] = {0xe8, 0xae, 0xbe, 0xe5, 0xa4, 0x87, 0xe8, 0xbf, 0x90, 0xe8, 0xa1, 0x8c, 0xe4, 0xbf, 0xa1, 0xe6, 0x81, 0xaf, 0xe5, 0x91, 0xa8, 0xe6, 0x9c, 0x9f, 0xe4, 0xb8, 0x8a, 0xe6, 0x8a, 0xa5, 0x0};
unsigned char m_gatewayRep[ ] = {0xe7, 0xbd, 0x91, 0xe5, 0x85, 0xb3, 0xe4, 0xbf, 0xa1, 0xe6, 0x81, 0xaf, 0xe4, 0xb8, 0x8a, 0xe6, 0x8a, 0xa5, 0x0};
unsigned char m_rtuInfoRep[ ] = {0x52, 0x54, 0x55, 0xe4, 0xbf, 0xa1, 0xe6, 0x81, 0xaf, 0xe4, 0xb8, 0x8a, 0xe6, 0x8a, 0xa5, 0x0};


unsigned char m_rtuDataRep[ ] = {0xe5, 0xae, 0x9e, 0xe6, 0x97, 0xb6, 0xe6, 0x95, 0xb0, 0xe6, 0x8d, 0xae, 0xe5, 0x88, 0x97, 0xe8, 0xa1, 0xa8, 0xe4, 0xb8, 0x8a, 0xe6, 0x8a, 0xa5,0x0};
unsigned char m_alarmDataRep[ ] = {0xe6, 0x8a, 0xa5, 0xe8, 0xad, 0xa6, 0xe6, 0x95, 0xb0, 0xe6, 0x8d, 0xae, 0xe5, 0xae, 0x9e, 0xe6, 0x97, 0xb6, 0xe4, 0xb8, 0x8a, 0xe6, 0x8a, 0xa5, 0x0};
unsigned char m_signallistRep[ ] = {0xe4, 0xbf, 0xa1, 0xe5, 0x8f, 0xb7, 0xe4, 0xbf, 0xa1, 0xe6, 0x81, 0xaf, 0xe5, 0x88, 0x97, 0xe8, 0xa1, 0xa8, 0xe4, 0xb8, 0x8a, 0xe4, 0xbc, 0xa0, 0x0};

unsigned char m_alarmContRep[ ] = {0xe5, 0x91, 0x8a, 0xe8, 0xad, 0xa6, 0xe5, 0x86, 0x85, 0xe5, 0xae, 0xb9, 0xe6, 0x95, 0xb0, 0xe6, 0x8d, 0xae, 0x0};
unsigned char m_alarmResRep[ ] = {0xe6, 0x8a, 0xa5, 0xe8, 0xad, 0xa6, 0xe6, 0x81, 0xa2, 0xe5, 0xa4, 0x8d, 0x0};
unsigned char m_curValue[ ] = {0xe5, 0xbd, 0x93, 0xe5, 0x89, 0x8d, 0xe5, 0x80, 0xbc, 0x0};

#define GATEWAY_PUB_TOPIC		"pub/GWList_RLY"
#define RTU_INFO_PUB_TOPIC		"pub/DeviceSetToVR_RLY"
#define RTU_LIST_PUB_TOPIC		"pub/SignalList"
#define RTU_DATA_PUB_TOPIC		"pub/InTimeData"
#define ALARM_PUB_TOPIC			"pub/Alarm"
#define DEVICE_INFO_PUB_TOPIC	"pub/DeviceStates"
#define RTU_UPDATE_TOPIC		"pub/SignalSetToVR"

#define READ_COIL_STATUS		0x01
#define READ_INPUT_STATUS		0x02
#define READ_HOLDING_REGISTERS	0x03
#define READ_INPUT_REGISTERS	0x04
#define FORCE_SINGLE_COIL		0x05


#define MODBUS_PID_FILE "/var/run/modbus.pid"

static unsigned char m_router_sn[16] = {0};
//static unsigned char m_rtu_res_buf[MAX_RTU_PACKET_LENGTH] = {0}; 

static int m_rtu_svr_socket = -1;
static int m_heartbeat_ack_count = 0;

static struct sockaddr_in m_rtu_svr_addr;

// -------------- IOT SDK define --------------------

#define MSG_LEN_MAX 100


int socket_id;
sem_t	m_json_send_sem;

volatile int m_connect_state = 0;
#define MAX_QUEUE_SIZE 32

typedef struct alarm_info_t
{
    char signalId[24];
    char signalName[256];
    int  regAddr;
    int type;
    char maxVal[12];
    char minVal[12];
    char ctrlAble[8];
    char oper[6];
    int grade;
    char note[256];
    int alarmStatus;
    int datatype;
} ALARM_INFO_T;

ALARM_INFO_T m_alarmInfo[12];
static int m_max_alarm_num = 0;
static unsigned int m_rtu_seq_num = 0;

typedef struct node * PNode;
typedef struct node
{
    char  *elem;
    char   topic[128];
    PNode next;
} Node;



typedef struct
{
    PNode front;
    PNode rear;
    int size;
} Queue;

Queue *m_json_event_queue;
pthread_mutex_t m_queue_mutex = PTHREAD_MUTEX_INITIALIZER;

#define RCVBUFSIZE 4096
#define UART_NUM   3
#define UART_PARA_LEN UART_NUM*20
#define SEND 1
#define RECV 0


static volatile int connect_flag = 1;

char *getCurTime(char *curTime, int len);
static int wait_sock(int fd, int sec, int usec);

//The return value is number of utf-8 code
static int enc_unicode_to_utf8_one(unsigned long unic, unsigned char *poutput,int outsize)
{    

	if(poutput == NULL || outsize < 6)
	{
		return -1;
	}
	if ( unic <= 0x0000007F )
	{
		// * U-00000000 - U-0000007F:  0xxxxxxx  
		*poutput     = (unic & 0x7F);
		return 1;
	}
	else if ( unic >= 0x00000080 && unic <= 0x000007FF )
	{
		// * U-00000080 - U-000007FF:  110xxxxx 10xxxxxx  
		*(poutput+1) = (unic & 0x3F) | 0x80;
		*poutput     = ((unic >> 6) & 0x1F) | 0xC0;
		return 2;
	}
	else if ( unic >= 0x00000800 && unic <= 0x0000FFFF )
	{
		// * U-00000800 - U-0000FFFF:  1110xxxx 10xxxxxx 10xxxxxx  
		*(poutput+2) = (unic & 0x3F) | 0x80;
		*(poutput+1) = ((unic >>  6) & 0x3F) | 0x80;
		*poutput     = ((unic >> 12) & 0x0F) | 0xE0;
		return 3;
	}
	else if ( unic >= 0x00010000 && unic <= 0x001FFFFF )
	{
		// * U-00010000 - U-001FFFFF:  11110xxx 10xxxxxx 10xxxxxx 10xxxxxx  
		*(poutput+3) = (unic & 0x3F) | 0x80;
		*(poutput+2) = ((unic >>  6) & 0x3F) | 0x80;
		*(poutput+1) = ((unic >> 12) & 0x3F) | 0x80;
		*poutput     = ((unic >> 18) & 0x07) | 0xF0;
		return 4;
	}
	else if ( unic >= 0x00200000 && unic <= 0x03FFFFFF )
	{
		// * U-00200000 - U-03FFFFFF:  111110xx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx  
		*(poutput+4) = (unic & 0x3F) | 0x80;
		*(poutput+3) = ((unic >>  6) & 0x3F) | 0x80;
		*(poutput+2) = ((unic >> 12) & 0x3F) | 0x80;
		*(poutput+1) = ((unic >> 18) & 0x3F) | 0x80;
		*poutput     = ((unic >> 24) & 0x03) | 0xF8;
		return 5;
	}
	else if ( unic >= 0x04000000 && unic <= 0x7FFFFFFF )
	{
		// * U-04000000 - U-7FFFFFFF:  1111110x 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx  
		*(poutput+5) = (unic & 0x3F) | 0x80;
		*(poutput+4) = ((unic >>  6) & 0x3F) | 0x80;
		*(poutput+3) = ((unic >> 12) & 0x3F) | 0x80;
		*(poutput+2) = ((unic >> 18) & 0x3F) | 0x80;
		*(poutput+1) = ((unic >> 24) & 0x3F) | 0x80;
		*poutput     = ((unic >> 30) & 0x01) | 0xFC;
		return 6;
	}

	return 0;
}

//The value of return is the real data length of hex buffer
static int string_to_hex(char *instr,char *hex,int inlen,int hexlen)
{
        int i;
        unsigned char *data = NULL;
        unsigned char high_byte;
  		unsigned char low_byte;
  		int num_h,num_l;
		int result = 0;   //the last hex data len

        if(instr == NULL || hex == NULL)
        {
        	return -1;
        }

		if((inlen / 2) > hexlen)
		{
			return -1;
		}

		data = instr;
        for(i = 0; i < inlen; i = i + 2)
        {

                high_byte = *(data+ i);
                low_byte = *(data + i +1);

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

                hex[result++] = (unsigned char)(num_h << 4 | num_l);                 
        }
		return result;
}

//remove "%u" from string
static int remove_ch(char *strin,char *strout,int outsize)
{
	
	if(strin == NULL || strout == NULL)
	{
		return -1;
	}
	if(strlen(strin) > outsize)
	{
		return -1;
	}
	while(*strin++ != '\0')
	{
		if(*strin == '%' || *strin == 'u')
		{
			continue;
		}
		else
		{
			*strout++ = *strin;
		}
		
	}
	*strout = '\0';
	
	return 0;
}

//two byte hex is one long unicode data
//return the length of lbuf
static int unicode_to_long_arr(unsigned char *hex,unsigned long *lbuf,int inlen,int outlen)
{
	int i;
	unsigned short high = 0,low = 0;
	int lbuf_num = 0; 
	
	if(hex == NULL || lbuf == NULL)
	{
		return -1;
	}
	if((inlen / 2) > outlen)
	{
		return -1;
	}

	for(i = 0; i < inlen; i = i + 2)
	{
		high = hex[i] << 8;
		low  = hex[i + 1];
		lbuf[lbuf_num++] = (unsigned long)(high | low);
	}
	return lbuf_num;
}
/*
instr:get form nvram_get().The result string of formate as "%u6DF1%u5733".
	  so,we need to remove '%u',change to as "6DF15733"
*/
static char *enc_unicode_to_utf8_string(unsigned char *instr, unsigned char *outstr, int outlen)
{
	unsigned char hexbuf[8] = {0};
	unsigned long unico = 0;
	unsigned char tmp_buf[6] = {0};
	int str_hex_num = 0;
	int utf_num = 0;
	int total_utf_num = 0;
	char *p = NULL;
	int plen = 0;
	
	if(instr == NULL || outstr == NULL)
	{
		syslog(LOG_INFO,"Para error!");
        return NULL;
	}
	p = instr;
    memset(outstr, 0, outlen);
	//search by two bytes
	while(plen < strlen(instr))
	{
		if(!strncmp(p + plen,"%u",2)) //is %u
		{
			//p + plen + 2 =>jump %u two bytes formate four bytes
			if((str_hex_num = string_to_hex(p + plen + 2,hexbuf,4,sizeof(hexbuf))) == -1)
			{
				syslog(LOG_INFO,"String change to hex error!");
	            return NULL;
			}		
			unico = (unsigned long)((hexbuf[0] << 8) | hexbuf[1]);
			if((utf_num = enc_unicode_to_utf8_one(unico, tmp_buf,sizeof(tmp_buf))) != -1)
			{
				strncpy(outstr + total_utf_num,tmp_buf,utf_num);
				total_utf_num += utf_num;
				memset(tmp_buf,0,sizeof(tmp_buf));
			}
			else
			{
				syslog(LOG_INFO,"Change to UTF-8 error!");
	            return NULL;
			}
			plen += 6;
			memset(hexbuf,0,sizeof(hexbuf));
		}
		else	//not %u
		{
			strncpy(outstr + total_utf_num,p + plen,1);
			total_utf_num += 1;
			plen += 1;
		}
		if(total_utf_num > outlen)
		{
			syslog(LOG_INFO,"Out of input buffer,error!");
			return NULL;
		}

	}
	return outstr;
}

Queue *InitQueue( )
{
    Queue *pqueue = (Queue *)malloc(sizeof(Queue));

    if(pqueue != NULL)
    {
        pqueue->front = NULL;
        pqueue->rear = NULL;
        pqueue->size = 0;
    }
    return pqueue;
}



int IsEmpty(Queue *pqueue)
{
    if(pqueue->front == NULL && pqueue->rear == NULL && pqueue->size == 0)
        return 1;
    else
        return 0;
}


int GetSize(Queue *pqueue)
{
    return pqueue->size;
}


PNode EnQueue(Queue *pqueue, char *element, char *topic)
{
    if (element == NULL)
    {
        return NULL;
    }

    if (pqueue->size == MAX_QUEUE_SIZE)
    {
        return NULL;
    }

    PNode pnode = (PNode)malloc(sizeof(Node));
    if(pnode != NULL)
    {
        memset(pnode, 0, sizeof(Node));
        //pnode->elem = cJSON_CreateObject();
        //memcpy(pnode->elem, element, sizeof(cJSON));
        pnode->elem = (char *)malloc(strlen(element) + 1);
        if (pnode->elem == NULL)
        {
            free(pnode);
            return NULL;
        }
        //pnode->elem = cJSON_Duplicate(element, 1);
        memset(pnode->elem, 0, strlen(element) + 1);
        memcpy(pnode->elem, element, strlen(element));
        memcpy(pnode->topic, topic, strlen(topic));
        pnode->next = NULL;

        pthread_mutex_lock(&m_queue_mutex);
        if(IsEmpty(pqueue))
        {
            pqueue->front = pnode;
        }
        else
        {
            pqueue->rear->next = pnode;
        }
        pqueue->rear = pnode;
        pqueue->size++;
        pthread_mutex_unlock(&m_queue_mutex);
    }

    return pnode;
}


char *DeQueue(Queue *pqueue, char **element, char *topic)
{
    PNode pnode = pqueue->front;

    if(IsEmpty(pqueue) != 1 && pnode != NULL)
    {
        pthread_mutex_lock(&m_queue_mutex);
        //memcpy(*element, pnode->elem, sizeof(cJSON));
        //*element = cJSON_Duplicate(pnode->elem, 1);
        *element = pnode->elem;
        //cJSON_Delete(pnode->elem);
        memcpy(topic, pnode->topic, strlen(pnode->topic));
        pqueue->size--;
        pqueue->front = pnode->next;
        free(pnode);

        if(pqueue->size == 0)
        {
            pqueue->rear = NULL;
        }
        pthread_mutex_unlock(&m_queue_mutex);
    }


    return *element;
}


void ClearQueue(Queue *pqueue)
{
    char *elem;
    char topic[128];

    while(IsEmpty(pqueue) != 1)
    {
        DeQueue(pqueue, &elem, topic);
        free(elem);
    }
}


void DestroyQueue(Queue *pqueue)
{
    if(IsEmpty(pqueue)!=1)
    {
        ClearQueue(pqueue);
    }

    free(pqueue);
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

    if (len > 1000)
        max = 1000;
    else
        max = len;

    for (i = 0; i < max; i++)
    {
        ptr = &str[i * 3];
        sprintf(ptr, "%02x ", (unsigned char )*(data + i));
    }
//	data = str;
    if (nvram_get_int("modbus_debug_switch") == 1)
    {
        syslog(LOG_DEBUG, "%s:%s", (op == 1) ? "SEND>" : "RECV<", str);
    }
    // syslog(LOG_DEBUG, "%s---%s---", (op == 1) ? "SEND>>" : "RECV<<", data);

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

static int send_packet(void* socket_info, const void* buf, unsigned int count)
{
    int fd = *((int*)socket_info);
    //int ret = write_timeout(fd, buf, count, 500);
    //return ret;
    return send(fd, buf, count, 0);
}

static int init_socket(mqtt_broker_handle_t* broker, const char* hostname, short port)
{
    int flag = 1;
    // int keepalive = 3; // Seconds
    //int keepalive = 30;
    // Create the socket
    if((socket_id = socket(PF_INET, SOCK_STREAM, 0)) < 0)
        return -1;

    // Disable Nagle Algorithm
    if (setsockopt(socket_id, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(flag)) < 0)
    {
    	close(socket_id);
    	socket_id = -1;
        return -2;
	}
    struct sockaddr_in socket_address;
    // Create the stuff we need to connect
    socket_address.sin_family = AF_INET;
    socket_address.sin_port = htons(port);
    socket_address.sin_addr.s_addr = inet_addr(hostname);

    // Connect the socket
    if((connect(socket_id, (struct sockaddr*)&socket_address, sizeof(socket_address))) < 0)
    {
    	close(socket_id);
    	socket_id = -1;
        return -1;
	}
    // MQTT stuffs
//    mqtt_set_alive(broker, keepalive);
    broker->socket_info = (void*)&socket_id;
    broker->send = send_packet;

    return 0;
}

static int close_socket(mqtt_broker_handle_t* broker)
{
    int fd = *((int*)broker->socket_info);
    return close(fd);
}




static int read_packet(int timeout, char *packet_buffer, int len)
{
    //int i;
    //int len_byte = 1;

    if(timeout > 0)
    {
        fd_set readfds;
        struct timeval tmv;

        // Initialize the file descriptor set
        FD_ZERO (&readfds);
        FD_SET (socket_id, &readfds);

        // Initialize the timeout data structure
        tmv.tv_sec = timeout;
        tmv.tv_usec = 0;

        // select returns 0 if timeout, 1 if input available, -1 if error
        if(select(socket_id + 1, &readfds, NULL, NULL, &tmv) <= 0)
        {
        	syslog(LOG_INFO, "read_packet select timeout, time = %d sec", timeout);
            return -2;
        }
    }

    int total_bytes = 0, bytes_rcvd, packet_length;
    memset(packet_buffer, 0, len);
#if 0
    //add by jerry for mqtt head length
    while(total_bytes < 5) // Reading fixed header
    {
        if((bytes_rcvd = recv(socket_id, (packet_buffer+total_bytes), 5, 0)) <= 0)
            return -1;
        total_bytes += bytes_rcvd; // Keep tally of total bytes
    }
    for(i = 1; i <= 4; i++)
    {
        if(((packet_buffer[i] >> 7) & 1))
        {
            len_byte++;
            continue;
        }
        break;
    }
    switch(len_byte)
    {
    case 1:
        packet_length = packet_buffer[1] + 2;
        break;
    case 2:
        packet_length = (packet_buffer[1] & 0x7f) + packet_buffer[2]*128 + 3;
        break;
    case 3:
        packet_length = (packet_buffer[1] & 0x7f) + (packet_buffer[2] & 0x7f)*128 + packet_buffer[3]*128*128 + 4;
        break;
    case 4:
        packet_length = (packet_buffer[1] & 0x7f) + packet_buffer[2]*128 + packet_buffer[3]*128*128 + packet_buffer[4]*128*128*128 + 5;
        break;
 	defalt:
        packet_length = packet_buffer[1] + 2;
        break;
    }

    while(total_bytes < packet_length) // Reading the packet
    {
        if((bytes_rcvd = recv(socket_id, (packet_buffer+total_bytes), RCVBUFSIZE, 0)) <= 0)
            return -1;
        total_bytes += bytes_rcvd; // Keep tally of total bytes
    }
#endif

    while (total_bytes < 2) // Reading fixed header
    {
        if ((bytes_rcvd = recv(socket_id, (packet_buffer+total_bytes), RCVBUFSIZE, 0)) <= 0)
        {
        	syslog(LOG_INFO, "read_packet recv fix header err, err = %s", strerror(errno));
            return -1;
        }
        
        total_bytes += bytes_rcvd; // Keep tally of total bytes
    }

    packet_length = packet_buffer[1] + 2; // Remaining length + fixed header length

    while (total_bytes < packet_length) // Reading the packet
    {
        if ((bytes_rcvd = recv(socket_id, (packet_buffer + total_bytes), RCVBUFSIZE, 0)) <= 0)
        {
        	syslog(LOG_INFO, "read_packet recv err, err = %s", strerror(errno));
            return -1;
        }
        total_bytes += bytes_rcvd; // Keep tally of total bytes
    }

    return packet_length;
}




void kill_pidfile_tk(const char *pidfile)
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


static void modbus_sig_handler(int sig)
{
    switch (sig)
    {
    case SIGTERM:
    case SIGKILL:
    case SIGINT:
        modbus_gotterm = 1;
        syslog(LOG_NOTICE, "Got a signal<SIGTERM, SIGKILL, SIGINT>! exit!!");
        close_db(m_signal_db);
        sleep(3);
        exit(0);
        break;
    case SIGHUP:
        syslog(LOG_NOTICE, "Got a signal<SIGHUP>! exit!!");
        close_db(m_signal_db);
        modbus_gothup = 1;
        exit(0);
        break;
    case SIGUSR1:
        modbus_gotuser = 1;
        break;
    case SIGUSR2:
        modbus_gotuser = 2;
        break;
    }
}


static void modbus_deamon()
{
    struct sigaction sa;
    FILE *fp;

    if ( fork()  !=0 )
        exit(0);



    sa.sa_handler = modbus_sig_handler;
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


    kill_pidfile_tk(MODBUS_PID_FILE);
    if ((fp = fopen(MODBUS_PID_FILE, "w")) != NULL)
    {
        fprintf(fp, "%d", getpid());
        fclose(fp);
    }

    syslog(LOG_NOTICE, "==== Copyright (C) 2012-2013 Detran Ltd  ====");

}


static void add_json_value(char *buf, unsigned int buf_size, const char *name, const char *value)
{
    if (!buf || !name || !value)
    {
        return;
    }

    snprintf(buf + strlen(buf), buf_size - strlen(buf) - 1, "\\\"%s\\\":\\\"%s\\\",", name, value);
}

static void add_json_int_value(char *buf, unsigned int buf_size, const char *name, int value)
{
    if (!buf || !name || !value)
    {
        return;
    }

    snprintf(buf + strlen(buf), buf_size - strlen(buf) - 1, "\\\"%s\\\":%d,", name, value);
}


static void modbus_config_init()
{
    syslog(LOG_NOTICE, "----MODBUS Parameters Init. Start----");

    modbus_config.mode = nvram_get_int("modbus_mode");
    modbus_config.tcp_mode = nvram_get_int("modbus_tcp_mode");

    strcpy(modbus_config.svr_domain, nvram_safe_get("modbus_server_domain")); //modbus tcp client mode
    modbus_config.svr_port = nvram_get_int("modbus_server_port");

    modbus_config.bind_port = nvram_get_int("modbus_bind_port"); // modbus tcp server mode

    modbus_config.rate = nvram_get_int("modbus_serial_rate"); //RTU config

    if (strcmp(nvram_safe_get("modbus_serial_parity"), "none") == 0)
    {
        modbus_config.parity = 'N';
    }
    else if (strcmp(nvram_safe_get("modbus_serial_parity"), "even") == 0)
    {
        modbus_config.parity = 'E';
    }
    else
    {
        modbus_config.parity = 'O';
    }

    modbus_config.databits = nvram_get_int("modbus_serial_databits");

    modbus_config.stopbits = nvram_get_int("modbus_serial_stopbits");

    modbus_config.streamcontrol = '0';
#if 0
    syslog(LOG_NOTICE, "----mode = %d, tcp mode = %d, server ip = %s, server port = %d, bind port = %d ",
           modbus_config.mode,
           modbus_config.tcp_mode,
           modbus_config.svr_domain,
           modbus_config.svr_port,
           modbus_config.bind_port);
#endif
    syslog(LOG_NOTICE, "----MODBUS Parameters Init. End----");
}



static int _vstrsep(char *buf, const char *sep, ...)
{
    va_list ap;
    char **p;
    int n;

    n = 0;
    va_start(ap, sep);
    while ((p = va_arg(ap, char **)) != NULL)
    {
        if ((*p = strsep(&buf, sep)) == NULL) break;
        ++n;
    }
    va_end(ap);
    return n;
}

int Bytes2String(const unsigned char* src, char* dst, int len)
{
    const char tab[]="0123456789ABCDEF";
    int i;

    for (i = 0; i < len; i++)
    {
        *dst++ = tab[*src >> 4];
        *dst++ = tab[*src & 0x0f];
        src++;
    }

    *dst = '\0';
    return len * 2;
}


int String2Bytes(const char* str, unsigned char* buf, int len)
{
#if 0
    int i;
    for(i=0; i<len; i+=2)
    {
        if(*src>='0' && *src<='9')
            *dst = (*src - '0') << 4;
        else
            *dst = (*src - 'A' + 10) << 4;

        src++;

        if(*src>='0' && *src<='9')
            *dst |= *src - '0';
        else
            *dst |= *src - 'A' + 10;

        src++;
        dst++;
    }

    return len / 2;
#endif

    int i; // k = 0; //,j = 0;
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
        //      sprintf(&buf[i*3],"%02x ",num);
    }
    return len / 2;
}

#define vstrsep(buf, sep, args...) _vstrsep(buf, sep, args, NULL)



typedef struct
{
    unsigned long total;
    unsigned long free;
    unsigned long shared;
    unsigned long buffers;
    unsigned long cached;
    unsigned long swaptotal;
    unsigned long swapfree;
    unsigned long maxfreeram;
} meminfo_t;


static int get_memory(meminfo_t *m)
{
    FILE *f;
    char s[128];
    int ok = 0;

    memset(m, 0, sizeof(*m));
    if ((f = fopen("/proc/meminfo", "r")) != NULL)
    {
        while (fgets(s, sizeof(s), f))
        {

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
            else if (strncmp(s, "SwapTotal:", 10) == 0)
            {
                m->swaptotal = strtoul(s + 12, NULL, 10) * 1024;
                ++ok;
            }
            else if (strncmp(s, "SwapFree:", 9) == 0)
            {
                m->swapfree = strtoul(s + 11, NULL, 10) * 1024;
                ++ok;
                break;
            }
        }
        fclose(f);
    }

    if (ok == 0)
    {
        return 0;
    }
    m->maxfreeram = m->free;

	if (nvram_match("t_cafree", "1"))
	{
		m->maxfreeram += (m->cached + m->buffers);
	}
	
    return 1;
}



int set_rtu_time(modbus_t *ctx_rtu)
{
    unsigned char respBuf[512] = {0};
    char cmdRtc[20] = {0};
    int n = 0;
    time_t t;

    memset(cmdRtc, 0, sizeof(cmdRtc));

    cmdRtc[0] = 0x01;
    cmdRtc[1] = 0x47;
    time(&t);
    memcpy(respBuf, &t, 4);
    //memcpy(cmdRtc + 2, &t, 4);
    cmdRtc[2] = respBuf[3];
    cmdRtc[3] = respBuf[2];
    cmdRtc[4] = respBuf[1];
    cmdRtc[5] = respBuf[0];
    unsigned short crc = crc16(cmdRtc, 6);
    cmdRtc[6] = crc >> 8;
    cmdRtc[7] = crc & 0x00FF;
    syslog(LOG_NOTICE, "guochgz --------------> get time is %u", t);
    int fd = ctx_rtu->s;
    n = write(fd, cmdRtc, 8);
    if (n != -1)
    {
        print_hex(cmdRtc, 8, 1);
        n = wait_sock(fd, 2, 0);
        if (n <= 0)
        {
            syslog(LOG_NOTICE, "----MODBUS read timeout or failed");
            return 0 ;
        }

        n = read(fd, respBuf, sizeof(respBuf));
        if (n < 0)
        {
            syslog(LOG_NOTICE, "----MODBUS read failed");
            return 0 ;
        }

        print_hex(respBuf, n, 0);
    }
    return 1;
}


int get_rtu_time(modbus_t *ctx_rtu)
{
    unsigned char respBuf[512] = {0};
    char cmdRtc[20] = {0};
    int n = 0;

    memset(cmdRtc, 0, sizeof(cmdRtc));

    cmdRtc[0] = 0x01;
    cmdRtc[1] = 0x46;
    unsigned short crc = crc16(cmdRtc, 2);
    cmdRtc[2] = crc >> 8;
    cmdRtc[3] = crc & 0x00FF;

    int fd = ctx_rtu->s;
    n = write(fd, cmdRtc, 4);
    if (n != -1)
    {
        print_hex(cmdRtc, 4, 1);
        n = wait_sock(fd, 2, 0);
        if (n <= 0)
        {
            syslog(LOG_NOTICE, "----MODBUS read timeout or failed");
            return 0 ;
        }

        n = read(fd, respBuf, sizeof(respBuf));
        if (n < 0)
        {
            syslog(LOG_NOTICE, "----MODBUS read failed");
            return 0 ;
        }

        print_hex(respBuf, n, 0);
        unsigned int utcTime = 0;
        //memcpy(&utcTime, respBuf + 2, 4);
        cmdRtc[0] = respBuf[5];
        cmdRtc[1] = respBuf[4];
        cmdRtc[2] = respBuf[3];
        cmdRtc[3] = respBuf[2];
        memcpy(&utcTime, cmdRtc, 4);
        syslog(LOG_NOTICE, "guochgz --------------> get time is %u, ntohl  %u", utcTime, ntohl(utcTime));
        if (utcTime > 1503045840) //2017-08-18 16:50:00 maybe
        {
            time_t timep;
            struct tm *p;
            char curTime[64] = {0};
            timep = utcTime;
            p = localtime(&timep);

            snprintf(curTime, sizeof(curTime) - 1, "date -s '%d-%02d-%02d %02d:%02d:%02d'",
                     1900 + p->tm_year,
                     1 + p->tm_mon,
                     p->tm_mday,
                     p->tm_hour,
                     p->tm_min,
                     p->tm_sec);
            syslog(LOG_NOTICE, "guochgz --------------> curtime is %s", curTime);
            system(curTime);
        }
    }
    return 1;
}


int set_rtu_config(modbus_t *ctx_rtu)
{
    UART_CFG_T	uartCfg[UART_NUM];
    int rc;
    int i,j;

    for (i = 0; i < UART_NUM; i++)
    {
        int count = 0;
        char *nv, *nvp, *b;
        //int n;
        char rate_arr[32] = {0},databit_arr[32] = {0},parity_arr[32] = {0},stopbit_arr[32] = {0},slave_arr[32] = {0};

        memset(&uartCfg[i], 0, sizeof(UART_CFG_T));

        if (i == 0)
        {
            sprintf(rate_arr,"%s","serial_rate");
            sprintf(databit_arr,"%s","serial_databits");
            sprintf(parity_arr,"%s","serial_parity");
            sprintf(stopbit_arr,"%s","serial_stopbits");
            sprintf(slave_arr,"%s","slave_id");
        }
        else
        {
            sprintf(rate_arr,"serial_rate%d",(i + 1) );
            sprintf(databit_arr,"serial_databits%d",(i + 1) );
            sprintf(parity_arr,"serial_parity%d",(i + 1) );
            sprintf(stopbit_arr,"serial_stopbits%d",(i + 1) );
            sprintf(slave_arr,"slave_id%d",(i + 1) );
        }

        uartCfg[i].baudrate = nvram_get_int(rate_arr);
        uartCfg[i].databit = (unsigned char)nvram_get_int(databit_arr);
        uartCfg[i].stopbit = (unsigned char)nvram_get_int(stopbit_arr);
        if (strcmp(nvram_safe_get(parity_arr), "none") == 0)
        {
            uartCfg[i].paritybit = 0x0;
        }
        else if (strcmp(nvram_safe_get(parity_arr), "even") == 0)
        {
            uartCfg[i].paritybit = 0x2;
        }
        else
        {
            uartCfg[i].paritybit = 0x1;
        }

        if (nvram_safe_get(slave_arr) != NULL)
        {
            if (strlen(nvram_safe_get(slave_arr)) != 0)
            {
                nvp = nv = strdup(nvram_safe_get(slave_arr));
                if (!nv) continue;
                while ((b = strsep(&nvp, ",")) != NULL)
                {
                    uartCfg[i].modbus_slave_addr[count] = (unsigned char)atoi(b);
                    count++;
                }
                uartCfg[i].modbus_slave_count = (unsigned char)count;
                free(nv);
            }

        }

        syslog(LOG_INFO,
               "set to (Uart%d)---->modbus_slave_count:%d, baudrate:%d, databit:%d, stopbit:%d, paritybit:%d",
               i + 1,
               uartCfg[i].modbus_slave_count,
               uartCfg[i].baudrate,
               uartCfg[i].databit,
               uartCfg[i].stopbit,
               uartCfg[i].paritybit);
        for (j = 0; j < strlen(uartCfg[i].modbus_slave_addr); j++)
        {
            syslog(LOG_INFO,"Uart%d slave id:%d",i+1,uartCfg[i].modbus_slave_addr[j]);
        }
    }

    modbus_set_slave(ctx_rtu, 0x01);

    rc = modbus_write_registers(ctx_rtu, 0x0003, UART_PARA_LEN, uartCfg);
    if (rc == -1)
    {
        syslog(LOG_ERR, "modbus_write_registers failed ret = %d\n", rc);
        return -1;
    }

    nvram_set("modbus_serial_ok", "OK");
    return 0;
}

int send_rtu_scripts(modbus_t *ctx_rtu)
{
    int rc ;

#define MAX_MOD_REG_SEND	64
#define RTU_SCRIPTS_START_ADDRESS	0x007C //if 4 uarts 0x0054 + 80

    char *rtu_scr = nvram_safe_get("rtu_scripts");
    if (rtu_scr == NULL || strlen(rtu_scr) <= 1)
    {
        return 0;
    }

    unsigned short sci_addr = RTU_SCRIPTS_START_ADDRESS;
    int len = strlen(rtu_scr);


    syslog(LOG_ERR, "%d, %s", len, rtu_scr + 68);
    print_hex(rtu_scr + 68, len - 68, 1);
    int pos = 0;


    while (len > 0)
    {
        char scr_buf[244] = {0};

        memset(scr_buf, 0, sizeof(scr_buf));
        // the max reg is 110.
        if (len >= (MAX_MOD_REG_SEND << 1) - 2)
        {
            scr_buf[0] = 0x0;
            memcpy(&scr_buf[2], rtu_scr + pos, (MAX_MOD_REG_SEND << 1) - 2);
            pos += ((MAX_MOD_REG_SEND << 1) - 2);
            len -= ((MAX_MOD_REG_SEND << 1) - 2);

            rc = modbus_write_registers(ctx_rtu, sci_addr, MAX_MOD_REG_SEND, scr_buf);
            if (rc == -1)
            {
                syslog(LOG_ERR, "modbus_write_registers failed ret = %d\n", rc);
                return -1;
            }
            sci_addr += ((MAX_MOD_REG_SEND << 1) - 2);
        }
        else
        {
            scr_buf[0] = 0x1;
            memcpy(&scr_buf[2], rtu_scr + pos, len);
            pos += len;
            if (len % 2)
            {
                rc = modbus_write_registers(ctx_rtu, sci_addr++, ((len + 1) / 2) + 1, scr_buf);
            }
            else
            {
                rc = modbus_write_registers(ctx_rtu, sci_addr++, (len / 2) + 1, scr_buf);
            }
            if (rc == -1)
            {
                syslog(LOG_ERR, "modbus_write_registers failed ret = %d\n", rc);
                return -1;
            }
            len = 0;
            break;
        }
    }

    return 0;
}

#define REPORT_DEV_INFO_PERIOD		60
#define N_CYCLE_DELETE_COUNT		10


int encode_devinfo_pack( )
{
    char begin_format[128] = "{\"company\":\"%s\",\"data\":\"{";
    char end_format[128] = "}\",\"message\":\"%s\",\"reportTime\":\"%s\"}";
    char buf[4096] = {0};
    char cur_time[32] = {0};
    struct sysinfo si;
    char devInfo[24];
    meminfo_t mem;


    sysinfo(&si);

    get_memory(&mem);


    memset(buf, 0, sizeof(buf));

    snprintf(buf, sizeof(buf) - 1, begin_format, m_detrantech);
    add_json_value(buf, sizeof(buf), "devid", nvram_safe_get("router_sn"));
    add_json_value(buf, sizeof(buf), "version", nvram_safe_get("rt52_rtu_ver"));
    add_json_value(buf, sizeof(buf), "state", check_wanup() == 0 ? "0" : "1");
    add_json_value(buf, sizeof(buf), "ip", nvram_safe_get("wan_ipaddr"));
    add_json_value(buf, sizeof(buf), "picktime", getCurTime(cur_time, sizeof(cur_time)));
    add_json_value(buf, sizeof(buf), "lastconnect", nvram_safe_get("mqtt_last_cnnt"));
    add_json_value(buf, sizeof(buf), "lastsent", nvram_safe_get("mqtt_last_sent"));
    add_json_int_value(buf, sizeof(buf), "deviceType", 1);
    add_json_int_value(buf, sizeof(buf), "packCount", m_total_pack);
    add_json_value(buf, sizeof(buf), "lossRate", "0.00");
    snprintf(devInfo, sizeof(devInfo) - 1, "%.2f%%", ((mem.total - mem.maxfreeram) * 100.0 / mem.total));
    add_json_value(buf, sizeof(buf), "ram", devInfo);
    snprintf(devInfo, sizeof(devInfo), "%.2f%%", si.loads[0] / 65536.0 + si.loads[1] / 65536.0 + si.loads[2] / 65536.0 );
    add_json_value(buf, sizeof(buf), "cpu", devInfo);
    snprintf(buf + strlen(buf) - 1, sizeof(buf) - strlen(buf) - 1, end_format, m_deviceRep, getCurTime(cur_time, sizeof(cur_time)));

    char *res = EnQueue(m_json_event_queue, buf, DEVICE_INFO_PUB_TOPIC);
    if (res != NULL)
    {
    	sem_post(&m_json_send_sem);
    }
}


void *report_devInfo_thread_routine(void *arg)
{
    static int del_count = 0;
	char cur_time[32] = {0};
	
    while (1)
    {
        sleep(REPORT_DEV_INFO_PERIOD);

        encode_devinfo_pack( );

		getCurTime(cur_time, sizeof(cur_time));
		
        select_time_slice(m_signal_db, cur_time, cur_time);
        
        del_count++;
        if (del_count >= N_CYCLE_DELETE_COUNT)
        {
            del_count = 0;
            delete_sinal_data_N_day_before(m_signal_db, 7 * 86400);
        }
    }
}

char *getCurTime(char *curTime, int len)
{
    time_t timep;
    struct tm *p;

    time(&timep);
    p = localtime(&timep);

    snprintf(curTime, len - 1, "%d-%02d-%02d %02d:%02d:%02d",
             1900 + p->tm_year,
             1 + p->tm_mon,
             p->tm_mday,
             p->tm_hour,
             p->tm_min,
             p->tm_sec);
    return curTime;
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
    res = select(fd + 1, &fdvar, NULL, NULL, &tv);

    return res;
}


int encode_gateway_pack( )
{
    char cur_time[32] = {0};
    char begin_format[128] = "{\"company\":\"%s\",\"data\":\"{";
    char end_format[128] = "}\",\"message\":\"%s\",\"reportTime\":\"%s\"}";
    char buf[4096] = {0};
    unsigned char utf[256] = {0};

    memset(buf, 0, sizeof(buf));

    snprintf(buf, sizeof(buf) - 1, begin_format, m_detrantech);
    add_json_value(buf, sizeof(buf), "appid", nvram_safe_get("iot_appid"));
    add_json_value(buf, sizeof(buf), "devid", nvram_safe_get("router_sn"));
    add_json_value(buf, sizeof(buf), "mac", nvram_safe_get("et0macaddr"));
    add_json_value(buf, sizeof(buf), "ip", nvram_safe_get("lan_ipaddr"));
    add_json_value(buf, sizeof(buf), "port", nvram_safe_get("http_lanport"));
    add_json_value(buf, sizeof(buf), "prjcode", nvram_safe_get("iot_projid"));
    add_json_value(buf, sizeof(buf), "prjname", enc_unicode_to_utf8_string(nvram_safe_get("iot_projname"), utf, sizeof(utf)));
    add_json_value(buf, sizeof(buf), "city", enc_unicode_to_utf8_string(nvram_safe_get("iot_city"), utf, sizeof(utf)));
    add_json_value(buf, sizeof(buf), "area", enc_unicode_to_utf8_string(nvram_safe_get("iot_area"), utf, sizeof(utf)));
    add_json_value(buf, sizeof(buf), "address", enc_unicode_to_utf8_string(nvram_safe_get("iot_addr"), utf, sizeof(utf)));
    add_json_value(buf, sizeof(buf), "lastact", nvram_safe_get("mqtt_last_sent"));
    add_json_value(buf, sizeof(buf), "createdAt", nvram_safe_get("mqtt_createat"));
    add_json_value(buf, sizeof(buf), "longitude", nvram_safe_get("iot_longitude"));
    add_json_value(buf, sizeof(buf), "latitude", nvram_safe_get("iot_latitude"));
    add_json_value(buf, sizeof(buf), "type", "GateWay");
    add_json_value(buf, sizeof(buf), "name", enc_unicode_to_utf8_string(nvram_safe_get("iot_gateway_name"), utf, sizeof(utf)));
    add_json_value(buf, sizeof(buf), "lastact", nvram_safe_get("mqtt_last_sent"));
    add_json_value(buf, sizeof(buf), "createdAt", nvram_safe_get("mqtt_createat"));
    snprintf(buf + strlen(buf) - 1, sizeof(buf) - strlen(buf) - 1, end_format, m_gatewayRep, getCurTime(cur_time, sizeof(cur_time)));

    char *res = EnQueue(m_json_event_queue, buf, GATEWAY_PUB_TOPIC);
    if (res != NULL)
    {
    	sem_post(&m_json_send_sem);
    }

    return 0;
}


int encode_rtu_pack( )
{
    char cur_time[32] = {0};
    char begin_format[128] = "{\"company\":\"%s\",\"data\":\"{";
    char end_format[128] = "}\",\"message\":\"%s\",\"reportTime\":\"%s\"}";
    char buf[4096] = {0};
	unsigned char utf[256] = {0};
	
    memset(buf, 0, sizeof(buf));

    snprintf(buf, sizeof(buf) - 1, begin_format, m_detrantech);
    add_json_value(buf, sizeof(buf), "appid", nvram_safe_get("iot_appid"));
    add_json_value(buf, sizeof(buf), "devid", nvram_safe_get("router_sn"));
    add_json_value(buf, sizeof(buf), "mac", nvram_safe_get("et0macaddr"));
    add_json_value(buf, sizeof(buf), "prjcode", nvram_safe_get("iot_projid"));
    add_json_value(buf, sizeof(buf), "prjname", enc_unicode_to_utf8_string(nvram_safe_get("iot_projname"), utf, sizeof(utf)));
    add_json_value(buf, sizeof(buf), "city", enc_unicode_to_utf8_string(nvram_safe_get("iot_city"), utf, sizeof(utf)));
    add_json_value(buf, sizeof(buf), "area", enc_unicode_to_utf8_string(nvram_safe_get("iot_area"), utf, sizeof(utf)));
    add_json_value(buf, sizeof(buf), "address", enc_unicode_to_utf8_string(nvram_safe_get("iot_addr"), utf, sizeof(utf)));
    add_json_value(buf, sizeof(buf), "longitude", nvram_safe_get("iot_longitude"));
    add_json_value(buf, sizeof(buf), "latitude", nvram_safe_get("iot_latitude"));
    add_json_value(buf, sizeof(buf), "lastact", nvram_safe_get("mqtt_last_sent"));
    add_json_value(buf, sizeof(buf), "createdAt", nvram_safe_get("mqtt_createat"));
    add_json_value(buf, sizeof(buf), "type", "RTU");
    add_json_value(buf, sizeof(buf), "name", enc_unicode_to_utf8_string(nvram_safe_get("iot_rtu_name"), utf, sizeof(utf)));
    add_json_value(buf, sizeof(buf), "enable", nvram_match("mqtt_enable_rtu", "1") ? "True" : "False");
    add_json_int_value(buf, sizeof(buf), "uprate", nvram_get_int("iot_report_interval"));
    add_json_value(buf, sizeof(buf), "gatewayId", nvram_safe_get("router_sn"));
    snprintf(buf + strlen(buf) - 1, sizeof(buf) - strlen(buf) - 1, end_format, m_rtuInfoRep, getCurTime(cur_time, sizeof(cur_time)));
    char *res = EnQueue(m_json_event_queue, buf, RTU_INFO_PUB_TOPIC);
    if (res != NULL)
    {
    	sem_post(&m_json_send_sem);
    }

    return 0;
}


int encode_alarm_data_pack(int index, int status, char *respBuf)
{
    char begin_format[128] = "{\"company\":\"%s\",\"data\":\"{";
    char end_format[128] = "}\",\"message\":\"%s\",\"reportTime\":\"%s\"}";
    char buf[4096] = {0};
    char cur_time[32] = {0};
    char content[1024];
	unsigned char utf[256] = {0};
	
    if (respBuf == NULL)
    {
        return -1;
    }

    getCurTime(cur_time, sizeof(cur_time));
    snprintf(content, sizeof(content) - 1, "%s %s %s: %s", cur_time, enc_unicode_to_utf8_string(m_alarmInfo[index].note, utf, sizeof(utf)), m_curValue, respBuf);

    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf) - 1, begin_format, m_detrantech);
    add_json_value(buf, sizeof(buf), "signalid", m_alarmInfo[index].signalId);
    add_json_value(buf, sizeof(buf), "signalval", respBuf);
    add_json_int_value(buf, sizeof(buf), "alaramlevel", m_alarmInfo[index].grade);
    add_json_value(buf, sizeof(buf), "alarmtime", cur_time);
    add_json_value(buf, sizeof(buf), "content", content);
    add_json_value(buf, sizeof(buf), "devid", nvram_safe_get("router_sn"));
    //add_json_value(buf, sizeof(buf), "signalid", m_alarmInfo[index].signalId);
    add_json_int_value(buf, sizeof(buf), "state", status);
    snprintf(buf + strlen(buf) - 1, sizeof(buf) - strlen(buf) - 1, end_format, m_alarmDataRep, getCurTime(cur_time, sizeof(cur_time)));

    char *res = EnQueue(m_json_event_queue, buf, ALARM_PUB_TOPIC);
    if (res != NULL)
    {
    	sem_post(&m_json_send_sem);
    }

    return 0;
}



int encode_alarm_pack(int index, int status, char *respBuf)
{
    char begin_format[128] = "{\"company\":\"%s\",\"data\":\"{";
    char end_format[128] = "}\",\"message\":\"%s\",\"reportTime\":\"%s\"}";
    char buf[4096] = {0};
    char cur_time[32] = {0};
    char content[256];
	unsigned char utf[256] = {0};
	
    if (respBuf == NULL)
    {
        return -1;
    }

    memset(buf, 0, sizeof(buf));

    snprintf(buf, sizeof(buf) - 1, begin_format, m_detrantech);

    add_json_value(buf, sizeof(buf), "devid", nvram_safe_get("router_sn"));
    add_json_value(buf, sizeof(buf), "signalid", m_alarmInfo[index].signalId);
    //memset(utf, 0, sizeof(utf));
    add_json_value(buf, sizeof(buf), "signalname", enc_unicode_to_utf8_string(m_alarmInfo[index].signalName, utf, sizeof(utf)));
    add_json_value(buf, sizeof(buf), "maxval", m_alarmInfo[index].maxVal);
    snprintf(content, sizeof(content) - 1, "%d", m_alarmInfo[index].type);
    add_json_value(buf, sizeof(buf), "valtype", content);
    add_json_value(buf, sizeof(buf), "minval", m_alarmInfo[index].minVal);
    add_json_value(buf, sizeof(buf), "controlable", m_alarmInfo[index].ctrlAble);
    add_json_value(buf, sizeof(buf), "opertype", m_alarmInfo[index].oper);

    snprintf(buf + strlen(buf) - 1, sizeof(buf) - strlen(buf) - 1, end_format, m_alarmDataRep, getCurTime(cur_time, sizeof(cur_time)));

    char *res = EnQueue(m_json_event_queue, buf, ALARM_PUB_TOPIC);
    if (res != NULL)
    {
    	sem_post(&m_json_send_sem);
    }

    return 0;
}



int encode_signal_info_pack( )
{
    char begin_format[128] = "{\"company\":\"%s\",\"data\":\"{\\\"devid\\\":\\\"%s\\\",\\\"list\\\":[";
    char end_format[128] = "]}\",\"message\":\"%s\",\"reportTime\":\"%s\"}";
    char buf[16384] = {0};
    char cur_time[32] = {0};
    char *nv, *nvp, *b;
    int n;
	unsigned char utf[256] = {0};

    nvp = nv = strdup(nvram_safe_get("rtu_signalinfo_list"));
    if (!nv)
    {
        return -1;
    }

    memset(buf, 0, sizeof(buf));

    snprintf(buf, sizeof(buf) - 1, begin_format, m_detrantech, nvram_safe_get("router_sn"));

    while ((b = strsep(&nvp, ">")) != NULL)
    {
        char *signalid, *signalname, *valtype, *maxval, *minval, *ctrlable, *oper;
        n = vstrsep(b, "<", &signalid, &signalname, &valtype, &maxval, &minval, &ctrlable, &oper);
        if (n < 7)
        {
            continue ;
        }
        insert_signal_info(m_signal_db, signalid, signalname, atoi(valtype), maxval, minval, atoi(ctrlable), oper);
        //     syslog(LOG_NOTICE, "%s %s %s %s %s %s %s", signalid, signalname, valtype, maxval, minval, ctrlable, oper);

        strcat(buf, "{");
        add_json_value(buf, sizeof(buf), "signalid", signalid);
        add_json_value(buf, sizeof(buf), "signalname", enc_unicode_to_utf8_string(signalname, utf, sizeof(utf)));
        add_json_value(buf, sizeof(buf), "valtype", valtype);
        add_json_value(buf, sizeof(buf), "maxval", maxval);
        add_json_value(buf, sizeof(buf), "minval", minval);
        if (strcmp(ctrlable, "true") == 0)
        {
            add_json_value(buf, sizeof(buf), "controlable", "true");
        }
        else
        {
            add_json_value(buf, sizeof(buf), "controlable", "false");
        }
        add_json_value(buf, sizeof(buf), "opertype", oper);
        snprintf(buf + strlen(buf) - 1, sizeof(buf) - strlen(buf), "},");
    }

    snprintf(buf + strlen(buf) - 1, sizeof(buf) - strlen(buf),
             end_format, m_signallistRep, getCurTime(cur_time, sizeof(cur_time)));

    free(nv);

    char *res = EnQueue(m_json_event_queue, buf, RTU_LIST_PUB_TOPIC);
    if (res != NULL)
    {
    	sem_post(&m_json_send_sem);
    }

    return 0;
}



int encode_signal_data_pack( )
{
    char begin_format[128] = "{\"company\":\"%s\",\"data\":\"{\\\"devid\\\":\\\"%s\\\",\\\"list\\\":[";
    char end_format[128] = "]}\",\"message\":\"%s\",\"reportTime\":\"%s\"}";
    char buf[16384] = {0};
    char cur_time[32] = {0};
    char *nv, *nvp, *b;
    int n;
    char signal_nv_name[32] = {0};
    char orig_nv_name[32] = {0};
    char val_nv_name[32] = {0};
    char picktime_nv_name[32] = {0};


    nvp = nv = strdup(nvram_safe_get("rtu_signalinfo_list"));
    if (!nv)
    {
        return -1;
    }

    memset(buf, 0, sizeof(buf));

    snprintf(buf, sizeof(buf) - 1, begin_format, m_detrantech, nvram_safe_get("router_sn"));

    while ((b = strsep(&nvp, ">")) != NULL)
    {
        char *signalid, *signalname, *valtype, *maxval, *minval, *ctrlable, *oper;
        n = vstrsep(b, "<", &signalid, &signalname, &valtype, &maxval, &minval, &ctrlable, &oper);
        if (n < 7)
        {
            continue ;
        }


        snprintf(signal_nv_name, sizeof(signal_nv_name), "signalid_%s", signalid);
        snprintf(orig_nv_name, sizeof(orig_nv_name), "originval_%s", signalid);
        snprintf(val_nv_name, sizeof(val_nv_name), "signalval_%s", signalid);
        snprintf(picktime_nv_name, sizeof(picktime_nv_name), "picktime_%s", signalid);

        if (nvram_get(signal_nv_name) == NULL || atoi(nvram_get(signal_nv_name)) != atoi(signalid))
        {
            continue ;
        }

        strcat(buf, "{");
        add_json_value(buf, sizeof(buf), "signalid", nvram_get(signal_nv_name));
        add_json_value(buf, sizeof(buf), "originval", nvram_get(orig_nv_name));
        add_json_value(buf, sizeof(buf), "signalval", nvram_get(val_nv_name));
        add_json_value(buf, sizeof(buf), "picktime", nvram_get(picktime_nv_name));
        snprintf(buf + strlen(buf) - 1, sizeof(buf) - strlen(buf), "},");

        update_signal_data_upload_flag(m_signal_db, nvram_get(signal_nv_name), nvram_get(picktime_nv_name));
    }
    free(nv);
    snprintf(buf + strlen(buf) - 1, sizeof(buf) - strlen(buf),
             end_format, m_rtuDataRep, getCurTime(cur_time, sizeof(cur_time)));

    char *res = EnQueue(m_json_event_queue, buf, RTU_DATA_PUB_TOPIC);
    if (res != NULL)
    {
    	sem_post(&m_json_send_sem);
    }

    return 0;
}

void *pub_thread_routine(void *arg)
{
    /* mqtt connect */
    mqtt_broker_handle_t broker;
    int sleep_int = nvram_get_int("iot_report_interval");


    if (sleep_int < 1)
    {
        sleep_int = 1;
    }


    encode_gateway_pack( );

    encode_rtu_pack( );


    encode_signal_info_pack( );


    m_connect_state = 1;
    while (1)
    {
        encode_signal_data_pack( );
        sleep(sleep_int * 60);
    }

    mqtt_disconnect(&broker);
    close_socket(&broker);
}

int get_alarm_info_index(int regAddr)
{
    int i = 0;

    while (i < m_max_alarm_num)
    {
        if (m_alarmInfo[i].regAddr == regAddr)
        {
            return i;
        }
        i++;
    }
    return -1;
}

int get_alarm_info_list( )
{
    char *nv, *nvp, *b;
    char *id, *name, *regAddr, *type,*maxVal, *minVal, *datatype, *ctrlAble, *oper, *grade, *note;
    int n, num = 0;

    nvp = nv = strdup(nvram_safe_get("rtu_alarminfo_list"));
    if (!nv)
    {
        return 0;
    }

    while ((b = strsep(&nvp, ">")) != NULL)
    {
        n = vstrsep(b, "<", &id, &name, &regAddr, &type, &maxVal, &minVal, &datatype, &ctrlAble, &oper, &grade, &note);
        if (n < 11)
        {
            continue;
        }

        memcpy(m_alarmInfo[num].signalId, id, strlen(id));
        memset(m_alarmInfo[num].signalName, 0, sizeof(m_alarmInfo[num].signalName));
        memcpy(m_alarmInfo[num].signalName, name, strlen(name));
        m_alarmInfo[num].regAddr = atoi(regAddr);
        m_alarmInfo[num].type = atoi(type);
        memcpy(m_alarmInfo[num].maxVal, maxVal, strlen(maxVal));
        memcpy(m_alarmInfo[num].minVal, minVal, strlen(minVal));
        m_alarmInfo[num].datatype= atoi(datatype);
        memcpy(m_alarmInfo[num].ctrlAble, ctrlAble, strlen(ctrlAble));
        memcpy(m_alarmInfo[num].oper ,oper, strlen(oper));
        m_alarmInfo[num].grade = atoi(grade);
        memset(m_alarmInfo[num].note, 0, sizeof(m_alarmInfo[num].note));
        memcpy(m_alarmInfo[num].note, note, strlen(note));

        syslog(LOG_NOTICE, "%s %s %d %d %s %s %s %s %d %s %d",
               m_alarmInfo[num].signalId,
               m_alarmInfo[num].signalName,
               m_alarmInfo[num].regAddr,
               m_alarmInfo[num].type,
               m_alarmInfo[num].maxVal,
               m_alarmInfo[num].minVal,
               m_alarmInfo[num].ctrlAble,
               m_alarmInfo[num].oper,
               m_alarmInfo[num].grade,
               m_alarmInfo[num].note,
               m_alarmInfo[num].datatype);
        num++;
    }
    free(nv);
    m_max_alarm_num = num;

    return 0;
}


unsigned char get_sum(const unsigned char *buf, unsigned int buf_len)
{
	unsigned int	i;
	unsigned char	sum = 0;

	for (i = 0; i < buf_len; i++)
	{
		sum += buf[i];
	}
	return (sum);
}

void get_login_key(const char *sn, char *key, unsigned int key_size)
{       
	char    s1[8] = "", s2[8] = "", s3[8] = "", s4[36] = "";
    char    s0[128] = "+d$(SR(-Q7>.8F}d]]%(,Al{p##4m^kuElzu@ZAp9?{Pby5AV9GaX5_65_I^?6wc#qXBsY3-u0cZ)nx_(?B_S!rh_=i!P`aRR<rGruSj20D;{<y#[;_.<Sszm]x@?-o";
    unsigned int    i, pos = 0;

    
    for (i = 0; i < 8; i ++)
    {
    	s1[i] = (sn[i] + sn[8 + i]) / 2; 
        pos = s1[i];
        s2[i] = s0[pos];
    }

    des_set_key(s2);
    des_run(s3, s1, DES_ENCRYPT);
    md5_code_string((unsigned char *)s3, sizeof(s3), s4);
    strncpy(key, s4, key_size);
}     


int encode_rtu_login_pack(unsigned char *buf, int buf_len)
{
	RTU_CMD_HEAD_T *cmd = (RTU_CMD_HEAD_T *)buf;
	RTU_CMD_TLV_T  *tlv = (RTU_CMD_TLV_T *)(buf + sizeof(RTU_CMD_HEAD_T) + 1);
	unsigned char key[32] = {0};
	int length;
	char *rt52_ver;
	
	memset(buf, 0, buf_len);
	
	cmd->head = 0xAA;
	memcpy(cmd->ver, "\x01\x00", 2);
	cmd->seq = htonl(m_rtu_seq_num++);
	strncpy(cmd->dev_sn, m_router_sn, 8); 
	cmd->cmdid = htons(RTU_LOGIN_CMD);
	
	buf[sizeof(RTU_CMD_HEAD_T)] = 0x2;
	
	memset(tlv->tag, 0x0, sizeof(tlv->tag));
	tlv->tag[3] = 0x2;
	tlv->len = htons(sizeof(RTU_CMD_TLV_T) + 32);
	
	get_login_key(cmd->dev_sn, key, sizeof(key));
	
	memcpy(buf + sizeof(RTU_CMD_HEAD_T) + 4 + 2 + 1, key, sizeof(key));

	tlv = (RTU_CMD_TLV_T *)(buf + sizeof(RTU_CMD_HEAD_T) + 1 + 4 + 2 + 32);
	memset(tlv->tag, 0x0, sizeof(tlv->tag));
	tlv->tag[3] = 0x6;

	rt52_ver = nvram_safe_get("rt52_rtu_ver");
	if (rt52_ver == NULL)
	{
		return 0;
	}
	tlv->len = htons(sizeof(RTU_CMD_TLV_T) + strlen(rt52_ver));
	
	memcpy(buf + sizeof(RTU_CMD_HEAD_T) + 1 + 4 + 2 + 32 + 4 + 2, rt52_ver, strlen(rt52_ver));
	
	length = sizeof(RTU_CMD_HEAD_T) + 2 + 1 + 4 + 2 + 32 + 4 + 2 + strlen(rt52_ver);
	cmd->length = htons(length);
	
	buf[sizeof(RTU_CMD_HEAD_T) + 1 + 4 + 2 + 32 + 4 + 2 + strlen(rt52_ver)] = get_sum(buf, length - 2);
	buf[sizeof(RTU_CMD_HEAD_T) + 1 + 4 + 2 + 32 + 4 + 2 + strlen(rt52_ver) + 1] = 0xBB;

	print_hex(buf, length, 1);

	return length;
}


int encode_rtu_logout_pack(unsigned char *buf, int buf_len)
{
	RTU_CMD_HEAD_T *cmd = (RTU_CMD_HEAD_T *)buf;
	int length;

	
	memset(buf, 0, buf_len);
	cmd->head = 0xAA;
	memcpy(cmd->ver, "\x01\x00", 2);
	cmd->seq = htonl(m_rtu_seq_num++);
	strncpy(cmd->dev_sn, m_router_sn, 8); 
	cmd->cmdid = htons(RTU_LOGOUT_CMD);

	buf[sizeof(RTU_CMD_HEAD_T)] = 0x0;
	length = sizeof(RTU_CMD_HEAD_T) + 1 + 2;
	cmd->length = htons(length);
	buf[sizeof(RTU_CMD_HEAD_T) + 1] = get_sum(buf, length - 2);
	buf[sizeof(RTU_CMD_HEAD_T) + 2] = 0xBB;

	print_hex(buf, length, 1);

	return length;
}



int encode_rtu_heartbeat_pack(unsigned char *buf, int buf_len)
{
	RTU_CMD_HEAD_T *cmd = (RTU_CMD_HEAD_T *)buf;
	int length;
	
	memset(buf, 0, buf_len);
	cmd->head = 0xAA;
	memcpy(cmd->ver, "\x01\x00", 2);
	cmd->seq = htonl(m_rtu_seq_num++);
	strncpy(cmd->dev_sn, m_router_sn, 8); 
	cmd->cmdid = htons(RTU_HEARTBEAT_CMD);

	buf[sizeof(RTU_CMD_HEAD_T)] = 0x0;

	length = sizeof(RTU_CMD_HEAD_T) + 1 + 2;
	cmd->length = htons(length);
	buf[sizeof(RTU_CMD_HEAD_T) + 1] = get_sum(buf, length - 2);
	buf[sizeof(RTU_CMD_HEAD_T) + 2] = 0xBB;

	//print_hex(buf, length, 1);
	//syslog(LOG_INFO, "HEAD LENGTH: %d, total packet length: %d\r\n", sizeof(RTU_CMD_HEAD_T), length);
	return length;
}

int encode_rtu_alarm_pub_pack(unsigned char *buf, int buf_len, unsigned char *valaddr, unsigned short regaddr, int datatype, unsigned char status)
{
    RTU_CMD_HEAD *cmd = (RTU_CMD_HEAD *)buf;
    char *nv, *nvp, *b;
    unsigned short reg;
    RTU_CMD_TLV  *tlv = NULL;
    unsigned int length, tlv_len;
    char outBuf[12] = {0};
    unsigned char *valtmp;
	int n;

    memset(buf, 0, buf_len);
	cmd->cmdid = htons(0x0010);
	cmd->seq = htonl(m_rtu_seq_num++);
	cmd->version = htons(0x0300);
	cmd->safe_flag = 0;		//安全标识:1启用, 0不启用
	cmd->type = 0;	//0: M2M指令，1: Lora指令
	memcpy(cmd->dev_sn, m_router_sn, sizeof(cmd->dev_sn)); 
	length = sizeof(RTU_CMD_HEAD);

    memset(outBuf, 0, sizeof(outBuf));

    reg = htons(regaddr);
    valtmp = valaddr;
    memcpy(outBuf,valtmp, 4);

	n = sizeof(outBuf);
	tlv_len = 0; 
	tlv = (RTU_CMD_TLV *)(buf + length);

	memset(tlv, 0, sizeof(tlv));

	tlv->tlv_tag = htons(0x0130);

	*(tlv->tlv_value + tlv_len) = 0x02;		//告警数据 
	tlv_len += 1;
	*(tlv->tlv_value + tlv_len) = 0x01;
	tlv_len += 1;
	memcpy(tlv->tlv_value + tlv_len, &reg, 2);
	tlv_len += 2;
	memcpy(tlv->tlv_value + tlv_len, outBuf, n);
	tlv_len += n;

//	print_hex(buf + length, tlv_len + 4, 1);

	tlv->tlv_len = htons(tlv_len);
	length += (tlv_len + 4);
    cmd->length = htons(length);

//	print_hex(buf, length, 1);

    return length;
}

#if 0
int encode_rtu_pub_pack(unsigned char *buf, int buf_len)
{
	RTU_CMD_HEAD *cmd = (RTU_CMD_HEAD *)buf;
	char *nv, *nvp, *b;
    int n;
    char slaveid_nv_name[32] = {0};
    char regAddr_nv_name[32] = {0};
    char val_nv_name[32] = {0};
    char valtype_nv_name[32] = {0};
	RTU_CMD_TLV  *tlv = NULL;
	unsigned int length, tlv_len;
	unsigned short regAddr = 0;
	char outBuf[12] = {0};
    int valueType = 0;
    unsigned short startAddr = 0;
    unsigned short naddr = 0;
	int i;

    memset(buf, 0, buf_len);
	cmd->cmdid = htons(0x0010);
	cmd->seq = htonl(m_rtu_seq_num++);
	cmd->version = htons(0x0300);
	cmd->safe_flag = 0;		//安全标识:1启用, 0不启用
	cmd->type = 0;	//0: M2M指令，1: Lora指令
	memcpy(cmd->dev_sn, m_router_sn, sizeof(cmd->dev_sn)); 
	length = sizeof(RTU_CMD_HEAD);

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
        
		tlv = (RTU_CMD_TLV *)(buf + length);

		memset(tlv, 0, sizeof(tlv));
		tlv_len = 0;

		tlv->tlv_tag = htons(0x0130);
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

	cmd->length = htons(length);
	//print_hex(buf, length, 1);

    syslog(LOG_NOTICE, "Publish Packet data ok!");
	//unsigned char str[1024] = {0};
	//HexToStr(buf, str, length);
    //syslog(LOG_NOTICE, "Publish Data:%s, len:%d", str, length);

	return length;
}
#endif

static int m2m_get_host(const char *name, char *ipbuf)
{
    struct hostent *hp = NULL;
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

	if ((len > 7) && (1 == inet_pton(AF_INET, ipbuf, &sin_addr)))
	{
		ip = sin_addr.s_addr;
		return ip;
	}
	
	return 0;
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

	if(bind(sockfd, (struct sockaddr *)&local_addr, sizeof(local_addr)) < 0)
	{
		syslog(LOG_ERR, "M2M UDP Socket Bind Error!!!");
		return -1;
	}

	//bzero(&serveraddr, sizeof(serveraddr));
	bzero(&m_rtu_svr_addr, sizeof(m_rtu_svr_addr));
	m_rtu_svr_addr.sin_family = AF_INET;
	m_rtu_svr_addr.sin_port = htons(dest_port);
	m_rtu_svr_addr.sin_addr.s_addr = dest_ip;

	return sockfd;
}


#define UDP_MAX_SEND_COUNT 1

static int udp_socket_send(int socket_fd, char *pdu_buf, int pdu_len)
{
	int send_len = -1;


	send_len = sendto(socket_fd, pdu_buf, pdu_len, 0, (struct sockaddr *)&m_rtu_svr_addr, sizeof(m_rtu_svr_addr));
	if (send_len == -1)
	{
		syslog(LOG_ERR, "RTU UDP Socket Send Error(%d):%s: %d", errno, strerror(errno), socket_fd);
	}    
  
	//print_hex(pdu_buf, pdu_len, SEND);
	return send_len;
}



//socket receive interface
static int udp_socket_recv(int socket_fd, char *pdu_buf, int pdu_len)
{
	int recv_len = -1;
	struct sockaddr_in fromaddr;
	int fromaddr_len = sizeof(fromaddr);
	
	
	if (wait_sock(socket_fd, 2, 0)<=0)
	{
		syslog(LOG_NOTICE, "M2M UDP Recv Timeout");
		return -1;
	}

	recv_len = recvfrom(socket_fd, pdu_buf, pdu_len, 0 , (struct sockaddr *)&fromaddr, &fromaddr_len);
	
	print_hex(pdu_buf, recv_len, RECV);
	
	if(fromaddr.sin_addr.s_addr != m_rtu_svr_addr.sin_addr.s_addr)
	{
		syslog(LOG_ERR,"------Ambitious data from :%x------------",fromaddr.sin_addr.s_addr);
		return 0;
	}

	return recv_len;
}

static int process_rtu_packet(int socket_fd, unsigned char *pdu_ptr, int pdu_len)
{
	RTU_CMD_HEAD *rtu_req, *rtu_res;
	RTU_CMD_TLV *tlv_req, *tlv_res;
	char *rtu_buf, tmp_buf[1024];
	char modbus_res_buf[4500];
	char tlv_res_buf[1024];
	int len = 0, tlv_len = 0, tmp_len = 0, rtu_req_len = 0;
	unsigned char devAddr = 0;
	unsigned short regAddr = 0;
	int tlv_value = 0;
	unsigned char str[1024] = {0};

	rtu_req = (RTU_CMD_HEAD *)pdu_ptr;
	rtu_res = (RTU_CMD_HEAD *)modbus_res_buf;

	HexToStr(pdu_ptr, str, pdu_len);
	syslog(LOG_NOTICE, "RTU Recv: %s, len: %d", str, pdu_len);
	syslog(LOG_DEBUG, "RTU Request: len(%02x) cmdid(%02x) pkid(%02x) ver(%02x)", 
		ntohs(rtu_req->length), ntohs(rtu_req->cmdid), ntohl(rtu_req->seq), ntohs(rtu_req->version));
	
	if (ntohs(rtu_req->length) > pdu_len)
	{
		syslog(LOG_ERR, "Recv M2M Len: %d > pdu_len: %d", rtu_req->length, pdu_len);
		return -1;
	}
	
	rtu_res->seq = rtu_req->seq;
	m_rtu_seq_num = ntohl(rtu_req->seq) + 1;
	rtu_res->version = rtu_req->version;
	rtu_res->safe_flag = rtu_req->safe_flag;		//安全标识:1启用, 0不启用
	rtu_res->type = rtu_req->type;	//0: M2M指令，1: Lora指令
	memcpy(rtu_res->dev_sn, m_router_sn, sizeof(rtu_res->dev_sn)); 

	switch (ntohs(rtu_req->cmdid))
	{
		//case RTU_LOGIN_ACK:
		//	syslog(LOG_NOTICE, "RTU Command(%02x) RTU_LOGIN_ACK!!!", ntohs(rtu_req->cmdid));
		//	break;
		//case RTU_LOGOUT_ACK:
		//	syslog(LOG_NOTICE, "RTU Command(%02x) RTU_LOGOUT_ACK!!!", ntohs(rtu_req->cmdid));
		//	break;
		//case RTU_HEARTBEAT_ACK:
		//	syslog(LOG_NOTICE, "RTU Command(%02x) RTU_HEARTBEAT_ACK!!!", ntohs(rtu_req->cmdid));
		//	break;
		//case RTU_PUB_ACK:
		//	syslog(LOG_NOTICE, "RTU Command(%02x) RTU_PUB_ACK!!!", ntohs(rtu_req->cmdid));
		//	if (pdu_ptr[sizeof(RTU_CMD_HEAD)] == 0x00)
		//	{
		//		syslog(LOG_NOTICE, "RTU Command(%02x): success!!!", ntohs(rtu_req->cmdid));
		//	}
		//	else
		//	{
		//		syslog(LOG_ERR, "RTU Command(%02x): TLV error!!!", ntohs(rtu_req->cmdid));
		//	}
		//	break;
#if 0
		case RTU_SUB_CMD:
			syslog(LOG_NOTICE, "RTU Command(%02x) RTU_SUB_CMD!!!", ntohs(rtu_req->cmdid));
			rtu_res->cmdid = htons(RTU_SUB_ACK);
			memcpy(tmp_buf, pdu_ptr + sizeof(RTU_CMD_HEAD_T), pdu_len - sizeof(RTU_CMD_HEAD_T));	
			while (len < (pdu_len - sizeof(RTU_CMD_HEAD_T)))
			{
				tmp_len = 0;
				tlv_req = (RTU_CMD_TLV_T *)(tmp_buf + len);
				tlv_res = (RTU_CMD_TLV_T *)(tlv_res_buf + tlv_len);

				tlv_value = tlv_req->tlv_value[0] << 24 | tlv_req->tlv_value[1] << 16 		\
							| tlv_req->tlv_value[2] << 8 | tlv_req->tlv_value[3];
				if (tlv_value == 0x01000000)
				{
					上传所有传感量;
				}
				else
				{
					tlv_res->tlv_tag = htons(TAG_COLL_DATA);
					//tlv_res->tlv_tag = htons(0x0130);
					memcpy(tlv_res->tlv_value, tlv_req->tlv_value, 4);
					devAddr = tlv_req->tlv_value[1];
					regAddr = (tlv_req->tlv_value[2] << 8) | tlv_req->tlv_value[3];

					{获取相应设备相应传感器数值}	//???
					memcpy(tlv_res_buf + tlv_len + 8, 传感器数值, 传感器值位数);	//平台下发一个TLV命令固定长为8
					tmp_len = 传感器值位数 + 8;		//本个TLV长度
					tlv_len += tmp_len;				//累计多个TLV总长度
					tlv_res->tlv_len = tmp_len - 4;
					len += 8;
				}
			}
			*(modbus_res_buf + sizeof(RTU_CMD_HEAD_T)) = 0x00;
			memcpy(modbus_res_buf + sizeof(RTU_CMD_HEAD_T) + 1, tlv_res_buf, tlv_len);
			rtu_req_len = sizeof(RTU_CMD_HEAD_T) + tlv_len;
			rtu_res->length = htons(rtu_req_len);
			udp_socket_send(socket_fd, modbus_res_buf, rtu_req_len);
			break;
		case RTU_OUTPUT_CMD:
			syslog(LOG_NOTICE, "RTU Command(%02x) RTU_OUTPUT_CMD!!!", ntohs(rtu_req->cmdid));
			rtu_res->cmdid = htons(RTU_OUTPUT_ACK);
			memcpy(tmp_buf, pdu_ptr + sizeof(RTU_CMD_HEAD_T), pdu_len - sizeof(RTU_CMD_HEAD_T));	
			while (len < (pdu_len - sizeof(RTU_CMD_HEAD_T)))
			{
				tmp_len = 0;
				tlv_req = (RTU_CMD_TLV_T *)(tmp_buf + len);
				devAddr = tlv_req->tlv_value[1];
				regAddr = (tlv_req->tlv_value[2] << 8) | tlv_req->tlv_value[3];
				tmp_len = tlv_req->tlv_len - 4;		//待写入的数据流位数
				{写入寄存器}	//???
				len += tlv_req->tlv_len + 4;
			}
			*(modbus_res_buf + sizeof(RTU_CMD_HEAD_T)) = 0x00;
			rtu_req_len = sizeof(RTU_CMD_HEAD_T) + 1;
			rtu_res->length = htons(rtu_req_len);
			udp_socket_send(socket_fd, modbus_res_buf, rtu_req_len);
			break;
		case RTU_SCRIPT_GET_CMD:
			syslog(LOG_NOTICE, "RTU Command(%02x) RTU_SCRIPT_GET_CMD!!!", ntohs(rtu_req->cmdid));
			rtu_res->cmdid = htons(RTU_SCRIPT_GET_ACK);
		 	rtu_buf = nvram_safe_get("rtu_scripts");
			if ((rtu_buf == NULL) || (strlen(rtu_buf) <= 1))
			{
				*(modbus_res_buf + sizeof(RTU_CMD_HEAD)) = 0x01;		//获取脚本失败
				syslog(LOG_NOTICE, "RTU Command(%02x) Get scripts fail!!!", ntohs(rtu_req->cmdid));
				rtu_req_len = sizeof(RTU_CMD_HEAD) + 1;
				rtu_res->length = htons(rtu_req_len);
				udp_socket_send(socket_fd, modbus_res_buf, rtu_req_len);
			}
			else
			{
				*(modbus_res_buf + sizeof(RTU_CMD_HEAD)) = 0x00;		//获取脚本成功
				syslog(LOG_NOTICE, "RTU Command(%02x) Get scripts success!!!", ntohs(rtu_req->cmdid));
				len = strlen(rtu_buf);
				memcpy(modbus_res_buf + sizeof(RTU_CMD_HEAD) + 1, rtu_buf, len);
				rtu_req_len = sizeof(RTU_CMD_HEAD) + 1 + len;
				rtu_res->length = htons(rtu_req_len);

				memset(str, 0, 1024);
				HexToStr(modbus_res_buf, str, rtu_req_len);
				syslog(LOG_NOTICE, "RTU_SCRIPT_GET_ACK:%s", str);

				udp_socket_send(socket_fd, modbus_res_buf, rtu_req_len);
			}
			break;
		case RTU_SCRIPT_SET_CMD:
			syslog(LOG_NOTICE, "RTU Command(%02x) RTU_SCRIPT_SET_CMD!!!", ntohs(rtu_req->cmdid));
			rtu_res->cmdid = htons(RTU_SCRIPT_SET_ACK);
			memcpy(tmp_buf, pdu_ptr + sizeof(RTU_CMD_HEAD), pdu_len - sizeof(RTU_CMD_HEAD));	
			nvram_set("rtu_scripts", tmp_buf);		//???
			*(modbus_res_buf + sizeof(RTU_CMD_HEAD)) = 0x00;		//设置脚本成功
			rtu_req_len = sizeof(RTU_CMD_HEAD) + 1;
			rtu_res->length = htons(rtu_req_len);

			memset(str, 0, 1024);
			HexToStr(modbus_res_buf, str, rtu_req_len);
			syslog(LOG_NOTICE, "RTU_SCRIPT_SET_ACK:%s", str);

			udp_socket_send(socket_fd, modbus_res_buf, rtu_req_len);
			break;
#endif
		default:
			break;
	}

	return 0;
}

static int process_req(int socket_fd)
{
	int		 iRcv;
	int		 fromlen;
	char	 *hdr;
	char	 pdubuf[MAX_RTU_PACKET_LENGTH];
	struct sockaddr_in  from_addr;

	memset(pdubuf, 0, sizeof(pdubuf));

	if (wait_sock(socket_fd , 1 , 0) == 0)
	{
		return (-1);
	}

	fromlen = sizeof(from_addr);
	iRcv = udp_socket_recv(socket_fd, pdubuf, sizeof(pdubuf));
	if (iRcv < sizeof(RTU_CMD_HEAD_T))
	{
		syslog(LOG_ERR, "iRcv: %d != RTU HEAD LEN: %d", iRcv, sizeof(RTU_CMD_HEAD_T));
		close_socket(socket_fd);
		return (-1);
	}

	hdr = pdubuf;

	process_rtu_packet(socket_fd, hdr, iRcv);
}

void rtu_pub_alarm_thread_routine(unsigned char *valaddr, short regaddr, int datatype, unsigned char status)
{
    unsigned char buf[MAX_RTU_PACKET_LENGTH] = {0};
    int pkt_length;
    int ret;

    if (m_rtu_svr_socket < 0 || valaddr == NULL)
    {
        return;
    }
    pkt_length = encode_rtu_alarm_pub_pack(buf, sizeof(buf), valaddr, regaddr, datatype,status);
    ret = udp_socket_send(m_rtu_svr_socket, buf, pkt_length);
    if (ret == -1)
    {
        close(m_rtu_svr_socket);
        m_rtu_svr_socket = -1;
    }

}

static int modbus_get_host(const char *name, char *ipbuf)
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



void *send_pkt_thread_routine(void *arg)
{
    char cur_time[32] = {0};
    int packet_length;
    uint8_t packet_buffer[RCVBUFSIZE];
    uint16_t msg_id, msg_id_rcv;
    mqtt_broker_handle_t broker;
	int ret;

	
    m_total_pack = 0;

    while (1)
    {
        char *elem = NULL;
        char topic[128] = {0};

        if (connect_flag == 1)
        {
            nvram_set("mqtt_link_st", "disconnected");
            syslog(LOG_NOTICE, "send_pkt_thread_routine re-connect\n");
            mqtt_init(&broker, nvram_safe_get("router_sn"));//client_id
            mqtt_init_auth(&broker, nvram_safe_get("iot_username"), nvram_safe_get("iot_passwd"));//usrname and passwd

            
            while(init_socket(&broker, nvram_safe_get("iot_hostname"), nvram_get_int("iot_port")) < 0)
            {
                syslog(LOG_ERR, "Init socket error!\n");
                sleep(2);
            }

            // >>>>> CONNECT
            if(mqtt_connect(&broker) < 0)
            {
                syslog(LOG_ERR, "Mqtt connect error!\n");
                mqtt_disconnect(&broker);
                close_socket(&broker);
                continue ;
            }

            // <<<<< CONNACK
            packet_length = read_packet(2, packet_buffer, sizeof(packet_buffer));
            if(packet_length < 0)
            {
                syslog(LOG_ERR, "Error(%d) on read packet!\n", packet_length);
                mqtt_disconnect(&broker);
                close_socket(&broker);
                continue;
            }

            if(MQTTParseMessageType(packet_buffer) != MQTT_MSG_CONNACK)
            {
                syslog(LOG_ERR, "CONNACK expected!\n");
                mqtt_disconnect(&broker);
                close_socket(&broker);
                continue;
            }
            syslog(LOG_NOTICE, "send_pkt_thread_routine 5\n");

            if(packet_buffer[3] != 0x00)
            {
                syslog(LOG_ERR, "CONNACK failed!\n");
                mqtt_disconnect(&broker);
                close_socket(&broker);
                continue;
            }

            
            connect_flag = 0;
            nvram_set("mqtt_link_st", "connected");
            nvram_set("mqtt_last_cnnt", getCurTime(cur_time, sizeof(cur_time)));
        }

        sem_wait(&m_json_send_sem);
        memset(topic, 0, sizeof(topic));
        DeQueue(m_json_event_queue, &elem, topic);

        //syslog(LOG_NOTICE, "send_pkt_thread_routine -- %s -- %d -- %s\n", topic, strlen(elem), elem);
		if (elem == NULL)
		{
			syslog(LOG_NOTICE, "send_pkt_thread_routine elem is NULL\n");
			continue ;
		}
		
        memset(packet_buffer,0,sizeof(packet_buffer));
        ret = mqtt_publish_with_qos(&broker, topic, elem, 1, 1, &msg_id);
        if (ret < 0)
        {
        	syslog(LOG_ERR, "pub data failed!\n");
            connect_flag = 1;
            mqtt_disconnect(&broker);
            close_socket(&broker);
            m_total_pack = 0;
            nvram_set("mqtt_link_st", "disconnected");
            sleep(2);
            continue ;
        }
        m_total_pack++;

        free(elem);
        elem = NULL;
        #if 1
        packet_length = read_packet(2, packet_buffer, sizeof(packet_buffer));
        if(packet_length < 0)
        {
            syslog(LOG_ERR, "Error(%d) on read packet!\n", packet_length);
            connect_flag = 1;
            mqtt_disconnect(&broker);
            close_socket(&broker);
            m_total_pack = 0;
            nvram_set("mqtt_link_st", "disconnected");
            sleep(2);
            continue ;
        }

        if(MQTTParseMessageType(packet_buffer) != MQTT_MSG_PUBACK)
        {
            syslog(LOG_ERR, "PUBACK expected!\n");
            connect_flag = 1;
            mqtt_disconnect(&broker);
            close_socket(&broker);
            nvram_set("mqtt_link_st", "disconnected");
            m_total_pack = 0;
            sleep(2);
            continue;
        }
        //syslog(LOG_NOTICE, "send_pkt_thread_routine 7\n");
        msg_id_rcv = mqtt_parse_msg_id(packet_buffer);
        if(msg_id != msg_id_rcv)
        {
            syslog(LOG_ERR, "%d message id was expected, but %d message id was found!\n", msg_id, msg_id_rcv);
            continue;
        }
		#endif
        //syslog(LOG_NOTICE, "send_pkt_thread_routine 8\n");
        nvram_set("mqtt_last_sent", getCurTime(cur_time, sizeof(cur_time)));
    }

	return NULL;
}

int read_rtu_version(modbus_t *ctx_rtu)
{
    unsigned char respBuf[512] = {0};
    char cmdVer[20] = {0};
    int n = 0;
    char rtuVersion[10] = {0};


    memset(cmdVer, 0, sizeof(cmdVer));

    cmdVer[0] = 0x01;
    cmdVer[1] = 0x48;
    unsigned short crc = crc16(cmdVer, 2);
    cmdVer[2] = crc >> 8;
    cmdVer[3] = crc & 0x00FF;

    int fd = ctx_rtu->s;
    n = write(fd, cmdVer, 4);
    if (n != -1)
    {
        print_hex(cmdVer, 4, 1);
        n = wait_sock(fd, 2, 0);
        if (n <= 0)
        {
            syslog(LOG_NOTICE, "----MODBUS read timeout or failed");
            return 0 ;
        }

        n = read(fd, respBuf, sizeof(respBuf));
        if (n < 0)
        {
            syslog(LOG_NOTICE, "----MODBUS read failed");
            return 0 ;
        }

        print_hex(respBuf, n, 0);

        memcpy(rtuVersion, respBuf + 1, 8);
        nvram_set("rt52_rtu_ver", rtuVersion);
        syslog(LOG_INFO, "guochgz---> rtu version is %s\r\n", rtuVersion);
        return 0;
    }

    return -1;
}

int read_alarm_status(modbus_t *ctx_rtu)
{
    unsigned char respBuf[512] = {0};
    char respBuf_2[512] = {0};
    int n;
    char cmdAlarm[20] = {0};
    memset(cmdAlarm, 0, sizeof(cmdAlarm));

    cmdAlarm[0] = 0x01;
    cmdAlarm[1] = 0x41;
    unsigned short crc = crc16(cmdAlarm, 2);
    cmdAlarm[2] = crc >> 8;
    cmdAlarm[3] = crc & 0x00FF;
    int fd = ctx_rtu->s;
    n = write(fd, cmdAlarm, 4);
    if (n != -1)
    {
        print_hex(cmdAlarm, 4, 1);
        n = wait_sock(fd, 2, 0);
        if (n <= 0)
        {
            syslog(LOG_NOTICE, "----MODBUS read timeout or failed");
            return -1 ;
        }

        n = read(fd, respBuf, sizeof(respBuf));
        if (n < 0)
        {
            syslog(LOG_NOTICE, "----MODBUS read failed");
            return -1 ;
        }

        print_hex(respBuf, n, 0);

        char nItem = respBuf[2];
        int i = 0;
        while (i < (int)nItem)
        {
            char cur_time[32] = {0};
            char alarm_nv_name[32] = {0};
            char alarm_state[32] = {0};
            char alarm_time[32] = {0};
            unsigned short alarmNum;
            unsigned char  status;
            long alarmValue1;
            float alarmValue2;



            memcpy(&alarmNum, respBuf + 3 + i * 7, 2);
            alarmNum = ntohs(alarmNum);
            status = respBuf[3 + i * 7 + 2];
            int index = get_alarm_info_index(alarmNum);
            if (index == -1)
            {
            	i++;
                continue ;
            }
            if(m_alarmInfo[index].datatype == 0)//integer
            {
                memcpy(&alarmValue1, respBuf + 3 + i * 7 + 3, 4);
                snprintf(respBuf_2, sizeof(respBuf_2) - 1, "%d", alarmValue1);
                syslog(LOG_INFO, "MT-oBuf item - 0x%02x, status = 0x%02x, value : 0x%02x", alarmNum, status, alarmValue1);
            }
            else//float
            {
                memcpy(&alarmValue2, respBuf + 3 + i * 7 + 3, 4);
                syslog(LOG_INFO,"-->float:%02x, %02x, %02x, %02x",respBuf[3 + i * 7 + 3],respBuf[3 + i * 7 + 4],respBuf[3 + i * 7 + 5],respBuf[3 + i * 7 + 6]);
                snprintf(respBuf_2, sizeof(respBuf_2) - 1, "%.2f", alarmValue2);
                syslog(LOG_INFO, "MF-oBuf item - 0x%02x, status = 0x%02x, value : 0x%02x", alarmNum, status, alarmValue2);
            }

            //syslog(LOG_NOTICE, "M-%d\n", index);

            snprintf(alarm_nv_name, sizeof(alarm_nv_name), "alarmval_%s", m_alarmInfo[index].signalId);
            nvram_set(alarm_nv_name, respBuf_2);


            if (status == 1)
            {
                //add by jerry for web
                snprintf(alarm_time, sizeof(alarm_time), "alarmtime_%s", m_alarmInfo[index].signalId);
                nvram_set(alarm_time, cur_time);

                snprintf(alarm_state, sizeof(alarm_state), "alarmstate_%s", m_alarmInfo[index].signalId);
                nvram_set(alarm_state, "1");

                encode_alarm_pack(index, status, respBuf_2);

                encode_alarm_data_pack(index, status, respBuf_2);
                m_alarmInfo[index].alarmStatus = 1;
            }

            if (status == 0)
            {
                if (m_alarmInfo[index].alarmStatus == 1)
                {
                    m_alarmInfo[index].alarmStatus = 0;


                    //add by jerry for web
                    snprintf(alarm_time, sizeof(alarm_time), "alarmtime_%s", m_alarmInfo[index].signalId);
                    nvram_set(alarm_time, cur_time);
                    snprintf(alarm_state, sizeof(alarm_state), "alarmstate_%s", m_alarmInfo[index].signalId);
                    nvram_set(alarm_state, "0");

                    encode_alarm_data_pack(index, status, respBuf_2);
                }
            }
            if(nvram_match("m2m_mode","enable"))
            {

                rtu_pub_alarm_thread_routine(&respBuf[3 + i * 7 + 3],alarmNum,m_alarmInfo[index].datatype,status);

            }
            wait_sock(0, 0, 10000);
            i++;
        }
    }

    return 0;
}


int parse_modbus_04_cmd(char *sigid, char *respBuf, int nBytes, unsigned short type, unsigned short vlen)
{
    char signal_nv_name[32] = {0};
    char orig_nv_name[32] = {0};
    char val_nv_name[32] = {0};
    char picktime_nv_name[32] = {0};
    char cur_time[24] = {0};
    float result3;
    short result1;
    long result2;
    char respBuf_2[512];
    long temp;

    
    //syslog(LOG_NOTICE, "----MODBUS read nbytes = %d  ----", nBytes);
    
    print_hex(respBuf, nBytes << 1, 0);
    if (strlen(sigid) != 0)
    {
        Bytes2String(respBuf, respBuf_2, (nBytes << 1 <= sizeof(respBuf_2)) ? nBytes << 1 : sizeof(respBuf_2));
        //snprintf(oBuf[count], sizeof(oBuf[count]) - 1, "\"%s\":\"%s\"", desc, respBuf_2);

        snprintf(signal_nv_name, sizeof(signal_nv_name), "signalid_%s", sigid);
        nvram_set(signal_nv_name, sigid);

        snprintf(orig_nv_name, sizeof(orig_nv_name), "originval_%s", sigid);
        nvram_set(orig_nv_name, respBuf_2);

        snprintf(picktime_nv_name, sizeof(picktime_nv_name), "picktime_%s", sigid);
        nvram_set(picktime_nv_name, getCurTime(cur_time, sizeof(cur_time)));
    }

    switch(type)
    {
    case 1://default
        Bytes2String(respBuf, respBuf_2, (nBytes << 1 <= sizeof(respBuf_2)) ? nBytes << 1 : sizeof(respBuf_2));
        if (strlen(sigid) != 0)
        {
            snprintf(val_nv_name, sizeof(val_nv_name), "signalval_%s", sigid);
            nvram_set(val_nv_name, respBuf_2);
            insert_signal_data(m_signal_db, nvram_get(signal_nv_name), nvram_get(orig_nv_name), nvram_get(val_nv_name), nvram_get(picktime_nv_name));
        }
        //snprintf(oBuf[count], sizeof(oBuf[count]) - 1, "\"%s\":\"%s\"", desc, respBuf_2);
        break;
    case 2://short
    case 3://word
        //	result1 = (short)(respBuf[0] << 8 | respBuf[1]);
        memcpy(&result1, respBuf, 2);
        //snprintf(oBuf[count], sizeof(oBuf[count]) - 1, "\"%s\":%d", desc, result1);
        snprintf(respBuf_2, sizeof(respBuf_2) - 1, "%d", result1);
        if (strlen(sigid) != 0)
        {
            snprintf(val_nv_name, sizeof(val_nv_name), "signalval_%s", sigid);
            nvram_set(val_nv_name, respBuf_2);
            insert_signal_data(m_signal_db, nvram_get(signal_nv_name), nvram_get(orig_nv_name), nvram_get(val_nv_name), nvram_get(picktime_nv_name));
        }
        break;
    case 4://long
    case 5://dword
       // temp = (long)(respBuf[0] << 24 | respBuf[1] << 16 | respBuf[2] << 8 | respBuf[3]);
        //memcpy(&result2, &temp, 4);
        memcpy(&result2, respBuf, 4);
        //snprintf(oBuf[count], sizeof(oBuf[count]) - 1, "\"%s\":%d", desc, result2);
        snprintf(respBuf_2, sizeof(respBuf_2) - 1, "%d", result2);
        if (strlen(sigid) != 0)
        {
            snprintf(val_nv_name, sizeof(val_nv_name), "signalval_%s", sigid);
            nvram_set(val_nv_name, respBuf_2);
            insert_signal_data(m_signal_db, nvram_get(signal_nv_name), nvram_get(orig_nv_name), nvram_get(val_nv_name), nvram_get(picktime_nv_name));
        }
        break;
    case 6://float
        //temp = (long)(respBuf[0] << 24 | respBuf[1] << 16 | respBuf[2] << 8 | respBuf[3]);
        memcpy(&result3, respBuf, 4);

        switch(vlen)
        {
        case 0:
            //snprintf(oBuf[count], sizeof(oBuf[count]) - 1,"\"%s\":%.f", desc,result3);
            snprintf(respBuf_2, sizeof(respBuf_2) - 1, "%.f", result3);
            break;
        case 1:
            //snprintf(oBuf[count],  sizeof(oBuf[count]) - 1,"\"%s\":%.1f", desc,result3);
            snprintf(respBuf_2, sizeof(respBuf_2) - 1, "%.1f", result3);
            break;
        case 2:
            //snprintf(oBuf[count], sizeof(oBuf[count]) - 1,"\"%s\":%.2f", desc,result3);
            snprintf(respBuf_2, sizeof(respBuf_2) - 1, "%.2f", result3);
            break;
        case 3:
            //snprintf(oBuf[count], sizeof(oBuf[count]) - 1,"\"%s\":%.3f", desc,result3);
            snprintf(respBuf_2, sizeof(respBuf_2) - 1, "%.3f", result3);
            break;
        case 4:
            //snprintf(oBuf[count],  sizeof(oBuf[count]) - 1,"\"%s\":%.4f", desc,result3);
            snprintf(respBuf_2, sizeof(respBuf_2) - 1, "%.4f", result3);
            break;
        case 5:
            //snprintf(oBuf[count], sizeof(oBuf[count]) - 1,"\"%s\":%.5f", desc,result3);
            snprintf(respBuf_2, sizeof(respBuf_2) - 1, "%.5f", result3);
            break;
        default:
            syslog(LOG_INFO, "Not support the length now, %d!", type);
            break;
        }

        if (strlen(sigid) != 0 && vlen <= 5)
        {
            snprintf(val_nv_name, sizeof(val_nv_name), "signalval_%s", sigid);
            nvram_set(val_nv_name, respBuf_2);
            insert_signal_data(m_signal_db, nvram_get(signal_nv_name), nvram_get(orig_nv_name), nvram_get(val_nv_name), nvram_get(picktime_nv_name));
        }
        break;
    default:
    	syslog(LOG_INFO, "Not support the data type now!");
        break;
    }
    return 0;
}

static modbus_t *open_modbus( )
{
	modbus_t *ctx_rtu = NULL;
	int rc = 0;
	int err_count = 0;

	
	while (err_count <= 5)
    {
    	struct timeval tv;
    	
        if (!wait_action_idle(10))
        {
            syslog(LOG_NOTICE, "router is busy");
            continue;
        }

        ctx_rtu = modbus_new_rtu(RTU_PORT, 115200, 'N', 8, 1);
        modbus_set_debug(ctx_rtu, TRUE);
        modbus_set_error_recovery(ctx_rtu,
                                  MODBUS_ERROR_RECOVERY_LINK |
                                  MODBUS_ERROR_RECOVERY_PROTOCOL);

        tv.tv_sec = 2;
        tv.tv_usec = 0;
        modbus_set_response_timeout(ctx_rtu, &tv);
        rc = modbus_connect(ctx_rtu) ;
        if (rc == -1)
        {
            sleep(5);
            err_count++;
        }
        else
        {
            break;
        }
    }

    return ctx_rtu;
}

static char *get_mount_dir(char *mount_dir, int len)
{
    FILE *fp = NULL;
    char buf[256] = {0};
    char part[64] = {0}, dir[64] = {0}, other[128] = {0};

    if (mount_dir == NULL)
    {
        return NULL;
    }

    fp = fopen("/proc/mounts", "r");
    if (fp == NULL)
    {
        printf("open mount files failed\r\n");
        return NULL;
    }

    while (fgets(buf, sizeof(buf) - 1, fp) != NULL)
    {
        if (strncmp(buf, "/dev/sda1", 9) == 0)
        {
            printf("got usb mount\r\n");
            sscanf(buf, "%s %s %s", part, dir, other);
            printf("part = %s, dir = %s, other = %s", part, dir, other);
            strncpy(mount_dir, dir, len);
            fclose(fp);
            return mount_dir;
        }
        else
        {
            continue ;
        }
    }

    fclose(fp);
    return NULL;
}


int main(int argc, char *argv[])
{
#define OPEN_DB_MAX_COUNT	5
    modbus_t *ctx_rtu;
    int rc; 
    static int modbus_err_count = 0;
	int db_err_count = 0;
    
    openlog("MODBUS", LOG_PID, LOG_USER);
	unsigned char mac[6] = {0};
	
    modbus_deamon( );

    modbus_config_init( );
    m_json_event_queue = InitQueue( );
    rc = sem_init(&m_json_send_sem, 0, 0);
    if (rc < 0)
    {
        syslog(LOG_NOTICE, "Initiate semaphore  failed");
        return 0;
    }

	sprintf(m_router_sn, "%s", nvram_safe_get("router_sn"));
//	ether_atoe(nvram_safe_get("et0macaddr"), mac);
//	snprintf(m_router_sn, 
//				sizeof(m_router_sn), 
//				"%02x%02x%02x%02x", 
//				mac[2], mac[3], mac[4], mac[5]);
//	
    while (!check_wanup( ))
    {
        sleep(2);
        syslog(LOG_NOTICE, "----MODBUS waiting for online, sleep 2 secs ----");
        continue ;
    }

	while (db_err_count <= OPEN_DB_MAX_COUNT)
	{
		if (!wait_action_idle(10))
        {
            syslog(LOG_NOTICE, "router is busy");
            continue;
        }
        syslog(LOG_NOTICE, "[IMPORTANT]----ready to open database  !!!----");
	    m_signal_db = open_db(MODBUS_DATABASE);
	    if (m_signal_db == NULL)
	    {
	    	syslog(LOG_NOTICE, "[IMPORTANT]----open database failed, please check hardware !!!----");
	    	sleep(5);
			
	    	if (db_err_count == OPEN_DB_MAX_COUNT)
	    	{
	    		//syslog(LOG_NOTICE, " Reboot System");

				//killall("modem_watchdog", SIGTERM);
				//system("killall -9 modem_watchdog");
				//sleep(20);
	    	}
	    	db_err_count++;
	    }
	    else
	    {
	    	break;
	    }
    }
    
    create_signal_data_dto_table(m_signal_db);
    create_signal_info_dto_table(m_signal_db);
    create_index_on_singalid(m_signal_db);
    create_picktime_index_on_singalid(m_signal_db);

    ctx_rtu = open_modbus( );
    if (ctx_rtu == NULL)
    {
    	sem_destroy(&m_json_send_sem);
    	DestroyQueue(m_json_event_queue);
    	syslog(LOG_NOTICE, "[IMPORTANT]----MODBUS open failed, please check hardware !!!----");
    	return 0;
    }

    
    m_connect_state = 0;
    set_rtu_config(ctx_rtu);

    send_rtu_scripts(ctx_rtu);

    get_rtu_time(ctx_rtu);

    read_rtu_version(ctx_rtu);

    memset(m_alarmInfo, 0, sizeof(ALARM_INFO_T) * 12);

	char *almTmp = nvram_safe_get("rtu_alarminfo_list");
    if (almTmp != NULL && *almTmp != 0x0)
    {
    	syslog(LOG_NOTICE, "modbusCmdTable is NULL, %02x ", *almTmp);
        get_alarm_info_list( );
    }

#if 0
    pthread_t pub_tid, sub_tid, pub_tid1, pub_tid2;
    pthread_attr_t attr;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    rc = pthread_create(&pub_tid1, &attr, &pub_thread_routine, NULL);
    if (rc < 0)
    {
        syslog(LOG_ERR, "Create pub report thread failed");
        modbus_close(ctx_rtu);
        modbus_free(ctx_rtu);
        sem_destroy(&m_json_send_sem);
    	DestroyQueue(m_json_event_queue);
        return -1;
    }

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    rc = pthread_create(&sub_tid, &attr, &report_devInfo_thread_routine, NULL);
    if (rc < 0)
    {
        syslog(LOG_ERR, "Create pub report thread failed");
        modbus_close(ctx_rtu);
        modbus_free(ctx_rtu);
        sem_destroy(&m_json_send_sem);
    	DestroyQueue(m_json_event_queue);
        return -1;
    }


    pthread_attr_init(&attr);
    size_t stacksize;
    pthread_attr_getstacksize(&attr, &stacksize);
    pthread_attr_setstacksize(&attr, stacksize << 4);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    rc = pthread_create(&pub_tid, &attr, &send_pkt_thread_routine, NULL);
    if (rc < 0)
    {
        syslog(LOG_ERR, "Create pub report thread failed");
        modbus_close(ctx_rtu);
        modbus_free(ctx_rtu);
        sem_destroy(&m_json_send_sem);
    	DestroyQueue(m_json_event_queue);
        return -1;
    }
#endif
    while (1)
    {
        char *nv, *nvp, *b;
        char *cmd, *startAddr, *nValue, *data_type, *value_len, *devAddr, *sigid, *desc;
        int n;
        char fc_code[2];
        unsigned short addr, length, slaveId, type, vlen;
        char outBuf[12];
        unsigned char respBuf[512];
        char respBuf_2[512];
        int count = 0; 
        int sleep_int = nvram_get_int("iot_cycle_interval");


        if (sleep_int <= 0)
        {
            sleep_int = 1;
        }

        if (modbus_gotuser == 2)
        {
            modbus_gotuser = 0;
            set_rtu_time(ctx_rtu);
        }

		if (!wait_action_idle(10))
        {
            syslog(LOG_NOTICE, "router is busy");
            continue;
        }

        nv = nvram_safe_get("modbusCmdTable");
        if (nv == NULL || *nv == 0x0)
        {
        	syslog(LOG_NOTICE, "modbusCmdTable is NULL ");

			almTmp = nvram_safe_get("rtu_alarminfo_list");
        	if (almTmp != NULL && *almTmp != 0x0)
			{
                syslog(LOG_NOTICE, "modbusCmdTable <2> ");
	        	read_alarm_status(ctx_rtu);
			}
		
        	sleep(sleep_int);
           	continue;
        }
        
        nvp = nv = strdup(nvram_safe_get("modbusCmdTable"));
        if (!nv)
        {
        	modbus_close(ctx_rtu);
            modbus_free(ctx_rtu);
            sem_destroy(&m_json_send_sem);
    		DestroyQueue(m_json_event_queue);
            return 0;
        }

		if (modbus_err_count >= 30)
		{
			modbus_close(ctx_rtu);
            modbus_free(ctx_rtu);
            ctx_rtu = open_modbus( );
			if (ctx_rtu == NULL)
			{
				sem_destroy(&m_json_send_sem);
				DestroyQueue(m_json_event_queue);
				syslog(LOG_NOTICE, "[IMPORTANT]----MODBUS open failed, please check hardware !!!----");
				return 0;
			}
		}
		
        // read modbus cmd, parse it, and read data from rtu, got signal data. 
        while ((b = strsep(&nvp, ">")) != NULL)
        {
            // save as xxx_sigid nvram.
            char signal_nv_name[32] = {0};
            char orig_nv_name[32] = {0};
            char val_nv_name[32] = {0};
            char picktime_nv_name[32] = {0};
            char cur_time[24] = {0};


            memset(respBuf,0,sizeof(respBuf));
            memset(respBuf_2,0,sizeof(respBuf_2));
            //memset(oBuf[count],0,sizeof(oBuf[count]));

            n = vstrsep(b, "<", &cmd, &startAddr, &nValue, &data_type, &value_len, &devAddr, &sigid, &desc);
            if (n < 8)
            {
                continue;
            }

            n = String2Bytes(cmd, fc_code, 2);
            if (n != 1)
            {
                syslog(LOG_NOTICE, "----MODBUS fmt nvram cmd failed, unknown function code ,skipped ----");
                continue ;
            }
          /*  n = String2Bytes(startAddr, outBuf, strlen(startAddr));
            if (n != 2)
            {
                syslog(LOG_NOTICE, "----MODBUS fmt nvram cmd failed, unknown regaddr , skipped ----");
                continue ;
            }

            memcpy(&addr, outBuf, n);*/
            addr = (unsigned short)atoi(startAddr);
           // addr = ntohs(addr);
            length = atoi(nValue);
            slaveId = atoi(devAddr);
            type = atoi(data_type);
            vlen = atoi(value_len);
            //syslog(LOG_NOTICE, "----MODBUS 0x01 fmt vlen = %02x, %d, %d, %d %d ----", addr, length, slaveId, type, vlen);
            modbus_set_slave(ctx_rtu, slaveId);

            switch (fc_code[0])
            {
            case READ_COIL_STATUS:
                //modbus_read_bits
                n = modbus_read_bits(ctx_rtu, addr, length, respBuf);
                if (n != -1)
                {
                	modbus_err_count = 0;
                    syslog(LOG_NOTICE, "----MODBUS read nbytes = %d  ----", n);
                    print_hex(respBuf, n << 1, 0);
                    Bytes2String(respBuf + 2, respBuf_2, ((n - 2) << 1 <= sizeof(respBuf_2)) ? (n - 2) << 1 : sizeof(respBuf_2));
                    if (strlen(sigid) != 0)
                    {
                        snprintf(signal_nv_name, sizeof(signal_nv_name), "signalid_%s", sigid);
                        nvram_set(signal_nv_name, sigid);

                        snprintf(orig_nv_name, sizeof(orig_nv_name), "originval_%s", sigid);
                        nvram_set(orig_nv_name, respBuf_2);

                        snprintf(val_nv_name, sizeof(val_nv_name), "signalval_%s", sigid);
                        nvram_set(val_nv_name, respBuf_2);

                        snprintf(picktime_nv_name, sizeof(picktime_nv_name), "picktime_%s", sigid);
                        nvram_set(picktime_nv_name, getCurTime(cur_time, sizeof(cur_time)));
                        insert_signal_data(m_signal_db, nvram_get(signal_nv_name), nvram_get(orig_nv_name), nvram_get(val_nv_name), nvram_get(picktime_nv_name));
                    }
                }
                else
                {
                	modbus_err_count++;
                    continue ;
                }
                break;
            case READ_INPUT_STATUS:
                n = modbus_read_input_bits(ctx_rtu, addr, length, respBuf);
                if (n != -1)
                {
                	modbus_err_count = 0;
                    syslog(LOG_NOTICE, "----MODBUS read nbytes = %d  ----", n);
                    snprintf(respBuf_2, sizeof(respBuf_2) - 1, "%d", respBuf[0]);                  
                    if (strlen(sigid) != 0)
                    {
                        snprintf(signal_nv_name, sizeof(signal_nv_name), "signalid_%s", sigid);
                        nvram_set(signal_nv_name, sigid);

                        snprintf(orig_nv_name, sizeof(orig_nv_name), "originval_%s", sigid);
                        nvram_set(orig_nv_name, respBuf_2);

                        snprintf(val_nv_name, sizeof(val_nv_name), "signalval_%s", sigid);
                        nvram_set(val_nv_name, respBuf_2);

                        snprintf(picktime_nv_name, sizeof(picktime_nv_name), "picktime_%s", sigid);
                        nvram_set(picktime_nv_name, getCurTime(cur_time, sizeof(cur_time)));

                        insert_signal_data(m_signal_db, nvram_get(signal_nv_name), nvram_get(orig_nv_name), nvram_get(val_nv_name), nvram_get(picktime_nv_name));
                    }

                    if (strcmp("enable", nvram_safe_get("m2m_mode")) == 0)
                	{
                		Bytes2String(respBuf, respBuf_2, (length << 1 <= sizeof(respBuf_2)) ? length << 1 : sizeof(respBuf_2));
                		
                		snprintf(signal_nv_name, sizeof(signal_nv_name), "slaveid_%s", sigid);
       	 				nvram_set(signal_nv_name, devAddr);

       	 				snprintf(signal_nv_name, sizeof(signal_nv_name), "regAddr_%s", sigid);
       	 				nvram_set(signal_nv_name, startAddr);

       	 				snprintf(signal_nv_name, sizeof(signal_nv_name), "rtuval_%s", sigid);
                        nvram_set(signal_nv_name, respBuf_2);

                        snprintf(signal_nv_name, sizeof(signal_nv_name), "valueType_%s", sigid);
       	 				nvram_set(signal_nv_name, data_type);
                	}
                }
                else
                {
                	modbus_err_count++;
                    continue ;
                }

                break;
            case READ_HOLDING_REGISTERS:
                n = modbus_read_registers(ctx_rtu, addr, length, respBuf, type);
                if (n != -1)
                {
                	modbus_err_count = 0;
                    syslog(LOG_NOTICE, "----MODBUS read nbytes = %d  ----", n);
                    print_hex(respBuf, n << 1, 0);
                    Bytes2String(respBuf + 2, respBuf_2, ((n - 2) << 1 <= sizeof(respBuf_2)) ? (n - 2) << 1 : sizeof(respBuf_2));
                }
                else
                {
                	modbus_err_count++;
                    continue ;
                }

                break;
            case READ_INPUT_REGISTERS:
                //modbus_read_bits
                n = modbus_read_input_registers(ctx_rtu, addr, length, respBuf, type);
                if (n != -1)
                {
                	modbus_err_count = 0;
                	parse_modbus_04_cmd(sigid, respBuf, n, type, vlen);
                	if (strcmp("enable", nvram_safe_get("m2m_mode")) == 0)
                	{
                		Bytes2String(respBuf, respBuf_2, (length << 1 <= sizeof(respBuf_2)) ? length << 1 : sizeof(respBuf_2));
                		
                		snprintf(signal_nv_name, sizeof(signal_nv_name), "slaveid_%s", sigid);
       	 				nvram_set(signal_nv_name, devAddr);

       	 				snprintf(signal_nv_name, sizeof(signal_nv_name), "regAddr_%s", sigid);
       	 				nvram_set(signal_nv_name, startAddr);

       	 				snprintf(signal_nv_name, sizeof(signal_nv_name), "rtuval_%s", sigid);
       	 				nvram_set(signal_nv_name, respBuf_2);
       	 				
                        snprintf(signal_nv_name, sizeof(signal_nv_name), "valueType_%s", sigid);
       	 				nvram_set(signal_nv_name, data_type);
                	}
                }
                else
                {
                	modbus_err_count++;
                    syslog(LOG_ERR, "modbus_read_input_registers read = -1");
                    continue ;
                }

                break;
            case FORCE_SINGLE_COIL:
                n = modbus_write_bit(ctx_rtu, addr, length);
                if (n != -1)
                {
                	modbus_err_count = 0;
                    syslog(LOG_NOTICE, "----MODBUS read nbytes = %d  ----", n);
                    print_hex(respBuf, n << 1, 0);
                    Bytes2String(respBuf, respBuf_2, (n << 1 <= sizeof(respBuf_2)) ? n << 1 : sizeof(respBuf_2));
                }
                else
                {
                	modbus_err_count++;
                    continue ;
                }
                break;
            default:
                syslog(LOG_NOTICE, "----MODBUS illegal nvram cmd %02x, skipped ----", fc_code[0]);
                break;
            }
            count++;
        }
        free(nv);

		almTmp = nvram_safe_get("rtu_alarminfo_list");
		if (almTmp != NULL && *almTmp != 0x0)
		{
			syslog(LOG_NOTICE, "----MODBUS read to read alarm status ----");
        	read_alarm_status(ctx_rtu);
		}
		
        sleep(sleep_int);
    }


    /* Close the connection */
    modbus_close(ctx_rtu);
    modbus_free(ctx_rtu);
    DestroyQueue(m_json_event_queue);
    sem_destroy(&m_json_send_sem);
    return 0;
}

