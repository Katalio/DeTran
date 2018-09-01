#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <errno.h>
#include <arpa/inet.h>

#define PORT 9527

typedef struct _rtu_cmd_head
{
	unsigned short length;
	unsigned short cmdid;
	unsigned int seq;
	unsigned short version;
	unsigned char safe_flag;
	unsigned char type;
	char dev_sn[16];
} RTU_CMD_HEAD_T;

typedef struct _rtu_cmd_tlv
{
	unsigned short tlv_tag;
	unsigned short tlv_len;
	char tlv_value[1024];
} RTU_CMD_TLV_T;

void print_hex(char *data, int len, int op);
int String2Bytes(const char* str, unsigned char* buf, int len);
int encode_rtu_pub_pack(unsigned char *buf, int buf_len);

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
}

int String2Bytes(const char* str, unsigned char* buf, int len)
{
    int i; 		// k = 0; //,j = 0;
    const char *data;
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

int encode_rtu_pub_pack(unsigned char *buf, int buf_len)
{
	RTU_CMD_HEAD_T *cmd = (RTU_CMD_HEAD_T *)buf;
    int n;
    char slaveid_nv_name[32] = {0};
    char regAddr_nv_name[32] = {0};
    char val_nv_name[32] = {0};
    char valtype_nv_name[32] = {0};
	RTU_CMD_TLV_T  *tlv = NULL;
	unsigned int length, tlv_len;
	unsigned short regAddr;
	char outBuf[12] = {0};
    int valueType = 0;
    unsigned short regAddr_value;
	char slvid_value = 0, *val_value = NULL;
	int i;
	int k = 3;

    memset(buf, 0, buf_len);
	cmd->cmdid = htons(0x0010);
	cmd->seq = htonl(12345678);
	cmd->version = htons(0x0300);
	cmd->safe_flag = 0;		//安全标识:1启用, 0不启用
	cmd->type = 0;	//0: M2M指令，1: Lora指令
	memcpy(cmd->dev_sn, "00:90:4C:06:50:2D", sizeof(cmd->dev_sn)); 
	length = sizeof(RTU_CMD_HEAD_T);

	slvid_value = 0x01;		//设备地址
	regAddr_value = 100;	//寄存器地址
	val_value = "40015002";		//寄存器值

	while(k){
		//encode tlv
		memset(outBuf, 0, sizeof(outBuf));
		
   	//	if (slvid_value == NULL || regAddr_value == NULL || val_value  == NULL)
   	//	{
   	//	    continue ;
   	//	}

   		n = String2Bytes(val_value, outBuf, strlen(val_value));
   	//	if (n != 4 && n != 2)
   	//	{
   	//	    syslog(LOG_NOTICE, "----RTU Pub Function, get reg value failed ,skipped ----");
   	//	    continue ;
   	//	}
    	
		//tlv_len = sizeof(RTU_CMD_TLV_T) + n;

		tlv = (RTU_CMD_TLV_T  *)(buf + length);

		memset(tlv, 0, sizeof(tlv));
		tlv_len = 0;

		tlv->tlv_tag = htons(0x0130);
		*(tlv->tlv_value + tlv_len)= 0x01;
		tlv_len += 1;
		*(tlv->tlv_value + tlv_len)= slvid_value;
		tlv_len += 1;
		regAddr_value = htons(regAddr_value);
		memcpy(tlv->tlv_value + tlv_len, &regAddr_value, 2) ;
		tlv_len += 2;
		memcpy(tlv->tlv_value + tlv_len, outBuf, n);	
		tlv_len += n;
		
		tlv->tlv_len = htons(tlv_len);
    	length += tlv_len + 4;

		slvid_value += 1;		
		regAddr_value += 100;	
			
		k--;
	}
	cmd->length = htons(length);
//	print_hex(buf, length, 1);

	return length;
}

int main(void)
{
	int fd;
	int n;
	char buff[1024];
	int pkt_len = 0;
	socklen_t len;
	struct sockaddr_in mm;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd < 0) {
		perror("create socket error!");
		return 1;
	}
	printf("create socket successfully\n");

	mm.sin_family = AF_INET;
	mm.sin_port = htons(PORT);
	mm.sin_addr.s_addr = INADDR_ANY;
//	mm.sin_addr.s_addr = inet_addr("192.168.6.14");

	len = sizeof(mm);

	pkt_len = encode_rtu_pub_pack(buff, sizeof(buff));
	printf("pkt_len is %d\n", pkt_len);
	n = sendto(fd, buff, pkt_len, 0, (struct sockaddr *) &mm, len);
	if(n <= 0) {
		perror("send data error");
		close(fd);
		return 1;
	}
	printf("Send data successfully\n");

	close(fd);
	return 0;

}


