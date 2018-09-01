#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct _M2M_PROTOCOL_HDR_T
{
	unsigned short len;
	unsigned short cmd_id;
	unsigned int packet_id;
	unsigned short version;
	unsigned char safe_flag;
	unsigned char type;
	char product_id[16];
} M2M_PROTOCOL_HDR_T;

typedef struct _M2M_PROTOCOL_TLV
{
	unsigned short tlv_tag;		
	unsigned short tlv_len;		
	char tlv_value[1024];		
}M2M_PROTOCOL_TLV;

typedef struct _M2M_LOGIN_NVRAM
{
	unsigned short tag_id;
	char *name;
} M2M_LOGIN_NVRAM;

M2M_LOGIN_NVRAM info[] = 
{
	{0x000F, "router_type"},
	{0x0011, "router_sn"},
	{0x000D, "os_version"},
	{0xffff, NULL}
};

unsigned int packet_id = 0;
unsigned char *product_id = "RT52_0D:0D:0D:0D";

int main()
{
	int i = 0, j;
	unsigned char hb_buf[1024];
	unsigned char tlv_buf[1024];
	unsigned char tlv_total_buf[1024];
	int hb_len = 0;
	int tlv_len = 0;	//single tlv length
	int length = 0;		//totla tlv length
	M2M_PROTOCOL_HDR_T *hb = (M2M_PROTOCOL_HDR_T *)hb_buf;
	M2M_PROTOCOL_TLV *tlv = (M2M_PROTOCOL_TLV *)tlv_buf;

	while(1)
	{
		memset(hb_buf, 0, sizeof(hb_buf));
		memset(tlv_total_buf, 0, sizeof(tlv_total_buf));
		hb_len = 0;
		length = 0;
		i = 0;

		hb->cmd_id = htons(0x0001);
		hb->packet_id = htonl(packet_id++);
		hb->version = htons(0x0300);
		hb->safe_flag = 0;		//安全标识:1启用, 0不启用
		hb->type = 0;	//0: M2M指令，1: Lora指令
		memcpy(hb->product_id, product_id, sizeof(hb->product_id));
		hb_len += sizeof(M2M_PROTOCOL_HDR_T);
		
		while(info[i].name != NULL)
		{
			tlv_len = 0;
			memset(tlv_buf, 0, sizeof(tlv_buf));
			tlv->tlv_tag = htons(info[i].tag_id);
			sprintf(tlv->tlv_value, "%s", info[i].name);
			tlv_len = strlen(tlv->tlv_value);
			tlv->tlv_len = htons(tlv_len);

			memcpy(tlv_total_buf + length, tlv_buf, tlv_len + 4);
			length += tlv_len + 4;

			i++;
		}

		printf("Total TLV:");
		for(j = 0; j < length; j++)
			printf("%3.2x", tlv_total_buf[j]);
		printf("\n");

		memcpy(hb_buf + hb_len, tlv_total_buf, length);
		hb_len += length;

		printf("hb_len is %d\n", hb_len);
		hb->len = htons(hb_len);

		printf("DATA:");
		for(i = 0; i < hb_len; i++)
			printf("%3.2x", hb_buf[i]);
		printf("\n");
		sleep(5);
		printf("-----------------------\n");
	}
	return 0;
}

