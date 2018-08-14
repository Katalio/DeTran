#include "dtu.h"

#define DEVICE "/dev/ttyS0"
#define BUFF_SIZE 2048 

/* init serial port and return the fd */
static int serial_port_init(void);

static char *package_data(unsigned char *in, unsigned char *out, int len);
static int send_cmd(int serlfd, FILE *filefd, unsigned char cmd);	
static int file_getsize(FILE *fd);
static short int file_checksum(FILE *fd);
static unsigned short int final_checksum = 0;

static int serial_port_init(void)
{
	int fd;
	struct termios tms;

	fd = open(DEVICE, O_RDWR | O_NOCTTY | O_NDELAY);
	if(fd < 0) {
		perror("Opne device fail!");
		return -1;
	}
	
	printf("Open %s successfully\n", DEVICE);

	tcgetattr(fd, &tms);
	tcflush(fd, TCIOFLUSH);

	/* set baud rate */
	cfsetispeed(&tms, B57600);
	cfsetospeed(&tms, B57600);

	/* set data bits */
	tms.c_cflag &= ~CSIZE;
	tms.c_cflag |= CS8;

	/* set parity bits */
	tms.c_iflag &= ~INPCK;
	tms.c_cflag &= ~ PARENB;

	/* set stop bits */
	tms.c_cflag &= ~CSTOPB;

	/* 设置为原始模式 */
	tms.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);
	tms.c_oflag &= ~OPOST;

	if(tcsetattr(fd, TCSANOW, &tms) != 0) {
		perror("Fail to set serial params!");
		return -1;
	}

	return fd;
}

static char *package_data(unsigned char *in, unsigned char *out, int len)
{
	unsigned char filesum = 0;
	short length = len + 16;
	int i;

	memcpy(out + 2, &length, 2);	//数据总长
	memcpy(out + 12, &len, 2);		//读取长度
	memcpy(out + 14, in, len);		
	for(i = 0; i < length - 2; i ++)
	{
		filesum += *(out + i);
	}
	*(out + length - 2) = filesum;		//校验和
	*(out + length - 1) = 0xBB;			//包尾

	return (out);
}

static int send_cmd(int serlfd, FILE *filefd, unsigned char cmd)
{
	unsigned char buff[BUFF_SIZE];			
	unsigned long freq = 40100000;
	unsigned int filesize = 0;
	unsigned short int checksum = 0;
	unsigned char filesum = 0;
	short len = 0;
	int fd = 0;
	int i;
	
	memset(buff, 0, BUFF_SIZE);
	*(buff + len) = 0xAA;	//包头
	len += 1;
	*(buff + len) = cmd;	//包类型，指令
	len += 3;
	switch(cmd)
	{
		case SET_PARAMS:
			memcpy(buff + len, &freq, 4);	//频率
			len += 4; 
			*(buff + len) = 0x00;	//带宽
			len += 1;
			*(buff + len) = 0x60;	//扩频因子
			len += 1;
			*(buff + len) = 15;		//输出功率
			len += 1;
			*(buff + len) = 255;	//网络ID
			len += 1;

			break;
		case RESET:
			break;	
		case UPDATE:
			fd = fileno(filefd);
			filesize = file_getsize(filefd);
			checksum = file_checksum(filefd);
			memcpy(buff + len, &fd, 4);		//文件ID		
			len += 4;
			memcpy(buff + len, &filesize, 4);	
			len += 4;
			memcpy(buff + len, &checksum, 2);	//文件校验和
			len += 2;

			break;
		case DOWNLOAD_FW_OK:
			break;	
		default:
			break;
	}

	len += 1;
	*(buff + len) = 0xBB;	//包尾
	len += 1;
	memcpy(buff + 2, &len, 2);	//数据包总长度

	for(i = 0; i < len - 2; i ++)
	{
		filesum += buff[i];
	}
	*(buff + len - 2) = filesum;	//数据包校验和

	printf("Send cmd: ");
	for(i = 0; i < len; i ++)
		printf("%3.2x", buff[i]);
	printf("\n");

	write(serlfd, buff, len);
}

static int file_getsize(FILE *fd)
{
	int len = 0;

	fseek(fd, 0, SEEK_END);
	len = ftell(fd);
	fseek(fd, 0, SEEK_SET);

	return len;
}

static short file_checksum(FILE *fd)
{
	unsigned short sum = 0;
	unsigned char tmp[BUFF_SIZE] = {0};
	int i, n = 0;
	int len = 0;
	unsigned char mm = 0;

	#if 1
	while(!feof(fd))
	{
		memset(tmp, 0, BUFF_SIZE);
		n = fread(tmp, 1, BUFF_SIZE, fd);
		for(i = 0; i < n; i ++)
		{
			sum += tmp[i];
		}
	}
	#else
	len = file_getsize(fd);
	while(len)
	{
		fread(&mm, 1, 1, fd);
		sum += mm;

		len --;
	}
	#endif

	printf("文件长度校验和: %d\n", sum);

	return sum;
}

int main(int argc, char *argv[])
{
	if(argc < 2)
	{
		printf("%s params are less than 2\n", argv[0]);
		return -1;
	}

	FILE *filefd = NULL;
	int serlfd = 0;
	int offset = 0;
	short int read_len = 0;
	unsigned char filesum = 0;
	unsigned char tmpbuff[BUFF_SIZE];
	unsigned char recvbuff[BUFF_SIZE];
	unsigned char sendbuff[BUFF_SIZE];
	int n = 0, m = 0, len = 0;
	int start = 0, end = 0;
	int i = 0;
	int x, y, z;

	serlfd = serial_port_init();
	filefd = fopen(argv[1], "r+");
	if(NULL == filefd)
	{
		printf("Open %s fail!\n", argv[1]);
		return -1;
	}
	printf("Open %s successfully\n", argv[1]);

	printf("文件长 %d\n", file_getsize(filefd));
	send_cmd(serlfd, filefd, UPDATE);	//升级
	fseek(filefd, 0, SEEK_SET);		//指向文件开始位置
	
	fd_set rfds;

	printf("文件下载中...\n");
	while(!feof(filefd))
	{
		printf("%s------------------------------%d\n", __FUNCTION__, __LINE__);

		FD_ZERO(&rfds);
		FD_SET(0, &rfds);
		FD_SET(serlfd, &rfds);

		if(select(serlfd + 1, &rfds, NULL, NULL, NULL) < 0)
		{
			perror("Select error");
			return -1;
		}

		if(FD_ISSET(serlfd, &rfds))
		{
			memset(recvbuff, 0, BUFF_SIZE);
			n = read(serlfd, recvbuff, BUFF_SIZE);	//请求下载数据包长度
			printf("n = %d\n", n);
			if(n < 0)
			{
				perror("read serial fail");
				fclose(filefd);
				close(serlfd);
				return -1;
			}
			recvbuff[n] = '\0';
			printf("Recv: ");
			for(z = 0; z < n; z ++)
				printf("%3.2x", recvbuff[z]);
			printf("\n");
		}
		/* i, filesum每次进入需重置 */
		i = 0;		
		filesum = 0;
		while(recvbuff[i] != '\0') 
		{
			if(recvbuff[i] == (unsigned char)0xAA)
			{
				start = i;
				end = i + 1;
				if(recvbuff[i+1] == (unsigned char)DOWNLOAD_FW_CODE)
				{
					while((recvbuff[end] != (unsigned char)0xBB) 
							&& (recvbuff[end] != (unsigned char)0xAA)) //找到包尾或下一个包头
					{
						end ++;
					}
					if(recvbuff[end] == (unsigned char)0xAA)
					{
						printf("Data issue, throw away\n");
						i = end;	
					}
					else
					{
						len = end - start + 1;
						for(z = start; z < end - 1; z ++)
						{
							filesum += recvbuff[z];
						}
						if((len != (recvbuff[i+3] << 8 | recvbuff[i+2])) 
										|| (recvbuff[end-1] != filesum))	//数据包有问题
						{
							printf("Data issue, throw away\n");
							i += len;
						}
						else	
						{
							read_len = recvbuff[start+12] | (recvbuff[start+13] << 8);	//请求读取长度
							printf("请求读取长度 %d\n", read_len);
							offset = recvbuff[start+8] | (recvbuff[start+9] << 8) 
										| (recvbuff[start+10] << 16) | (recvbuff[start+11] << 24);
							printf("offset = %d\n", offset);
							fseek(filefd, offset, SEEK_SET);			//指向偏移位置
							memset(sendbuff, 0, BUFF_SIZE);
							m = fread(sendbuff, 1, read_len, filefd);	//实际读取长度
							if(m > 0)
							{
								printf("实际读取长度 %d\n", m);

								for(x = 0, y = start; y <= end; x ++, y ++)
								{
									tmpbuff[x] = recvbuff[y];
								}

								package_data(sendbuff, tmpbuff, m);
								for(z = 14; z < m + 14; z ++)
								{
									final_checksum += tmpbuff[z];
								}
								printf("Final check sum is %d\n", final_checksum);

								write(serlfd, tmpbuff, m + 16);

								i += len;
							}
						}
					}
				}
				else
				{
					while((recvbuff[end] != (unsigned char)0xBB) 
							&& (recvbuff[end] != (unsigned char)0xAA))	
					{
						end ++;
					}
					if(recvbuff[end] == (unsigned char)0xAA)
					{
						printf("Data issue, throw away\n");
						i = end;	
					}
					else
					{
						len = end - start + 1;
						i += len;		
					}
				}
			}
			else
			{
				i ++;
			}
		}	
		printf("***************************************\n");
	}

	printf("文件下载完成!\n");
	send_cmd(serlfd, filefd, RESET);	//重启

	fclose(filefd);
	close(serlfd);

	return 0;
}




