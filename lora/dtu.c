#include "dtu.h"

#define PORT 8080 
#define DEVICE "/dev/ttyS0"
#define BUFF_SIZE 2048 

/* init serial port and return the fd */
static int serial_port_init(void);

static int tcp_client_handler(void);
static int udp_client_handler(void);
static int send_cmd(int fd, unsigned char cmd);	
static int recv_ack(int fd);
static int package_data(unsigned char *in, unsigned char *out, int length);
static int analysis_data(unsigned char *in, unsigned char *out, int length);

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
	tms.c_lflag &= ~(ECHO | ECHONL | ICANON | IEXTEN | ISIG);
	tms.c_oflag &= ~OPOST;

	if(tcsetattr(fd, TCSANOW, &tms) != 0) {
		perror("Fail to set serial params!");
		return -1;
	}

	return fd;
}

static int package_data(unsigned char *in, unsigned char *out, int length)
{
	short filesum = 0;
	short len = 0;
	int i;

	*(out + len) = 0xAA;	//包头
	len += 1;
	*(out + len) = SEND_TO_LORA;	//包类型，指令
	len += 3;
	strncpy(out + len, in, length);
	len += length;

	len += 1;
	*(out + len) = 0xBB;	//包尾
	len += 1;
	memcpy(out + 2, &len, 2);	//数据包总长度

	for(i = 0; i < len - 2; i ++)
	{
		filesum += out[i];
	}
	*(out + len - 2) = filesum;	//校验和

	length = len;	//同length += 6;

	printf("打包好的数据:");
	for(i = 0; i < len; i ++)
	{
		printf("%3.2x", out[i]);
	}
	printf("\n");

	return length;
}

static int analysis_data(unsigned char *in, unsigned char *out, int length)
{
	int i = 0, j = 0;
	int start = 0;
	int end = 0;
	int len = 0;
	int index = 0;
	unsigned char filesum = 0;

	while(in[i] != '\0')
	{
		if(in[i] == (unsigned char)0XAA)	//找到包头
		{
			start = i;
			end = i + 1;

			if((in[i+1] == (unsigned char)SEND_TO_LORA))
			{
				while((in[end] != (unsigned char)0xBB) 
					&& (in[end] != (unsigned char)0xAA))	//找到包尾或下一个包头
				{
					end ++;
				}
				if(in[end] == (unsigned char)0xAA)
				{
					printf("Data issue, throw away\n");
					i = end;	
				}
				else
				{
					len = end - start + 1;
					for(j = start; j < end - 1; j ++)
					{
						filesum += in[j];
					}
					if((len != (in[i+3] << 8 | in[i+2])) || (in[end-1] != filesum))		//数据包有问题
					{
						printf("Data issue, throw away\n");
						i += len;
					}
					else
					{
						printf("Send data to node successfully\n");
						i += len;		//回应包占6个字节
					}
				}
			}	
			else if(in[i+1] == (unsigned char)ERROR)
			{
				while((in[end] != (unsigned char)0xBB) 
					&& (in[end] != (unsigned char)0xAA))	//找到包尾或下一个包头
				{
					end ++;
				}
				if(in[end] == (unsigned char)0xAA)
				{
					printf("Data issue, throw away\n");
					i = end;	
				}
				else
				{
					len = end - start + 1;
					for(j = start; j < end - 1; j ++)
					{
						filesum += in[j];
					}
					if((len != (in[i+3] << 8 | in[i+2])) || (in[end-1] != filesum))		//数据包有问题
					{
						printf("Data issue, throw away\n");
						i += len;
					}
					else
					{
						printf("Send data to node failed\n");
						i += 7;		//错误包占7个字节
					}
				}
			}
			else if(in[i+1] == (unsigned char)SEND_TO_SERVER)	
			{
				while((in[end] != (unsigned char)0xBB) 
					&& (in[end] != (unsigned char)0xAA))	//找到包尾或下一个包头
				{
					end ++;
				}
				if(in[end] == (unsigned char)0xAA)
				{
					printf("Data issue, throw away\n");
					i = end;	
				}
				else
				{
					len = end - start + 1;		//整个包的长度
					for(j = start; j < end - 1; j ++)
					{
						filesum += in[j];
					}
					if((len != (in[i+3] << 8 | in[i+2])) || (in[end-1] != filesum))		//数据包有问题
					{
						printf("Data issue, throw away\n");
						i += len;
					}
					else
					{
						for(j = index; j < len - 6; start ++, j ++)
						{
							out[j] = in[start+4];	
						}
						index = j;	//记下out当前长度

						i += len;
					}
				}
			}
			else
			{
				while((in[end] != (unsigned char)0xBB) 
					&& (in[end] != (unsigned char)0xAA))	//找到包尾或下一个包头
				{
					end ++;
				}
				if(in[end] == (unsigned char)0xAA)
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

	length = strlen(out);

	return length;
}

static int send_cmd(int fd, unsigned char cmd)
{
	unsigned char buff[BUFF_SIZE];			
	short len = 0;
	short filesum = 0;
	unsigned int freq = 510000000;
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
			*(buff + len) = 0x90;	//带宽
			len += 1;
			*(buff + len) = 0xC0;	//扩频因子
			len += 1;
			*(buff + len) = 15;		//输出功率
			len += 1;
			*(buff + len) = 255;	//网络ID
			len += 1;

			break;
		case RESET:
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
	*(buff + len - 2) = filesum;	//校验和

	printf("Send cmd: ");
	for(i = 0; i < len; i ++)
		printf("%3.2x", buff[i]);
	printf("\n");

	write(fd, buff, len);
}

static int recv_ack(int fd)
{
	int n = 0;
	unsigned char cmd;
	unsigned char buff[BUFF_SIZE];
	fd_set rfds;

	FD_ZERO(&rfds);
	FD_SET(0, &rfds);
	FD_SET(fd, &rfds);

	if(select(fd + 1, &rfds, NULL, NULL, NULL) < 0)
	{
		perror("Select error");
		return -1;
	}

	if(FD_ISSET(fd, &rfds))
	{
		n = read(fd, buff, BUFF_SIZE);
		if (n < 0)
		{
			perror("Read ack msg fail");
			return -1;
		}
	}

	cmd = buff[1];
	switch(cmd)
	{
		case SET_PARAMS:
			if(buff[4] == 1)
			{
				break;
			}
			else 
			{
				return -1;
			}

		case DOWNLOAD_FW_OK:
			break;

		default:
			break;
	}

	return 0;
}

static int tcp_client_handler(void)
{
	int cltfd;
	int maxfd;
	socklen_t len;
	struct sockaddr_in svr;
	unsigned char sendin[BUFF_SIZE];
	unsigned char recvin[BUFF_SIZE];
	unsigned char sendout[BUFF_SIZE];
	unsigned char recvout[BUFF_SIZE];
	int n, m, i;

	cltfd = socket(AF_INET, SOCK_STREAM, 0);
	if(cltfd < 0) {
		perror("create socket error!");
		return -1;
	} else {
		printf("success to create socket %d\n", cltfd);
	}

	bzero(&svr, sizeof(svr));		//initialize memory of the struct
	svr.sin_family = AF_INET;
	svr.sin_port = htons(PORT);
//	svr.sin_addr.s_addr = htonl(INADDR_ANY);
	svr.sin_addr.s_addr = inet_addr("192.168.1.8");
	bzero(&(svr.sin_zero), 8);

	len = sizeof(svr);	
	if(connect(cltfd, (struct sockaddr *)&svr, len) < 0) {
		perror("connect error!");
		close(cltfd);
		return -1;
	} else {
		printf("success connect to server!\n");
	}

	fd_set rfds;
	int fd = serial_port_init();

	send_cmd(fd, SET_PARAMS);	//设置参数
	if(recv_ack(fd) < 0)
	{
		perror("Set Lora parameters failed");
		return -1;
	}
	printf("Set Lora parameters successfully\n");

	send_cmd(fd, RESET);	//重启

	while(1) {
		FD_ZERO(&rfds);
		FD_SET(0, &rfds);
		FD_SET(cltfd, &rfds);
		FD_SET(fd, &rfds);

		maxfd = (cltfd > fd) ? cltfd : fd;
		n = select(maxfd + 1, &rfds, NULL, NULL, NULL);
		if(n < 0) {
			perror("select() error!");
			close(cltfd);
			close(fd);
			return -1;
		}

		if(FD_ISSET(cltfd, &rfds)) {	//平台数据转发到节点
			memset(recvin, 0, BUFF_SIZE);
			memset(recvout, 0, BUFF_SIZE);
			n = recv(cltfd, recvin, BUFF_SIZE, 0);
			if(n < 0) {
				perror("recv() error!");
				close(cltfd);
				return -1;
			}
			printf("recv from tcp: %d, %s\n", n, recvin);

			m = package_data(recvin, recvout, n);	//封包
			write(fd, recvout, m);
		}
	
		if(FD_ISSET(fd, &rfds)) {	//节点数据转发到平台
			memset(sendin, 0, BUFF_SIZE);
			memset(sendout, 0, BUFF_SIZE);
			n = read(fd, sendin, BUFF_SIZE);
			sendin[n] = '\0';
			printf("The size recv from serial port: %d\n", n);
			printf("Recv data:");
			for(i = 0; i < n; i ++)
			{
				printf("%3.2x", sendin[i]);
			}
			printf("\n");

			m = analysis_data(sendin, sendout, n);	//解包
			n = send(cltfd, sendout, m, 0);
			if(n < 0) {
				perror("send() error!");
				close(cltfd);
				return -1;
			}
		}
	}
	
	close(cltfd);
	close(fd);

	return 0;
}

static int udp_client_handler(void)
{
	int cltfd;
	int maxfd;
	int n, m, i;
	unsigned char sendin[BUFF_SIZE];
	unsigned char recvin[BUFF_SIZE];
	unsigned char sendout[BUFF_SIZE];
	unsigned char recvout[BUFF_SIZE];
	socklen_t len;
	struct sockaddr_in mm;

	cltfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(cltfd < 0) {
		perror("create socket error!");
		return -1;
	}
	printf("create socket successfully!\n");

	mm.sin_family = AF_INET;
	mm.sin_port = htons(PORT);
//	mm.sin_addr.s_addr = htonl(INADDR_ANY);
	mm.sin_addr.s_addr = inet_addr("192.168.1.8");

	len = sizeof(mm);
	int fd = serial_port_init();
	fd_set rfds;
	
	send_cmd(fd, SET_PARAMS);	//设置参数
	if(recv_ack(fd) < 0)
	{
		perror("Set Lora parameters failed");
		return -1;
	}
	printf("Set Lora parameters successfully\n");

	send_cmd(fd, RESET);	//重启

//	sendto(cltfd, "hello", 5, 0, (struct sockaddr *) &mm, len);
	while(1) {
		FD_ZERO(&rfds);
		FD_SET(0, &rfds);
		FD_SET(cltfd, &rfds);
		FD_SET(fd, &rfds);

		maxfd = (cltfd > fd) ? cltfd : fd;
		n = select(maxfd + 1, &rfds, NULL, NULL, NULL);
		if(n < 0) {
			perror("select() error!");
			close(cltfd);
			close(fd);
			return -1;
		}

		if(FD_ISSET(fd, &rfds)) {
			memset(sendin, 0, BUFF_SIZE);
			memset(sendout, 0, BUFF_SIZE);
			n = read(fd, sendin, BUFF_SIZE);
			sendin[n] = '\0';
			printf("The size recv from serial port: %d\n", n);
			printf("Recv data:");
			for(i = 0; i < n; i ++)
			{
				printf("%3.2x", sendin[i]);
			}
			printf("\n");

			m = analysis_data(sendin, sendout, n);	//解包
			n = sendto(cltfd, sendout, m, 0, (struct sockaddr *) &mm, len);
			if(n < 0) {
				perror("send data error");
				close(cltfd);
				return -1;
			}
		}
		
		if(FD_ISSET(cltfd, &rfds)) {
			memset(recvin, 0, BUFF_SIZE);
			memset(recvout, 0, BUFF_SIZE);
			n = recvfrom(cltfd, recvin, BUFF_SIZE, 0, (struct sockaddr *)&mm, &len);
			if(n < 0) {
				perror("recv data error");
				close(cltfd);
				return -1;
			}
			printf("recv from tcp: %d, %s\n", n, recvin);

			m = package_data(recvin, recvout, n);	//封包
			write(fd, recvout, m);
		}
	}

	close(cltfd);
	close(fd);

	return 0;
}

int main(int argc, char *argv[])
{
	if(argc < 2)
	{
		printf("%s params are less than 2\n", argv[0]);
		return -1;
	}

	if(!strcmp("tcp", argv[1]))
	{
		tcp_client_handler();
	}
	else if(!strcmp("udp", argv[1]))
	{
		udp_client_handler();
	}
	else
	{
		printf("Invalid params with %s, please input <tcp> or <udp>\n", argv[1]);
		return -1;
	}

	return 0;
}



