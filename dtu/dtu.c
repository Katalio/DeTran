#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <termios.h>
#include <string.h>
#include <error.h>

#define PORT 8080 
#define DEVICE "/dev/ttyS0"
#define BUFF_SIZE 2048 
#define MAX_CLIENT_NUM 10

/* init serial port and return the fd */
static int serial_port_init(void);

/* choose to be server or client */
static void trans_data_with_tcp(char *);
static void trans_data_with_udp(char *);

static int tcp_server_handler(void);
static int tcp_client_handler(void);
static int udp_server_handler(void);
static int udp_client_handler(void);

static int serial_port_init(void)
{
	int fd;
	struct termios tms;

	fd = open(DEVICE, O_RDWR);
	if(fd < 0) {
		perror("Opne device fail!");
		return -1;
	}
	
	printf("Open %s successfully\n", DEVICE);

	tcgetattr(fd, &tms);
	tcflush(fd, TCIOFLUSH);

	/* set baud rate */
	cfsetispeed(&tms, B115200);
	cfsetospeed(&tms, B115200);

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

static void trans_data_with_tcp(char *ends_mode)
{
	if(!strcmp("server", ends_mode))
	{
		tcp_server_handler();
	}
	else if(!strcmp("client", ends_mode))
	{
		tcp_client_handler();
	}
	else
	{
		printf("Invalid params with %s, please input <server> or <client>\n", ends_mode);
	}
}

static void trans_data_with_udp(char *ends_mode)
{
	if(!strcmp("server", ends_mode))
	{
		udp_server_handler();
	}
	else if(!strcmp("client", ends_mode))
	{
		udp_client_handler();
	}
	else
	{
		printf("Invalid params with %s, please input <server> or <client>\n", ends_mode);
	}
}

static int tcp_server_handler(void)
{
	int svrfd;
	int cltfd;
	int maxfd;
	socklen_t len;
	struct sockaddr_in svr;
	struct sockaddr_in clt;
	char recvbuff[BUFF_SIZE];
	char sendbuff[BUFF_SIZE];
	int n;

	svrfd = socket(AF_INET, SOCK_STREAM, 0);
	if(svrfd < 0) {
		perror("create socket error!");
		return -1;
	} else {
		printf("Success to create socket %d\n", svrfd);
	}

	bzero(&svr, sizeof(svr));		//initialize memory of the struct
	svr.sin_family = AF_INET;
	svr.sin_port = htons(PORT);
	svr.sin_addr.s_addr = htonl(INADDR_ANY);
	bzero(&(svr.sin_zero), 8);

	if(bind(svrfd, (struct sockaddr *) &svr, sizeof(svr)) != 0) {
		printf("bind address fail!\n");
		close(svrfd);
		return -1;
	} else {
		printf("success to bind address!\n");
	}

	if(listen(svrfd, MAX_CLIENT_NUM) != 0) {
		perror("listen socket error!");
		close(svrfd);
		return -1;
	} else {
		printf("listening...\n");
	}

	len = sizeof(clt);
	cltfd = accept(svrfd, (struct sockaddr *)&clt, &len);
	if(cltfd < 0) {
		perror("accept error!");
		close(svrfd);
		return -1;
	} else {
		printf("success to create an new socket for communication!\n");	
	} 
	
	fd_set rfds;

	int fd = serial_port_init();

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
		
		if(FD_ISSET(fd, &rfds)) {	//串口获取到数据并发送到网口?有问题
			memset(sendbuff, 0, BUFF_SIZE);
			n = read(fd, sendbuff, BUFF_SIZE);
			sendbuff[n] = '\0';
			printf("recv from serial port:length is %d, %s", n, sendbuff);
			n = send(cltfd, sendbuff, n, 0);
			if(n < 0) {
				perror("send() error!");
				close(cltfd);
				return -1;
			}
		}
		
		if(FD_ISSET(cltfd, &rfds)) {	//网口获取到数据并发送到串口
			memset(recvbuff, 0, BUFF_SIZE);
			n = recv(cltfd, recvbuff, BUFF_SIZE, 0);
			if(n < 0) {
				perror("recv() error!");
				close(cltfd);
				return -1;
			}

			write(fd, recvbuff, n);
			printf("recv from TCP/UDP:%s\n", recvbuff);
			printf("\n");
		}
	}

	close(cltfd);
	close(svrfd);
	close(fd);

	return 0;
}

static int tcp_client_handler(void)
{
	int cltfd;
	int maxfd;
	socklen_t len;
	struct sockaddr_in svr;
	char tmp_buff[BUFF_SIZE];
	char sendbuff[BUFF_SIZE];
	char recvbuff[BUFF_SIZE];
	int n;

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

		if(FD_ISSET(cltfd, &rfds)) {
			memset(recvbuff, 0, BUFF_SIZE);
			n = recv(cltfd, recvbuff, BUFF_SIZE, 0);
			if(n < 0) {
				perror("recv() error!");
				close(cltfd);
				return -1;
			}
			write(fd, recvbuff, n);
		}
	
		if(FD_ISSET(fd, &rfds)) {	//串口获取到数据并发送到网口
			memset(sendbuff, 0, BUFF_SIZE);
			n = read(fd, sendbuff, BUFF_SIZE);
			sendbuff[n] = '\0';
			printf("recv from serial port:length is %d, %s", n, sendbuff);
			n = send(cltfd, sendbuff, n, 0);
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

static int udp_server_handler(void)
{
	int svrfd;
	int maxfd;
	struct sockaddr_in svr;
	struct sockaddr_in clt;
	socklen_t len;
	int n, m;
	char sendbuff[BUFF_SIZE];
	char recvbuff[BUFF_SIZE];

	svrfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(svrfd < 0) {
		perror("create socket error!");
		return -1;
	}
	printf("create socket successfully!\n");

	svr.sin_family = AF_INET;
	svr.sin_port = htons(PORT);
	svr.sin_addr.s_addr = htonl(INADDR_ANY);

	if(bind(svrfd, (struct sockaddr *) &svr, sizeof(svr)) != 0) {
		perror("bind() error!");
		close(svrfd);
		return -1;
	}
	printf("bind successfully!\n");
	printf("waiting...\n");

	len = sizeof(clt);
	int fd = serial_port_init();	

	fd_set rfds;

	while(1) {
		FD_ZERO(&rfds);
		FD_SET(0, &rfds);
		FD_SET(svrfd, &rfds);
		FD_SET(fd, &rfds);

		maxfd = (svrfd > fd) ? svrfd : fd;
		n = select(maxfd + 1, &rfds, NULL, NULL, NULL);
		if(n < 0) {
			perror("select() error!");
			close(svrfd);
			close(fd);
			return -1;
		}

		if(FD_ISSET(svrfd, &rfds)) {
			n = recvfrom(svrfd , recvbuff, BUFF_SIZE, 0, (struct sockaddr *)&clt, &len);
			if(n <= 0) {
				perror("recv data error!");
				close(svrfd);
				return -1;
			}

			recvbuff[n] = '\0';
			write(fd, recvbuff, n);
		}
	
		if(FD_ISSET(fd, &rfds)) {	//串口获取到数据并发送到网口
			memset(sendbuff, 0, BUFF_SIZE);
			n = read(fd, sendbuff, BUFF_SIZE); 
			sendbuff[n] = '\0';
			printf("recv from serial port:length is %d, %s", n, sendbuff);
			m = sendto(svrfd, sendbuff, strlen(sendbuff), 0, (struct sockaddr *) &clt, len);
			if(m < 0) {
				perror("send data error!");
				close(svrfd);
				return -1;
			}
		}
	}

	close(svrfd);
	close(fd);

	return 0;
}

static int udp_client_handler(void)
{
	int cltfd;
	int maxfd;
	int n;
	char sendbuff[BUFF_SIZE];
	char recvbuff[BUFF_SIZE];
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
			memset(sendbuff, 0, BUFF_SIZE);
			n = read(fd, sendbuff, BUFF_SIZE);
			sendbuff[n] = '\0';
			printf("recv from serial port:length is %d, %s", n, sendbuff);
			n = sendto(cltfd, sendbuff, strlen(sendbuff), 0, (struct sockaddr *) &mm, len);
			if(n <= 0) {
				perror("send data error");
				close(cltfd);
				return -1;
			}
		}
		
		if(FD_ISSET(cltfd, &rfds)) {
			memset(recvbuff, 0, BUFF_SIZE);
			n = recvfrom(cltfd, recvbuff, BUFF_SIZE, 0, (struct sockaddr *)&mm, &len);
			if(n <= 0) {
				perror("recv data error");
				close(cltfd);
				return -1;
			}
			write(fd, recvbuff, n);
		}
	}

	close(cltfd);
	close(fd);

	return 0;
}

int main(int argc, char *argv[])
{
	if(argc < 3)
	{
		printf("%s params are less than 3\n", argv[0]);
		return -1;
	}

	if(!strcmp("tcp", argv[1]))
	{
		trans_data_with_tcp(argv[2]);
	}
	else if(!strcmp("udp", argv[1]))
	{
		trans_data_with_udp(argv[2]);
	}
	else
	{
		printf("Invalid params with %s, please input <tcp> or <udp>\n", argv[1]);
		return -1;
	}

	return 0;
}



