#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <termios.h>
#include <errno.h>

#define STTY_DEV "/dev/ttyS0"
#define BUFF_SIZE 1024

int setOption(int fd)
{
	struct termios opt;

	tcgetattr(fd, &opt);
	tcflush(fd, TCIOFLUSH);

	cfsetispeed(&opt, B115200);
	cfsetospeed(&opt, B115200);

	opt.c_cflag &= ~CSIZE;
	opt.c_cflag |= CS8;

	opt.c_cflag &= ~PARENB;
	opt.c_iflag &= ~INPCK;

	opt.c_cflag &= ~CSTOPB;

	if(tcsetattr(fd, TCSANOW, &opt) != 0) {
		perror("set error");
		return 1;
	}

	tcflush(fd, TCIOFLUSH);

	return 0;
}

int main()
{
	int fd, n;
	char buff[BUFF_SIZE];

//	fd = open(STTY_DEV, O_RDWR | O_NOCTTY);
	fd = open(STTY_DEV, O_RDWR);
	if(fd < 0) {
		perror("open fail");
		return 1;
	}

	printf("Open %s success!\n", STTY_DEV);
	printf("waiting for data...\n");

	if(setOption(fd) != 0) {
		perror("set fail");
		close(fd);
		return 1;
	}

	while(1) {
		tcflush(fd, TCIOFLUSH);
		memset(buff, 0, BUFF_SIZE);
		n = read(fd, buff, BUFF_SIZE);
		if(n < 0) {
			perror("read fail");
			return 1;
		}
		buff[n] = '\0';

		printf("recv from serial port: %s\n", buff);
		if(!strncmp(buff, "quit", 4)) {
			printf("program will exit\n");
			break;
		}
	}

	close(fd);

	return 0;
}











