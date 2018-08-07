#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <termios.h>
#include <errno.h>
#include <iconv.h>

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
	iconv_t cd;
	char buff[BUFF_SIZE];

	char phone[20] = "+8613550047244";
	char sms_number[20] = "+8617666100723";
	char sms_gb2312[100] = "Innocence";	
	char sms_utf8[100];
	char *sms_in = sms_gb2312;
	char *sms_out = sms_utf8;
	int len, i, tmp;
	size_t gb2312_len, utf8_len;

	fd = open(STTY_DEV, O_RDWR);
	if(fd < 0) {
		perror("open fail");
		return 1;
	}

	printf("Open device success!\n");

	if(setOption(fd) != 0) {
		perror("set fail");
		close(fd);
		return 1;
	}

	if(phone[0] == '+') {
		for(i = 0; i < strlen(phone) - 1; i ++)
			phone[i] = phone[i+1];
	}
	phone[i] = '\0';

	len = strlen(phone);
	if((len % 2) != 0) {
		phone[len] = 'F';
		phone[len+1] = '\0';
	}

	len = strlen(phone);
	for(i = 0; i < len; i += 2) {
		tmp = phone[i];
		phone[i] = phone[i+1];
		phone[i+1] = tmp;
	}

	if(sms_number[0] == '+') {
		for(i = 0; i < strlen(sms_number) - 1; i ++)
			sms_number[i] = sms_number[i+1];
	}

	len = strlen(sms_number);
	if((len % 2) != 0) {
		sms_number[len] = 'F';
		sms_number[len+1] = '\0';
	}

	len = strlen(sms_number);
	for(i = 0; i < len; i += 2) {
		tmp = sms_number[i];
		sms_number[i] = sms_number[i+1];
		sms_number[i+1] = tmp;
	}

	len = strlen(sms_number);
	for(i = len+2; i > 0; i --) 
		sms_number[i] = sms_number[i-2];
	sms_number[len+3] = '\0';

	strncpy(sms_number, "91", 2);

	n = strlen(sms_number) / 2;
	
	len = strlen(sms_number);
	for(i = len+2; i > 0; i --) 
		sms_number[i] = sms_number[i-2];
	sms_number[len+3] = '\0';
	
	sms_number[0] = (char)(n/10) + 48;
	sms_number[1] = (char)(n%10) + 48;

	cd = iconv_open("utf-8", "gb2312");
	if(cd == 0) {
		perror("create iconv handle");
		close(fd);
		return 1;
	}

	gb2312_len = strlen(sms_gb2312);
	utf8_len = 100;

	n = iconv(cd, &sms_in, &gb2312_len, &sms_out, &utf8_len);
	if(n < 0) {
		perror("convert code");
		close(fd);
		return 1;
	}	

	iconv_close(cd);

	strcpy(buff, "AT+CMGF=0\n");
	write(fd, buff, strlen(buff));

	n = read(fd, buff, BUFF_SIZE);
	if(n < 0) {
		perror("set pdu mode error");
		close(fd);
		return 1;
	}

	if(strncmp(buff, "OK", 2) != 0) {
		perror("set pdu mode error");
		close(fd);
		return 1;
	}

	sprintf(buff, "AT+CMGS=%d\n", utf8_len);
	write(fd, buff, strlen(buff));
	write(fd, sms_utf8, utf8_len);

	printf("send message OK!\n");

	close(fd);

	return 0;
}

