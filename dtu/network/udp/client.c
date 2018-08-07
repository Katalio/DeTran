#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <errno.h>

#define PORT 9527

int main()
{
	int fd;
	int n;
	char buff[1024];
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

	len = sizeof(mm);

	strcpy(buff, "time");
	n = sendto(fd, buff, sizeof(buff), 0, (struct sockaddr *) &mm, len);
	if(n <= 0) {
		perror("send data error");
		close(fd);
		return 1;
	}

	printf("send time request\n");

	n = recvfrom(fd, buff, sizeof(buff), 0, (struct sockaddr *)&mm, &len);
	if(n <= 0) {
		perror("recv data error");
		close(fd);
		return 1;
	}

	buff[n] = '\0';
	printf("time is: %s", buff);

	strcpy(buff, "quit");
	n = sendto(fd, buff, sizeof(buff), 0, (struct sockaddr *) &mm, len);
	if(n <= 0) {
		perror("send data error");
		close(fd);
		return 1;
	}
	printf("send quit command\n");

	close(fd);
	return 0;
}

