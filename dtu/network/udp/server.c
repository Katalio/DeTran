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
	struct sockaddr_in local;
	struct sockaddr_in from;
	socklen_t len;
	int n;
	char buff[1024];
	time_t cur_time;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd < 0) {
		perror("Create socket error!");
		return 1;
	}
	printf("Create socket successfully\n");

	local.sin_family = AF_INET;
	local.sin_port = htons(PORT);
	local.sin_addr.s_addr = INADDR_ANY;

	if(bind(fd, (struct sockaddr *) &local, sizeof(local)) != 0) {
		perror("bind() error!");
		close(fd);
		return 1;
	}
	printf("bind successfully\n");
	printf("waiting...\n");

	len = sizeof(from);
	
	while(1) {
		n = recvfrom(fd , buff, sizeof(buff), 0, (struct sockaddr *)&from, &len);
		if(n <= 0) {
			perror("recv data error!");
			close(fd);
			return 1;
		}

		buff[n] = '\0';
		printf("client request: %s\n", buff);

		if(strncmp(buff, "quit", 4) == 0)
			break;

		if(strncmp(buff, "time", 4) == 0) {
			cur_time = time(NULL);
			strcpy(buff, asctime(gmtime(&cur_time)));
			sendto(fd, buff, sizeof(buff), 0, (struct sockaddr *) &from, len);
		}
	}

	close(fd);
	return 0;
}


