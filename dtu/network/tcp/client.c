#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>

#define PORT 51061 
#define MAX_COMMAND 4

int main()
{
	int fd;
	socklen_t len;
	struct sockaddr_in srv;
	char tmp_buff[1024];
	char sendbuff[1024];
	char recvbuff[1024];
	int i,n;
	char *buff[MAX_COMMAND] = {"stop", "test", "exit", "quit"};
	struct timeval tv;

	tv.tv_sec = 5;
	tv.tv_usec = 0;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if(fd < 0) {
		perror("create socket error!");
		return 0;
	} else {
		printf("Success to create socket %d\n", fd);
	}

	bzero(&srv, sizeof(srv));		//initialize memory of the struct
	srv.sin_family = AF_INET;
	srv.sin_port = htons(PORT);
	srv.sin_addr.s_addr = htons(INADDR_ANY);
	bzero(&(srv.sin_zero), 8);

	len = sizeof(srv);	
	if(connect(fd, (struct sockaddr *)&srv, len) < 0) {
		perror("Connect error!");
		close(fd);
		return 1;
	} else {
		printf("Success connect to server!\n");
	}
#if 0
	for(i = 0; i < MAX_COMMAND; i++) {
		send(fd, buff[i], 1024, 0);
		n = recv(fd, tmp_buff, 1024, 0);
		tmp_buff[n] = '\0';
		printf("send = %s, receive = %s\n", buff[i], tmp_buff);

		if(strncmp(tmp_buff, "quit", 4) == 0)
			break;
	}
#else

	fd_set rfds;

	while(1) {
		FD_ZERO(&rfds);
		FD_SET(0, &rfds);
		FD_SET(fd, &rfds);

		n = select(fd + 1, &rfds, NULL, NULL, &tv);
		if(n == -1) {
			perror("select() error!");
			close(fd);
			return 1;
		}
		else if(n == 0)
		{
			printf("client time out\n");
			sleep(3);
		}
		else
		{
			if(FD_ISSET(fd, &rfds)) {
				memset(recvbuff, 0, 1024);
				n = recv(fd, recvbuff, 1024, 0);
				if(n < 0) {
					perror("recv() error!");
					close(fd);
					return 1;
				}
				printf("server: %s", recvbuff);			
			}
		
			if(FD_ISSET(0, &rfds)) {
				memset(sendbuff, 0, 1024);
				read(1, sendbuff, 1024);
				n = send(fd, sendbuff, strlen(sendbuff), 0);
				if(n < 0) {
					perror("send() error!");
					close(fd);
					return 1;
				}
			}
		}
	}
#endif
	close(fd);

	return 0;
} 

