#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>

#define PORT 51061 
#define MAX_CLIENT_NUM 10

int main()
{
	int srvfd;
	int clientfd;
	socklen_t len;
	struct sockaddr_in srv;
	struct sockaddr_in clt;
	char recvbuff[1024];
	char sendbuff[1024];
	int n;
	struct timeval tv;

	tv.tv_sec = 5;
	tv.tv_usec = 0;

	srvfd = socket(AF_INET, SOCK_STREAM, 0);
	if(srvfd < 0) {
		perror("create socket error!");
		return 1;
	} else {
		printf("Success to create socket %d\n", srvfd);
	}

	bzero(&srv, sizeof(srv));		//initialize memory of the struct
	srv.sin_family = AF_INET;
	srv.sin_port = htons(PORT);
	srv.sin_addr.s_addr = htons(INADDR_ANY);
	bzero(&(srv.sin_zero), 8);

	if(bind(srvfd, (struct sockaddr *) &srv, sizeof(srv)) != 0) {
		printf("bind address fail! %d\n", errno);
		close(srvfd);
		return 1;
	} else {
		printf("Success to bind address!\n");
	}

	if(listen(srvfd, MAX_CLIENT_NUM) != 0) {
		perror("listen socket error!");
		close(srvfd);
		return 1;
	} else {
		printf("Success to listen!\n");
	}

	len = sizeof(clt);
	clientfd = accept(srvfd, (struct sockaddr *)&clt, &len);
	if(clientfd < 0) {
		perror("accept error!");
		close(srvfd);
		return 1;
	} 
#if 0
	while((n = recv(clientfd, buff, 1024, 0)) > 0) {
		buff[n] = '\0';
		printf("number of receive bytes = %d\n", n);
		printf("data = %s\n", buff);

		fflush(stdout);
		send(clientfd, buff, n, 0);
		if(strncmp(buff, "qiut", 4) == 0)
			break;
	}
#else
	fd_set rfds;

	while(1) {
		FD_ZERO(&rfds);
		FD_SET(0, &rfds);
		FD_SET(clientfd, &rfds);

		n = select(clientfd + 1, &rfds, NULL, NULL, &tv);
		if(n == -1) {
			perror("select() error!");
			close(clientfd);
			return 1;
		}
		else if(n == 0)
		{
			printf("server time out\n");
			sleep(3);
		}
		else
		{
			if(FD_ISSET(0, &rfds)) {
				memset(sendbuff, 0, 1024);
				read(1, sendbuff, 1024);
				n = send(clientfd, sendbuff, strlen(sendbuff), 0);
				if(n < 0) {
					perror("send() error!");
					close(clientfd);
					return 1;
				}
			}
			
			if(FD_ISSET(clientfd, &rfds)) {
				memset(recvbuff, 0, 1024);
				n = recv(clientfd, recvbuff, 1024, 0);
				if(n < 0) {
					perror("recv() error!");
					close(clientfd);
					return 1;
				}
				printf("client: %s\n", recvbuff);			
				send(clientfd, "e=>'0'|u=>'1,0,1,300'", strlen("e=>'0'|u=>'1,0,1,300'"), 0);
			}
		}
	}

#endif
	close(clientfd);
	close(srvfd);

	return 0;
}

