#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 51061 

int main()
{
	int srvfd;
	int clientfd;
	FILE *fp;
	socklen_t len;
	struct sockaddr_in srv;
	struct sockaddr_in clt;
	char recvbuff[1024];
	int n;

	srvfd = socket(AF_INET, SOCK_STREAM, 0);
	if(srvfd < 0) {
		perror("create socket error!");
		return 1;
	} else {
		printf("Success to create socket %d\n", srvfd);
	}

	fp = fopen("txt", "a+");
	bzero(&srv, sizeof(srv));		//initialize memory of the struct
	srv.sin_family = AF_INET;
	srv.sin_port = htons(PORT);
	srv.sin_addr.s_addr = htons(INADDR_ANY);

	if(bind(srvfd, (struct sockaddr *) &srv, sizeof(srv)) != 0) {
		printf("bind address fail! %d\n", errno);
		close(srvfd);
		return 1;
	} else {
		printf("Success to bind address!\n");
	}

	if(listen(srvfd, 10) != 0) {
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

	while(1)
	{
		memset(recvbuff, 0, 1024);
		n = recv(clientfd, recvbuff, 1024, 0);
		if(n > 0) {
			if (!strncmp(recvbuff, "quit", 4))
				break;

			fwrite(recvbuff, 1, n, fp);
		}
	}

	fclose(fp);
	close(clientfd);
	close(srvfd);

	return 0;
}

