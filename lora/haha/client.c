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

int main(int argc, char **argv)
{
	if(argc != 2)
	{
		printf("Params are not equal to 2\n");
		return -1;
	}
	
	int fd;
	FILE *fp;
	int offset = 0;
	struct sockaddr_in srv;
	char sendbuff[1024];
	int n, m;

	fp = fopen(argv[1], "r+");
	if (NULL == fp)
	{
		printf("Open %s fail\n", argv[1]);
	}

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

	if(connect(fd, (struct sockaddr *)&srv, sizeof(srv)) < 0) {
		perror("Connect error!");
		close(fd);
		return -1;
	} else {
		printf("Success connect to server!\n");
	}

	fseek(fp, 0, SEEK_SET);
	while(!feof(fp))
	{
		memset(sendbuff, 0, 1024);
		fseek(fp, offset, SEEK_SET);
		m = fread(sendbuff, 1, 1024, fp);
		if(m > 0)
		{
			n = send(fd, sendbuff, m, 0);
			if(n < 0) {
				perror("send() error!");
				close(fd);
				return -1;
			}

			offset += m;
		}
	}

	send(fd, "quit", 4, 0);

	fclose(fp);
	close(fd);

	return 0;
} 


