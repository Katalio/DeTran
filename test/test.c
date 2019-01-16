#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int func(char* buf)
{
	memset(buf, 0, sizeof(buf));
	memcpy(buf, "worldhahahah", 1024);

	return strlen(buf);
}

int main()
{
	char dataBuf[1024];
	char *p;
	long n;

	printf("%ld, %s\n", strlen(dataBuf), dataBuf);

	n = func(dataBuf);

	p = dataBuf;

	printf("%ld\n", n);
	printf("%s\n", p);
	printf("%s\n", dataBuf);
}
