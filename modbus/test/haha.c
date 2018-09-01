#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if 0
void HexToStr(unsigned char *des, unsigned char *src, int len)
{
	char low, high;
	int i;

	for (i = 0; i < len; i++)
	{
		high = 48 + src[i] / 16;
		low = 48 + src[i] % 16;
		if (high > 57) 
			high += 7;
		if (low > 57)
			low += 7;
		
		des[i*2] = high;
		des[i*2+1] = low;
	}

	des[len*2] = '\0';
}
#else
void HexToStr(const char *idata, unsigned char *odata, int len)
{
	int i;

	for (i = 0; i < len; i++)
	{
		sprintf(odata + i*3, "%02x ", idata[i]);
	}
}
#endif

void func(unsigned char *buf, int len)
{
	unsigned char str[1024] = {0};

	HexToStr(buf, str, len);

	printf("%s-------------------%d\n", __FUNCTION__, __LINE__);
	printf("%s\n", str);
}

int main()
{
	unsigned char ibuf[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0D, 0x0F, 0x11};
	unsigned char obuf[1024] = {0};

	//HexToStr(obuf, ibuf, 9);
	//printf("%s\n", obuf);

	func(ibuf, 9);

	//HexToStr(ibuf, obuf, 9);
	//printf("%s\n", obuf);
}




















