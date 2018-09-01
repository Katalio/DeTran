//#ifndef _MD5_H_066A0C4C-8D5C-4698-8AF8-421A1CA8442C
//#define _MD5_H_066A0C4C-8D5C-4698-8AF8-421A1CA8442C

#ifndef	_MD5_INC
#define	_MD5_INC

#define MD5 5

#ifndef MD
  #define MD MD5
#endif

#ifndef PROTOTYPES
  #define PROTOTYPES 1
#endif

typedef unsigned char*          PUCHAR;
typedef unsigned short int      UINT2;
typedef unsigned int            UINT4;
typedef unsigned char           UCHAR;

#if PROTOTYPES
  #define PROTO_LIST(list) list
#else
  #define PROTO_LIST(list) ()
#endif

typedef struct
{
  UINT4 state[4];
  UINT4 count[2];
  UCHAR buffer[64];
} MD5_CTX;

void MD5Init PROTO_LIST ((MD5_CTX* Md5_ctx));
void MD5Update PROTO_LIST ((MD5_CTX* Md5_ctx, PUCHAR Input, UINT4 Legth));
void MD5Final PROTO_LIST ((UCHAR Digest[16], MD5_CTX* Md5_ctx));

//#ifdef MD5_BCB5
#include <stdio.h>
#include<string.h>

//非多线程安全
//char * md5_code_string(unsigned char *input);
char * md5_code_string(unsigned char *input, int Len, char *Result);

//获取文件MD5, md5为输出参数，至少33字节大小
int get_file_md5(const char *filename, char *md5);
//#endif

//#endif

#endif		//end  of _MD5_INC
