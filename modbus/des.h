#include <string.h>
#include <stdio.h>

#ifndef	_DES_INC
#define	_DES_INC

enum    {DES_ENCRYPT, DES_DECRYPT};

//// 加/解密 Type—ENCRYPT:加密,DECRYPT:解密
void des_run(char Out[8], char In[8], char Type);
//// 设置密钥
void des_set_key(const char Key[8]);

#endif	//end of _DES_INC

