#include <string.h>
#include <stdio.h>

#ifndef	_DES_INC
#define	_DES_INC

enum    {DES_ENCRYPT, DES_DECRYPT};

//// ��/���� Type��ENCRYPT:����,DECRYPT:����
void des_run(char Out[8], char In[8], char Type);
//// ������Կ
void des_set_key(const char Key[8]);

#endif	//end of _DES_INC

