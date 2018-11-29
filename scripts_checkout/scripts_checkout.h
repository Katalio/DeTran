#ifndef _SCRIPTS_CHECKOUT_H_
#define _SCRIPTS_CHECKOUT_H_

#define offsetof(TYPE,MEMBER)   ((size_t) &((TYPE *)0)->MEMBER)
#define container_of(PTR,TYPE,MEMBER)    ({  \
    const typeof(((TYPE *)0)->MEMBER) *__mptr=(PTR);  \
    (TYPE *) ((char *)__mptr - offsetof(TYPE,MEMBER)); })

#define MAX_SCRIPTS_LENGTH (6 * 1024 - 2)

#define ERROR_MSG_LENGTH 1024

#define AI_REGISTER_NUM	12
#define DI_REGISTER_NUM 16
#define MAX_REGISTER_NUM 65535

#define ERROR_NUM 128 
#define PARAMS_TOTAL_NUM 512
#define LINE_SIZE 1024

/* error codes */
typedef enum
{
	ERR_SCRIPTS_OVERSIZE = (1 << 0),	//脚本总长度超过了6K-2个字节
	ERR_REG_OUTBOUNDS = (1 << 1),	//包括AI(12)、DI(16)、RTU可用的总的寄存器(65535)三种
	ERR_CMD_INVALID = (1 << 2),	//检查指令是否合法
	ERR_VARTYPE_INVALID = (1 << 3),	//检查变量类型是否合法
	ERR_FORMAT = (1 << 4),	//检查指令格式
	ERR_PARAM_UNDEFINED = (1 << 5),	//参数未定义
	ERR_DEFVAR_CONFLICTING = (1 << 6),	//参数重复定义
	ERR_DEFVAR_PREVERSION = (1 << 7),	//指令执行后还有变量定义
	ERR_DEFVAR_CONFUSING = (1 << 8),	//变量错误定义
	ERR_VARTYPE_CONFUSING = (1 << 9),	//变量和值不匹配
	ERR_PARAM_EXCESS = (1 << 10),	//初始化或访问数组越界
	ERR_THRESH = (1 << 11),	//主要针对SET_THV
	ERR_SERIAL_RDREG = (1 << 12),	//v20指令和modbus指令读取的寄存器个数不匹配
	ERR_IFCMD_EXCESS = (1 << 13),	//只针对IF语句，IF嵌套超过3个
	ERR_IFCMD_NO_MATCH = (1 << 14),	//指令不匹配，针对IF ENDIF组合
	ERR_NO_CTRL_OUTPUT = (1 << 15)
} script_syntax_error_code;

typedef struct
{
	unsigned int linenum;
	/* error code */
	script_syntax_error_code error_code;
	/* meaning of error code */
	char error_msg[ERROR_MSG_LENGTH];
} script_syntax_error_info;

typedef struct
{
	char var_name[32];
	char var_type[2];
	unsigned int var_count;	//对于数组来说可能有多个值
} params_defined_info;

/* functions */
/*
 *功能：检测脚本的语法错误
 *输入：脚本文件
 *返回值：错误代码
 */
int scripts_checkout(const char *scripts);

#endif	/* _SCRIPTS_CHECKOUT_H_ */
