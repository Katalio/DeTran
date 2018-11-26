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

/* valid commands */
const char *script_cmds[] =
{
	"VAR",	//定义单个变量
	"VARS",	//定义数组变量
	"INTF",	//定义单个变量，同时给定寄存器地址
	"INTFS",	//定义数组变量，同时给定寄存器首地址
	"SET_THV",	//对变量设置阈值，触发上报
	"CTRL",	//定义由平台控制的单个变量，向本机DO输出
	"CTRLS",	//定义由平台控制的数组变量，向本机DO输出
	"UCTRL",	//定义由平台控制的单个变量，向串口发送控制输出
	"UCTRLS",	//定义由平台控制的数组变量，向串口发送控制输出
	"SET_ADDR",	
	"CAL",	//用于计算，结果为浮点数
	"IN_D",	//读取本机DI量，可连续读取
	"IN_UD",	//通过串口读取DI量，一般是485或232，可连续读取
	"IN_UD_B",	//同上
	"IN_A",	//读取本机AI量，可连续读取
	"IN_AE",	//读取AI量，并将其转换成电流值
	"IN_ACAE",	//读取交流电电流
	"IN_ATEMP",	//读取芯片温度
	"IN_AMVOL",	//读取主电源电压
	"IN_ABVOL",	//读取电池电压
	"IN_UA",	//通过串口读取AI量，一般是485或232，可连续读取
	"IN_UA_B",	//同上
	"IN_UF_B",	//同IN_UA，但1个变量对应2个寄存器
	"IN_UFD_B",	//同IN_UA，但1个变量对应4个寄存器
	"OUT_D",	//向本机DI输出控制
	"OUT_U",	//向串口发送输出控制
	"DO_CTRL",	//用于执行CTRL/CTRLS/UCTRL/UCTRLS输出变量的输出控制
	"IF",	
	"ELSE",
	"ENDIF",
	"SLEEP",
	"CONTINUE",
	NULL
};

/* valid data type--
 * B:无符号单字节整形
 * W:无符号双字节整形
 * L:有符号四字节整形
 * U:无符号四字节整形
 * F:四字节浮点数 */
const char *scripts_vartype[] = {"B", "W", "L", "U", "F", NULL};

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
/*
 *功能：输出错误信息
 */
void show_errMsg(void);
#endif	/* _SCRIPTS_CHECKOUT_H_ */
