
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/reboot.h>
#include <stdint.h>
#include <syslog.h>
#include <ctype.h>
#include <errno.h>

#include "scripts_checkout.h"

#define ERROR_NUM 64
#define PARAMS_TOTAL_NUM 512
#define LINE_SIZE 1024 

script_syntax_error_info err_infolist[ERROR_NUM] = {0};	//每个错误(错误码可重复)对应一个struct类型的信息
params_defined_info params_definfo[PARAMS_TOTAL_NUM] = {0};	//已定义的参数及其类型
char cmd_info[1024][16];
int regAddr_info[1024];

unsigned int DEFINED_COUNT= 0;	//已定义参数的个数
unsigned int LINENUM = 1;	//用于记录错误行号(当前行号)
unsigned int err_tail = 0;	//最后一个错误信息结构体位置的下一位,便于写入下一条错误信息
char error_msg_buf[ERROR_MSG_LENGTH];	//错误具体提示信息

#define vstrsep(buf, sep, args...) _vstrsep(buf, sep, args, NULL)

int _vstrsep(char *buf, const char *sep, ...)	//变参为char **型
{
	va_list ap;
	char **p, *k;
	int n = 0;

	va_start(ap, sep);
	while((p = va_arg(ap, char **)) != NULL)
	{
loop:	k = strsep(&buf, sep);
		if(k == NULL || *k == '\n')
			break;

		if(strlen(k) == 0)
			goto loop;

		*p = k;
		++ n;
	}
	va_end(ap);

	return n;
}

int scripts_getline(char *line, const char *scripts)
{
	static int cur_index = 0;
	unsigned int whichline = 1;
	int index = 0;
	int i = 0;

	memset(line, 0, LINE_SIZE);

	//读取当前行
	while((scripts[cur_index] != '\n') && (scripts[cur_index] != '\0'))
	{
		line[i ++] = scripts[cur_index ++];
	}
	if(scripts[cur_index] == '\n')
		line[i] = scripts[cur_index];
	cur_index ++;	//cur_index++是为了指向'\n'的后一个字符，即下一行开头

	LINENUM ++;	//指向下一行

	//printf("line:%s, %ld\n", line, strlen(line));
	return strlen(line);
}

void add_cmd_to_cmdInfo(char *cmd)
{
	char (*p)[16] = cmd_info;	

//	printf("cmd before add:%s\n", cmd);
	while(strlen(*p) != 0)
	{
//		printf("*p:%s\n", *p);
		p ++;
	}

	strcpy(*p, cmd);
//	printf("add ok\n");
//	printf("#################\n");
}

void add_variable_to_defInfo(char *name, char *type, unsigned int count)
{
	strncpy(params_definfo[DEFINED_COUNT].var_name, name, 32);
	strncpy(params_definfo[DEFINED_COUNT].var_type, type, 1);
	params_definfo[DEFINED_COUNT].var_count = count;

	DEFINED_COUNT ++;
}

void set_Msg_to_errInfo(unsigned int linenum, script_syntax_error_code error_code, char *error_msg)
{
	err_infolist[err_tail].linenum = linenum - 1;	//LINENUM记录的是当前行的下一行
	err_infolist[err_tail].error_code = error_code;
	strncpy(err_infolist[err_tail].error_msg, error_msg, ERROR_MSG_LENGTH);

	err_tail ++;
}

void show_errMsg(void)
{
	int i;

	for(i = 0; err_infolist[i].linenum != 0; i++)
		printf("[Scripts error]:%s at %d line, ERROR_CODE[%d]\n", err_infolist[i].error_msg, err_infolist[i].linenum, err_infolist[i].error_code);
		//syslog(LOG_ERR, "[Scritps error]:%s at line %d, ERROR_CODE[%d]", err_infolist[i].error_msg, err_infolist[i].linenum, err_infolist[i].error_code);
}

char *get_cmd(char *cmd, char *line)
{
#if 0
	char *nv, *nvp, *p, *q;

	nvp = nv = strdup(line);
	
loop:
	p = strsep(&nvp, " (;	");
 
	if(p == NULL)
		return p;

	if(strlen(p) == 0)
	{
		goto loop;
	}

	q = strsep(&p, "\n");
	strcpy(cmd, q);

	free(nv);
#else
	char *cp, *cq;
	int i = 0, len = 0;

	cp = line;
	while((isspace((int) *cp) || *cp == '	') && (*cp != '\0'))
	{
		cp ++;
	}
	cq = cp;
	if(*cp != '\0')
	{
		while((!isspace((int) *cp) && (*cp != '(') && (*cp != '\r') && (*cp != '	') && (*cp != ';')) && (*cp != '\0'))
		{
			cp ++;
			len ++;
		}
		strncpy(cmd, cq, len);
	}
#endif

	return cmd;
}

int get_varname(char *var_name, char *buf)
{
	char *p, *q, *nv, *nvp, var_count[8] = {0};
	int i = 0, j = 0, count = 0;

	nv = nvp = strdup(buf);
	if(strchr(buf, '='))
	{
		p = strsep(&nvp, "=");

		if(q = strchr(buf, '['))
		{
			while((*(p + i) != ' ') && (*(p + i) != '[') && (*(p + i) != '\n') && (*(p + i) != 0))
			{
				var_name[i] = p[i];
				i ++;
			}

			for(i = 1; *(q + i) != ']'; i ++, j ++)
			{
				var_count[j] = q[i];
			}

			count = atoi(var_count);
		}
		else
		{
			while((*(p + i) != ' ') && (*(p + i) != '\n') && (*(p + i) != 0))
			{
				var_name[i] = p[i];
				i ++;
			}

			count = 1;
		}
	}
	else
	{
		p = strsep(&nvp, ";");

		if(q = strchr(buf, '['))
		{
			while((*(p + i) != ' ') && (*(p + i) != '[') && (*(p + i) != '\n') && (*(p + i) != 0))
			{
				var_name[i] = p[i];
				i ++;
			}

			for(i = 1; (*(q + i) != ']'); i ++, j ++)
			{
				var_count[j] = q[i];
			}

			count = atoi(var_count);
		}
		else
		{
			while((*(p + i) != ' ') && (*(p + i) != '\n') && (*(p + i) != 0))
			{
				var_name[i] = p[i];
				i ++;
			}

			count = 1;
		}
	}
	free(nv);

	return count;
}

int cmd_check(char *cmd)
{
	char **cmds_ptr = script_cmds;

	while(*cmds_ptr)
	{
		if(strcmp(*cmds_ptr, cmd) == 0)
		{
			//将指令加入指令集
			add_cmd_to_cmdInfo(cmd);
			return 1;
		}

		cmds_ptr ++;
	}

	memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
	snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid commamd '%s' for V20\"", cmd);
	set_Msg_to_errInfo(LINENUM, ERR_CMD_INVALID, error_msg_buf);

	return 0;
}

int vartype_check(char *type)
{
	char **vartype_ptr = scripts_vartype;

	while(*vartype_ptr)
	{
		if(strcmp(*vartype_ptr, type) == 0)
			return 1;

		vartype_ptr ++;
	}

	memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
	snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid variable type '%s' for V20\"", type);
	set_Msg_to_errInfo(LINENUM, ERR_VARTYPE_INVALID, error_msg_buf);

	return 0;
}

int aidi_type_check(char *var_name, char *var_type)
{
	int err_flag = 0;

	if(strcmp(var_name, "DI") == 0)
	{
		if(strncmp(var_type, "B", 1) != 0)
		{
			memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
			snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid variable type '%s' for 'DI'\"", var_type);
			set_Msg_to_errInfo(LINENUM, ERR_VARTYPE_CONFUSING, error_msg_buf);

			err_flag = 1;
		}
	}

	if(strcmp(var_name, "AI") == 0)
	{
		if(strncmp(var_type, "W", 1) != 0)
		{
			memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
			snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid variable type '%s' for 'AI'\"", var_type);
			set_Msg_to_errInfo(LINENUM, ERR_VARTYPE_CONFUSING, error_msg_buf);

			err_flag = 1;
		}
	}

	return err_flag;
}

int brackets_check(char *line)
{
	int len = strlen(line);
	int bracket_ls = 0, bracket_rs = 0;	//小括号
	int bracket_lm = 0, bracket_rm = 0;	//中括号
	int bracket_lb = 0, bracket_rb = 0;	//大括号
	int i;

	for(i = 0; i < len; i ++)
	{
		if(*(line + i) == '(')
			bracket_ls += 1;
		if(*(line + i) == ')')
			bracket_rs += 1;
		if(*(line + i) == '[')
			bracket_lm += 1;
		if(*(line + i) == ']')
			bracket_rm += 1;
		if(*(line + i) == '{')
			bracket_lb += 1;
		if(*(line + i) == '}')
			bracket_rb += 1;
	}

	if((bracket_ls != bracket_rs) || (bracket_lm != bracket_rm) || (bracket_lb != bracket_rb))
	{
		memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
		snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"unpaired brackets\"");
		set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);

		return 1;
	}

	return 0;
}

int aidi_reg_check(char *var_name, unsigned int var_count)
{
	int err_flag = 0;

	if(strcmp(var_name, "DI") == 0)
	{
		if(var_count > DI_REGISTER_NUM)
		{
			memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
			snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"registers beyond 16 for 'DI'\"");
			set_Msg_to_errInfo(LINENUM, ERR_REG_OUTBOUNDS, error_msg_buf);

			err_flag = 1;
		}
	}

	if(strcmp(var_name, "AI") == 0)
	{
		if(var_count > AI_REGISTER_NUM)
		{
			memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
			snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"registers beyond 12 for 'AI'\"");
			set_Msg_to_errInfo(LINENUM, ERR_REG_OUTBOUNDS, error_msg_buf);

			err_flag = 1;
		}
	}

	return err_flag;
}

int arr_format_check(char *line)
{
	int n, len;
	int i, j, error_code = 0;
	char *p, tmp[LINE_SIZE] = {0};

	p = strchr(line, '{');
	len = strlen(p);
	for(i = 0, j = 0; i < len; i ++)
	{
		if(*(p + i) != ' ')
			tmp[j++] = p[i];
	}

	for(i = 0; i < strlen(tmp) - 1; i ++)
	{
		if(((*(tmp + i) == ',') || (*(tmp + i) == '{')) && (*(tmp + i + 1) == ','))	
		{
			memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
			snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid format in array initializer\"");
			set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);

			return 1;
		}
	}

	return 0;
}

int arr_excess_check(char *line)
{
	int len;
	int i, n = 0;

	len = strlen(line);
	for(i = 0; i < len; i ++)
	{
		if(*(line + i) == ',')
			n += 1;
	}

	if(n == 0)
		return 0;
	else
		return (n + 1);
}

int endsymbol_check(char *line)
{
	char *p, *q = NULL, cmd[16] = {0};

	get_cmd(cmd, line);
	if(!strcmp(cmd, "IF") || !strcmp(cmd, "ELSE") || !strcmp(cmd, "ENDIF"))
	{
		p = strchr(line, '\n');
		q = strchr(line, ';');
	}
	else
	{
		p = strchr(line, ';');
	}

	if((p != NULL) && (q == NULL))
	{
		return 1;
	}
	else
	{
		if(q != NULL)
		{
			memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
			snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"unexpected ';' for '%s'\"", cmd);
			set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);
		}

		if(p == NULL)
		{
			memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
			if(!strcmp(cmd, "IF") || !strcmp(cmd, "ELSE") || !strcmp(cmd, "ENDIF"))
			{
				snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"expected '\\n' at the end\"");
			}
			else
			{
				snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"expected ';' at the end\"");
			}
			set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);
		}
	}

	return 0;
}

int regAddr_confdef_check(int addr)
{
	int i = 0;

	while(*(regAddr_info + i))
	{
		if(regAddr_info[i] == addr)
		{
			memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
			snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"'%d' has been used by others\"", addr);
			set_Msg_to_errInfo(LINENUM, ERR_REG_OUTBOUNDS, error_msg_buf);

			return 1;
		}

		i ++;
	}

	regAddr_info[i] = addr;

	return 0;
}

int params_confdef_check(char *name, char *type, unsigned int count)
{
	int i = 0;

	while(i < DEFINED_COUNT)
	{
		if(strcmp(params_definfo[i].var_name, name) == 0)
		{
			memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
			snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"conflicting types for '%s'\"", name);
			set_Msg_to_errInfo(LINENUM, ERR_DEFVAR_CONFLICTING, error_msg_buf);

			return 1;
		}

		i ++;
	}

	add_variable_to_defInfo(name, type, count);	//若没定义则加入参数定义数组中

	return 0;
}

int params_undefined_check(char *name)
{
	int i = 0;

	while(i < DEFINED_COUNT)
	{
		if(strcmp(params_definfo[i].var_name, name) == 0)
		{
			return 0;
		}

		i ++;
	}

	memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
	snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"'%s' undefined\"", name);
	set_Msg_to_errInfo(LINENUM, ERR_PARAM_UNDEFINED, error_msg_buf);

	return 1;
}

params_defined_info *get_params_info(char *name)
{
	params_defined_info *head;
	int i = 0;
	char *ptr;

	while(i < DEFINED_COUNT)
	{
		if(strcmp(params_definfo[i].var_name, name) == 0)
		{
			break;
		}

		i ++;
	}

	ptr = params_definfo[i].var_name;
	head = container_of(ptr, params_defined_info, var_name);

	return head;
}

int defvar_preversion_check(void)
{
	char (*p)[16] = cmd_info;

	while(strlen(*p) != 0)
	{
		if(strcmp(*p, "VAR") && strcmp(*p, "VARS") && strcmp(*p, "INTF") && strcmp(*p, "INTFS")\
			&& strcmp(*p, "CTRL") && strcmp(*p, "CTRLS") && strcmp(*p, "UCTRL") && strcmp(*p, "UCTRLS"))
		{
			memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
			snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"variable defined after excuting\"");
			set_Msg_to_errInfo(LINENUM, ERR_DEFVAR_PREVERSION, error_msg_buf);
		
			return 1;
		}

		p ++;
	}

	return 0;
}

int scripts_oversize(unsigned int scripts_len)
{
	if(scripts_len > MAX_SCRIPTS_LENGTH)
	{
		memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
		snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"the script size[%d] is more than MAX_SIZE[%d]\"", scripts_len, MAX_SCRIPTS_LENGTH);
		set_Msg_to_errInfo(2, ERR_SCRIPTS_OVERSIZE, error_msg_buf);

		return 1;
	}
	
	return 0;
}

int ctrl_output_check(void)
{
	char (*p)[16] = cmd_info;
	int err_flag = 1;

	while(strlen(*p) != 0)
	{
		if(!strcmp(*p, "CTRL") || !strcmp(*p, "CTRLS") || !strcmp(*p, "UCTRL") || !strcmp(*p, "UCTRLS"))
		{
			err_flag = 0;
		}

		p ++;
	}

	if(err_flag)
	{
		memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
		snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"no variable need to output in 'DO_CTRL'\"");
		set_Msg_to_errInfo(LINENUM, ERR_NO_CTRL_OUTPUT, error_msg_buf);
		
		return 1;
	}

	return 0;
}

int pow2(int base, int n)
{
	int ret = 1;

	while(n --)
	{
		ret *= base;
	}

	return ret;
}

int str_to_hex(char *s)
{
	int len = strlen(s);
	int i, t, sum = 0;

	for(i = 0; i < len; i ++)
	{
		if(s[i] >= '0' && s[i] <= '9')
        {
            t = s[i] - '0';
        }
        else if(s[i] >= 'a' && s[i] <= 'z')
        {
            t = s[i] - 'a' + 10;
        }
        else if(s[i] >= 'A' && s[i] <= 'Z')
        {
            t = s[i] - 'A' + 10;
        }

		sum += t * pow2(16, len - i - 1);
	}

	return sum;
}

int Numofstr(char *Mstr, char *substr)
{
	int number = 0;
	char *p, *q;	//字符串辅助指针

	while(*Mstr != '\0')
	{
	    p = Mstr;
	    q = substr;

	    while((*p == *q) && (*p != '\0') && (*q != '\0'))
	    {
	        p ++;
	        q ++;
	    }
	    if((*q == '\0') && (*p != '='))
	    {
	        number ++;
	    }
	    Mstr ++;
	}

	return number;
}

int brackets_exist_check(char *str)	//only for IF
{
	int brackets_count = 0, symbols_count = 0;
	char *symbols_info[] = {"==", "!=", "<", "<=", ">", ">=", NULL};
	char **p, *q;

	p = symbols_info;
	while(*p)
	{
		symbols_count += Numofstr(str, *p);

		p ++;
	}

	q = str;
	while(*q)
	{
		if(*q == '(')
			brackets_count += 1;

		q ++;
	}

	if((brackets_count == 0) && (symbols_count == 0))
		return 3;

	if(brackets_count == symbols_count)
		return 0;
	else if(brackets_count < symbols_count) 
		return 1;
	else 
		return 2;
}

int NestofIF_check(void)
{
	char (*p)[16], (*q)[16];
	int if_count = 0;
	int if_index = 0, endif_index = 0;
	int i = 0, j = 0;

 	p = q = cmd_info;

	while(strlen(*p) != 0)	//找到第四个IF所在位置
	{
		if(!strcmp(*p, "IF"))
		{
			if_count += 1;	
		}

		if(if_count > 3)
		{
			if_index = i;	
			break;
		}

		p ++;
		i ++;
	}

	while(strlen(*q) != 0)	//找到第一个ENDIF所在位置
	{
		if(!strcmp(*q, "ENDIF"))
		{
			endif_index = j;
			break;
		}

		q ++;
		j ++;
	}

//	printf("if:%d, endif:%d\n", if_index, endif_index);
	if((if_index < endif_index) || ((if_index != 0) && (endif_index == 0)))	//说明嵌套超过3层了
	{
		return 1;	
	}

	return 0;
}

int scripts_checkout(const char *scripts)
{
	int error_code = 0;
	char line[LINE_SIZE];
	int i, j, n, len;
	char *p, *nv, *nvp, *cp, *cq;
	char *cmd, *regAddr, *var_type, *var_name_b;
	char var_name[16], tmp_name[16];
	unsigned int var_count = 0;	//元素的个数，针对数组变量来说，单个变量为1
	char *start_num, *read_count;	//读入寄存器的开始编号及个数
	char *modbus_cmd, *overtime;
	params_defined_info *head;
	unsigned int cur_size = 0, total_size;

	total_size = strlen(scripts);

	if(scripts_oversize(total_size))
	{
		error_code |= ERR_SCRIPTS_OVERSIZE;	

		return error_code;
	}

	memset(line, 0, LINE_SIZE);
	while(cur_size < total_size)
	{
		cur_size += scripts_getline(line, scripts);

		cp = line;
		while((isspace((int) *cp) || *cp == '\n' || *cp =='\r') && *cp != '\0')
		{
			cp++;
		}
		if(*cp == '\0')
		{
			continue;
		}

		char cmds[16] = {0};			

		if(endsymbol_check(line) == 0)	//检查有无结束符
		{
			error_code |= ERR_FORMAT;
		}

		get_cmd(cmds, line);

		if(cmd_check(cmds) == 0)	//检查指令是否合法
		{
			error_code |= ERR_CMD_INVALID;	
		}
		
		if(brackets_check(line))	//检查括号是否成对
		{
			error_code |= ERR_FORMAT;
		}

		nv = nvp = strdup(line);

		if(!strcmp(cmds, "VAR") || !strcmp(cmds, "VARS"))
		{
			//检查是否指令开始执行后还存在变量定义的指令
			if(defvar_preversion_check())
			{
				error_code |= ERR_DEFVAR_PREVERSION;
			}

			memset(var_name, 0, 16);
			n = vstrsep(nvp, "	; ", &cmd, &var_type, &var_name_b);
			if(n == 3)
			{
				if(vartype_check(var_type) == 0)	//检查变量类型是否合法
				{
					error_code |= ERR_VARTYPE_INVALID;
				}
				//获取变量名，检查是否重复定义
				var_count = get_varname(var_name, var_name_b);
				if(var_count <= 0)
				{
					memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid initializer '%s'\"", var_name);
					set_Msg_to_errInfo(LINENUM, ERR_PARAM_EXCESS, error_msg_buf);
					error_code |= ERR_PARAM_EXCESS;
				}
				if(params_confdef_check(var_name, var_type, var_count))
				{
					error_code |= ERR_DEFVAR_CONFLICTING;
				}
				//若变量为AI或DI，检查类型是否为B或W
				if(aidi_type_check(var_name, var_type))
				{
					error_code |= ERR_VARTYPE_CONFUSING;
				}

				if(!strcmp(cmds, "VAR"))
				{
					if(strchr(var_name_b, '[') != NULL)
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"unexpected '[]' for 'VAR'\"");
						set_Msg_to_errInfo(LINENUM, ERR_DEFVAR_CONFUSING, error_msg_buf);
						error_code |= ERR_DEFVAR_CONFUSING;	
					}
				}
				if(!strcmp(cmds, "VARS"))
				{
					len = 0;
					for(i = 0; i < strlen(var_name_b); i ++)
					{
						if(*(var_name_b + i) == '[')
							len += 1;		
					}
					if(len == 0)
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"expected '[]' for 'VARS'\"");
						set_Msg_to_errInfo(LINENUM, ERR_DEFVAR_CONFUSING, error_msg_buf);
						error_code |= ERR_DEFVAR_CONFUSING;	
					}
					else if(len > 1)
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"V20 only support one-demensional array\"");
						set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);
						error_code |= ERR_FORMAT;	
					}
					//若变量为AI或DI，检查寄存器定义是否越界
					if(aidi_reg_check(var_name, var_count))
					{
						error_code |= ERR_REG_OUTBOUNDS;
					}
					//若数组赋初值，检查所赋初值个数是否大于定义的个数及格式
					if(strchr(line, '='))
					{
						if(arr_format_check(line))
						{
							error_code |= ERR_FORMAT;
						}
						else if(arr_excess_check(line) > var_count)
						{
							memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
							snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"excess elements in array initializer\"");
							set_Msg_to_errInfo(LINENUM, ERR_PARAM_EXCESS, error_msg_buf);
							error_code |= ERR_PARAM_EXCESS;
						}
					}
				}
			}
			else
			{
				memset(error_msg_buf, 0, ERROR_MSG_LENGTH);

				if(n < 3)
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too few elements for '%s'\"", cmds);
				else
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too more elements for '%s'\"", cmds);

				set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);
				error_code |= ERR_FORMAT;	
			}
		}
		else if(!strcmp(cmds, "INTF") || !strcmp(cmds, "INTFS"))
		{
			//检查是否指令开始执行后还存在变量定义
			if(defvar_preversion_check())
			{
				error_code |= ERR_DEFVAR_PREVERSION;
			}

			memset(var_name, 0, 16);
			n = vstrsep(nvp, "	; ", &cmd, &regAddr, &var_type, &var_name_b);
			if(n == 4)
			{
				//检查地址是否越界
				if(atoi(regAddr) > MAX_REGISTER_NUM)
				{
					memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"available registers can not beyond 65535\"");
					set_Msg_to_errInfo(LINENUM, ERR_REG_OUTBOUNDS, error_msg_buf);

					error_code |= ERR_REG_OUTBOUNDS;
				}
				else
				{
					//检查地址是否被其它变量占用
					if(regAddr_confdef_check(atoi(regAddr)))
					{
						error_code |= ERR_REG_OUTBOUNDS;
					}
				}
				//检查变量类型是否合法
				if(vartype_check(var_type) == 0)
				{
					error_code |= ERR_VARTYPE_INVALID;
				}
				//获取变量名，检查是否重复定义
				var_count = get_varname(var_name, var_name_b);
				if(var_count <= 0)
				{
					memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid initializer '%s'\"", var_name);
					set_Msg_to_errInfo(LINENUM, ERR_PARAM_EXCESS, error_msg_buf);
					error_code |= ERR_PARAM_EXCESS;
				}
				if(params_confdef_check(var_name, var_type, var_count))
				{
					error_code |= ERR_DEFVAR_CONFLICTING;
				}
				//若变量为AI或DI，检查类型是否为B或W
				if(aidi_type_check(var_name, var_type))
				{
					error_code |= ERR_VARTYPE_CONFUSING;
				}
				
				if(!strcmp(cmds, "INTF"))
				{
					if(strchr(var_name_b, '[') != NULL)
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"unexpected '[]' for 'INTF'\"");
						set_Msg_to_errInfo(LINENUM, ERR_DEFVAR_CONFUSING, error_msg_buf);
						error_code |= ERR_DEFVAR_CONFUSING;	
					}
				}
				if(!strcmp(cmds, "INTFS"))
				{
					len = 0;
					for(i = 0; i < strlen(var_name_b); i ++)
					{
						if(*(var_name_b + i) == '[')
							len += 1;		
					}
					if(len == 0)
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"expected '[]' for 'VARS'\"");
						set_Msg_to_errInfo(LINENUM, ERR_DEFVAR_CONFUSING, error_msg_buf);
						error_code |= ERR_DEFVAR_CONFUSING;	
					}
					else if(len > 1)
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"V20 only support one-demensional array\"");
						set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);
						error_code |= ERR_FORMAT;	
					}
					//若变量为AI或DI，检查寄存器定义是否越界
					if(aidi_reg_check(var_name, var_count))
					{
						error_code |= ERR_REG_OUTBOUNDS;
					}
					//若数组赋初值，检查所赋初值个数是否大于定义的个数及格式
					if(strchr(line, '='))
					{
						if(arr_format_check(line))
						{
							error_code |= ERR_FORMAT;
						}
						else if(arr_excess_check(line) > var_count)
						{
							memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
							snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"excess elements in array initializer\"");
							set_Msg_to_errInfo(LINENUM, ERR_PARAM_EXCESS, error_msg_buf);
							error_code |= ERR_PARAM_EXCESS;
						}
					}
				}
			}
			else
			{
				memset(error_msg_buf, 0, ERROR_MSG_LENGTH);

				if(n < 4)
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too few elements for '%s'\"", cmds);
				else
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too more elements for '%s'\"", cmds);

				set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);
				error_code |= ERR_FORMAT;	
			}
		}
		else if(!strcmp(cmds, "CTRL") || !strcmp(cmds, "CTRLS"))
		{
			//检查是否指令开始执行后还存在变量定义
			if(defvar_preversion_check())
			{
				error_code |= ERR_DEFVAR_PREVERSION;
			}

			memset(var_name, 0, 16);
			n = vstrsep(nvp, "	; ", &cmd, &regAddr, &var_type, &var_name_b);
			if(n == 4)
			{
				//检查地址是否越界
				if(atoi(regAddr) > MAX_REGISTER_NUM)
				{
					memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"available registers can not beyond 65535\"");
					set_Msg_to_errInfo(LINENUM, ERR_REG_OUTBOUNDS, error_msg_buf);

					error_code |= ERR_REG_OUTBOUNDS;
				}
				else
				{
					//检查地址是否被其它变量占用
					if(regAddr_confdef_check(atoi(regAddr)))
					{
						error_code |= ERR_REG_OUTBOUNDS;
					}
				}
				//检查变量类型是否合法
				if(vartype_check(var_type) == 0)
				{
					error_code |= ERR_VARTYPE_INVALID;
				}
				//获取变量名，检查是否重复定义
				var_count = get_varname(var_name, var_name_b);
				if(var_count <= 0)
				{
					memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid initializer '%s'\"", var_name);
					set_Msg_to_errInfo(LINENUM, ERR_PARAM_EXCESS, error_msg_buf);
					error_code |= ERR_PARAM_EXCESS;
				}
				if(params_confdef_check(var_name, var_type, var_count))
				{
					error_code |= ERR_DEFVAR_CONFLICTING;
				}
				
				if(!strcmp(cmds, "CTRL"))
				{
					if(strchr(var_name_b, '[') != NULL)
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"unexpected '[]' for 'CTRL'\"");
						set_Msg_to_errInfo(LINENUM, ERR_DEFVAR_CONFUSING, error_msg_buf);
						error_code |= ERR_DEFVAR_CONFUSING;	
					}
				}
				if(!strcmp(cmds, "CTRLS"))
				{
					len = 0;
					for(i = 0; i < strlen(var_name_b); i ++)
					{
						if(*(var_name_b + i) == '[')
							len += 1;		
					}
					if(len == 0)
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"expected '[]' for 'VARS'\"");
						set_Msg_to_errInfo(LINENUM, ERR_DEFVAR_CONFUSING, error_msg_buf);
						error_code |= ERR_DEFVAR_CONFUSING;	
					}
					else if(len > 1)
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"V20 only support one-demensional array\"");
						set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);
						error_code |= ERR_FORMAT;	
					}

					if(strchr(line, '='))
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"no need to value assignment for 'CTRLS'\"");
						set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);
						error_code |= ERR_FORMAT;
					}
				}
			}
			else
			{
				memset(error_msg_buf, 0, ERROR_MSG_LENGTH);

				if(n < 4)
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too few elements for '%s'\"", cmds);
				else
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too more elements for '%s'\"", cmds);

				set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);
				error_code |= ERR_FORMAT;	
			}
		}
		else if(!strcmp(cmds, "UCTRL") || !strcmp(cmds, "UCTRLS"))
		{
			char *mb_regAddr;

			//检查是否指令开始执行后还存在变量定义
			if(defvar_preversion_check())
			{
				error_code |= ERR_DEFVAR_PREVERSION;
			}

			memset(var_name, 0, 16);
			n = vstrsep(nvp, "	; ", &cmd, &regAddr, &mb_regAddr, &var_type, &var_name_b);
			if(n == 5)
			{
				//检查地址是否越界
				if(atoi(regAddr) > MAX_REGISTER_NUM)
				{
					memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"available registers can not beyond 65535\"");
					set_Msg_to_errInfo(LINENUM, ERR_REG_OUTBOUNDS, error_msg_buf);

					error_code |= ERR_REG_OUTBOUNDS;
				}
				else
				{
					//检查地址是否被其它变量占用
					if(regAddr_confdef_check(atoi(regAddr)))
					{
						error_code |= ERR_REG_OUTBOUNDS;
					}
				}
				//检查变量类型是否合法
				if(vartype_check(var_type) == 0)
				{
					error_code |= ERR_VARTYPE_INVALID;
				}
				//获取变量名，检查是否重复定义
				var_count = get_varname(var_name, var_name_b);
				if(var_count <= 0)
				{
					memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid initializer '%s'\"", var_name);
					set_Msg_to_errInfo(LINENUM, ERR_PARAM_EXCESS, error_msg_buf);
					error_code |= ERR_PARAM_EXCESS;
				}
				if(params_confdef_check(var_name, var_type, var_count))
				{
					error_code |= ERR_DEFVAR_CONFLICTING;
				}
				
				if(!strcmp(cmds, "UCTRL"))
				{
					if(strchr(var_name_b, '[') != NULL)
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"unexpected '[]' for 'UCTRL'\"");
						set_Msg_to_errInfo(LINENUM, ERR_DEFVAR_CONFUSING, error_msg_buf);
						error_code |= ERR_DEFVAR_CONFUSING;	
					}
				}
				if(!strcmp(cmds, "UCTRLS"))
				{
					len = 0;
					for(i = 0; i < strlen(var_name_b); i ++)
					{
						if(*(var_name_b + i) == '[')
							len += 1;		
					}
					if(len == 0)
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"expected '[]' for 'VARS'\"");
						set_Msg_to_errInfo(LINENUM, ERR_DEFVAR_CONFUSING, error_msg_buf);
						error_code |= ERR_DEFVAR_CONFUSING;	
					}
					else if(len > 1)
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"V20 only support one-demensional array\"");
						set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);
						error_code |= ERR_FORMAT;	
					}

					if(strchr(line, '='))
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"no need to value assignment for 'UCTRLS'\"");
						set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);
						error_code |= ERR_FORMAT;
					}
				}
			}
			else
			{
				memset(error_msg_buf, 0, ERROR_MSG_LENGTH);

				if(n < 5)
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too few elements for '%s'\"", cmds);
				else
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too more elements for '%s'\"", cmds);

				set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);
				error_code |= ERR_FORMAT;	
			}
		}
		else if(!strcmp(cmds, "SET_THV"))
		{
			char *thr_up, *thr_low;
			n = vstrsep(nvp, "	; ", &cmd, &var_name_b, &thr_low, &thr_up);
			if(n == 4)
			{
				//检查变量是否定义
				if(params_undefined_check(var_name_b))
				{
					error_code |= ERR_PARAM_UNDEFINED;	
				}
				else
				{
					var_count = get_varname(var_name, var_name_b);
					if(var_count <= 0)
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid element subscript for '%s'\"", var_name);
						set_Msg_to_errInfo(LINENUM, ERR_PARAM_EXCESS, error_msg_buf);
						error_code |= ERR_PARAM_EXCESS;
					}
					//检查变量类型是否是F
					head = get_params_info(var_name_b);
					if(strncmp(head->var_type, "F", 1) != 0)
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"type of '%s' must be 'F'\"", var_name_b);
						set_Msg_to_errInfo(LINENUM, ERR_VARTYPE_CONFUSING, error_msg_buf);
						error_code |= ERR_VARTYPE_CONFUSING;	
					}
					//检查阈值是否前小后大
					if(atoi(thr_low) > atoi(thr_up))
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid initializer[%d > %d]\"", atoi(thr_low), atoi(thr_up));
						set_Msg_to_errInfo(LINENUM, ERR_THRESH, error_msg_buf);
						error_code |= ERR_THRESH;	
					}
				}
			}
			else
			{
				memset(error_msg_buf, 0, ERROR_MSG_LENGTH);

				if(n < 4)
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too few elements for '%s'\"", cmds);
				else
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too more elements for '%s'\"", cmds);

				set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);
				error_code |= ERR_FORMAT;	
			}
		}
		else if(!strcmp(cmds, "CAL"))
		{
			cp = strchr(line, ' ');
			while(1)
			{
				memset(var_name, 0, 16);
				memset(tmp_name, 0, 16);
				len = 0;
				while((isspace((int) *cp) || *cp == '	' || *cp == '=' || *cp == '+' || *cp == '-' || *cp == '*' || *cp == '/'\
					|| *cp == '~' || *cp == '&' || *cp == '|' || *cp == '^' || *cp == '<' || *cp == '>') && (*cp != '\0'))
				{
					cp ++;
				}
				cq = cp;
				if(*cp == '\0' || *cp == ';' || *cp == '\n')
				{
					break;
				}
				else
				{
					while(((!isspace((int) *cp)) && (*cp != '	') && (*cp != '+') && (*cp != '-') && (*cp != '*') && (*cp != '/')\
						&& (*cp != '~') && (*cp != '&') && (*cp != '|') && (*cp != '^')\
						&& (*cp != '<') && (*cp != '>') && (*cp != '\r') && (*cp != ';')) && (*cp != '\0'))
					{
						cp ++;
						len ++;
					}
					strncpy(tmp_name, cq, len);

					if((atoi(tmp_name) == 0) && (atof(tmp_name) == 0))	//过滤常量
					{
						var_count = get_varname(var_name, tmp_name);
						//检查变量是否定义
						if(params_undefined_check(var_name))
						{
							error_code |= ERR_PARAM_UNDEFINED;	
						}
						else
						{
							head = get_params_info(var_name);
							if(var_count > head->var_count)
							{
								memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
								snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"register beyond access for '%s'\"", var_name);
								set_Msg_to_errInfo(LINENUM, ERR_REG_OUTBOUNDS, error_msg_buf);
								error_code |= ERR_REG_OUTBOUNDS;
							}
							else if(var_count <= 0)
							{
								memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
								snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid element subscript for '%s'\"", var_name);
								set_Msg_to_errInfo(LINENUM, ERR_PARAM_EXCESS, error_msg_buf);
								error_code |= ERR_PARAM_EXCESS;
							}
						}
					}
				}
			}
		}
		else if(!strcmp(cmds, "IN_D") || !strcmp(cmds, "IN_A"))
		{
			n = vstrsep(nvp, ", ;	", &cmd, &start_num, &read_count);
			if(n == 3)
			{
				if(atoi(start_num) <= 0)
				{
					memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid start address\"");
					set_Msg_to_errInfo(LINENUM, ERR_PARAM_EXCESS, error_msg_buf);
					error_code |= ERR_PARAM_EXCESS;
				}
				if(!strcmp(cmds, "IN_D"))
				{
					//检查变量是否定义
					if(params_undefined_check("DI"))
					{
						error_code |= ERR_PARAM_UNDEFINED;	
					}
					else	
					{
						head = get_params_info("DI");
						if((atoi(start_num) + atoi(read_count) - 1) > head->var_count)
						{
							memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
							snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"register beyond access\"");
							set_Msg_to_errInfo(LINENUM, ERR_REG_OUTBOUNDS, error_msg_buf);
							error_code |= ERR_REG_OUTBOUNDS;
						}
					}
				}
				if(!strcmp(cmds, "IN_A"))
				{
					//检查变量是否定义
					if(params_undefined_check("AI"))
					{
						error_code |= ERR_PARAM_UNDEFINED;	
					}
					else 
					{
						head = get_params_info("AI");
						if((atoi(start_num) + atoi(read_count) - 1) > head->var_count)
						{
							memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
							snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"register beyond access\"");
							set_Msg_to_errInfo(LINENUM, ERR_REG_OUTBOUNDS, error_msg_buf);
							error_code |= ERR_REG_OUTBOUNDS;
						}
					}
				}
			}
			else
			{
				memset(error_msg_buf, 0, ERROR_MSG_LENGTH);

				if(n < 3)
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too few elements for '%s'\"", cmds);
				else
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too more elements for '%s'\"", cmds);

				set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);
				error_code |= ERR_FORMAT;	
			}
		}
		else if(!strcmp(cmds, "IN_UD") || !strcmp(cmds, "IN_UD_B") || !strcmp(cmds, "IN_UA")	\
				 || !strcmp(cmds, "IN_UA_B") || !strcmp(cmds, "IN_UF_B") || !strcmp(cmds, "IN_UFD_B"))
		{
			char tmp[5] = {0};

			memset(var_name, 0, 16);
			n = vstrsep(nvp, ", ;	", &cmd, &var_name_b, &read_count, &modbus_cmd, &overtime);
			if(n == 5)
			{
				//检查变量是否定义
				var_count = get_varname(var_name, var_name_b);
				if(params_undefined_check(var_name))
				{
					error_code |= ERR_PARAM_UNDEFINED;	
				}
				else
				{
					if(var_count <= 0)
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid element subscript for '%s'\"", var_name);
						set_Msg_to_errInfo(LINENUM, ERR_PARAM_EXCESS, error_msg_buf);
						error_code |= ERR_PARAM_EXCESS;
					}
					//检查超时
					if(atoi(overtime) <= 0)
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid value for overtime\"");
						set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);
						error_code |= ERR_FORMAT;	
					}

					head = get_params_info(var_name);
					if((var_count + atoi(read_count) - 1) > head->var_count)
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"register beyond access\"");
						set_Msg_to_errInfo(LINENUM, ERR_REG_OUTBOUNDS, error_msg_buf);
						error_code |= ERR_REG_OUTBOUNDS;
					}
					//检查modbus指令格式
					if(strlen(modbus_cmd) != 13)
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid modbus command for '%s'\"", cmds);
						set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);
						error_code |= ERR_FORMAT;	
					}

					for(i = 8, j = 0; i < 12; i ++, j ++)
					{
						tmp[j] = modbus_cmd[i];
					}
					tmp[j] = '\0';

					if(!strcmp(cmds, "IN_UD") || !strcmp(cmds, "IN_UD_B") || !strcmp(cmds, "IN_UA") || !strcmp(cmds, "IN_UA_B"))	
					{
						if(atoi(read_count) != str_to_hex(tmp))
						{
							memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
							snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"registers read of V20 don't match with that of modbus\"");
							set_Msg_to_errInfo(LINENUM, ERR_SERIAL_RDREG, error_msg_buf);
							error_code |= ERR_SERIAL_RDREG;	
						}
					}
					if(!strcmp(cmds, "IN_UF_B"))	
					{
						if(strncmp(head->var_type, "F", 1) != 0)
						{
							memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
							snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"type of '%s' must be 'F'\"", var_name);
							set_Msg_to_errInfo(LINENUM, ERR_VARTYPE_CONFUSING, error_msg_buf);
							error_code |= ERR_VARTYPE_CONFUSING;	
						}

						if((atoi(read_count) * 2) != str_to_hex(tmp))
						{
							memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
							snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"registers read of V20 don't match with that of modbus\"");
							set_Msg_to_errInfo(LINENUM, ERR_SERIAL_RDREG, error_msg_buf);
							error_code |= ERR_SERIAL_RDREG;	
						}
					}
					if(!strcmp(cmds, "IN_UFD_B"))	
					{
						if(strncmp(head->var_type, "F", 1) != 0)
						{
							memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
							snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"type of '%s' must be 'F'\"", var_name);
							set_Msg_to_errInfo(LINENUM, ERR_VARTYPE_CONFUSING, error_msg_buf);
							error_code |= ERR_VARTYPE_CONFUSING;	
						}

						if((atoi(read_count) * 4) != str_to_hex(tmp))
						{
							memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
							snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"registers read of V20 don't match with that of modbus\"");
							set_Msg_to_errInfo(LINENUM, ERR_SERIAL_RDREG, error_msg_buf);
							error_code |= ERR_SERIAL_RDREG;	
						}
					}
				}
			}
			else
			{
				memset(error_msg_buf, 0, ERROR_MSG_LENGTH);

				if(n < 5)
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too few elements for '%s'\"", cmds);
				else
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too more elements for '%s'\"", cmds);

				set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);
				error_code |= ERR_FORMAT;	
			}
		}
		else if(!strcmp(cmds, "IN_AE") || !strcmp(cmds, "IN_ACAE"))
		{
			char *per;

			memset(var_name, 0, 16);
			n = vstrsep(nvp, ", ;	", &cmd, &var_name_b, &per, &read_count);
			if(n == 4)
			{
				//检查变量是否定义
				var_count = get_varname(var_name, var_name_b);
				if(params_undefined_check(var_name))
				{
					error_code |= ERR_PARAM_UNDEFINED;	
				}
				else 
				{
					if(var_count <= 0)
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid element subscript for '%s'\"", var_name);
						set_Msg_to_errInfo(LINENUM, ERR_PARAM_EXCESS, error_msg_buf);
						error_code |= ERR_PARAM_EXCESS;
					}
					//检查变量类型是否是F
					head = get_params_info(var_name);
					if(strncmp(head->var_type, "F", 1) != 0)
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"type of '%s' must be 'F'\"", var_name);
						set_Msg_to_errInfo(LINENUM, ERR_VARTYPE_CONFUSING, error_msg_buf);
						error_code |= ERR_VARTYPE_CONFUSING;	
					}
					if((atoi(per) * atoi(read_count) + var_count - 1) > head->var_count)
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"register beyond access\"");
						set_Msg_to_errInfo(LINENUM, ERR_PARAM_EXCESS, error_msg_buf);
						error_code |= ERR_PARAM_EXCESS;
					}
				}
			}
			else
			{
				memset(error_msg_buf, 0, ERROR_MSG_LENGTH);

				if(n < 4)
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too few elements for '%s'\"", cmds);
				else
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too more elements for '%s'\"", cmds);

				set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);
				error_code |= ERR_FORMAT;	
			}
		}
		else if(!strcmp(cmds, "IN_ATEMP") || !strcmp(cmds, "IN_AMVOL") || !strcmp(cmds, "IN_ABVOL"))
		{
			memset(var_name, 0, 16);
			n = vstrsep(nvp, " ;	", &cmd, &var_name_b);
			if(n == 2)
			{
				//检查变量是否定义
				var_count = get_varname(var_name, var_name_b);
				if(params_undefined_check(var_name))
				{
					error_code |= ERR_PARAM_UNDEFINED;	
				}
				else 
				{
					//检查变量类型是否是F
					head = get_params_info(var_name);
					if(strncmp(head->var_type, "F", 1) != 0)
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"type of '%s' must be 'F'\"", var_name);
						set_Msg_to_errInfo(LINENUM, ERR_VARTYPE_CONFUSING, error_msg_buf);
						error_code |= ERR_VARTYPE_CONFUSING;	
					}
				}
			}
			else
			{
				memset(error_msg_buf, 0, ERROR_MSG_LENGTH);

				if(n < 2)
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too few elements for '%s'\"", cmds);
				else
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too more elements for '%s'\"", cmds);

				set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);
				error_code |= ERR_FORMAT;	
			}
		}
		else if(!strcmp(cmds, "OUT_D"))
		{
			char *channel, *value;

			n = vstrsep(nvp, ", ;	", &cmd, &channel, &value);
			if(n == 3)
			{
				if(atoi(channel) > DI_REGISTER_NUM)
				{
					memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid output register channel\"");
					set_Msg_to_errInfo(LINENUM, ERR_PARAM_EXCESS, error_msg_buf);
					error_code |= ERR_PARAM_EXCESS;
				}
			}
			else
			{
				memset(error_msg_buf, 0, ERROR_MSG_LENGTH);

				if(n < 3)
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too few elements for '%s'\"", cmds);
				else
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too more elements for '%s'\"", cmds);

				set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);
				error_code |= ERR_FORMAT;	
			}
		}
		else if(!strcmp(cmds, "OUT_U"))
		{
			n = vstrsep(nvp, ", ;	", &cmd, &modbus_cmd, &overtime);
			if(n == 3)
			{
				//检查超时
				if(atoi(overtime) <= 0)
				{
					memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid value for overtime\"");
					set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);
					error_code |= ERR_FORMAT;	
				}
				//检查modbus指令格式
				if(strlen(modbus_cmd) != 12)
				{
					memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid modbus command for '%s'\"", cmds);
					set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);
					error_code |= ERR_FORMAT;	
				}
			}
			else
			{
				memset(error_msg_buf, 0, ERROR_MSG_LENGTH);

				if(n < 3)
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too few elements for '%s'\"", cmds);
				else
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too more elements for '%s'\"", cmds);

				set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);
				error_code |= ERR_FORMAT;	
			}
		}
		else if(!strcmp(cmds, "DO_CTRL"))
		{
			if(ctrl_output_check())
			{
				error_code |= ERR_NO_CTRL_OUTPUT;	
			}
		}
		else if(!strcmp(cmds, "IF"))
		{
			//IF最多支持3层嵌套
			if(NestofIF_check())
			{
				memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
				snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too more nested levels for 'IF'\"");
				set_Msg_to_errInfo(LINENUM, ERR_IFCMD_EXCESS, error_msg_buf);
				error_code |= ERR_IFCMD_EXCESS;	
			}

			if(brackets_exist_check(line) == 1)	//only for IF
			{
				memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
				snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"each condition need parentheses\"");
				set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);
				error_code |= ERR_FORMAT;	
			}
			else if(brackets_exist_check(line) == 2)	//only for IF
			{
				memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
				snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"expected condition for 'IF'\"");
				set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);
				error_code |= ERR_FORMAT;	
			}
			else if(brackets_exist_check(line) == 3)	//only for IF
			{
				memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
				snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid format for 'IF'\"");
				set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);
				error_code |= ERR_FORMAT;
			}
			else
			{
				cp = strchr(line, '(');
				while(1)
				{
					memset(var_name, 0, 16);
					memset(tmp_name, 0, 16);
					len = 0;
					while((isspace((int) *cp) || *cp == '	' || *cp == '=' || *cp == '(' || *cp == ')' || *cp == ';'\
						|| *cp == '!' || *cp == '&' || *cp == '|' || *cp == '<' || *cp == '>') && (*cp != '\0'))
					{
						cp ++;
					}
					cq = cp;
					if(*cp == '\0' || *cp == '\n')
					{
						break;
					}
					else
					{
						while(((!isspace((int) *cp)) && (*cp != '	') && (*cp != '=') && (*cp != '(')\
								&& (*cp != ')') && (*cp != '!') && (*cp != '&') && (*cp != '|')\
								&& (*cp != '<') && (*cp != '>') && (*cp != ';') && (*cp != '\r')) && (*cp != '\0'))
						{
							cp ++;
							len ++;
						}
						strncpy(tmp_name, cq, len);

						if((atoi(tmp_name) == 0) && (atof(tmp_name) == 0) && (strcmp(tmp_name, "0")))	//过滤常量
						{
							var_count = get_varname(var_name, tmp_name);
							//检查变量是否定义
							if(params_undefined_check(var_name))
							{
								error_code |= ERR_PARAM_UNDEFINED;	
							}
							else
							{
								head = get_params_info(var_name);
								if(var_count > head->var_count)
								{
									memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
									snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"register beyond access for '%s'\"", var_name);
									set_Msg_to_errInfo(LINENUM, ERR_REG_OUTBOUNDS, error_msg_buf);
									error_code |= ERR_REG_OUTBOUNDS;
								}
								else if(var_count <= 0)
								{
									memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
									snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid element subscript for '%s'\"", var_name);
									set_Msg_to_errInfo(LINENUM, ERR_PARAM_EXCESS, error_msg_buf);
									error_code |= ERR_PARAM_EXCESS;
								}
							}
						}
					}
				}
			}
		}
		else if(!strcmp(cmds, "SLEEP"))
		{
			char *pause;

			n = vstrsep(nvp, " ;	", &cmd, &pause);
			if(n == 2)
			{
				if(atoi(pause) <= 0)
				{
					memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"pause must > 0\"");
					set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);
					error_code |= ERR_FORMAT;	
				}
			}
			else
			{
				memset(error_msg_buf, 0, ERROR_MSG_LENGTH);

				if(n < 2)
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too few elements for '%s'\"", cmds);
				else
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too more elements for '%s'\"", cmds);

				set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);
				error_code |= ERR_FORMAT;	
			}
		}

		free(nv);
	}

	return error_code;
}

void show_cmdInfo(void)
{
	char (*p)[16] = cmd_info;

	printf("cmd_info:\n");
	while(strlen(*p) != 0)
	{
		printf("%s\n", *p);

		p ++;
	}
}

int main()
{
	int error_code = 0;
	char *scripts = "  VARS 	 W 	 AI[12];	\n"\
					"	VARS B DI[3];\n"\
					"VAR F tmp;\n"\
					"\n"\
					"   \n"\
					"VAR F DA;\n"\
					"VAR W wspd;\n"\
					"VAR F TEMP_V;\n"\
					"VAR F MAIN_VOL;\n"\
					"VAR F BATTERY_VOL;\n"\
					"VARS 	B UDI01[17];\n"\
					"VARS F UAI02[17];\n"\
					"INTF 1004 F wspdx;\n"\
					"INTFS 2018 F wsdu[2];\n"\
					"INTFS 2019 F AIV[2];\n"\
					"CTRL 4000 B LDO1=0;\n"\
					"CTRLS 4001 B LDOS[2];\n"\
					"UCTRL 4002 30001 B UDO1=0;\n"\
					"UCTRLS 4003 30001 B UDO2[2];\n"\
					"IN_D 1, 3;\n"\
					"IN_A 1, 2;\n"\
					"IF(tmp == 0)\n"\
					"ELSE\n"\
					"ENDIF\n"\
					"SET_THV tmp 20 30;\n"\
					"CAL tmp = AI[1] / 4096 * 3.3 / 165 * 1000 - 4;\n"\
					"CAL wsdu[1] = tmp * 100 / 16;\n"\
					"CAL tmp = AI[2] / 4096 * 3.3 / 165 * 1000 - 4;\n"\
					"	CAL wsdu[2] = tmp * 100 / 16 - 20;\n"\
					"IN_UA wspd, 1, 020300160001A, 100;\n"\
					"IN_UD UDI01[1],8,090200000008A, 200;\n"\
					"IN_UF_B UAI02[1],1,010300000002A, 300;\n"\
					"IN_UFD_B DA,1,090300000004A, 400;\n"\
					"CAL wspdx = wspd / 10;\n"\
					"IN_ATEMP TEMP_V;\n"\
					"IN_AMVOL MAIN_VOL;\n"\
					"IN_ABVOL BATTERY_VOL;\n"\
					"IN_AE AIV[1],1,2;\n"\
					"IN_ACAE AIV[1],1,2;\n"\
					"OUT_U 09050001FF00, 500;\n"\
					"OUT_D 16, 0;\n"\
					"DO_CTRL;\n"\
					"CONTINUE;\n"\
					"SLEEP 1000;";

	error_code = scripts_checkout(scripts);
	//show_cmdInfo();
	if(error_code)
	{
		show_errMsg();	

		return -1;
	}
	
	printf("Scripts check ok.\n");
	//syslog(LOG_NOTICE, "Scripts check ok.");

	return 0;
}

