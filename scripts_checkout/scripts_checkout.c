
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

/* valid commands */
const char *script_cmds[] =
{
	"SET_ADDR",
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
	"ALARM",
	"SET_AL",
	"REL_AL",
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

#define is_cal_operator(cp) ((isspace((int) *cp) || *cp == '=' || *cp == '+' || *cp == '-' || *cp == '*' || *cp == '/'\
							|| *cp == '~' || *cp == '&' || *cp == '|' || *cp == '^' || *cp == '<' || *cp == '>') && (*cp != '\0'))
#define is_not_cal_operator(cp) (((!isspace((int) *cp)) && (*cp != '+') && (*cp != '-') && (*cp != '*') && (*cp != '/')\
									&& (*cp != '~') && (*cp != '&') && (*cp != '|') && (*cp != '^')\
									&& (*cp != '<') && (*cp != '>') && (*cp != ';')) && (*cp != '\0'))
#define lack_cal_operator(cp) ((*cp != '+') && (*cp != '-') && (*cp != '*') && (*cp != '/') && (*cp != '<')\
								&& (*cp != '>') && (*cp != '~') && (*cp != '&') && (*cp != '|') && (*cp != '^')\
								&& (*cp != '=') && (*cp != ';') && (*cp != '\n') && (*cp != '\0'))
#define is_if_operator(cp) ((isspace((int) *cp) || *cp == '=' || *cp == '(' || *cp == ')' || *cp == ';'\
								|| *cp == '!' || *cp == '&' || *cp == '|' || *cp == '<' || *cp == '>') && (*cp != '\0'))
#define is_not_if_operator(cp) (((!isspace((int) *cp)) && (*cp != '=') && (*cp != '(')\
								&& (*cp != ')') && (*cp != '!') && (*cp != '&') && (*cp != '|')\
								&& (*cp != '<') && (*cp != '>') && (*cp != ';')) && (*cp != '\0'))

#define vstrsep(buf, sep, args...) _vstrsep(buf, sep, args, NULL)
int _vstrsep(char *buf, const char *sep, ...)	//变参为char **型
{
	va_list ap;
	char **p, *k;
	int n = 0;

	va_start(ap, sep);
	while((p = va_arg(ap, char **)) != NULL)
	{
		do {
	 		k = strsep(&buf, sep);
			if(k == NULL)
				break;
		} while(strlen(k) == 0);

		if(k == NULL || *k == '\n')
			break;

		*p = k;
		++ n;
	}
	va_end(ap);

	return n;
}

int scripts_getline(char *line, const char *scripts, int cur_index, int *LINENUM)
{
	int i = 0;
	int num = *LINENUM;
	int ret;

	//读取当前行
	while((scripts[cur_index] != '\n') && (scripts[cur_index] != '\0') && (i < LINE_SIZE))
	{
		line[i ++] = scripts[cur_index ++];
	}
	ret = i;
	if(i < LINE_SIZE)
	{
		if(scripts[cur_index] == '\n')
		{
			line[i] = scripts[cur_index];
			ret = i + 1;
		}
		cur_index ++;	//cur_index++是为了指向'\n'的后一个字符，即下一行开头		
	}
	num ++;	//指向下一行
	*LINENUM = num;
		
	return ret;
}

int is_null_line(char *line)
{
	char *cp = line;

	while(isspace((int) *cp) && *cp != '\0')
	{
		cp ++;
	}
	if(*cp == '\0')
	{
		return 1;	
	}

	return 0;
}

void add_cmd_to_cmdInfo(char (*cmd_info)[16], char *cmd)
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

void add_variable_to_defInfo(params_defined_info *params_definfo, char *name, char *type, unsigned int count)
{
	params_defined_info *tail = params_definfo;

	while(strlen(tail->var_name) != 0)
	{
		tail ++;
	}

	strncpy(tail->var_name, name, 32);
	strncpy(tail->var_type, type, 1);
	tail->var_count = count;
}

void set_Msg_to_errInfo(script_syntax_error_info *errlist, unsigned int linenum, script_syntax_error_code error_code, char *error_msg)
{
	script_syntax_error_info *tail = errlist;

	while(tail->linenum != 0)
	{
		tail ++;
	}
	tail->linenum = linenum - 1;	//linenum记录的是当前行的下一行
	tail->error_code = error_code;
	strncpy(tail->error_msg, error_msg, ERROR_MSG_LENGTH);
}

void show_errMsg(script_syntax_error_info *err_infolist)
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
	int len = 0;

	cp = line;
	while(isspace((int) *cp) && (*cp != '\0'))
	{
		cp ++;
	}
	cq = cp;
	if(*cp != '\0')
	{
		while((!isspace((int) *cp) && (*cp != '(') && (*cp != ';')) && (*cp != '\0'))
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
	char tmp_name[32] = {0};

	nv = nvp = strdup(buf);
	if(strchr(buf, '='))
	{
		p = strsep(&nvp, "=");

		if(q = strchr(buf, '['))
		{
			while(!isspace((int) *(p + i)) && (*(p + i) != '[') && (*(p + i) != '\n') && (*(p + i) != '\0'))
			{
				tmp_name[i] = p[i];
				i ++;
			}

			for(i = 1; *(q + i) != ']' && *(q + i) != '\0'; i ++, j ++)
			{
				var_count[j] = q[i];
			}

			count = atoi(var_count);
		}
		else
		{
			while(!isspace((int) *(p + i)) && (*(p + i) != '\n') && (*(p + i) != '\0'))
			{
				tmp_name[i] = p[i];
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
			while(!isspace((int) *(p + i)) && (*(p + i) != '[') && (*(p + i) != '\n') && (*(p + i) != '\0'))
			{
				tmp_name[i] = p[i];
				i ++;
			}

			for(i = 1; (*(q + i) != ']') && *(q + i) != '\0'; i ++, j ++)
			{
				var_count[j] = q[i];
			}

			count = atoi(var_count);
		}
		else
		{
			while(!isspace((int) *(p + i)) && (*(p + i) != '\n') && (*(p + i) != '\0'))
			{
				tmp_name[i] = p[i];
				i ++;
			}

			count = 1;
		}
	}
	free(nv);

	strncpy(var_name, tmp_name, 32);

	return count;
}

params_defined_info *get_params_info(params_defined_info *params_definfo, char *name)
{
	params_defined_info *head, *tail;
	char *ptr;

	tail = params_definfo;
	while(strlen(tail->var_name) != 0)
	{
		if(strcmp(tail->var_name, name) == 0)
		{
			break;
		}

		tail ++;
	}

	ptr = tail->var_name;
	head = container_of(ptr, params_defined_info, var_name);

	return head;
}

int cmd_check(char (*cmd_info)[16], char *cmd)
{
	char **cmds_ptr = script_cmds;

	while(*cmds_ptr)
	{
		if(strcmp(*cmds_ptr, cmd) == 0)
		{
			//将指令加入指令集
			add_cmd_to_cmdInfo(cmd_info, cmd);
			return 1;
		}

		cmds_ptr ++;
	}

	return 0;
}

int vartype_check(char *type, script_syntax_error_info *err_infolist, int LINENUM, char *error_msg_buf)
{
	char **vartype_ptr = scripts_vartype;
	int error_code = 0;

	while(*vartype_ptr)
	{
		if(strcmp(*vartype_ptr, type) == 0)
			return 0;

		vartype_ptr ++;
	}

	memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
	snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid variable type '%s' for V20\"", type);
	set_Msg_to_errInfo(err_infolist, LINENUM, ERR_VARTYPE_INVALID, error_msg_buf);
	error_code |= ERR_VARTYPE_INVALID;

	return error_code;
}

int aidi_type_check(char *var_name, char *var_type)
{
	int err_flag = 0;

	if(strcmp(var_name, "DI") == 0)
	{
		if(strncmp(var_type, "B", 1) != 0)
		{
			err_flag = 1;
		}
	}

	if(strcmp(var_name, "AI") == 0)
	{
		if(strncmp(var_type, "W", 1) != 0)
		{
			err_flag = 1;
		}
	}

	return err_flag;
}

int cmds_format_check(char *line, char *var_name_b)
{
	int err_flag = 0;
	char *p;

	p = strstr(line, var_name_b);

	p += strlen(var_name_b);

	while(isspace((int) *p) && *p != '\0')
		p ++;

	if(*p != ';' && *p != '\n' && *p != '\0')
		err_flag = 1;

	return err_flag;
}

int cmds_format_checkout(char *line, char *var_name_b, script_syntax_error_info *err_infolist, int LINENUM, char *error_msg_buf)
{
	int error_code = 0;

	if(strchr(line, '=') == NULL)
	{
		if(cmds_format_check(line, var_name_b))
		{
			memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
			snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"exist initial value without '='\"");
			set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);
			error_code |= ERR_FORMAT;	
		}
	}

	return error_code;
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

	return (n + 1);
}

int init_value_type_check(params_defined_info *params_definfo, char *line, char *var_name,\
							script_syntax_error_info *err_infolist, int LINENUM, char *error_msg_buf)
{
	params_defined_info *head;
	char *cp, *cq, tmp[16], cmd[16] = {0};
	int i = 0, len = 0, n = 0;
	int ex_flag = 0, error_code = 0;
	int counter = 0;

	get_cmd(cmd, line);
	head = get_params_info(params_definfo, var_name);
	if(strchr(line, '='))
	{
		//变量类型不为浮点型则检查
		if(!strcmp(cmd, "VARS") || !strcmp(cmd, "INTFS"))	//数组
		{
			if(cp = strchr(line, '{'))
			{
				cp ++;
				while(1)
				{
					memset(tmp, 0, 16);
					len = 0;
					n = 0;
					ex_flag = 0;
					while(((*cp == ' ') || (*cp == '\t') || (*cp == '\r')) && (*cp != '\0'))
					{
						cp ++;
					}
					cq = cp;
					if(*cp == '}' || *cp == ';' || *cp == '\n' || *cp == '\0')
					{
						break;
					}
					else
					{
						while((!isspace((int) *cp) && (*cp != ',')) && (*cp != '}') && (*cp != ';') && (*cp != '\0'))
						{
							cp ++;
							len ++;
						}
						if(len == 0)
						{
							cp ++;
							continue;
						}

						strncpy(tmp, cq, len);
						counter += 1;

						if((tmp[0] > '9' || tmp[0] < '0') && tmp[0] != '-')
							ex_flag = 1;

						for(i = 0; i < strlen(tmp); i ++)
						{
							if(*(tmp + i) == '.')
								n ++;

							if((*(tmp + i) > '9' || *(tmp + i) < '0') 
									&& (*(tmp + i) != '.' && *(tmp + i) != '-'))
							{
								ex_flag = 1;	
							}
						}
						if(n == 1 && !ex_flag)
						{
							cp = strchr(tmp, '.');
							if(*(cp + 1) > '9' || *(cp + 1) < '0')
							{
								memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
								snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid value '%s'\"", tmp);
								set_Msg_to_errInfo(err_infolist, LINENUM, ERR_VARTYPE_CONFUSING, error_msg_buf);

								error_code |= ERR_VARTYPE_CONFUSING;
							}
							if(strncmp(head->var_type, "F", 1) != 0)
							{
								memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
								snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"'%s' is float, but type of '%s' is '%s'\"", tmp, var_name, head->var_type);
								set_Msg_to_errInfo(err_infolist, LINENUM, ERR_VARTYPE_CONFUSING, error_msg_buf);

								error_code |= ERR_VARTYPE_CONFUSING;
							}
						}
						else if(n > 1 || ex_flag)
						{
							memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
							snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid value '%s'\"", tmp);
							set_Msg_to_errInfo(err_infolist, LINENUM, ERR_VARTYPE_CONFUSING, error_msg_buf);

							error_code |= ERR_VARTYPE_CONFUSING;
						}

						if(*cp == ',')
							cp ++;
					}
				}
			}
		}
		else	//非数组
		{
			memset(tmp, 0, 16);

			cp = strchr(line, '=');
			cp ++;
			while(((*cp == ' ') || (*cp == '\t') || (*cp == '\r')) && (*cp != '\0'))
			{
				cp ++;
			}
			cq = cp;
			if(*cp == ';' || *cp == '\n' || *cp == '\0')
			{
				memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
				snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid initial value or no initial value next to '='\"");
				set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);

				error_code |= ERR_FORMAT;
				return error_code;
			}
			while((!isspace((int) *cp)) && (*cp != ';') && (*cp != '\0'))
			{
				cp ++;
				len ++;
			}

			strncpy(tmp, cq, len);
			counter += 1;

			while(isspace((int) *cp) && (*cp != ';') && (*cp != '\n') && (*cp != '\0'))
			{
				cp ++;
			}
			if(*cp != ';' && *cp != '\n' && *cp != '\0')
			{
				memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
				snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid initial value\"");
				set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);

				error_code |= ERR_FORMAT;
			}

			if((tmp[0] > '9' || tmp[0] < '0') && tmp[0] != '-')
				ex_flag = 1;

			for(i = 0; i < strlen(tmp); i ++)
			{
				if(*(tmp + i) == '.')
					n ++;

				if((*(tmp + i) > '9' || *(tmp + i) < '0') 
						&& (*(tmp + i) != '.' && *(tmp + i) != '-'))
				{
					ex_flag = 1;	
				}
			}
			if(n == 1 && !ex_flag)	//正确的浮点数
			{
				cp = strchr(tmp, '.');
				if(*(cp + 1) > '9' || *(cp + 1) < '0')
				{
					memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid value '%s'\"", tmp);
					set_Msg_to_errInfo(err_infolist, LINENUM, ERR_VARTYPE_CONFUSING, error_msg_buf);

					error_code |= ERR_VARTYPE_CONFUSING;
				}
				if(strncmp(head->var_type, "F", 1) != 0)
				{
					memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"'%s' is float, but type of '%s' is '%s'\"", tmp, var_name, head->var_type);
					set_Msg_to_errInfo(err_infolist, LINENUM, ERR_VARTYPE_CONFUSING, error_msg_buf);

					error_code |= ERR_VARTYPE_CONFUSING;
				}
			}
			else if(n > 1 || ex_flag)
			{
				memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
				snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid value '%s'\"", tmp);
				set_Msg_to_errInfo(err_infolist, LINENUM, ERR_VARTYPE_CONFUSING, error_msg_buf);

				error_code |= ERR_VARTYPE_CONFUSING;
			}
		}

		n = arr_excess_check(line);
		if(n < counter)
		{
			memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
			snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"somewhere missing ','\"");
			set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);

			error_code |= ERR_FORMAT;
		}
	}

	return error_code;
}

int init_value_type_checkout(params_defined_info *params_definfo, char *line, char *var_name,\
                                  script_syntax_error_info *err_infolist, int LINENUM, char *error_msg_buf)
{
	int n = 0, error_code = 0;

	if(n = init_value_type_check(params_definfo, line, var_name, err_infolist, LINENUM, error_msg_buf))
	{
		if(n & ERR_VARTYPE_CONFUSING)
		{
			error_code |= ERR_VARTYPE_CONFUSING;	
		}
		if(n & ERR_FORMAT)
		{
			error_code |= ERR_FORMAT;	
		}
	}

	return error_code;
}

int variable_format_check(params_defined_info *params_definfo, char *cmd, char *var_name_b,\
							script_syntax_error_info *err_infolist, int LINENUM, char *error_msg_buf)
{
	params_defined_info *head;
	char var_name[32] = {0};
	int len = 0, error_code = 0;
	int i;
	
	for(i = 0; i < strlen(var_name_b); i ++)
	{
		if(*(var_name_b + i) == '[')
			len += 1;		
	}

	get_varname(var_name, var_name_b);
	head = get_params_info(params_definfo, var_name);
	if((head->var_count > 1) || (!strcmp(cmd, "VARS") || !strcmp(cmd, "INTFS") || !strcmp(cmd, "CTRLS") || !strcmp(cmd, "UCTRLS")))
	{
		if(len == 0)
		{
			memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
			snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"expected '[]' for '%s'\"", var_name);
			set_Msg_to_errInfo(err_infolist, LINENUM, ERR_DEFVAR_CONFUSING, error_msg_buf);
			error_code |= ERR_DEFVAR_CONFUSING;	
		}
		else if(len > 1)
		{
			memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
			snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"V20 only support one-demensional array\"");
			set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);
			error_code |= ERR_FORMAT;	
		}
	}
	else if(head->var_count == 1)
	{
		if(strchr(var_name_b, '['))
		{
			memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
			snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"unexpected '[]' for '%s' or confusing definition for '%s' before\"", var_name, var_name);
			set_Msg_to_errInfo(err_infolist, LINENUM, ERR_DEFVAR_CONFUSING, error_msg_buf);
			error_code |= ERR_DEFVAR_CONFUSING;
		}
	}

	return error_code;
}

int variable_format_checkout(params_defined_info *params_definfo, char *cmds, char *var_name_b,\
							script_syntax_error_info *err_infolist, int LINENUM, char *error_msg_buf)
{
	int n = 0, error_code = 0;

	if(n = variable_format_check(params_definfo, cmds, var_name_b, err_infolist, LINENUM, error_msg_buf))
	{
		if(n & ERR_DEFVAR_CONFUSING)
		{
			error_code |= ERR_DEFVAR_CONFUSING;
		}
		if(n & ERR_FORMAT)
		{
			error_code |= ERR_FORMAT;
		}
	}

	return error_code;
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
		return 1;
	}

	return 0;
}

int check_equals(char *line)
{
	int len = strlen(line);
	int i, num = 0;
	char cmd[32] = {0};

	get_cmd(cmd, line);
	if(strchr(line, '='))
	{
		for(i = 0; i < len; i ++)
		{
			if(*(line + i) == '=')
				num += 1;
		}

		if(strcmp(cmd, "IF"))
		{
			if(num > 1)
			{
				return 1;
			}
		}
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
			err_flag = 1;
		}
	}

	if(strcmp(var_name, "AI") == 0)
	{
		if(var_count > AI_REGISTER_NUM)
		{
			err_flag = 1;
		}
	}

	return err_flag;
}

int arr_format_check(char *line)
{
	int len;
	int i, j, error_code = 0;
	char *p, tmp[LINE_SIZE] = {0};

	p = strchr(line, '{');
	len = strlen(p);
	for(i = 0, j = 0; i < len; i ++)
	{
		if(!isspace((int) *(p + i)) && *(p + i) != '\0')
			tmp[j++] = p[i];
	}

	for(i = 0; i < strlen(tmp) - 1; i ++)
	{
		if(((*(tmp + i) == ',') || (*(tmp + i) == '{')) && ((*(tmp + i + 1) == ',') || (*(tmp + i + 1) == '}'))) 
		{
			return 1;
		}
	}

	return 0;
}

int endsymbol_check(char *line, script_syntax_error_info *err_infolist, int LINENUM, char *error_msg_buf)
{
	char *p = NULL, *q = NULL, *l = NULL, cmd[16] = {0};
	int i, k = 0;
	int err_flag = 0;

	get_cmd(cmd, line);
	if(!strcmp(cmd, "IF") || !strcmp(cmd, "ELSE") || !strcmp(cmd, "ENDIF"))
	{
		p = strchr(line, '\n');
		q = strchr(line, ';');

		if(q != NULL)
		{
			memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
			snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"unexpected ';' for '%s'\"", cmd);
			set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);

			err_flag = 1;
		}

		if(p == NULL)
		{
			memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
			snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"expected '\\n' at the end\"");
			set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);

			err_flag = 1;
		}
	}
	else
	{
		for(i = 0; i < strlen(line); i ++)
		{
			if(line[i] == ';')
				k ++;
		}

		if(k < 1)
		{
			memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
			snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"expected ';' at the end\"");
			set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);

			err_flag = 1;
		}
		else	
		{
			if(k > 1)
			{
				memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
				snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too more ';' in the line\"");
				set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);

				err_flag = 1;
			}

			l = strrchr(line, ';');
			l ++; 
			while(isspace((int) *l) && (*l != '\0'))
			{
				l ++;
			}
			if((*l != '\n') && (*l != '\0'))
			{
				memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
				snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"';' is not at end of the line\"");
				set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);

				err_flag = 1;
			}
		}
	}

	return err_flag;
}

int regAddr_confdef_check(int *regAddr_info, int addr)
{
	int i = 0;

	while(*(regAddr_info + i))
	{
		if(regAddr_info[i] == addr)
		{
			return 1;
		}

		i ++;
	}

	regAddr_info[i] = addr;

	return 0;
}

int params_confdef_check(params_defined_info *params_definfo, char *name, char *type, unsigned int count,\
								script_syntax_error_info *err_infolist, int LINENUM, char *error_msg_buf)
{
	params_defined_info *tail = params_definfo;
	int error_code = 0;

	while(strlen(tail->var_name) != 0)
	{
		if(strcmp(tail->var_name, name) == 0)
		{
			memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
			snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"conflicting types for '%s'\"", name);
			set_Msg_to_errInfo(err_infolist, LINENUM, ERR_DEFVAR_CONFLICTING, error_msg_buf);
			error_code |= ERR_DEFVAR_CONFLICTING;
			return error_code;
		}

		tail ++;
	}

	add_variable_to_defInfo(params_definfo, name, type, count);	//若没定义则加入参数定义数组中

	return 0;
}

int params_undefined_check(params_defined_info *params_definfo, char *name,\
						script_syntax_error_info *err_infolist, int LINENUM, char *error_msg_buf)
{
	params_defined_info *tail = params_definfo;
	int error_code = 0;

	while(strlen(tail->var_name) != 0)
	{
		if(strcmp(tail->var_name, name) == 0)
		{
			return 0;
		}

		tail ++;
	}

	memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
	snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"'%s' undefined\"", name);
	set_Msg_to_errInfo(err_infolist, LINENUM, ERR_PARAM_UNDEFINED, error_msg_buf);
	error_code |= ERR_PARAM_UNDEFINED;	

	return error_code;
}

int cal_format_check(char *line, script_syntax_error_info *err_infolist, int LINENUM, char *error_msg_buf)
{
	//两个操作符不能相邻，数字不能被分隔开(此处包括空格和TAB键)，例如3 * 5 78 /+ 2	1之类的
	char *op_characters[] = {"~", "+", "-", "*", "/", "&", "|", "^", "<<", ">>", NULL};
	char **p, tmp[8];
	int i = 0, op_flag = 0;
	int error_flag = 0;

	if(strchr(line, '=') == NULL)
	{
		memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
		snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"expected '=' for 'CAL'\"");
		set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);

		error_flag = 1;
	}

	while(*(line + i))
	{
		p = op_characters;
		memset(tmp, 0, sizeof(tmp));
		if(!isspace((int) *(line + i)))
		{
			if(*(line + i) == '>')
			{
				if((*(line + i + 1) == '>') && (*(line + i + 2) != '>'))
				{
					strcpy(tmp, ">>");
				}
				else
				{
					memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"exist unknown operator\"");
					set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);

					error_flag = 1;
				}
			}
			else if(*(line + i) == '<')
			{
				if((*(line + i + 1) == '<') && (*(line + i + 2) != '<'))
				{
					strcpy(tmp, "<<");
				}
				else
				{
					memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"exist unknown operator\"");
					set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);

					error_flag = 1;
				}
			}
			else 
			{
				tmp[0] = *(line + i);
			}

			if(*(line + i) == '-')	//区分减号还是负号
			{
				if((*(line + i + 1) >= '0') && (*(line + i + 1) <= '9'))	
				{
					i ++;
					continue;
				}
			}

			if(op_flag)
			{
				while(*p)
				{
					if(!strcmp(tmp, *p) || !strcmp(tmp, ";"))
					{
						if(strcmp(tmp, "~"))
						{
							memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
							snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"expected expression before '%s' token\"", tmp);
							set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);

							error_flag = 1;
							break;
						}
					}
					p ++;
				}
				if(*p == NULL)
				{
					op_flag = 0;
				}
			}

			p = op_characters;
			while(*p)
			{
				if(!strcmp(*p, tmp))
				{
					op_flag = 1;
					break;
				}
				p ++;
			}
			if(*p == NULL)
			{
				op_flag = 0;
			}
		}

		if(strlen(tmp) != 0)
			i += strlen(tmp);
		else
			i ++;
	}

	return error_flag;
}

int defvar_preversion_check(char (*cmd_info)[16], script_syntax_error_info *err_infolist, int LINENUM, char *error_msg_buf)
{
	char (*p)[16] = cmd_info;
	int error_code = 0;

	while(strlen(*p) != 0)
	{
		if(strcmp(*p, "SET_ADDR") && strcmp(*p, "VAR") && strcmp(*p, "VARS") && strcmp(*p, "INTF") && strcmp(*p, "INTFS")\
			&& strcmp(*p, "ALARM") && strcmp(*p, "CTRL") && strcmp(*p, "CTRLS") && strcmp(*p, "UCTRL") && strcmp(*p, "UCTRLS"))
		{
			memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
			snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"variable defined after excuting\"");
			set_Msg_to_errInfo(err_infolist, LINENUM, ERR_DEFVAR_PREVERSION, error_msg_buf);
			error_code |= ERR_DEFVAR_PREVERSION;
			return error_code;
		}

		p ++;
	}

	return 0;
}

int scripts_oversize(unsigned int scripts_len)
{
	if(scripts_len > MAX_SCRIPTS_LENGTH)
	{
		return 1;
	}
	
	return 0;
}

int ctrl_output_check(char (*cmd_info)[16])
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

	return err_flag;
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

	p = Mstr;
	while(*p != '\0')
	{
		q = substr;

	    while((*p != *q) && (*p != '\0'))
	        p ++;

	    while((*p == *q) && (*p != '\0') && (*q != '\0'))
	    {
	        p ++;
	        q ++;
	    }

	    if((*q == '\0') && (*p != '=') && (*p != '&') && (*p != '|'))
		{
			number ++;       							
	    }

		if((*p == '=') || (*p == '&') || (*p == '|'))
			p ++;
	}

	return number;
}

int brackets_exist_check(char *str)	//only for IF
{
	int brackets_count = 0, symbols_count = 0;
	char *symbols_info[] = {"==", "!=", "<", "<=", ">", ">=", "&&", "||", "&", "|", NULL};
	char **p, *q;
	int err_flag = -1;

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
	{
		err_flag = 1;
	}
	else if((brackets_count == 1) && (symbols_count == 1))
	{
		err_flag = 0;
	}
	else if((symbols_count == 2 * brackets_count - 1) || (symbols_count == 2 * brackets_count - 3))
	{
		err_flag = 0;
	}
	else
	{
		err_flag = 2;
	}
	
	return (err_flag);
}

int existIFbefore_check(char (*cmd_info)[16], char *cmd)
{
	char (*p)[16] = cmd_info;
	int err_flag = 1;

	while(strlen(*p) != 0)
	{
		if(!strcmp(*p, "IF"))
		{
			err_flag = 0;
		}
		p ++;
	}

	return err_flag;
}

int check_if_endif(char (*cmd_info)[16])
{
	char (*p)[16], (*q)[16];
	int if_count = 0, endif_count = 0;

 	p = q = cmd_info;

	while(strlen(*p) != 0)
	{
		if(!strcmp(*p, "IF"))
		{
			if_count += 1;	
		}
		p ++;
	}

	while(strlen(*q) != 0)
	{
		if(!strcmp(*q, "ENDIF"))
		{
			endif_count += 1;
		}

		q ++;
	}

	if(if_count != endif_count)
		return 1;

	return 0;
}

int NestofIF_check(char (*cmd_info)[16])
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
	if(if_index != 0)
	{
		if((if_index < endif_index) || (endif_index == 0))	//说明嵌套超过3层了
		{
			return 1;	
		}
	}

	return 0;
}

void show_cmdInfo(char (*cmd_info)[16])
{
	char (*p)[16] = cmd_info;

	printf("cmd_info:\n");
	while(strlen(*p) != 0)
	{
		printf("%s\n", *p);

		p ++;
	}
}

void show_params_defined(params_defined_info *params_definfo)
{
	int i;

	printf("Defined params:\n");
	printf("variable name\tvariable type\tvariable counter\n");
	for(i = 0; params_definfo[i].var_count != 0; i ++)
		printf("%s\t\t%s\t\t%d\n", params_definfo[i].var_name, params_definfo[i].var_type, params_definfo[i].var_count);
}

int scripts_checkout(const char *scripts)
{
	int error_code = 0, LINENUM = 1;
	char line[LINE_SIZE];
	char cmds[16];			
	int i, j, n, len;
	char *p, *nv, *nvp, *cp, *cq;
	char *cmd, *regAddr, *var_type, *var_name_b, *alarm_name;
	char var_name[16], tmp_name[16];
	int var_count = 0;	//元素的个数，针对数组变量来说，单个变量为1
	char *start_num, *read_count;	//读入寄存器的开始编号及个数
	char *modbus_cmd, *overtime;
	params_defined_info *head;
	unsigned int cur_size = 0, line_size, total_size;
	script_syntax_error_info err_infolist[ERROR_NUM] = {0};	//每个错误(错误码可重复)对应一个struct类型的信息
	params_defined_info params_definfo[PARAMS_TOTAL_NUM] = {0};	//已定义的参数及其类型
	char error_msg_buf[ERROR_MSG_LENGTH] = {0};	//错误具体提示信息
	char cmd_info[1024][16] = {0};
	int regAddr_info[1024] = {0};

	if(scripts == NULL)
	{
		printf("Scripts is NULL.\n");
		//syslog(LOG_NOTICE, "Scripts is NULL.");
		
		return error_code;
	}

	total_size = strlen(scripts);

	if(scripts_oversize(total_size))
	{
		memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
		snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"the script size[%d] is more than MAX_SIZE[%d]\"", total_size, MAX_SCRIPTS_LENGTH);
		set_Msg_to_errInfo(err_infolist, 2, ERR_SCRIPTS_OVERSIZE, error_msg_buf);
		error_code |= ERR_SCRIPTS_OVERSIZE;	

		show_errMsg(err_infolist);	
		return error_code;
	}

	while(cur_size < total_size)
	{
		memset(line, 0, LINE_SIZE);
		line_size = scripts_getline(line, scripts, cur_size, &LINENUM);
		if(line_size >= LINE_SIZE)
		{
			memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
			snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too much size for one line\"");
			set_Msg_to_errInfo(err_infolist, LINENUM, ERR_SCRIPTS_OVERSIZE, error_msg_buf);
			error_code |= ERR_SCRIPTS_OVERSIZE;	

			show_errMsg(err_infolist);	
			return error_code;
		}

		cur_size += line_size;

		//空行
		if(is_null_line(line))
			continue;

		if(endsymbol_check(line, err_infolist, LINENUM, error_msg_buf))	//检查有无结束符
		{
			error_code |= ERR_FORMAT;
		}

		memset(cmds, 0, sizeof(cmds));
		get_cmd(cmds, line);

		if(cmd_check(cmd_info, cmds) == 0)	//检查指令是否合法
		{
			memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
			snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid commamd '%s' for V20\"", cmds);
			set_Msg_to_errInfo(err_infolist, LINENUM, ERR_CMD_INVALID, error_msg_buf);
			error_code |= ERR_CMD_INVALID;	
		}
		
		if(brackets_check(line))	//检查括号是否成对
		{
			memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
			snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"unpaired brackets\"");
			set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);
			error_code |= ERR_FORMAT;
		}

		if(check_equals(line))
		{
			memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
			snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too more '='\"");
			set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);
			error_code |= ERR_FORMAT;
		}

		nv = nvp = strdup(line);
		memset(var_name, 0, 16);
		if(!strcmp(cmds, "SET_ADDR"))
		{
			char *slave;

			n = vstrsep(nvp, "	; ", &cmd, &slave);
			if(n == 2)
			{
				if(atoi(slave) <= 0)
				{
					memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"unknown slave address \"");
					set_Msg_to_errInfo(err_infolist, LINENUM, ERR_INVALID_SLAVE, error_msg_buf);
					error_code |= ERR_INVALID_SLAVE;
				}
			}
			else
			{
				memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
				snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too few elements for '%s'\"", cmds);
				set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);
				error_code |= ERR_FORMAT;
			}
		}
		else if(!strcmp(cmds, "VAR") || !strcmp(cmds, "VARS"))
		{
			//检查是否指令开始执行后还存在变量定义的指令
			error_code |= defvar_preversion_check(cmd_info, err_infolist, LINENUM, error_msg_buf);

			n = vstrsep(nvp, "	; ", &cmd, &var_type, &var_name_b);
			if(n == 3)
			{
				//检查变量类型是否合法
				error_code |= vartype_check(var_type, err_infolist, LINENUM, error_msg_buf);

				var_count = get_varname(var_name, var_name_b);
				if(var_count <= 0)
				{
					memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid initializer '%s'\"", var_name);
					set_Msg_to_errInfo(err_infolist, LINENUM, ERR_PARAM_EXCESS, error_msg_buf);
					error_code |= ERR_PARAM_EXCESS;
				}
				//获取变量名，检查是否重复定义
				error_code |= params_confdef_check(params_definfo, var_name, var_type, var_count, err_infolist, LINENUM, error_msg_buf);
				//若变量为AI或DI，检查类型是否为B或W
				if(aidi_type_check(var_name, var_type))
				{
					memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid variable type '%s' for '%s'\"", var_type, var_name);
					set_Msg_to_errInfo(err_infolist, LINENUM, ERR_VARTYPE_CONFUSING, error_msg_buf);
					error_code |= ERR_VARTYPE_CONFUSING;
				}

				error_code |= cmds_format_checkout(line, var_name_b, err_infolist, LINENUM, error_msg_buf);

				//检测所赋的值是否与变量类型相对应，只需检查浮点型即可	
				error_code |= init_value_type_checkout(params_definfo, line, var_name, err_infolist, LINENUM, error_msg_buf);

				if(!strcmp(cmds, "VAR"))
				{
					if(strchr(var_name_b, '[') != NULL)
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"unexpected '[]' for 'VAR'\"");
						set_Msg_to_errInfo(err_infolist, LINENUM, ERR_DEFVAR_CONFUSING, error_msg_buf);
						error_code |= ERR_DEFVAR_CONFUSING;	
					}
				}
				if(!strcmp(cmds, "VARS"))
				{
					//检查数组变量格式
					error_code |= variable_format_checkout(params_definfo, cmds, var_name_b, err_infolist, LINENUM, error_msg_buf);
					//若变量为AI或DI，检查寄存器定义是否越界
					if(aidi_reg_check(var_name, var_count))
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"'%s' over range\"", var_name);
						set_Msg_to_errInfo(err_infolist, LINENUM, ERR_REG_OUTBOUNDS, error_msg_buf);
						error_code |= ERR_REG_OUTBOUNDS;
					}
					//若数组赋初值，检查所赋初值个数是否大于定义的个数及格式
					if(strchr(line, '='))
					{
						if(strchr(line, '{') == NULL)
						{
							memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
							snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid initial value or no initial value next to '='\"");
							set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);
							error_code |= ERR_FORMAT;	
						}
						else
						{
							if(arr_format_check(line))
							{
								memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
								snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid format in array initializer\"");
								set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);
								error_code |= ERR_FORMAT;
							}
							else
							{
								if(arr_excess_check(line) > var_count)
								{
									memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
									snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"excess elements in array initializer\"");
									set_Msg_to_errInfo(err_infolist, LINENUM, ERR_PARAM_EXCESS, error_msg_buf);
									error_code |= ERR_PARAM_EXCESS;
								}
							}
						}
					}
				}
			}
			else
			{
				memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
				snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too few elements for '%s'\"", cmds);
				set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);
				error_code |= ERR_FORMAT;
			}
		}
		else if(!strcmp(cmds, "INTF") || !strcmp(cmds, "INTFS"))
		{
			//检查是否指令开始执行后还存在变量定义的指令
			error_code |= defvar_preversion_check(cmd_info, err_infolist, LINENUM, error_msg_buf);

			n = vstrsep(nvp, "	; ", &cmd, &regAddr, &var_type, &var_name_b);
			if(n == 4)
			{
				//检查地址是否越界
				if(atoi(regAddr) > MAX_REGISTER_NUM)
				{
					memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"available registers can not beyond 65535\"");
					set_Msg_to_errInfo(err_infolist, LINENUM, ERR_REG_OUTBOUNDS, error_msg_buf);

					error_code |= ERR_REG_OUTBOUNDS;
				}
				else
				{
					//检查地址是否被其它变量占用
					if(regAddr_confdef_check(regAddr_info, atoi(regAddr)))
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"'%s' has been used before\"", regAddr);
						set_Msg_to_errInfo(err_infolist, LINENUM, ERR_REG_OUTBOUNDS, error_msg_buf);
						error_code |= ERR_REG_OUTBOUNDS;
					}
				}
				//检查变量类型是否合法
				error_code |= vartype_check(var_type, err_infolist, LINENUM, error_msg_buf);

				var_count = get_varname(var_name, var_name_b);
				if(var_count <= 0)
				{
					memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid initializer '%s'\"", var_name);
					set_Msg_to_errInfo(err_infolist, LINENUM, ERR_PARAM_EXCESS, error_msg_buf);
					error_code |= ERR_PARAM_EXCESS;
				}
				//获取变量名，检查是否重复定义
				error_code |= params_confdef_check(params_definfo, var_name, var_type, var_count, err_infolist, LINENUM, error_msg_buf);
				//若变量为AI或DI，检查类型是否为B或W
				if(aidi_type_check(var_name, var_type))
				{
					memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid variable type '%s' for '%s'\"", var_type, var_name);
					set_Msg_to_errInfo(err_infolist, LINENUM, ERR_VARTYPE_CONFUSING, error_msg_buf);
					error_code |= ERR_VARTYPE_CONFUSING;
				}

				error_code |= cmds_format_checkout(line, var_name_b, err_infolist, LINENUM, error_msg_buf);

				//检测所赋的值是否与变量类型相对应，只需检查浮点型即可	
				error_code |= init_value_type_checkout(params_definfo, line, var_name, err_infolist, LINENUM, error_msg_buf);
				if(!strcmp(cmds, "INTF"))
				{
					if(strchr(var_name_b, '[') != NULL)
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"unexpected '[]' for 'INTF'\"");
						set_Msg_to_errInfo(err_infolist, LINENUM, ERR_DEFVAR_CONFUSING, error_msg_buf);
						error_code |= ERR_DEFVAR_CONFUSING;	
					}
				}
				if(!strcmp(cmds, "INTFS"))
				{
					//检查数组变量格式
					error_code |= variable_format_checkout(params_definfo, cmds, var_name_b, err_infolist, LINENUM, error_msg_buf);
					//若变量为AI或DI，检查寄存器定义是否越界
					if(aidi_reg_check(var_name, var_count))
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"'%s' over range\"", var_name);
						set_Msg_to_errInfo(err_infolist, LINENUM, ERR_REG_OUTBOUNDS, error_msg_buf);
						error_code |= ERR_REG_OUTBOUNDS;
					}
					//若数组赋初值，检查所赋初值个数是否大于定义的个数及格式
					if(strchr(line, '='))
					{
						if(strchr(line, '{') == NULL)
						{
							memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
							snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid initial value or no initial value next to '='\"");
							set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);
							error_code |= ERR_FORMAT;	
						}
						else
						{
							if(arr_format_check(line))
							{
								memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
								snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid format in array initializer\"");
								set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);
								error_code |= ERR_FORMAT;
							}
							else
							{
								if(arr_excess_check(line) > var_count)
								{
									memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
									snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"excess elements in array initializer\"");
									set_Msg_to_errInfo(err_infolist, LINENUM, ERR_PARAM_EXCESS, error_msg_buf);
									error_code |= ERR_PARAM_EXCESS;
								}
							}
						}
					}
				}
			}
			else
			{
				memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
				snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too few elements for '%s'\"", cmds);
				set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);
				error_code |= ERR_FORMAT;	
			}
		}
		else if(!strcmp(cmds, "CTRL") || !strcmp(cmds, "CTRLS"))
		{
			//检查是否指令开始执行后还存在变量定义的指令
			error_code |= defvar_preversion_check(cmd_info, err_infolist, LINENUM, error_msg_buf);

			n = vstrsep(nvp, "	; ", &cmd, &regAddr, &var_type, &var_name_b);
			if(n == 4)
			{
				//检查地址是否越界
				if(atoi(regAddr) > MAX_REGISTER_NUM)
				{
					memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"available registers can not beyond 65535\"");
					set_Msg_to_errInfo(err_infolist, LINENUM, ERR_REG_OUTBOUNDS, error_msg_buf);
					error_code |= ERR_REG_OUTBOUNDS;
				}
				else
				{
					//检查地址是否被其它变量占用
					if(regAddr_confdef_check(regAddr_info, atoi(regAddr)))
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"'%s' has been used before\"", regAddr);
						set_Msg_to_errInfo(err_infolist, LINENUM, ERR_REG_OUTBOUNDS, error_msg_buf);
						error_code |= ERR_REG_OUTBOUNDS;
					}
				}
				//检查变量类型是否合法
				error_code |= vartype_check(var_type, err_infolist, LINENUM, error_msg_buf);

				var_count = get_varname(var_name, var_name_b);
				if(var_count <= 0)
				{
					memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid initializer '%s'\"", var_name);
					set_Msg_to_errInfo(err_infolist, LINENUM, ERR_PARAM_EXCESS, error_msg_buf);
					error_code |= ERR_PARAM_EXCESS;
				}
				//获取变量名，检查是否重复定义
				error_code |= params_confdef_check(params_definfo, var_name, var_type, var_count, err_infolist, LINENUM, error_msg_buf);

				error_code |= cmds_format_checkout(line, var_name_b, err_infolist, LINENUM, error_msg_buf);

				if(!strcmp(cmds, "CTRL"))
				{
					if(strchr(var_name_b, '[') != NULL)
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"unexpected '[]' for 'CTRL'\"");
						set_Msg_to_errInfo(err_infolist, LINENUM, ERR_DEFVAR_CONFUSING, error_msg_buf);
						error_code |= ERR_DEFVAR_CONFUSING;	
					}
					//检测所赋的值是否与变量类型相对应，只需检查浮点型即可	
					error_code |= init_value_type_checkout(params_definfo, line, var_name, err_infolist, LINENUM, error_msg_buf);
				}
				if(!strcmp(cmds, "CTRLS"))
				{
					//检查数组变量格式
					error_code |= variable_format_checkout(params_definfo, cmds, var_name_b, err_infolist, LINENUM, error_msg_buf);
					if(strchr(line, '='))
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"no need to value assignment for 'CTRLS'\"");
						set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);
						error_code |= ERR_FORMAT;
					}
				}
			}
			else
			{
				memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
				snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too few elements for '%s'\"", cmds);
				set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);
				error_code |= ERR_FORMAT;	
			}
		}
		else if(!strcmp(cmds, "UCTRL") || !strcmp(cmds, "UCTRLS"))
		{
			char *mb_regAddr;

			//检查是否指令开始执行后还存在变量定义的指令
			error_code |= defvar_preversion_check(cmd_info, err_infolist, LINENUM, error_msg_buf);

			n = vstrsep(nvp, "	; ", &cmd, &regAddr, &mb_regAddr, &var_type, &var_name_b);
			if(n == 5)
			{
				//检查地址是否越界
				if(atoi(regAddr) > MAX_REGISTER_NUM)
				{
					memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"available registers can not beyond 65535\"");
					set_Msg_to_errInfo(err_infolist, LINENUM, ERR_REG_OUTBOUNDS, error_msg_buf);

					error_code |= ERR_REG_OUTBOUNDS;
				}
				else
				{
					//检查地址是否被其它变量占用
					if(regAddr_confdef_check(regAddr_info, atoi(regAddr)))
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"'%s' has been used before\"", regAddr);
						set_Msg_to_errInfo(err_infolist, LINENUM, ERR_REG_OUTBOUNDS, error_msg_buf);
						error_code |= ERR_REG_OUTBOUNDS;
					}
				}
				//检查变量类型是否合法
				error_code |= vartype_check(var_type, err_infolist, LINENUM, error_msg_buf);

				var_count = get_varname(var_name, var_name_b);
				if(var_count <= 0)
				{
					memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid initializer '%s'\"", var_name);
					set_Msg_to_errInfo(err_infolist, LINENUM, ERR_PARAM_EXCESS, error_msg_buf);
					error_code |= ERR_PARAM_EXCESS;
				}
				//获取变量名，检查是否重复定义
				error_code |= params_confdef_check(params_definfo, var_name, var_type, var_count, err_infolist, LINENUM, error_msg_buf);

				error_code |= cmds_format_checkout(line, var_name_b, err_infolist, LINENUM, error_msg_buf);

				if(!strcmp(cmds, "UCTRL"))
				{
					if(strchr(var_name_b, '[') != NULL)
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"unexpected '[]' for 'UCTRL'\"");
						set_Msg_to_errInfo(err_infolist, LINENUM, ERR_DEFVAR_CONFUSING, error_msg_buf);
						error_code |= ERR_DEFVAR_CONFUSING;	
					}
					//检测所赋的值是否与变量类型相对应，只需检查浮点型即可	
					error_code |= init_value_type_checkout(params_definfo, line, var_name, err_infolist, LINENUM, error_msg_buf);
				}
				if(!strcmp(cmds, "UCTRLS"))
				{
					//检查数组变量格式
					error_code |= variable_format_checkout(params_definfo, cmds, var_name_b, err_infolist, LINENUM, error_msg_buf);
					if(strchr(line, '='))
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"no need to value assignment for 'UCTRLS'\"");
						set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);
						error_code |= ERR_FORMAT;
					}
				}
			}
			else
			{
				memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
				snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too few elements for '%s'\"", cmds);
				set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);
				error_code |= ERR_FORMAT;	
			}
		}
		else if(!strcmp(cmds, "ALARM"))
		{
			//检查是否指令开始执行后还存在变量定义的指令
			error_code |= defvar_preversion_check(cmd_info, err_infolist, LINENUM, error_msg_buf);

			n = vstrsep(nvp, "	; ", &cmd, &regAddr, &var_type, &var_name_b);
			if(n == 4)
			{
				//检查地址是否越界
				if(atoi(regAddr) > MAX_REGISTER_NUM)
				{
					memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"available registers can not beyond 65535\"");
					set_Msg_to_errInfo(err_infolist, LINENUM, ERR_REG_OUTBOUNDS, error_msg_buf);

					error_code |= ERR_REG_OUTBOUNDS;
				}
				else
				{
					//检查地址是否被其它变量占用
					if(regAddr_confdef_check(regAddr_info, atoi(regAddr)))
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"address '%s' has been used before\"", regAddr);
						set_Msg_to_errInfo(err_infolist, LINENUM, ERR_REG_OUTBOUNDS, error_msg_buf);
						error_code |= ERR_REG_OUTBOUNDS;
					}
				}
				//检查变量类型是否合法
				error_code |= vartype_check(var_type, err_infolist, LINENUM, error_msg_buf);

				var_count = get_varname(var_name, var_name_b);
				if(var_count <= 0)
				{
					memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid initializer '%s'\"", var_name);
					set_Msg_to_errInfo(err_infolist, LINENUM, ERR_PARAM_EXCESS, error_msg_buf);
					error_code |= ERR_PARAM_EXCESS;
				}
				//获取变量名，检查是否重复定义
				error_code |= params_confdef_check(params_definfo, var_name, var_type, var_count, err_infolist, LINENUM, error_msg_buf);

				error_code |= cmds_format_checkout(line, var_name_b, err_infolist, LINENUM, error_msg_buf);

				//检测所赋的值是否与变量类型相对应，只需检查浮点型即可	
				error_code |= init_value_type_checkout(params_definfo, line, var_name, err_infolist, LINENUM, error_msg_buf);

				if(strchr(var_name_b, '[') != NULL)
				{
					memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"unexpected '[]' for 'ALARM'\"");
					set_Msg_to_errInfo(err_infolist, LINENUM, ERR_DEFVAR_CONFUSING, error_msg_buf);
					error_code |= ERR_DEFVAR_CONFUSING;	
				}
			}
			else
			{
				memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
				snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too few elements for '%s'\"", cmds);
				set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);
				error_code |= ERR_FORMAT;	
			}
		}
		else if(!strcmp(cmds, "SET_AL") || !strcmp(cmds, "REL_AL"))
		{
			int m, alarm_count;
			int err_flag = 0;

			memset(tmp_name, 0, 16);
			n = vstrsep(nvp, "	;, ", &cmd, &alarm_name, &var_name_b);
			if(n == 3)
			{
				//获取变量名
				var_count = get_varname(var_name, var_name_b);
				alarm_count = get_varname(tmp_name, alarm_name);
				if(var_count <= 0)
				{
					memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid element subscript for '%s'\"", var_name);
					set_Msg_to_errInfo(err_infolist, LINENUM, ERR_PARAM_EXCESS, error_msg_buf);
					error_code |= ERR_PARAM_EXCESS;
				}
				if(alarm_count <= 0)
				{
					memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid element subscript for '%s'\"", tmp_name);
					set_Msg_to_errInfo(err_infolist, LINENUM, ERR_PARAM_EXCESS, error_msg_buf);
					error_code |= ERR_PARAM_EXCESS;
				}
				//检查变量是否定义
				n = params_undefined_check(params_definfo, var_name, err_infolist, LINENUM, error_msg_buf);
				m = params_undefined_check(params_definfo, tmp_name, err_infolist, LINENUM, error_msg_buf);
				if(!n && !m)
				{
					//检查数组变量格式
					error_code |= variable_format_checkout(params_definfo, cmds, var_name_b, err_infolist, LINENUM, error_msg_buf);
					error_code |= variable_format_checkout(params_definfo, cmds, alarm_name, err_infolist, LINENUM, error_msg_buf);

					head = get_params_info(params_definfo, var_name);
					if(var_count > head->var_count)
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"register beyond access for '%s'\"", var_name);
						set_Msg_to_errInfo(err_infolist, LINENUM, ERR_REG_OUTBOUNDS, error_msg_buf);
						error_code |= ERR_REG_OUTBOUNDS;
					}
					head = get_params_info(params_definfo, tmp_name);
					if(alarm_count > head->var_count)
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"register beyond access for '%s'\"", tmp_name);
						set_Msg_to_errInfo(err_infolist, LINENUM, ERR_REG_OUTBOUNDS, error_msg_buf);
						error_code |= ERR_REG_OUTBOUNDS;
					}
					char timing[8] = {0};

					p = strstr(line, var_name_b);
					p += strlen(var_name_b);

					while(isspace((int) *p) || *p == ',' && *p != '\0')
						p ++;

					i = 0;
					while(*p != ';' && *p != '\n' && *p != '\0')
					{
						timing[i ++] = *(p ++);	
					}
					if(strlen(timing) == 0)
					{
						p --; //Now the pointer 'p' is pointing ';'
						while(isspace((int) *p)) p --;
						if(*p == ',')
						{
							memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
							snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"unexpected ',' before ';'\"");
							set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);
							error_code |= ERR_FORMAT;	
						}
					}
					else
					{
						if(atoi(timing) < 0)
						{
							err_flag = 1;
						}
						for(i = 0; i < strlen(timing); i++)
						{
							if((timing[i] < '0' || timing[i] > '9') && !isspace((int) *(timing + i)))
							{
								err_flag = 1;
							}
						}
						if(err_flag)
						{
							memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
							snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid value for timing\"");
							set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);
							error_code |= ERR_FORMAT;
						}
					}
				}
				else
				{
					error_code |= n;
					error_code |= m;
				}
			}
			else
			{
				memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
				snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too few elements for '%s'\"", cmds);
				set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);
				error_code |= ERR_FORMAT;	
			}
		}
		else if(!strcmp(cmds, "SET_THV"))
		{
			char *thr_up, *thr_low;

			n = vstrsep(nvp, "	; ", &cmd, &var_name_b, &thr_low, &thr_up);
			if(n == 4)
			{
				if(cmds_format_check(line, thr_up))
				{
					memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too more elements for '%s'\"", cmds);
					set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);
					error_code |= ERR_FORMAT;	
				}
				//获取变量名
				var_count = get_varname(var_name, var_name_b);
				if(var_count <= 0)
				{
					memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid element subscript for '%s'\"", var_name);
					set_Msg_to_errInfo(err_infolist, LINENUM, ERR_PARAM_EXCESS, error_msg_buf);
					error_code |= ERR_PARAM_EXCESS;
				}
				//检查变量是否定义
				if(n = params_undefined_check(params_definfo, var_name, err_infolist, LINENUM, error_msg_buf))
				{
					error_code |= n;
				}
				else
				{
					//检查数组变量格式
					error_code |= variable_format_checkout(params_definfo, cmds, var_name_b, err_infolist, LINENUM, error_msg_buf);
					//检查变量类型
					if(strchr(thr_low, '.') || strchr(thr_up, '.'))
					{
						head = get_params_info(params_definfo, var_name);
						if(strncmp(head->var_type, "F", 1) != 0)
						{
							memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
							snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"threshold has float value, but type of '%s' is '%s'\"", var_name_b, head->var_type);
							set_Msg_to_errInfo(err_infolist, LINENUM, ERR_VARTYPE_CONFUSING, error_msg_buf);
							error_code |= ERR_VARTYPE_CONFUSING;	
						}
					}
					//检查阈值是否前小后大
					if(atoi(thr_low) > atoi(thr_up))
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH,"\"invalid initializer[low:%d > up:%d]\"", atoi(thr_low), atoi(thr_up));
						set_Msg_to_errInfo(err_infolist, LINENUM, ERR_THRESH, error_msg_buf);
						error_code |= ERR_THRESH;	
					}
				}
			}
			else
			{
				memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
				snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too few elements for '%s'\"", cmds);
				set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);
				error_code |= ERR_FORMAT;	
			}
		}
		else if(!strcmp(cmds, "CAL"))
		{
			int f = 0;
			char retvar_name[16];
			char retvar_type[2];
			i = 0;	//统计变量个数
			if(cal_format_check(line, err_infolist, LINENUM, error_msg_buf))
			{
				error_code |= ERR_FORMAT;	
			}

			cp = line;
			while(1)
			{
				memset(var_name, 0, 16);
				memset(tmp_name, 0, 16);
				len = 0;
				while(is_cal_operator(cp))
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
					while(is_not_cal_operator(cp))
					{
						cp ++;
						len ++;
					}
					strncpy(tmp_name, cq, len);

					if(strcmp(tmp_name, cmds))	//过滤指令CAL
					{
						//变量之间必须有操作符
						cq += strlen(tmp_name);

						while(isspace((int) *cq) && *cq != '\0')
							cq ++;

						if(lack_cal_operator(cq))
						{
							memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
							snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"expected operator after '%s' token\"", tmp_name);
							set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);

							error_code |= ERR_FORMAT;
						}

						if(tmp_name[0] < '0' || tmp_name[0] > '9')	//过滤常量
						{
							i ++;

							//检查数组变量格式
							error_code |= variable_format_checkout(params_definfo, cmds, tmp_name, err_infolist,LINENUM,error_msg_buf);

							var_count = get_varname(var_name, tmp_name);
							//检查变量是否定义
							if(n = params_undefined_check(params_definfo, var_name, err_infolist, LINENUM, error_msg_buf))
							{
								error_code |= n;
							}
							else
							{
								head = get_params_info(params_definfo, var_name);
								if(var_count > head->var_count)
								{
									memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
									snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"register beyond access for '%s'\"", var_name);
									set_Msg_to_errInfo(err_infolist, LINENUM, ERR_REG_OUTBOUNDS, error_msg_buf);
									error_code |= ERR_REG_OUTBOUNDS;
								}
								else if(var_count <= 0)
								{
									memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
									snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid element subscript for '%s'\"", var_name);
									set_Msg_to_errInfo(err_infolist, LINENUM, ERR_PARAM_EXCESS, error_msg_buf);
									error_code |= ERR_PARAM_EXCESS;
								}
								if(i == 1)
								{
									if(strncmp(head->var_type, "B", 1) == 0)	//结果变量是单字节
									{
										f = 1;
										memset(retvar_name, 0, 16);
										memset(retvar_type, 0, 2);
										strcpy(retvar_name, head->var_name);
										strncpy(retvar_type, head->var_type, 1);
									}
								}
								if(f && (i != 1))
								{
									if(strncmp(head->var_type, retvar_type, 1) != 0)
									{
										memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
										snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"type of '%s' don't match that of '%s'\"", var_name, retvar_name);
										set_Msg_to_errInfo(err_infolist, LINENUM, ERR_VARTYPE_CONFUSING, error_msg_buf);
										error_code |= ERR_VARTYPE_CONFUSING;	
									}
								}
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
					set_Msg_to_errInfo(err_infolist, LINENUM, ERR_PARAM_EXCESS, error_msg_buf);
					error_code |= ERR_PARAM_EXCESS;
				}
				if(!strcmp(cmds, "IN_D"))
				{
					//检查变量是否定义
					if(n = params_undefined_check(params_definfo, "DI", err_infolist, LINENUM, error_msg_buf))
					{
						error_code |= n;
					}
					else	
					{
						head = get_params_info(params_definfo, "DI");
						if((atoi(start_num) + atoi(read_count) - 1) > head->var_count)
						{
							memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
							snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"register beyond access for 'DI'\"");
							set_Msg_to_errInfo(err_infolist, LINENUM, ERR_REG_OUTBOUNDS, error_msg_buf);
							error_code |= ERR_REG_OUTBOUNDS;
						}
					}
				}
				if(!strcmp(cmds, "IN_A"))
				{
					//检查变量是否定义
					if(n = params_undefined_check(params_definfo, "AI", err_infolist, LINENUM, error_msg_buf))
					{
						error_code |= n;
					}
					else 
					{
						head = get_params_info(params_definfo, "AI");
						if((atoi(start_num) + atoi(read_count) - 1) > head->var_count)
						{
							memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
							snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"register beyond access for 'AI'\"");
							set_Msg_to_errInfo(err_infolist, LINENUM, ERR_REG_OUTBOUNDS, error_msg_buf);
							error_code |= ERR_REG_OUTBOUNDS;
						}
					}
				}
			}
			else
			{
				memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
				snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too few elements for '%s'\"", cmds);
				set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);
				error_code |= ERR_FORMAT;	
			}
		}
		else if(!strcmp(cmds, "IN_UD") || !strcmp(cmds, "IN_UD_B") || !strcmp(cmds, "IN_UA")	\
				 || !strcmp(cmds, "IN_UA_B") || !strcmp(cmds, "IN_UF_B") || !strcmp(cmds, "IN_UFD_B"))
		{
			char tmp[5] = {0};

			n = vstrsep(nvp, ", ;	", &cmd, &var_name_b, &read_count, &modbus_cmd, &overtime);
			if(n == 5)
			{
				var_count = get_varname(var_name, var_name_b);
				//检查变量是否定义
				if(n = params_undefined_check(params_definfo, var_name, err_infolist, LINENUM, error_msg_buf))
				{
					error_code |= n;
				}
				else
				{
					//检查数组变量格式
					error_code |= variable_format_checkout(params_definfo, cmds, var_name_b, err_infolist, LINENUM, error_msg_buf);
					if(var_count <= 0)
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid element subscript for '%s'\"", var_name);
						set_Msg_to_errInfo(err_infolist, LINENUM, ERR_PARAM_EXCESS, error_msg_buf);
						error_code |= ERR_PARAM_EXCESS;
					}
					//检查超时
					if(atoi(overtime) <= 0)
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid value for overtime\"");
						set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);
						error_code |= ERR_FORMAT;	
					}

					head = get_params_info(params_definfo, var_name);
					if((var_count + atoi(read_count) - 1) > head->var_count)
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"register beyond access for '%s'\"", var_name);
						set_Msg_to_errInfo(err_infolist, LINENUM, ERR_REG_OUTBOUNDS, error_msg_buf);
						error_code |= ERR_REG_OUTBOUNDS;
					}
					//检查modbus指令格式
					if(strlen(modbus_cmd) != 13)
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid modbus command for '%s'\"", cmds);
						set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);
						error_code |= ERR_FORMAT;	
					}
					else
					{
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
								set_Msg_to_errInfo(err_infolist, LINENUM, ERR_SERIAL_RDREG, error_msg_buf);
								error_code |= ERR_SERIAL_RDREG;	
							}
						}
						if(!strcmp(cmds, "IN_UF_B"))	
						{
							if(strncmp(head->var_type, "F", 1) != 0)
							{
								memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
								snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"type of '%s' must be 'F'\"", var_name);
								set_Msg_to_errInfo(err_infolist, LINENUM, ERR_VARTYPE_CONFUSING, error_msg_buf);
								error_code |= ERR_VARTYPE_CONFUSING;	
							}

							if((atoi(read_count) * 2) != str_to_hex(tmp))
							{
								memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
								snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"registers read of V20 don't match with that of modbus\"");
								set_Msg_to_errInfo(err_infolist, LINENUM, ERR_SERIAL_RDREG, error_msg_buf);
								error_code |= ERR_SERIAL_RDREG;	
							}
						}
						if(!strcmp(cmds, "IN_UFD_B"))	
						{
							if(strncmp(head->var_type, "F", 1) != 0)
							{
								memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
								snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"type of '%s' must be 'F'\"", var_name);
								set_Msg_to_errInfo(err_infolist, LINENUM, ERR_VARTYPE_CONFUSING, error_msg_buf);
								error_code |= ERR_VARTYPE_CONFUSING;	
							}

							if((atoi(read_count) * 4) != str_to_hex(tmp))
							{
								memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
								snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"registers read of V20 don't match with that of modbus\"");
								set_Msg_to_errInfo(err_infolist, LINENUM, ERR_SERIAL_RDREG, error_msg_buf);
								error_code |= ERR_SERIAL_RDREG;	
							}
						}
					}
				}
			}
			else
			{
				memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
				snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too few elements for '%s'\"", cmds);
				set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);
				error_code |= ERR_FORMAT;	
			}
		}
		else if(!strcmp(cmds, "IN_AE") || !strcmp(cmds, "IN_ACAE"))
		{
			char *per;

			n = vstrsep(nvp, ", ;	", &cmd, &var_name_b, &per, &read_count);
			if(n == 4)
			{
				var_count = get_varname(var_name, var_name_b);
				//检查变量是否定义
				if(n = params_undefined_check(params_definfo, var_name, err_infolist, LINENUM, error_msg_buf))
				{
					error_code |= n;
				}
				else 
				{
					//检查数组变量格式
					error_code |= variable_format_checkout(params_definfo, cmds, var_name_b, err_infolist, LINENUM, error_msg_buf);
					if(var_count <= 0)
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid element subscript for '%s'\"", var_name);
						set_Msg_to_errInfo(err_infolist, LINENUM, ERR_PARAM_EXCESS, error_msg_buf);
						error_code |= ERR_PARAM_EXCESS;
					}
					//检查变量类型是否是F
					head = get_params_info(params_definfo, var_name);
					if(strncmp(head->var_type, "F", 1) != 0)
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"type of '%s' must be 'F'\"", var_name);
						set_Msg_to_errInfo(err_infolist, LINENUM, ERR_VARTYPE_CONFUSING, error_msg_buf);
						error_code |= ERR_VARTYPE_CONFUSING;	
					}
					if((atoi(per) * atoi(read_count) + var_count - 1) > head->var_count)
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"register beyond access\"");
						set_Msg_to_errInfo(err_infolist, LINENUM, ERR_PARAM_EXCESS, error_msg_buf);
						error_code |= ERR_PARAM_EXCESS;
					}
				}
			}
			else
			{
				memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
				snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too few elements for '%s'\"", cmds);
				set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);
				error_code |= ERR_FORMAT;	
			}
		}
		else if(!strcmp(cmds, "IN_ATEMP") || !strcmp(cmds, "IN_AMVOL") || !strcmp(cmds, "IN_ABVOL"))
		{
			n = vstrsep(nvp, " ;	", &cmd, &var_name_b);
			if(n == 2)
			{
				var_count = get_varname(var_name, var_name_b);
				//检查变量是否定义
				if(n = params_undefined_check(params_definfo, var_name, err_infolist, LINENUM, error_msg_buf))
				{
					error_code |= n;
				}
				else 
				{
					//检查数组变量格式
					error_code |= variable_format_checkout(params_definfo, cmds, var_name_b, err_infolist, LINENUM, error_msg_buf);
					//检查变量类型是否是F
					head = get_params_info(params_definfo, var_name);
					if(strncmp(head->var_type, "F", 1) != 0)
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"type of '%s' must be 'F'\"", var_name);
						set_Msg_to_errInfo(err_infolist, LINENUM, ERR_VARTYPE_CONFUSING, error_msg_buf);
						error_code |= ERR_VARTYPE_CONFUSING;	
					}
				}
			}
			else
			{
				memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
				snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too few elements for '%s'\"", cmds);
				set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);
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
					set_Msg_to_errInfo(err_infolist, LINENUM, ERR_PARAM_EXCESS, error_msg_buf);
					error_code |= ERR_PARAM_EXCESS;
				}
			}
			else
			{
				memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
				snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too few elements for '%s'\"", cmds);
				set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);
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
					set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);
					error_code |= ERR_FORMAT;	
				}
				//检查modbus指令格式
				if(strlen(modbus_cmd) != 13)
				{
					memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid modbus command for '%s'\"", cmds);
					set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);
					error_code |= ERR_FORMAT;	
				}
			}
			else
			{
				memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
				snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too few elements for '%s'\"", cmds);
				set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);
				error_code |= ERR_FORMAT;	
			}
		}
		else if(!strcmp(cmds, "DO_CTRL"))
		{
			if(ctrl_output_check(cmd_info))
			{
				memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
				snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"no variable need to output by 'DO_CTRL'\"");
				set_Msg_to_errInfo(err_infolist, LINENUM, ERR_NO_CTRL_OUTPUT, error_msg_buf);
				error_code |= ERR_NO_CTRL_OUTPUT;	
			}
		}
		else if(!strcmp(cmds, "IF"))
		{
			//IF最多支持3层嵌套
			if(NestofIF_check(cmd_info))
			{
				memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
				snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too more nested levels for 'IF'\"");
				set_Msg_to_errInfo(err_infolist, LINENUM, ERR_IFCMD_EXCESS, error_msg_buf);
				error_code |= ERR_IFCMD_EXCESS;	
			}

			n = brackets_exist_check(line);
			if(n == 1)	//nothing behind of IF
			{
				memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
				snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid format for 'IF'\"");
				set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);
				error_code |= ERR_FORMAT;	
			}
			else if(n == 2)
			{
				memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
				snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"brackets and conditions are unmatched\"");
				set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);
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
					while(is_if_operator(cp))
					{
						cp ++;
					}
					cq = cp;
					if(*cp == '\0')
					{
						break;
					}
					else
					{
						while(is_not_if_operator(cp))
						{
							cp ++;
							len ++;
						}
						strncpy(tmp_name, cq, len);

						if((atoi(tmp_name) == 0) && (atof(tmp_name) == 0) && (strncmp(tmp_name, "0", 1)))	//过滤常量
						{
							//检查数组变量格式
							error_code |= variable_format_checkout(params_definfo, cmds, tmp_name, err_infolist,LINENUM,error_msg_buf);

							var_count = get_varname(var_name, tmp_name);
							//检查变量是否定义
							if(n = params_undefined_check(params_definfo, var_name, err_infolist, LINENUM, error_msg_buf))
							{
								error_code |= n;
							}
							else
							{
								head = get_params_info(params_definfo, var_name);
								if(var_count > head->var_count)
								{
									memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
									snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"register beyond access for '%s'\"", var_name);
									set_Msg_to_errInfo(err_infolist, LINENUM, ERR_REG_OUTBOUNDS, error_msg_buf);
									error_code |= ERR_REG_OUTBOUNDS;
								}
								else if(var_count <= 0)
								{
									memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
									snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid element subscript for '%s'\"", var_name);
									set_Msg_to_errInfo(err_infolist, LINENUM, ERR_PARAM_EXCESS, error_msg_buf);
									error_code |= ERR_PARAM_EXCESS;
								}
							}
						}
					}
				}
			}
		}
		else if(!strcmp(cmds, "ELSE") || !strcmp(cmds, "ENDIF"))
		{
			//检查之前是否有IF
			if(existIFbefore_check(cmd_info, cmds))
			{
				memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
				snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"no 'IF' before '%s'\"", cmds);
				set_Msg_to_errInfo(err_infolist, LINENUM, ERR_IFCMD_NO_MATCH, error_msg_buf);
				error_code |= ERR_IFCMD_NO_MATCH;
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
					set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);
					error_code |= ERR_FORMAT;	
				}
			}
			else
			{
				memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
				snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too few elements for '%s'\"", cmds);
				set_Msg_to_errInfo(err_infolist, LINENUM, ERR_FORMAT, error_msg_buf);
				error_code |= ERR_FORMAT;	
			}
		}

		free(nv);
	}

	//检测IF与ENDIF个数是否相等
	if(check_if_endif(cmd_info))
	{
		memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
		snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"'IF' don't match 'ENDIF'\"");
		set_Msg_to_errInfo(err_infolist, LINENUM, ERR_IFCMD_NO_MATCH, error_msg_buf);

		error_code |= ERR_IFCMD_NO_MATCH;
	}

//	show_cmdInfo(cmd_info);
//	show_params_defined(params_definfo);
	if(error_code)
	{
		show_errMsg(err_infolist);	
	}

	return error_code;
}

int main()
{
	int error_code = 0;
#if 1
	/*
	char *scripts =	"VARS W AI[12];\n"\
					"VARS B DI[4]={2,3,5,8};\n"\
					"VAR F tmp;\n"\
					"VAR F DA;\n"\
					"VAR W wspd = 5;\n"\
					"VAR F TEMP_V;\n"\
					"VAR F MAIN_VOL;\n"\
					"VAR F BATTERY_VOL;\n"\
					"VARS F UDI01[17] = {1, -2.4};\n"\
					"VARS F UAI02[17];\n"\
					"INTF 1004 F wspdx = 5.7;\n"\
					"INTFS 1000 B DIV[16];\n"\
					"INTFS 2018 F wsdu[2];\n"\
					"INTFS 2019 F AIV[2];\n"\
					"CTRL 4000 B LDO1;\n"\
					"CTRLS 4001 B LDOS[2];\n"\
					"UCTRL 4002 30001 B UDO1 = 0;\n"\
					"UCTRLS 4003 30001 B UDO2[2];\n"\
					"IN_D 1, 3;\n"\
					"IN_A 1, 1;\n"\
					"IF (tmp == 0)\n"\
					"ELSE\n"\
					"ENDIF\n"\
					"SET_THV tmp -20 30;\n"\
					"CAL DIV[1] = DI[1] + 2;\n"\
					"CAL tmp = AI[1] / 4096 * -3.3 / 165 * 1000 - 4;\n"\
					"CAL wsdu[1] = tmp * 100 / 16 + 0.0;\n"\
					"CAL tmp = AI[2] / 4096 * 3.3 / 165 * 1000 - 4;\n"\
					"CAL wsdu[2] = tmp * 100 / 16 - 20;\n"\
					"IN_UA wspd, 1, 020300160001A, 100;\n"\
					"IN_UD UDI01[1], 8, 090200000008A, 200;\n"\
					"IN_UF_B UAI02[1], 2, 010300000004A, 300;\n"\
					"IN_UFD_B DA, 1, 090300000004A, 400;\n"\
					"CAL wspdx = wspd + 10;\n"\
					"IN_ATEMP TEMP_V;\n"\
					"IN_AMVOL MAIN_VOL;\n"\
					"IN_ABVOL BATTERY_VOL;\n"\
					"IN_AE AIV[1], 1, 2;\n"\
					"IN_ACAE AIV[1], 1, 2;\n"\
					"OUT_U 09050001FF00A, 500;\n"\
					"OUT_D 16, 0;\n"\
					"DO_CTRL;\n"\
					"CONTINUE;\n"\
					"SLEEP 1000;";
	*/
	char *scripts =	"SET_ADDR 1;\n"\
					"INTFS 5025 B ARV[16];\n"\
					"INTFS 5000 F ART[12];\n"\
					"INTFS 5060 F WS[2];\n"\
					"ALARM 5100 F V_AP1;\n"\
					"ALARM 5102 F V_AP2;\n"\
					"ALARM 5104 F V_AP3;\n"\
					"ALARM 5106 F V_AP4;\n"\
					"ALARM 5108 F V_AP5;\n"\
					"ALARM 5110 F V_AP6;\n"\
					"ALARM 5112 B V_AP7;\n"\
					"VARS W RGC[12]={16,16,16,16,16,16,16,0,0,0,0,0};\n"\
					"VARS W RGR[12]={25,25,5,25,0,0,0,0,0,0,0,0};\n"\
					"VARS W AI[12];\n"\
					"VARS B DI[16];\n"\
					"VARS W WSTMP[2];\n"\
					"VARS F TMP[12];\n"\
					"IN_A 1,12;\n"\
					"IN_D 1,16;\n"\
					"IN_UA_B WSTMP[1],2,030300020002A,100;\n"\
					"CAL WS[1] = WSTMP[1] / 10;\n"\
					"CAL WS[2] = WSTMP[2] / 10;\n"\
					"CAL TMP[1] = AI[1] / 4096 * 3.3 / 165 * 1000 - 4;\n"\
					"CAL TMP[2] = AI[2] / 4096 * 3.3 / 165 * 1000 - 4;\n"\
					"CAL TMP[3] = AI[3] / 4096 * 3.3 / 165 * 1000 - 4;\n"\
					"CAL TMP[4] = AI[4] / 4096 * 3.3 / 165 * 1000 - 4;\n"\
					"CAL TMP[5] = AI[5] / 4096 * 3.3 / 165 * 1000 - 4;\n"\
					"CAL TMP[6] = AI[6] / 4096 * 3.3 / 165 * 1000 - 4;\n"\
					"CAL TMP[7] = AI[7] / 4096 * 3.3 / 165 * 1000 - 4;\n"\
					"CAL TMP[8] = AI[8] / 4096 * 3.3 / 165 * 1000 - 4;\n"\
					"CAL TMP[9] = AI[9] / 4096 * 3.3 / 165 * 1000 - 4;\n"\
					"CAL TMP[10] = AI[10] / 4096 * 3.3 / 165 * 1000 - 4;\n"\
					"CAL TMP[11] = AI[11] / 4096 * 3.3 / 165 * 1000 - 4;\n"\
					"CAL TMP[12] = AI[12] / 4096 * 3.3 / 165 * 1000 - 4;\n"\
					"CAL ART[1] = TMP[1] / RGC[1] * RGR[1] / 10;\n"\
					"CAL ART[2] = TMP[2] / RGC[2] * RGR[2] / 10;\n"\
					"CAL ART[3] = TMP[3] / RGC[3] * RGR[3];\n"\
					"CAL ART[4] = TMP[4] / RGC[4] * RGR[4] / 10;\n"\
					"CAL ART[5] = TMP[5] / RGC[5] * RGR[5];\n"\
					"CAL ART[6] = TMP[6] / RGC[6] * RGR[6];\n"\
					"CAL ART[7] = TMP[7] / RGC[7] * RGR[7];\n"\
					"CAL ART[8] = TMP[8] / RGC[8] * RGR[8];\n"\
					"CAL ART[9] = TMP[9] / RGC[9] * RGR[9];\n"\
					"CAL ART[10] = TMP[10] / RGC[10] * RGR[10];\n"\
					"CAL ART[11] = TMP[11] / RGC[11] * RGR[11];\n"\
					"CAL ART[12] = TMP[12] / RGC[12] * RGR[12];\n"\
					"IF(ART[1]>1.6) || (ART[1]<1)\n"\
					"	       SET_AL V_AP1,ART[1],10;\n"\
					"ELSE\n"\
					"	       REL_AL V_AP1,ART[1];\n"\
					"ENDIF\n"\
					"IF(ART[2]>1.6) || (ART[2]<1)\n"\
					"	       SET_AL V_AP2,ART[2],10;\n"\
					"ELSE\n"\
					"	       REL_AL V_AP2,ART[2];\n"\
					"ENDIF\n"\
					"IF(ART[3]>2.8) || (ART[3]<1.8)\n"\
					"	       SET_AL V_AP3,ART[3],10;\n"\
					"ELSE\n"\
					"	       REL_AL V_AP3,ART[3];\n"\
					"ENDIF\n"\
					"IF(ART[4]>1.4) || (ART[4]<0.8)\n"\
					"	       SET_AL V_AP4,ART[4],10;\n"\
					"ELSE\n"\
					"	       REL_AL V_AP4,ART[4];\n"\
					"ENDIF\n"\
					"IF(WS[1]>38) || (WS[1]<18)\n"\
					"	       SET_AL V_AP5,WS[1],10;\n"\
					"ELSE\n"\
					"	       REL_AL V_AP5,WS[1];\n"\
					"ENDIF\n"\
					"IF(WS[2]>80) || (WS[2]<30)\n"\
					"	       SET_AL V_AP6,WS[2],10;\n"\
					"ELSE\n"\
					"	       REL_AL V_AP6,WS[2];\n"\
					"ENDIF\n"\
					"IF (ARV[1] == 0)\n"\
					"	CAL ARV[1] = DI[1] + 0;\n"\
					"	SET_AL V_AP7,ARV[1], 10;\n"\
					"ELSE\n"\
					"	CAL ARV[1] = DI[1] + 0;\n"\
					"	REL_AL V_AP7,ARV[1], 10;\n"\
					"ENDIF\n"\
					"SLEEP 2000;\n";
	/*
	char *scripts =	"SET_ADDR 1;\n"\
					"INTFS 4050 B YM[32];\n"\
					"INTFS 4000 F DB[10];\n"\
					"INTFS 5000 F DW[10];\n"\
					"VARS W TMP[22];\n"\
					"VARS W TMU[2];\n"\
					"VARS W TMQ[19];\n"\
					"VARS U TMY[2];\n"\
					"VARS U TMV[9];\n"\
					"IN_UD_B YM[1],32,010200000020A,100;\n"\
					"IN_UA_B TMP[1],6,03039C400006A,100;\n"\
					"IN_UA_B TMP[7],6,03039C530006A,100;\n"\
					"IN_UA_B TMP[13],2,03039C770002A,100;\n"\
					"IN_UA_B TMP[15],2,03039C7F0002A,100;\n"\
					"IN_UA_B TMP[17],2,03039C8A0002A,100;\n"\
					"IN_UA_B TMP[19],1,03039C8C0001A,100;\n"\
					"IN_UA_B TMP[20],2,03039CA20002A,200;\n"\
					"IN_UA_B TMP[22],1,03039CA40001A,100;\n"\
					"IN_UA_B TMQ[1],14,0203016E000EA,100;\n"\
					"IN_UA_B TMQ[15],2,020301820002A,100;\n"\
					"IN_UA_B TMQ[17],2,0203018A0002A,100;\n"\
					"IN_UA_B TMQ[19],1,020301920001A,100;\n"\
					"CAL DB[1] = TMP[2] << 16 | TMP[1];\n"\
					"CAL DB[2] = TMP[4] << 16 | TMP[3];\n"\
					"CAL DB[3] = TMP[6] << 16 | TMP[5];\n"\
					"CAL DB[4] = TMP[8] << 16 | TMP[7];\n"\
					"CAL DB[5] = TMP[10] << 16 | TMP[9];\n"\
					"CAL DB[6] = TMP[12] << 16 | TMP[11];\n"\
					"CAL DB[7] = TMP[14] << 16 | TMP[13];\n"\
					"CAL DB[8] = TMP[16] << 16 | TMP[15];\n"\
					"CAL TMU[1] = TMP[18] << 16 | TMP[17];\n"\
					"CAL TMU[2] = TMP[21] << 16 | TMP[20];\n"\
					"CAL TMY[1] = TMU[1] << 16 | TMP[19];\n"\
					"CAL TMY[2] = TMU[2] << 16 | TMP[22];\n"\
					"CAL TMV[1] = TMQ[1] << 16 | TMQ[2];\n"\
					"CAL TMV[2] = TMQ[3] << 16 | TMQ[4];\n"\
					"CAL TMV[3] = TMQ[5] << 16 | TMQ[6];\n"\
					"CAL TMV[4] = TMQ[7] << 16 | TMQ[8];\n"\
					"CAL TMV[5] = TMQ[9] << 16 | TMQ[10];\n"\
					"CAL TMV[6] = TMQ[11] << 16 | TMQ[12];\n"\
					"CAL TMV[7] = TMQ[13] << 16 | TMQ[14];\n"\
					"CAL TMV[8] = TMQ[15] << 16 | TMQ[16];\n"\
					"CAL TMV[9] = TMQ[17] << 16 | TMQ[18];\n"\
					"CAL DB[9] = TMY[1] * 0.0001;\n"\
					"CAL DB[10] = TMY[2] * 0.0001;\n"\
					"CAL DW[1] = TMV[1] * 0.0001;\n"\
					"CAL DW[2] = TMV[2] * 0.0001;\n"\
					"CAL DW[3] = TMV[3] * 0.0001;\n"\
					"CAL DW[4] = TMV[4] * 0.0001;\n"\
					"CAL DW[5] = TMV[5] * 0.0001;\n"\
					"CAL DW[6] = TMV[6] * 0.0001;\n"\
					"CAL DW[9] = TMV[9] * 0.0001;\n"\
					"IF (TMV[7] & 80000000H) || (TMV[7] | 80000000H) && (TMV[7] & 80000000H) && (TMV[7] | 80000000H)\n"\
					"	CAL TMV[7] = TMV[7] & 7FFFFFFFH;\n"\
					"CAL DW[7] = 0 - 1 * TMV[7] * 0.0001;\n"\
					"ELSE\n"\
					"	CAL DW[7] = TMV[7] * 0.0001;\n"\
					"ENDIF\n"\
					"IF (TMV[7] & 80000000H) || (TMV[7] | 80000000H) && (TMV[7] & 80000000H)\n"\
					"	CAL TMV[7] = TMV[7] & 7FFFFFFFH;\n"\
					"CAL DW[7] = 0 - 1 * TMV[7] * 0.0001;\n"\
					"ELSE\n"\
					"	CAL DW[7] = TMV[7] * 0.0001;\n"\
					"ENDIF\n"\
					"IF (TMV[8] & 80000000H) || (TMV[7] & 80000000H)\n"\
					"	CAL TMV[8] = TMV[8] & 7FFFFFFFH;\n"\
					"CAL DW[8] = 0 - 1 * TMV[8] * 0.0001;\n"\
					"ELSE\n"\
					"	CAL DW[8] = TMV[8] * 0.0001;\n"\
					"ENDIF\n"\
					"IF (TMQ[19] & 80000000H)\n"\
					"	CAL TMQ[19] = TMQ[19] & 7FFFFFFFH;\n"\
					"CAL DW[10] = 0 - 1 * TMQ[19] * 0.001;\n"\
					"ELSE\n"\
					"	CAL DW[10] = TMQ[19] * 0.001;\n"\
					"ENDIF\n"\
					"SLEEP 2000;\n";
	*/
#else
	char *scripts = NULL;
#endif
	error_code = scripts_checkout(scripts);
	
	if(scripts != NULL && error_code == 0)
		printf("Scripts check ok.\n");
	//syslog(LOG_NOTICE, "Scripts check ok.");

	return 0;
}

