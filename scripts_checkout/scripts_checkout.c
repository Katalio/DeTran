
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

#define ERROR_NUM 128 
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
	int i = 0;

	//读取当前行
	while((scripts[cur_index] != '\n') && (scripts[cur_index] != '\0') && (i < LINE_SIZE))
	{
		line[i ++] = scripts[cur_index ++];
	}
	if(i >= LINE_SIZE)
	{
		LINENUM ++;
		return i;
	}

	if(scripts[cur_index] == '\n')
	{
		line[i] = scripts[cur_index];

		cur_index ++;	//cur_index++是为了指向'\n'的后一个字符，即下一行开头

		LINENUM ++;	//指向下一行

//		printf("line:%s, %d\n", line, i + 1);

		return (i + 1);
	}

	cur_index ++;	//cur_index++是为了指向'\n'的后一个字符，即下一行开头

	LINENUM ++;	//指向下一行

//	printf("line:%s, %d\n", line, i);

	return i;
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
	err_infolist[err_tail].linenum = linenum - 1;	//linenum记录的是当前行的下一行
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

int init_value_type_check(char *line, char *var_name)
{
	params_defined_info *head;
	char *cp, *cq, tmp[16], cmd[16] = {0};
	int i = 0, len = 0, n = 0;
	int ex_flag = 0, error_code = 0;
	int counter = 0;

	get_cmd(cmd, line);
	head = get_params_info(var_name);
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
								set_Msg_to_errInfo(LINENUM, ERR_VARTYPE_CONFUSING, error_msg_buf);

								error_code |= ERR_VARTYPE_CONFUSING;
							}
							if(strncmp(head->var_type, "F", 1) != 0)
							{
								memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
								snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"'%s' is float, but type of '%s' is '%s'\"", tmp, var_name, head->var_type);
								set_Msg_to_errInfo(LINENUM, ERR_VARTYPE_CONFUSING, error_msg_buf);

								error_code |= ERR_VARTYPE_CONFUSING;
							}
						}
						else if(n > 1 || ex_flag)
						{
							memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
							snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid value '%s'\"", tmp);
							set_Msg_to_errInfo(LINENUM, ERR_VARTYPE_CONFUSING, error_msg_buf);

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
				set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);

				error_code |= ERR_FORMAT;
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
				set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);

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
					set_Msg_to_errInfo(LINENUM, ERR_VARTYPE_CONFUSING, error_msg_buf);

					error_code |= ERR_VARTYPE_CONFUSING;
				}
				if(strncmp(head->var_type, "F", 1) != 0)
				{
					memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"'%s' is float, but type of '%s' is '%s'\"", tmp, var_name, head->var_type);
					set_Msg_to_errInfo(LINENUM, ERR_VARTYPE_CONFUSING, error_msg_buf);

					error_code |= ERR_VARTYPE_CONFUSING;
				}
			}
			else if(n > 1 || ex_flag)
			{
				memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
				snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid value '%s'\"", tmp);
				set_Msg_to_errInfo(LINENUM, ERR_VARTYPE_CONFUSING, error_msg_buf);

				error_code |= ERR_VARTYPE_CONFUSING;
			}
		}

		n = arr_excess_check(line);
		if(n < counter)
		{
			memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
			snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"somewhere missing ','\"");
			set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);

			error_code |= ERR_FORMAT;
		}
	}

	return error_code;
}

int variable_format_check(char *var_name_b)
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
	head = get_params_info(var_name);
	if(head->var_count > 1)
	{
		if(len == 0)
		{
			memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
			snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"expected '[]' for '%s'\"", var_name);
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
		memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
		snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"unpaired brackets\"");
		set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);

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
				memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
				snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too more '='\"");
				set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);

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
			memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
			snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid format in array initializer\"");
			set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);

			return 1;
		}
	}

	return 0;
}

int endsymbol_check(char *line)
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
			set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);

			err_flag = 1;
		}

		if(p == NULL)
		{
			memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
			snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"expected '\\n' at the end\"");
			set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);

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
			set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);

			err_flag = 1;
		}
		else	
		{
			if(k > 1)
			{
				memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
				snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too more ';' in the line\"");
				set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);

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
				set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);

				err_flag = 1;
			}
		}
	}

	return err_flag;
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

int cal_format_check(char *line)
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
		set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);

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
					set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);

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
					set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);

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
							set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);

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
		snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"no variable need to output by 'DO_CTRL'\"");
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
	    p = Mstr;//IF(TMP === 0)
	    q = substr;// ==

	    while((*p == *q) && (*p != '\0') && (*q != '\0'))
	    {
	        p ++;
	        q ++;
	    }
	    if(*q == '\0' && *p != '=')
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

int existIFbefore_check(char *cmd)
{
	char (*p)[16] = cmd_info;
	int err_flag = 0, noif_flag = 1;

	while(strlen(*p) != 0)
	{
		if(!strcmp(*p, "IF"))
		{
			noif_flag = 0;
		}
		p ++;
	}

	if(noif_flag)
	{
		memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
		snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"no 'IF' before '%s'\"", cmd);
		set_Msg_to_errInfo(LINENUM, ERR_IFCMD_NO_MATCH, error_msg_buf);

		err_flag = 1;
	}

	return err_flag;
}

int check_if_endif(void)
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
	if(if_index != 0)
	{
		if((if_index < endif_index) || (endif_index == 0))	//说明嵌套超过3层了
		{
			return 1;	
		}
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
	int var_count = 0;	//元素的个数，针对数组变量来说，单个变量为1
	char *start_num, *read_count;	//读入寄存器的开始编号及个数
	char *modbus_cmd, *overtime;
	params_defined_info *head;
	unsigned int cur_size = 0, line_size, total_size;

	if(scripts == NULL)
	{
		printf("Scripts is NULL.\n");
		//syslog(LOG_NOTICE, "Scripts is NULL.");
		
		return error_code;
	}

	total_size = strlen(scripts);

	if(scripts_oversize(total_size))
	{
		error_code |= ERR_SCRIPTS_OVERSIZE;	

		return error_code;
	}

	while(cur_size < total_size)
	{
		memset(line, 0, LINE_SIZE);
		line_size = scripts_getline(line, scripts);
		if(line_size >= LINE_SIZE)
		{
			memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
			snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too much size for one line\"");
			set_Msg_to_errInfo(LINENUM, ERR_SCRIPTS_OVERSIZE, error_msg_buf);
			error_code |= ERR_SCRIPTS_OVERSIZE;	

			return error_code;
		}

		cur_size += line_size;

		cp = line;
		while(isspace((int) *cp) && *cp != '\0')
		{
			cp ++;
		}
		if(*cp == '\0')
		{
			continue;
		}

		char cmds[16] = {0};			

		if(endsymbol_check(line))	//检查有无结束符
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

		if(check_equals(line))
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
				if(strchr(line, '=') == NULL)
				{
					if(cmds_format_check(line, var_name_b))
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"exist initial value without '='\"");
						set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);
						error_code |= ERR_FORMAT;	
					}
				}
				//检测所赋的值是否与变量类型相对应，只需检查浮点型即可	
				if(n = init_value_type_check(line, var_name))
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
					//检查数组变量格式
					if(n = variable_format_check(var_name_b))
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
					//若变量为AI或DI，检查寄存器定义是否越界
					if(aidi_reg_check(var_name, var_count))
					{
						error_code |= ERR_REG_OUTBOUNDS;
					}
					//若数组赋初值，检查所赋初值个数是否大于定义的个数及格式
					if(strchr(line, '='))
					{
						if(strchr(line, '{') == NULL)
						{
							memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
							snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid initial value or no initial value next to '='\"");
							set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);
							error_code |= ERR_FORMAT;	
						}
						else
						{
							if(arr_format_check(line))
							{
								error_code |= ERR_FORMAT;
							}
							else
							{
								if(arr_excess_check(line) > var_count)
								{
									memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
									snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"excess elements in array initializer\"");
									set_Msg_to_errInfo(LINENUM, ERR_PARAM_EXCESS, error_msg_buf);
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
				if(strchr(line, '=') == NULL)
				{
					if(cmds_format_check(line, var_name_b))
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"exist initial value without '='\"");
						set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);
						error_code |= ERR_FORMAT;	
					}
				}
				//检测所赋的值是否与变量类型相对应，只需检查浮点型即可	
				if(n = init_value_type_check(line, var_name))
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
					//检查数组变量格式
					if(n = variable_format_check(var_name_b))
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
					//若变量为AI或DI，检查寄存器定义是否越界
					if(aidi_reg_check(var_name, var_count))
					{
						error_code |= ERR_REG_OUTBOUNDS;
					}
					//若数组赋初值，检查所赋初值个数是否大于定义的个数及格式
					if(strchr(line, '='))
					{
						if(strchr(line, '{') == NULL)
						{
							memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
							snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid initial value or no initial value next to '='\"");
							set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);
							error_code |= ERR_FORMAT;	
						}
						else
						{
							if(arr_format_check(line))
							{
								error_code |= ERR_FORMAT;
							}
							else
							{
								if(arr_excess_check(line) > var_count)
								{
									memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
									snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"excess elements in array initializer\"");
									set_Msg_to_errInfo(LINENUM, ERR_PARAM_EXCESS, error_msg_buf);
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
				if(strchr(line, '=') == NULL)
				{
					if(cmds_format_check(line, var_name_b))
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"exist initial value without '='\"");
						set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);
						error_code |= ERR_FORMAT;	
					}
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
					//检测所赋的值是否与变量类型相对应，只需检查浮点型即可	
					if(n = init_value_type_check(line, var_name))
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
				}
				if(!strcmp(cmds, "CTRLS"))
				{
					//检查数组变量格式
					if(n = variable_format_check(var_name_b))
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
				if(strchr(line, '=') == NULL)
				{
					if(cmds_format_check(line, var_name_b))
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"exist initial value without '='\"");
						set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);
						error_code |= ERR_FORMAT;	
					}
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
					//检测所赋的值是否与变量类型相对应，只需检查浮点型即可	
					if(n = init_value_type_check(line, var_name))
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
				}
				if(!strcmp(cmds, "UCTRLS"))
				{
					//检查数组变量格式
					if(n = variable_format_check(var_name_b))
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

			memset(var_name, 0, 16);
			n = vstrsep(nvp, "	; ", &cmd, &var_name_b, &thr_low, &thr_up);
			if(n == 4)
			{
				if(cmds_format_check(line, thr_up))
				{
					memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"too more elements for '%s'\"", cmds);
					set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);
					error_code |= ERR_FORMAT;	
				}
				//获取变量名
				var_count = get_varname(var_name, var_name_b);
				if(var_count <= 0)
				{
					memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid element subscript for '%s'\"", var_name);
					set_Msg_to_errInfo(LINENUM, ERR_PARAM_EXCESS, error_msg_buf);
					error_code |= ERR_PARAM_EXCESS;
				}
				//检查变量是否定义
				if(params_undefined_check(var_name))
				{
					error_code |= ERR_PARAM_UNDEFINED;	
				}
				else
				{
					//检查数组变量格式
					if(strchr(var_name_b, '['))
					{
						if(n = variable_format_check(var_name_b))
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
					}
					//检查变量类型
					if(strchr(thr_low, '.') || strchr(thr_up, '.'))
					{
						head = get_params_info(var_name);
						if(strncmp(head->var_type, "F", 1) != 0)
						{
							memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
							snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"threshold has float value, but type of '%s' is '%s'\"", var_name_b, head->var_type);
							set_Msg_to_errInfo(LINENUM, ERR_VARTYPE_CONFUSING, error_msg_buf);
							error_code |= ERR_VARTYPE_CONFUSING;	
						}
					}
					//检查阈值是否前小后大
					if(atoi(thr_low) > atoi(thr_up))
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"invalid initializer[low:%d > up:%d]\"", atoi(thr_low), atoi(thr_up));
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
			i = 0;	//统计变量个数
			if(cal_format_check(line))
			{
				error_code |= ERR_FORMAT;	
			}

			cp = line;
			while(1)
			{
				memset(var_name, 0, 16);
				memset(tmp_name, 0, 16);
				len = 0;
				while((isspace((int) *cp) || *cp == '=' || *cp == '+' || *cp == '-' || *cp == '*' || *cp == '/'\
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
					while(((!isspace((int) *cp)) && (*cp != '+') && (*cp != '-') && (*cp != '*') && (*cp != '/')\
						&& (*cp != '~') && (*cp != '&') && (*cp != '|') && (*cp != '^')\
						&& (*cp != '<') && (*cp != '>') && (*cp != ';')) && (*cp != '\0'))
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

						if((*cq != '+') && (*cq != '-') && (*cq != '*') && (*cq != '/') && (*cq != '<')\
								&& (*cq != '>') && (*cq != '~') && (*cq != '&') && (*cq != '|') && (*cq != '^')\
								&& (*cq != '=') && (*cq != ';') && (*cq != '\n') && (*cq != '\0'))
						{
							memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
							snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"expected operator after '%s' token\"", tmp_name);
							set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);

							error_code |= ERR_FORMAT;
						}

						if(tmp_name[0] < '0' || tmp_name[0] > '9')	//过滤常量
						{
							i ++;

							//检查数组变量格式
							if(n = variable_format_check(tmp_name))
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
								if(i == 1)	//结果变量必须是浮点型
								{
									if(strncmp(head->var_type, "F", 1) != 0)
									{
										memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
										snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"type of '%s' must be 'F'\"", var_name);
										set_Msg_to_errInfo(LINENUM, ERR_VARTYPE_CONFUSING, error_msg_buf);
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
							snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"register beyond access for 'DI'\"");
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
							snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"register beyond access for 'AI'\"");
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
				//检查数组变量格式
				if(strchr(var_name_b, '['))
				{
					if(n = variable_format_check(var_name_b))
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
				}
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
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"register beyond access for '%s'\"", var_name);
						set_Msg_to_errInfo(LINENUM, ERR_REG_OUTBOUNDS, error_msg_buf);
						error_code |= ERR_REG_OUTBOUNDS;
					}
					//检查modbus指令格式
					if(strlen(modbus_cmd) != 13)
					{
						memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
						snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"length of modbus command for '%s' != 13\"", cmds);
						set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);
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
				//检查数组变量格式
				if(strchr(var_name_b, '['))
				{
					if(n = variable_format_check(var_name_b))
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
				}
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
				//检查数组变量格式
				if(strchr(var_name_b, '['))
				{
					if(n = variable_format_check(var_name_b))
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
				}
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
				if(strlen(modbus_cmd) != 13)
				{
					memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
					snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"length of modbus command for '%s' != 13\"", cmds);
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

			n = brackets_exist_check(line);
			if(n == 1)	//only for IF
			{
				memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
				snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"each condition need parentheses\"");
				set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);
				error_code |= ERR_FORMAT;	
			}
			else if(n == 2)	//only for IF
			{
				memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
				snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"expected condition or valid operator for 'IF'\"");
				set_Msg_to_errInfo(LINENUM, ERR_FORMAT, error_msg_buf);
				error_code |= ERR_FORMAT;	
			}
			else if(n == 3)	//only for IF
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
					while((isspace((int) *cp) || *cp == '=' || *cp == '(' || *cp == ')' || *cp == ';'\
						|| *cp == '!' || *cp == '&' || *cp == '|' || *cp == '<' || *cp == '>') && (*cp != '\0'))
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
						while(((!isspace((int) *cp)) && (*cp != '=') && (*cp != '(')\
								&& (*cp != ')') && (*cp != '!') && (*cp != '&') && (*cp != '|')\
								&& (*cp != '<') && (*cp != '>') && (*cp != ';')) && (*cp != '\0'))
						{
							cp ++;
							len ++;
						}
						strncpy(tmp_name, cq, len);

						if((atoi(tmp_name) == 0) && (atof(tmp_name) == 0) && (strncmp(tmp_name, "0", 1)))	//过滤常量
						{
							//检查数组变量格式
							if(n = variable_format_check(tmp_name))
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
		else if(!strcmp(cmds, "ELSE") || !strcmp(cmds, "ENDIF"))
		{
			//检查之前是否有IF
			if(existIFbefore_check(cmds))
			{
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

	//检测IF与ENDIF个数是否相等
	if(check_if_endif())
	{
		memset(error_msg_buf, 0, ERROR_MSG_LENGTH);
		snprintf(error_msg_buf, ERROR_MSG_LENGTH, "\"'IF' don't match 'ENDIF'\"");
		set_Msg_to_errInfo(LINENUM, ERR_IFCMD_NO_MATCH, error_msg_buf);

		error_code |= ERR_IFCMD_NO_MATCH;
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

void show_params_defined(void)
{
	int i;

	printf("Defined params:\n");
	printf("variable name\tvariable type\tvariable counter\n");
	for(i = 0; params_definfo[i].var_count != 0; i ++)
		printf("%s\t\t%s\t\t%d\n", params_definfo[i].var_name, params_definfo[i].var_type, params_definfo[i].var_count);
}

int main()
{
	int error_code = 0;
#if 1
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
					"CAL tmp = AI[1] / 4096 * 3.3 / 165 * 1000 - 4;\n"\
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
					"IN_AE AIV[1],1,2;\n"\
					"IN_ACAE AIV[1],1,2;\n"\
					"OUT_U 09050001FF00A, 500;\n"\
					"OUT_D 16, 0;\n"\
					"DO_CTRL;\n"\
					"CONTINUE;\n"\
					"SLEEP 1000;";
#else
	char *scripts = NULL;
#endif
	error_code = scripts_checkout(scripts);
//	show_cmdInfo();
//	show_params_defined();
	if(error_code)
	{
		show_errMsg();	

		return -1;
	}
	
	if(scripts != NULL)
		printf("Scripts check ok.\n");
	//syslog(LOG_NOTICE, "Scripts check ok.");

	return 0;
}

