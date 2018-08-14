#ifndef __DTU_H__
#define __DTU_H__

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <termios.h>
#include <string.h>
#include <error.h>

/* Lora Module CMD */
#define READ_HW_VERSION 	0x01
#define READ_PARAMS 		0x03
#define SET_PARAMS 			0x04
#define RESET 				0x05
#define SEND_TO_LORA 		0xC1
#define SEND_TO_SERVER 		0xC2
#define UPDATE 				0xE1
#define DOWNLOAD_FW_CODE 	0xE2
#define DOWNLOAD_FW_OK 		0xE3
#define UPDATE_CANCLE 		0xE4
#define ERROR 				0xFF

#endif //__DTU_H__
