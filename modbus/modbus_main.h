/* tests/unit-test.h.  Generated from unit-test.h.in by configure.  */
/*
 * Copyright © 2008-2011 Stéphane Raimbault <stephane.raimbault@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _UNIT_TEST_H_
#define _UNIT_TEST_H_

/* Constants defined by configure.ac */
#define HAVE_INTTYPES_H 1
#define HAVE_STDINT_H 1

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#ifdef HAVE_STDINT_H
# ifndef _MSC_VER
# include <stdint.h>
# else
# include "stdint.h"
# endif
#endif

#define SERVER_ID         17
#define INVALID_SERVER_ID 18

const uint16_t UT_BITS_ADDRESS = 0x13;
const uint16_t UT_BITS_NB = 0x25;
const uint8_t UT_BITS_TAB[] = { 0xCD, 0x6B, 0xB2, 0x0E, 0x1B };

const uint16_t UT_INPUT_BITS_ADDRESS = 0xC4;
const uint16_t UT_INPUT_BITS_NB = 0x16;
const uint8_t UT_INPUT_BITS_TAB[] = { 0xAC, 0xDB, 0x35 };

const uint16_t UT_REGISTERS_ADDRESS = 0x6B;
/* Raise a manual exception when this adress is used for the first byte */
const uint16_t UT_REGISTERS_ADDRESS_SPECIAL = 0x6C;
const uint16_t UT_REGISTERS_NB = 0x3;
const uint16_t UT_REGISTERS_TAB[] = { 0x022B, 0x0001, 0x0064 };
/* If the following value is used, a bad response is sent.
   It's better to test with a lower value than
   UT_REGISTERS_NB_POINTS to try to raise a segfault. */
const uint16_t UT_REGISTERS_NB_SPECIAL = 0x2;

const uint16_t UT_INPUT_REGISTERS_ADDRESS = 0x08;
const uint16_t UT_INPUT_REGISTERS_NB = 0x1;
const uint16_t UT_INPUT_REGISTERS_TAB[] = { 0x000A };

const float UT_REAL = 916.540649;
const uint32_t UT_IREAL = 0x4465229a;

#define MODBUS_ENABLE		1
#define MODBUS_DISABLE		0

#define MODBUS_TCP_CLIENT	0
#define MODBUS_TCP_SERVER	1

//#define RTU_PORT	"/dev/ttyS0"
#define RTU_PORT	nvram_match("port_type","1")?"/dev/ttyS0":"/dev/ttyUSB0"

typedef struct _MODBUS_CONFIG
{
	int mode;
	int tcp_mode;
	char svr_domain[128];
	unsigned long svr_domain_ip;
	char svr_ip_str[16];
	unsigned long svr_ip;
	int bind_port;
	int svr_port;
	int rate;
	char parity;
	char databits;
	char stopbits;
	char streamcontrol;
} MODBUS_CONFIG;

#define RTU_LOGIN_CMD			0x0001
#define RTU_LOGIN_ACK			0x8001

#define RTU_LOGOUT_CMD			0x0002
#define RTU_LOGOUT_ACK			0x8002

#define RTU_HEARTBEAT_CMD		0x0003
#define RTU_HEARTBEAT_ACK		0x8003

#define RTU_SUB_CMD				0x0011
#define RTU_SUB_ACK				0x8011

#define RTU_OUTPUT_CMD			0x0012
#define RTU_OUTPUT_ACK			0x8012

#define RTU_SCRIPT_TRAP_CMD		0x0015
#define RTU_SCRIPT_TRAP_ACK		0x8015

#define RTU_TRANS_DATA_CMD		0x0007
#define RTU_TRANS_DATA_ACK		0x8007

#endif /* _UNIT_TEST_H_ */
