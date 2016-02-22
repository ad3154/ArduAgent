/*
  arduAgent.h - An Arduino library for a lightweight SNMP Agent.
  Copyright (C) 2016 Adrian Del Grosso
  All rights reserved.

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef arduAgent_h
#define arduAgent_h

#define SNMP_DEFAULT_PORT	161
#define SNMP_MIN_OID_LEN	2
#define SNMP_MAX_OID_LEN	64 // 128
#define SNMP_MAX_NAME_LEN	20
#define SNMP_MAX_VALUE_LEN      64  // 128 ??? should limit this
#define SNMP_MAX_PACKET_LEN     SNMP_MAX_VALUE_LEN + SNMP_MAX_OID_LEN + 25  //???
#define SNMP_FREE(s)   do { if (s) { free((void *)s); s=NULL; } } while(0)

#include "Arduino.h"
#include "Udp.h"

extern "C" {
	// callback function
	typedef void (*onPduReceiveCallback)(void);
}

typedef union uint64_u {
	uint64_t uint64;
	byte data[8];
};

typedef union int32_u {
	int32_t int32;
	byte data[4];
};

typedef union uint32_u {
	uint32_t uint32;
	byte data[4];
};

typedef union int16_u {
	int16_t int16;
	byte data[2];
};

typedef enum SNMP_API_STAT_CODES {
	SNMP_API_STAT_SUCCESS = 0,
	SNMP_API_STAT_MALLOC_ERR = 1,
	SNMP_API_STAT_NAME_TOO_BIG = 2,
	SNMP_API_STAT_OID_TOO_BIG = 3,
	SNMP_API_STAT_VALUE_TOO_BIG = 4,
	SNMP_API_STAT_PACKET_INVALID = 5,
	SNMP_API_STAT_PACKET_TOO_BIG = 6,
	SNMP_API_STAT_NO_SUCH_NAME = 7,
};

typedef enum SNMP_ERR_CODES {
	SNMP_ERR_NO_ERROR 	  		= 0,
	SNMP_ERR_TOO_BIG 	  		= 1,
	SNMP_ERR_NO_SUCH_NAME 		= 2,
	SNMP_ERR_BAD_VALUE 	  		= 3,
	SNMP_ERR_READ_ONLY 	  		= 4,
	SNMP_ERR_GEN_ERROR 	  		= 5,

	SNMP_ERR_NO_ACCESS	  		= 6,
	SNMP_ERR_WRONG_TYPE   			= 7,
	SNMP_ERR_WRONG_LENGTH 			= 8,
	SNMP_ERR_WRONG_ENCODING			= 9,
	SNMP_ERR_WRONG_VALUE			= 10,
	SNMP_ERR_NO_CREATION			= 11,
	SNMP_ERR_INCONSISTANT_VALUE 		= 12,
	SNMP_ERR_RESOURCE_UNAVAILABLE		= 13,
	SNMP_ERR_COMMIT_FAILED			= 14,
	SNMP_ERR_UNDO_FAILED			= 15,
	SNMP_ERR_AUTHORIZATION_ERROR		= 16,
	SNMP_ERR_NOT_WRITABLE			= 17,
	SNMP_ERR_INCONSISTEN_NAME		= 18
};

class arduAgentClass {
public:
	// Agent functions
	SNMP_API_STAT_CODES begin();
	SNMP_API_STAT_CODES begin(char *getCommName, char *setCommName, uint16_t port);
	void listen(void);
	SNMP_API_STAT_CODES requestPdu();
	SNMP_API_STAT_CODES responsePdu();
	void onPduReceive(onPduReceiveCallback pduReceived);
	void createResponsePDU(int respondValue);
	
	// Helper functions
	bool check_oid( const int inputoid[]);
	void getOID(byte input[]);
	int getOIDlength(void);
	SNMP_API_STAT_CODES send_response(void);
	void print_packet(void);
	void generate_errorPDU(SNMP_ERR_CODES CODE);

private:
	byte _packet[SNMP_MAX_PACKET_LEN];
	uint16_t _packetSize;
	uint16_t _packetPos;
	uint8_t _dstIp[4];
	char *_getCommName;
	size_t _getSize;
	char *_setCommName;
	size_t _setSize;
	onPduReceiveCallback _callback;
	
	//New PDU structure
	byte ans1Header;
	byte pdu_length;
	byte version[4];
	byte lengthCommunityName;
	char communityName[20];
	byte request[2];
	byte requestID[10];
	short int requestIDlength = 1;
	byte errorStatusCode[3];
	byte snmpIndex[3];
	byte varbindList[2];
	byte varbind[2];
	byte objectID;
	byte oidLength;
	short int oid[64] = {0x00};
	byte nulValue[2];
};

extern arduAgentClass arduAgent;

#endif