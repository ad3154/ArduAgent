/*
  arduAgent.cpp - An Arduino library for a lightweight SNMP Agent.
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

#include "arduAgent.h"
#include "EthernetUdp.h"

EthernetUDP Udp;

SNMP_API_STAT_CODES arduAgentClass::begin(){
	// set community names
	_getCommName = "public";
	_setCommName = "private";
	//
	// set community name set/get sizes
	_setSize = strlen(_setCommName);
	_getSize = strlen(_getCommName);
	//
	// init UDP socket
	Udp.begin(SNMP_DEFAULT_PORT);
	//
	return SNMP_API_STAT_SUCCESS;
}

void arduAgentClass::listen(void){
	// if bytes are available in receive buffer
	// and pointer to a function (delegate function)
	// isn't null, trigger the function
	
	/*A note here from Adrian... This was confusing to me at first
	so here's a quick explanation. If the callback variable is set,
	we actually go to the memory location of the function
	pduReceived and begin to run there. Its like a super
	ghetto goto by interrupt. Sorta. Makes me cringe.*/
	Udp.parsePacket();
	if ( Udp.available() && _callback != NULL ) (*_callback)();
}


SNMP_API_STAT_CODES arduAgentClass::begin(char *getCommName, char *setCommName, uint16_t port){
	/* THIS FUNCTION NEEDS TO BE REDONE*/
	// set community name set/get sizes
	_setSize = strlen(setCommName);
	_getSize = strlen(getCommName);
	//
	// validate get/set community name sizes
	if ( _setSize > SNMP_MAX_NAME_LEN + 1 || _getSize > SNMP_MAX_NAME_LEN + 1 ) {
		return SNMP_API_STAT_NAME_TOO_BIG;
	}
	//
	// set community names
	_getCommName = getCommName;
	_setCommName = setCommName;
	//
	// validate session port number
	if ( port == NULL || port == 0 ) port = SNMP_DEFAULT_PORT;
	//
	// init UDP socket
	Udp.begin(port);

	return SNMP_API_STAT_SUCCESS;
}

void arduAgentClass::onPduReceive(onPduReceiveCallback pduReceived){
	_callback = pduReceived;
}

SNMP_API_STAT_CODES arduAgentClass::requestPdu(){
	SNMP_ERR_CODES authenticated = SNMP_ERR_NO_ERROR;
	_packetSize = Udp.available();
	// reset packet array
	for (int rstCounter=0; rstCounter < SNMP_MAX_PACKET_LEN; rstCounter++)
	{
	_packet[rstCounter] = 0;
	}
	
	//Validate Packet Size
	if ( _packetSize != 0 && _packetSize > SNMP_MAX_PACKET_LEN ) {
		return SNMP_API_STAT_PACKET_TOO_BIG;
	}
	
	//Get the actual packet and store it for use
	Udp.read(_packet, _packetSize);
	
	
	
	//Check to see if the packet is a SNMPv1 packet
	//This value should always be 0x30
	if ( _packet[0] != 0x30)
	{
		return SNMP_API_STAT_PACKET_INVALID;
	}

	/* We have a pdu structure that was passed in.
	We'll now populate that structure from
	data we received in the buffer*/
	
	ans1Header = _packet[0];
	pdu_length = _packet[1];
	for(int i = 2; i<6; i++)
	{
		version[i-2] = _packet[i];
	}
	lengthCommunityName = _packet[6];
	for (int i = 0; i < (int) lengthCommunityName; i++)
	{
		communityName[i] = _packet[7+i];
	}
	request[0] = _packet[7+lengthCommunityName];
	request[1] = _packet[7+lengthCommunityName+1];
	requestID[0] = _packet[7+lengthCommunityName+2];
	requestID[1] = _packet[7+lengthCommunityName+3];
	requestID[2] = _packet[7+lengthCommunityName+4];
	if(requestID[1] > 1){
		requestIDlength=requestID[1];
		for(int i = 2; i<=requestIDlength; i++){
			requestID[i]=_packet[7+lengthCommunityName+5+i-2];
		}
	}
	errorStatusCode[0] = _packet[7+lengthCommunityName+4+requestIDlength];
	errorStatusCode[1] = _packet[7+lengthCommunityName+5+requestIDlength];
	errorStatusCode[2] = _packet[7+lengthCommunityName+6+requestIDlength];
	snmpIndex[0] = _packet[7+lengthCommunityName+7+requestIDlength];
	snmpIndex[1] = _packet[7+lengthCommunityName+8+requestIDlength];
	snmpIndex[2] = _packet[7+lengthCommunityName+9+requestIDlength];
	varbindList[0] = _packet[7+lengthCommunityName+10+requestIDlength];
	varbindList[1] = _packet[7+lengthCommunityName+11+requestIDlength];
	varbind[0] = _packet[7+lengthCommunityName+12+requestIDlength];
	varbind[1] = _packet[7+lengthCommunityName+13+requestIDlength];
	objectID = _packet[7+lengthCommunityName+14+requestIDlength];
	oidLength = _packet[7+lengthCommunityName+15+requestIDlength];
	for(int i=0; i < (int) oidLength; i++)
	{
		oid[i] = _packet[7+lengthCommunityName+16+i+requestIDlength];
	}	

	nulValue[0] = 0x05;
	nulValue[1] = 0x00;
	authenticated = generalAuthenticator();
	if(authenticated == SNMP_ERR_NO_ERROR)
	{
		return SNMP_API_STAT_SUCCESS;
	}
	else 
		return SNMP_API_STAT_PACKET_INVALID;
}

	void arduAgentClass::createResponsePDU(int respondValue){
	int lsb = (respondValue >> (8*0)) & 0xff;
	int slsb = (respondValue >> (8*1)) & 0xff;
	int smsb = (respondValue >> (8*2)) & 0xff;
	int msb = (respondValue >> (8*3)) & 0xff;
	int baseResponseAddress = 7+lengthCommunityName+16+oidLength+requestIDlength;
	int total_len = 8+lengthCommunityName+16+oidLength+requestIDlength+5;
	_packet[7+lengthCommunityName] = 0xa2;
	_packet[baseResponseAddress] = 0x02;
	_packet[baseResponseAddress+1] = 0x04;
	_packet[baseResponseAddress+2] = (uint8_t) msb;
	_packet[baseResponseAddress+3] = (uint8_t) smsb;
	_packet[baseResponseAddress+4] = (uint8_t) slsb;
	_packet[baseResponseAddress+5] = (uint8_t) lsb;
	_packet[1] = total_len-2;
	_packet[7+lengthCommunityName+1] = _packet[7+lengthCommunityName+1]+4;
	_packet[7+lengthCommunityName+11+requestIDlength] = 10+oidLength;
	_packet[7+lengthCommunityName+13+requestIDlength] = 8+oidLength;
}


void arduAgentClass::generate_errorPDU(SNMP_ERR_CODES CODE){
	int errorCodeLocation = 7+lengthCommunityName+6+requestIDlength;
	if (CODE==SNMP_ERR_TOO_BIG)
	{
		_packet[errorCodeLocation] = 0x01;
	}
	else if(CODE==SNMP_ERR_NO_SUCH_NAME)
	{
		_packet[errorCodeLocation] = 0x02;
	}
	else if (CODE==SNMP_ERR_BAD_VALUE)
	{
		_packet[errorCodeLocation] = 0x03;
	}
	else if (CODE==SNMP_ERR_READ_ONLY)
	{
		_packet[errorCodeLocation] = 0x04;
	}
	else if (CODE==SNMP_ERR_GEN_ERROR)
	{
		_packet[errorCodeLocation] = 0x05;
	}
	_packet[7+lengthCommunityName] = 0xa2;
	Udp.beginPacket(Udp.remoteIP(), Udp.remotePort());
	Udp.write(_packet, _packet[1]+2);
	Udp.endPacket();
}

void arduAgentClass::getOID(byte input[]){
	for (int i = 0; i < (int)oidLength; i++)
	{
		input[i] = oid[i];
	}
}

int arduAgentClass::getOIDlength(void){
	return oidLength;
}

bool arduAgentClass::check_oid(const int inputoid[]){
	for(int i = 2; i < oidLength; i++)
	{
		if(inputoid[i] != oid[i-1])
		{
			return false;
		}
	}
	return true;
}

SNMP_API_STAT_CODES arduAgentClass::send_response(void){
	if(!Udp.beginPacket(Udp.remoteIP(), Udp.remotePort()))
	{
		return SNMP_API_STAT_PACKET_INVALID;
	}
	Udp.write(_packet, _packet[1]+2);
	Udp.endPacket();
	return SNMP_API_STAT_SUCCESS;
}

void arduAgentClass::print_packet(void){
	    for(int i =0; i < 50; i++)
        {
          Serial.print( _packet[i], HEX );
          Serial.print(" ");
        }
	
}

SNMP_ERR_CODES arduAgentClass::generalAuthenticator(void){
	SNMP_ERR_CODES authd = SNMP_ERR_NO_ERROR;
	if (request[0] == 0xa0)
	{
		authd = authenticateGetCommunity();
	}
	else
	authd = authenticateSetCommunity();
	
	return authd;
}

SNMP_ERR_CODES arduAgentClass::authenticateGetCommunity(void){

	for (unsigned short int i=0;i<lengthCommunityName;i++)
	{
		if (communityName[i]!=_getCommName[i])
		{
			// If SNMPv2c Request
			if(_packet[4]==1)
			{		
			return SNMP_ERR_AUTHORIZATION_ERROR;
			}
			// Otherwise, return SNMPv1 Error
			else
			return SNMP_ERR_NO_SUCH_NAME;
		}
	}
	return SNMP_ERR_NO_ERROR;
}

SNMP_ERR_CODES arduAgentClass::authenticateSetCommunity(void){

	for (unsigned short int i=0;i<lengthCommunityName;i++)
	{
		if (communityName[i]!=_setCommName[i])
		{
			// If SNMPv2c Request
			if(_packet[4]==1)
			{
				return SNMP_ERR_AUTHORIZATION_ERROR;
			}
			// Otherwise, return SNMPv1 Error
			else
			return SNMP_ERR_NO_SUCH_NAME;
		}
	}
	return SNMP_ERR_NO_ERROR;
}

//Need to finish
SNMP_API_STAT_CODES snmpv2Interpreter(){
	return SNMP_API_STAT_SUCCESS;
}
	
// Create one global object
arduAgentClass arduAgent;