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

// Create UDP object
EthernetUDP Udp;

/**************************************************************************//**
 * Function: begin(without parameters)
 *
 * Description:
 * This is the default setup for the arduAgent Class. It makes the agent
 * use the default values of "public" and "private" for community names
 * and port 161 for communication. If the user wants to use different
 * values, he/she should call the other version of this function that
 * takes 3 parameters.
 * 
 *
 * Parameters: 
 * None
 *
 * Returns:
 *  SNMP_API_STAT_CODES SNMP_API_STAT_SUCCESS - Agent started
 *
 *****************************************************************************/
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

/**************************************************************************//**
 * Function: listen
 *
 * Description:
 * This is the function that runs every so often within the user's main program
 * to check to see if a PDU is available. If a packet is available, we jump
 * to our requestPdu function.
 * 
 *
 * Parameters: 
 * None
 *
 * Returns:
 *  None
 *
 *****************************************************************************/
void arduAgentClass::listen(void){
	// if bytes are available in receive buffer
	// and pointer to a function (delegate function)
	// isn't null, trigger the function
	
	/*If the callback variable is set,
	we actually go to the memory location of the function
	pduReceived and begin to run there. Its like a super
	ghetto goto.*/
	Udp.parsePacket();
	if ( Udp.available() && _callback != NULL ) (*_callback)();
}

/**************************************************************************//**
 * Function: begin(with parameters)
 *
 * Description:
 * This is the non-default setup for the arduAgent Class. It allows users
 * to modify the community names and port number the agent uses.
 * 
 *
 * Parameters: 
 * char *getCommName - The C string for the GET community
 * char *setCommName - The C string for the SET community
 * uint16_t port	 - Port number up to 65535
 *
 * Returns:
 *  SNMP_API_STAT_CODES SNMP_API_STAT_SUCCESS - Agent started
 *  SNMP_API_STAT_CODES SNMP_API_STAT_NAME_TOO_BIG - community name exceeds
 *		the maximum allowed in arduAgent.h
 *
 *****************************************************************************/
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

/**************************************************************************//**
 * Function: onPduReceive
 *
 * Description:
 * This function is how we jump back to the user's program after parsing
 * a received SNMP packet. We jump to the user's handler function
 * called onPduReceive. Consequently, their function MUST always
 * be named onPduReceive.
 * 
 *
 * Parameters: 
 * onPduReceiveCallback pduReceived
 *
 * Returns:
 *  None
 *
 *****************************************************************************/
void arduAgentClass::onPduReceive(onPduReceiveCallback pduReceived){
	_callback = pduReceived;
}

/**************************************************************************//**
 * Function: requestPDU
 *
 * Description:
 * This function does the real heavy lifting. It parses the entire SNMP
 * portion of a received packet into private data. It also performs several
 * error checks and authentication checks on the received packet.
 * 
 *
 * Parameters: 
 * None
 *
 * Returns:
 *  SNMP_API_STAT_CODES SNMP_API_STAT_SUCCESS - No errors - Packet parsed
 *  SNMP_API_STAT_CODES SNMP_ERR_TOO_BIG - Packet exceeds maximum packet size
 *		defined in arduAgent.h
 *	SNMP_API_STAT_CODES SNMP_API_STAT_PACKET_INVALID - Not an SNMP packet or
 *		client not authenticated
 *
 *****************************************************************************/
SNMP_API_STAT_CODES arduAgentClass::requestPdu(){
	SNMP_ERR_CODES authenticated = SNMP_ERR_NO_ERROR;
	int errorStatusCodeBaseAddress;
	_packetSize = Udp.available();
	// reset packet array
	for (int rstCounter=0; rstCounter < SNMP_MAX_PACKET_LEN; rstCounter++)
	{
	_packet[rstCounter] = 0;
	}
	
	//Validate Packet Size
	if ( _packetSize != 0 && _packetSize > SNMP_MAX_PACKET_LEN ) {
		arduAgent.generateErrorPDU(SNMP_ERR_TOO_BIG);
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
	errorStatusCodeBaseAddress = 7+lengthCommunityName+4+requestIDlength;
	errorStatusCode[0] = _packet[errorStatusCodeBaseAddress++];
	errorStatusCode[1] = _packet[errorStatusCodeBaseAddress++];
	errorStatusCode[2] = _packet[errorStatusCodeBaseAddress++];
	snmpIndex[0] = _packet[errorStatusCodeBaseAddress++];
	snmpIndex[1] = _packet[errorStatusCodeBaseAddress++];
	snmpIndex[2] = _packet[errorStatusCodeBaseAddress++];
	varbindList[0] = _packet[errorStatusCodeBaseAddress++];
	varbindList[1] = _packet[errorStatusCodeBaseAddress++];
	varbind[0] = _packet[errorStatusCodeBaseAddress++];
	varbind[1] = _packet[errorStatusCodeBaseAddress++];
	objectID = _packet[errorStatusCodeBaseAddress++];
	oidLength = _packet[errorStatusCodeBaseAddress];
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
		arduAgent.generateErrorPDU(authenticated);	
		return SNMP_API_STAT_PACKET_INVALID;
}

/**************************************************************************//**
 * Function: createResponsePDU (Integer)
 *
 * Description:
 * This function constructs an SNMP response packet specifically for the
 * SNMP data type "integer" and takes an integer as a parameter.
 * In other words, the int passed into this function will
 * be transmitted to the client in a GET response.
 * 
 *
 * Parameters: 
 * int respondValue - The integer the user wants to send to the client.
 *
 * Returns:
 *  None
 *
 *****************************************************************************/
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
	arduAgent.send_response();
}

/**************************************************************************//**
 * Function: createResponsePDU (C string)
 *
 * Description:
 * This function constructs an SNMP response packet specifically for the
 * SNMP data type "octet string" and takes a C string as a parameter.
 * In other words, the C string passed into this function will
 * be transmitted to the client in a GET response.
 * 
 *
 * Parameters: 
 * char respondValue[] - The C string the user wants to send to the client.
 *
 * Returns:
 *  None
 *
 *****************************************************************************/
void arduAgentClass::createResponsePDU(char respondValue[]){
		int baseResponseAddress = 7+lengthCommunityName+16+oidLength+requestIDlength;
		int stringLength = strlen(respondValue);
		int total_len = 8+lengthCommunityName+16+oidLength+requestIDlength+1;
		_packet[7+lengthCommunityName] = 0xa2;
		_packet[baseResponseAddress] = 0x04;
		_packet[baseResponseAddress+1] = stringLength;
		for (int i=0; i<stringLength;i++)
		{
			total_len++;
			_packet[baseResponseAddress+1+(i+1)] = respondValue[i];
			_packet[7+lengthCommunityName+1] = _packet[7+lengthCommunityName+1]+1;
		}
		_packet[1] = total_len-2;
		_packet[7+lengthCommunityName+11+requestIDlength] = 6+oidLength+stringLength;
		_packet[7+lengthCommunityName+13+requestIDlength] = 4+oidLength+stringLength;
		arduAgent.send_response();
}

/**************************************************************************//**
 * Function: generateErrorPDU
 *
 * Description:
 * This function constructs an SNMP response packet based on the error code
 * that is passed in. It also sends the resulting packet to the client.
 * 
 *
 * Parameters: 
 * SNMP_ERR_CODES CODE - The error code for which a response should be
 *      generated.
 *
 * Returns:
 *  None
 *
 *****************************************************************************/
void arduAgentClass::generateErrorPDU(SNMP_ERR_CODES CODE){
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
	else if (CODE==SNMP_ERR_AUTHORIZATION_ERROR)
	{
		_packet[errorCodeLocation] = 0x10;
	}
	_packet[7+lengthCommunityName] = 0xa2;
	Udp.beginPacket(Udp.remoteIP(), Udp.remotePort());
	Udp.write(_packet, _packet[1]+2);
	Udp.endPacket();
}

/**************************************************************************//**
 * Function: getOID
 *
 * Description:
 * This function returns the OID stored in private data.
 *
 * Parameters: 
 * byte input[] - A string into which the OID will be copied
 *
 * Returns:
 * None
 *
 *****************************************************************************/
void arduAgentClass::getOID(byte input[]){
	for (int i = 0; i < (int)oidLength; i++)
	{
		input[i] = oid[i];
	}
}

/**************************************************************************//**
 * Function: getOIDlength
 *
 * Description:
 * This function returns the length of the OID that was last received.
 * (The one stored in private data)
 *
 * Parameters: 
 * None
 *
 * Returns:
 * int oidLength - The length of the OID in private data
 *
 *****************************************************************************/
int arduAgentClass::getOIDlength(void){
	return oidLength;
}


/**************************************************************************//**
 * Function: checkOID
 *
 * Description:
 * This function checks the OID in the received packet against the
 * OID that's passed in as a null terminated string. This is used
 * in the user's program to send the correct response based on the
 * OID's they have defined.
 *
 * Parameters: 
 * None
 *
 * Returns:
 * false - OID didn't match
 * true - OID matched
 *
 *****************************************************************************/
bool arduAgentClass::checkOID(const int inputoid[]){
	for(int i = 2; i < oidLength; i++)
	{
		if(inputoid[i] != oid[i-1])
		{
			return false;
		}
	}
	return true;
}

/**************************************************************************//**
 * Function: send_response
 *
 * Description:
 * This function transmits whatever is in _packet.
 *
 * Parameters: 
 * None
 *
 * Returns:
 * SNMP_API_CODES SNMP_API_STAT_SUCCESS - No error (sent)
 * SNMP_API_CODES SNMP_API_STAT_PACKET_INVALID - bad packet (not sent)
 *
 *****************************************************************************/
SNMP_API_STAT_CODES arduAgentClass::send_response(void){
	if(!Udp.beginPacket(Udp.remoteIP(), Udp.remotePort()))
	{
		return SNMP_API_STAT_PACKET_INVALID;
	}
	Udp.write(_packet, _packet[1]+2);
	Udp.endPacket();
	return SNMP_API_STAT_SUCCESS;
}

/**************************************************************************//**
 * Function: print_packet
 *
 * Description:
 * This function is for debugging. It prints the received packet to a
 * serial port.
 *
 * Parameters: 
 * None
 *
 * Returns:
 * None
 *
 *****************************************************************************/
void arduAgentClass::print_packet(void){
	    for(int i =0; i < 50; i++)
        {
          Serial.print( _packet[i], HEX );
          Serial.print(" ");
        }
	
}

/**************************************************************************//**
 * Function: generalAuthenticator
 *
 * Description:
 * This function verifies the appropriate community name by calling 
 * authenticateGetCommunity or authenticateSetCommunity.
 *
 * Parameters: 
 * None
 *
 * Returns:
 * SNMP_ERR_CODES authd - The error code from authentication functions
 *
 *****************************************************************************/
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

/**************************************************************************//**
 * Function: authenticateGetCommunity
 *
 * Description:
 * This function verifies that the GET community name in the received packet
 * matches the specified community names passed into begin(), or the 
 * defaults if no parameters were passed to begin().
 *
 * Parameters: 
 * None
 *
 * Returns:
 * SNMP_ERR_CODES SNMP_ERR_NO_ERROR if GET community matches
 * SNMP_ERR_CODES SNMP_ERR_AUTHORIZATION_ERROR if SNMPv2c  and 
 *		GET community doesn't match
 * SNMP_ERR_CODES SNMP_ERR_NO_SUCH_NAME if SNMPv1 and GET community is wrong
 *
 *****************************************************************************/
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

/**************************************************************************//**
 * Function: authenticateSetCommunity
 *
 * Description:
 * This function verifies that the SET community name in the received packet
 * matches the specified community names passed into begin(), or the 
 * defaults if no parameters were passed to begin().
 *
 * Parameters: 
 * None
 *
 * Returns:
 * SNMP_ERR_CODES SNMP_ERR_NO_ERROR if SET community matches
 * SNMP_ERR_CODES SNMP_ERR_AUTHORIZATION_ERROR if SNMPv2c  and 
 *		SET community doesn't match
 * SNMP_ERR_CODES SNMP_ERR_NO_SUCH_NAME if SNMPv1 and SET community is wrong
 *
 *****************************************************************************/
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

	
// Create one global object
arduAgentClass arduAgent;