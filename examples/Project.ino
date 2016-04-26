#include <Ethernet.h>
#include <SPI.h>
#include <arduAgent.h>

static byte mac[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED };
//static byte ip[] = { 151, 159, 18, 201 };
//static byte gateway[] = { 151, 159, 18, 254 };
//static byte subnet[] = { 255, 255, 255, 0 };

// RFC1213-MIB OIDs
// .iso (.1)
// .iso.org (.1.3)
// .iso.org.dod (.1.3.6)
// .iso.org.dod.internet (.1.3.6.1)
// .iso.org.dod.internet.mgmt (.1.3.6.1.2)
// .iso.org.dod.internet.mgmt.mib-2 (.1.3.6.1.2.1)
// .iso.org.dod.internet.mgmt.mib-2.system (.1.3.6.1.2.1.1)
// .iso.org.dod.internet.mgmt.mib-2.system.sysDescr (.1.3.6.1.2.1.1.1)
int sysDescr[]     = {1,3,6,1,2,1,1,1,0};  // read-only  (DisplayString)
// .iso.org.dod.internet.mgmt.mib-2.system.sysObjectID (.1.3.6.1.2.1.1.2)
//static int sysObjectID[] = {1,3,6,1,2,1,1,2,0};  // read-only  (ObjectIdentifier)
// .iso.org.dod.internet.mgmt.mib-2.system.sysUpTime (.1.3.6.1.2.1.1.3)
int sysUpTime[]     = {1,3,6,1,2,1,1,3,0};  // read-only  (TimeTicks)
// .iso.org.dod.internet.mgmt.mib-2.system.sysContact (.1.3.6.1.2.1.1.4)
int sysContact[]    = {1,3,6,1,2,1,1,4,0};  // read-write (DisplayString)
// .iso.org.dod.internet.mgmt.mib-2.system.sysName (.1.3.6.1.2.1.1.5)
int sysName[]       = {1,3,6,1,2,1,1,5,0};  // read-write (DisplayString)
// .iso.org.dod.internet.mgmt.mib-2.system.sysLocation (.1.3.6.1.2.1.1.6)
int sysLocation[]   = {1,3,6,1,2,1,1,6,0};  // read-write (DisplayString)
// .iso.org.dod.internet.mgmt.mib-2.system.sysServices (.1.3.6.1.2.1.1.7)
int sysServices[]   = {1,3,6,1,2,1,1,7,0};  // read-only  (Integer)
// .iso.org.dod.internet.mgmt.mib-2.hostresourcesMIB.hrUpTime (.1.3.6.1.2.1.25.1.1)
int hrUpTime[]      = {1,3,6,1,2,1,25,1,1,0};
//	Example Writable OID	(.1.3.6.1.2.1.11.30)
int exampleWritableVar[]     = {1,3,6,1,2,1,11,30,0};
//
// Arduino defined OIDs
// .iso.org.dod.internet.private (.1.3.6.1.4)
// .iso.org.dod.internet.private.enterprises (.1.3.6.1.4.1)
// .iso.org.dod.internet.private.enterprises.arduino (.1.3.6.1.4.1.36582)
//
// RFC1213 local values
	static char locDescr[]              = "Description";// read-only (static)
	static uint32_t locUpTime           = 0;		    // read-only (static)
	static char locContact[20]          = "User";		// read-only (static)
	static char locName[20]             = "arduAgent";	// read-only (static)
	static char locLocation[20]         = "Somewhere USA";// read-only (static)
	static int32_t locServices          = 6;			// read-only (static)
  // Example writable value
  int exampleWritable			= 0;			//Read-write

uint32_t prevMillis = millis();
SNMP_API_STAT_CODES api_status;
SNMP_ERR_CODES status;


void pduReceived()
{
	api_status = arduAgent.requestPdu();
	
	if (api_status == SNMP_API_STAT_SUCCESS &&
	arduAgent.requestType() == SNMP_GET){
		/*Check defined OID's against received one here:
		You will need to edit this section for each
		variable you want to have available to the agent*/
		if(arduAgent.checkOID(sysDescr)){
			arduAgent.createResponsePDU(locDescr);
		}
		else if(arduAgent.checkOID(sysUpTime)){
			arduAgent.createResponsePDU(prevMillis/10);
			}else if(arduAgent.checkOID(hrUpTime)){
			arduAgent.createResponsePDU(prevMillis/10);
			}else if(arduAgent.checkOID(sysContact)){
			arduAgent.createResponsePDU(locContact);
			}else if(arduAgent.checkOID(sysLocation)){
			arduAgent.createResponsePDU(locLocation);
			}else if(arduAgent.checkOID(sysName)){
			arduAgent.createResponsePDU(locName);
			}else if(arduAgent.checkOID(exampleWritableVar)){
			arduAgent.createResponsePDU(exampleWritable);
			}else{
			arduAgent.generateErrorPDU(SNMP_ERR_NO_SUCH_NAME);
		}
		
	}
	else if (api_status == SNMP_API_STAT_SUCCESS &&
	arduAgent.requestType() == SNMP_SET){
		/*PLACE COMPARISONS TO WRITABLE OID'S HERE
		You will need to edit this section to match your
		particular application	*/
		if(arduAgent.checkOID(exampleWritableVar)){
			arduAgent.set(exampleWritable);
		}
	}
	else if (api_status == SNMP_API_STAT_PACKET_INVALID){
		arduAgent.generateErrorPDU(SNMP_ERR_GEN_ERROR);
	}
}

void setup()
{
  Serial.begin(9600);

  Ethernet.begin(mac);
  
  Serial.print("My IP address: ");
  for (byte thisByte = 0; thisByte < 4; thisByte++) {
    // print the value of each byte of the IP address:
    Serial.print(Ethernet.localIP()[thisByte], DEC);
    Serial.print(".");
  }
  Serial.println();


  
  api_status = arduAgent.begin();
  //
  //Serial.println("agent has begun");
  if ( api_status == SNMP_API_STAT_SUCCESS ) {
    arduAgent.onPduReceive(pduReceived);
    
    return;
  }
  
  
}


void loop() {
  // listen/handle for incoming SNMP requests
   arduAgent.listen();

  if ( millis() - prevMillis > 1000 ) {
    // increment previous milliseconds on Uptime counter
    prevMillis += 1000;
    
    // increment up-time counter
    locUpTime += 100;
  }
}

