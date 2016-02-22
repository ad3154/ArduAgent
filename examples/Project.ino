#include <Ethernet.h>
#include <SPI.h>
#include <atmelAgent.h>

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
//
// Arduino defined OIDs
// .iso.org.dod.internet.private (.1.3.6.1.4)
// .iso.org.dod.internet.private.enterprises (.1.3.6.1.4.1)
// .iso.org.dod.internet.private.enterprises.arduino (.1.3.6.1.4.1.36582)
//
// RFC1213 local values
static char locDescr[]              = "This is a description";// read-only (static)
static uint32_t locUpTime           = 0;                                        // read-only (static)
static char locContact[20]          = "Adrian";                     
static char locName[20]             = "arduAgent";                              
static char locLocation[20]         = "USA";                         
static int32_t locServices          = 6;      // read-only (static)


uint32_t prevMillis = millis();
SNMP_API_STAT_CODES api_status;
SNMP_ERR_CODES status;


void pduReceived()
{
  int temperature_integer = 0;
  byte receivedOID[100] = {0x00};
  bool sent = false;
  api_status = atmelAgent.requestPdu();
  
  if (api_status == SNMP_API_STAT_SUCCESS)
  {
   atmelAgent.getOID(receivedOID);
  //Check defined OID's against received one here:
     if(atmelAgent.check_oid(sysDescr)){
      
     }
     else if(atmelAgent.check_oid(sysUpTime)){
      atmelAgent.createResponsePDU(prevMillis/10);
      sent = atmelAgent.send_response();
     }else if(atmelAgent.check_oid(hrUpTime)){
      atmelAgent.createResponsePDU(prevMillis/10);
      sent = atmelAgent.send_response();
     }else{
      atmelAgent.generate_errorPDU();
     }
 
  }
}

void setup(){
  Serial.begin(9600);

  Ethernet.begin(mac);
  
  Serial.print("My IP address: ");
  for (byte thisByte = 0; thisByte < 4; thisByte++) {
    // print the value of each byte of the IP address:
    Serial.print(Ethernet.localIP()[thisByte], DEC);
    Serial.print(".");
  }
  Serial.println();


  
  api_status = atmelAgent.begin();
  //
  //Serial.println("agent has begun");
  if ( api_status == SNMP_API_STAT_SUCCESS ) {
    atmelAgent.onPduReceive(pduReceived);
    
    
    //
    return;
  }
  
  
}


void loop() {
  // listen/handle for incoming SNMP requests
   atmelAgent.listen();

  if ( millis() - prevMillis > 1000 ) {
    // increment previous milliseconds on Uptime counter
    prevMillis += 1000;
    
    // increment up-time counter
    locUpTime += 100;
  }
}
