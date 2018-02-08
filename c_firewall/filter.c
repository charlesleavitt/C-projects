/// \file filter.c  Version: 1.8
/// \brief Filters IP packets based on settings in a user supplied
/// configuration file.
/// Author: Charles Leavitt, cil9957
///

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "filter.h"
#include "pktUtility.h"

#define MAX_LINE_LEN  256

/// The type used to hold the configuration settings for a filter
typedef struct FilterConfig_S
{
   unsigned int localIpAddr;
   unsigned int localMask;
   bool blockInboundEchoReq;
   unsigned int numBlockedInboundTcpPorts;
   unsigned int* blockedInboundTcpPorts;
   unsigned int numBlockedIpAddresses;
   unsigned int* blockedIpAddresses;
} FilterConfig;


/// Adds an IP address to the blocked list
/// @param fltCfg The filter configuration to add the IP address to
/// @param ipAddr The IP address that is to be blocked
static void AddBlockedIpAddress(FilterConfig* fltCfg, unsigned int ipAddr);


/// Adds a TCP port to the list of blocked inbound TCP ports
/// @param fltCfg The filter configuration to add the TCP port to
/// @param The TCP port that is to be blocked
static void AddBlockedInboundTcpPort(FilterConfig* fltCfg, unsigned int port);


/// Helper function that calls strtok and sscanf to read the decimal point
/// separated IP address octets
/// @param ipAddr The destination into which the IP address octets are stored
static void ParseRemainderOfStringForIp(unsigned int* ipAddr);


/// Tests a packet to determine if it should be blocked due to either
/// the source or destination IP addresses.
/// @param fltCfg The filter configuration to use
/// @param addr The IP address to test
/// @return True if the packet is to be blocked
static bool BlockIpAddress(FilterConfig* fltCfg, unsigned int addr);


/// Tests a packet to determine if it should be blocked due to the destination
/// TCP port.
/// @param fltCfg The filter configuration to use
/// @param port The TCP port to test
/// @return True if the packet is to be blocked
static bool BlockInboundTcpPort(FilterConfig* fltCfg, unsigned int port);


/// Tests a packet's source and destination IP addresses against the local
/// network's IP address and net mask to determine if a packet is coming
/// into the network from the outside world.
/// @param fltCfg The filter configuration to use
/// @param srcAddr The source IP address that has been extracted from a packet
/// @param dstAddr The destination IP address that has been extracted from a packet
static bool PacketIsInbound(FilterConfig* fltCfg, unsigned int srcAddr, unsigned int dstAddr);


/// Creates an instance of a filter by allocating memory for a FilterConfig
/// and initializing its member variables.
/// @return A pointer to the new filter
IpPktFilter CreateFilter(void)
{
    IpPktFilter filter = calloc(1,sizeof(FilterConfig));
    return filter; 
}


/// Destroys an instance of a filter by freeing all of the dynamically
/// allocated memory associated with the filter.
/// @param filter The filter that is to be destroyed
void DestroyFilter(IpPktFilter filter)
{
   FilterConfig* fltCfg = filter;

   if(fltCfg->blockedIpAddresses != NULL)
      free(fltCfg->blockedIpAddresses);

   if(fltCfg->blockedInboundTcpPorts != NULL)
      free(fltCfg->blockedInboundTcpPorts);

   free(filter);
}


/// Configures a filter instance using the specified configuration file.
/// Reads the file line by line and uses strtok, strcmp, and sscanf to 
/// parse each line.  After each line is successfully parsed the result
/// is stored in the filter.  Blank lines are skipped.  When the end of
/// the file is encountered, the file is closed and the function returns.
/// @param filter The filter that is to be configured
/// @param filename The full path/filename of the configuration file that
/// is to be read.
/// @return True when successful
bool ConfigureFilter(IpPktFilter filter, char* filename)
{
   char buf[MAX_LINE_LEN];
   FILE* pFile;
   char* pToken;
   char* success;
   unsigned int ipAddr[4];
   unsigned int temp;
   unsigned int mask;
   unsigned int dstTcpPort;
   bool IsLocalNet = false;

   FilterConfig *fltCfg = (FilterConfig*)filter;
 
   pFile = fopen(filename, "r"); 
   if(pFile == NULL)
   {
      fprintf(stderr,"ERROR, invalid config file\n");
      return false;
   }

   while(1)
   {
      success = fgets(buf, MAX_LINE_LEN, pFile);
      if(success == NULL)
         break;  // end of file found

      pToken = strtok(buf, ":\n");
      if( pToken == NULL )
      {
         // empty line encountered
      }
      else if( strcmp(pToken, "LOCAL_NET") == 0 )
      {
         ParseRemainderOfStringForIp(ipAddr);
         temp = ConvertIpUIntOctetsToUInt(ipAddr);
         fltCfg->localIpAddr = temp;
         IsLocalNet = true;
        
         pToken = strtok(NULL, "/");
         sscanf(pToken, "%u", &temp);
         mask = 0;
         for(unsigned int i=0; i<temp; i++)
         {
            mask = mask >> 1;
            mask |= 0x80000000;
         }
         fltCfg->localMask = mask;

      }

      // Charles Leavitt implemented remainder of file parsing
      
      else if (strcmp(pToken, "BLOCK_PING_REQ") == 0 ) {
         fltCfg->blockInboundEchoReq = true; 
      }
      else if (strcmp(pToken, "BLOCK_IP_ADDR") == 0){
         ParseRemainderOfStringForIp(ipAddr);
         temp = ConvertIpUIntOctetsToUInt(ipAddr);
         AddBlockedIpAddress(fltCfg, temp);
      }
      else if ( strcmp(pToken, "BLOCK_INBOUND_TCP_PORT") == 0){
         pToken = strtok(NULL, "/");
         sscanf(pToken, "%u", &dstTcpPort);
         AddBlockedInboundTcpPort(fltCfg, dstTcpPort);
      }
   }
   // make sure a local network address was specified, else pop Error.
   if ( IsLocalNet == false) {
      fprintf(stderr, "Error, configuration file must set LOCAL_NET\n");
      fclose(pFile);
      return false;
   }
   fclose(pFile); 
   return true;
}


/// Uses the settings specified by the filter instance to determine
/// if a packet should be allowed or blocked.  The source and
/// destination IP addresses are extracted from each packet and
/// checked using the BlockIpAddress helper function. The IP protocol
/// is extracted from the packet and if it is ICMP or TCP then 
/// additional processing occurs. This processing blocks inbound packets
/// set to blocked TCP destination ports and inbound ICMP echo requests.
/// @param filter The filter configuration to use
/// @param pkt The packet to examine
/// @return True if the packet is allowed by the filter. False if the packet
/// is to be blocked
bool FilterPacket(IpPktFilter filter, unsigned char* pkt)
{
    // extract IP info from packet: 
    unsigned int srcIP = ExtractSrcAddrFromIpHeader(pkt);
    unsigned int destIP = ExtractDstAddrFromIpHeader(pkt);
    
    // check if the source or destination IPs are on Block list 
    if (BlockIpAddress(filter,srcIP)||(BlockIpAddress(filter,destIP)))
        return false;
    
    // check if packet is inbound
    if (PacketIsInbound(filter, srcIP, destIP) == true) {
        
        // Extract protocal from packet
        unsigned int protocol = ExtractIpProtocol(pkt);
        
        // check for TCP protocal # 6 
        if (protocol == IP_PROTOCOL_TCP) {
            // If extracted port is on block list, block
            if(BlockInboundTcpPort(filter, ExtractTcpDstPort(pkt))){
                return false;
            }
        }
        FilterConfig *ftc = filter;
        if(ftc->blockInboundEchoReq == true) {
        // check for ICMP protocal # 1
            if (protocol == IP_PROTOCOL_ICMP) {
                // If ICMP type is a ping request type #8, block
                if (ExtractIcmpType(pkt) == ICMP_TYPE_ECHO_REQ) {
                    return false;
                }
            }
        }
    }
    // Nothing blocked, allow packet
    return true;
}


/// Checks if an IP address is listed as blocked by the supplied filter.
/// @param fltCfg The filter configuration to use
/// @param addr The IP address that is to be checked
/// @return True if the IP address is to be blocked
static bool BlockIpAddress(FilterConfig* fltCfg, unsigned int addr) {
    
    // loop through blocked IPs in filter looking for blocked IP match
    for(unsigned int ip = 0; ip < fltCfg->numBlockedIpAddresses; ip++){
        if (addr == fltCfg->blockedIpAddresses[ip]){
            return true;
        }
    }
    return false;
}


/// Checks if a TCP port is listed as blocked by the supplied filter.
/// @param fltCfg The filter configuration to use
/// @param port The TCP port that is to be checked
/// @return True if the TCP port is to be blocked
static bool BlockInboundTcpPort(FilterConfig* fltCfg, unsigned int port) {
    
    // loop through the blocked ports in filter looking for a match
    for(unsigned int i = 0; i < fltCfg->numBlockedInboundTcpPorts; i++) {
        if (port == fltCfg->blockedInboundTcpPorts[i]) {
            return true;
        }
    }
    return false;
}


/// Checks if a packet is coming into the network from the external world. Uses
/// the localMask in the supplied filter configuration to compare the srcIpAddr
/// and dstIpAddr to the localIpAddr supplied in the filter configuration. If the
/// dstIpAddr is on the same network as the localIpAddr, and the srcIpAddr is not
/// on the same network as the localIpAddr then the packet is inbound.
/// @param fltCfg The filter configuration to use
/// @param srcIpAddr The source IP address of a packet
/// @param dstIpAddr The destination IP address of a packet
static bool PacketIsInbound(FilterConfig* fltCfg, unsigned int srcIpAddr, unsigned int dstIpAddr) {
    
    // get the network addresses
    unsigned int localNet = fltCfg->localIpAddr & fltCfg->localMask;
    unsigned int srcNet = srcIpAddr & fltCfg->localMask;
    unsigned int destNet = dstIpAddr & fltCfg->localMask;
    
    // check if the soucre ip is not on local net while dest ip is
    if ((localNet != srcNet) && (localNet == destNet)) {
        return true;
    }
    else {
        return false;
    }
}


/// Adds the specified IP address to the array of blocked IP addresses in the
/// specified filter configuration. This requires allocating additional memory
/// to extend the length of the array that holds the blocked IP addresses.
/// @param fltCfg The filter configuration to which the IP address is added
/// @param ipAddr The IP address that is to be blocked
static void AddBlockedIpAddress(FilterConfig* fltCfg, unsigned int ipAddr)
{
   unsigned int *pTemp;
   int num = fltCfg->numBlockedIpAddresses;

   if(num == 0)
      pTemp = (unsigned int*)malloc(sizeof(unsigned int));
   else
      pTemp = (unsigned int*)realloc( fltCfg->blockedIpAddresses, sizeof(unsigned int)*(num + 1) );
 
   assert(pTemp != NULL); 
   fltCfg->blockedIpAddresses = pTemp;
   fltCfg->blockedIpAddresses[num] = ipAddr;
   fltCfg->numBlockedIpAddresses++;
}


/// Adds the specified TCP port to the array of blocked TCP ports in the
/// specified filter configuration. This requires allocating additional
/// memory to extend the length of the array that holds the blocked ports.
/// @param fltCfg The filter configuration to which the TCP port is added
/// @param port The TCP port that is to be blocked
static void AddBlockedInboundTcpPort(FilterConfig* fltCfg, unsigned int port)
{
   unsigned int *pTemp;
   int num = fltCfg->numBlockedInboundTcpPorts;

   if(num == 0)
      pTemp = (unsigned int*)malloc(sizeof(unsigned int));
   else
      pTemp = (unsigned int*)realloc( fltCfg->blockedInboundTcpPorts, sizeof(unsigned int)*(num + 1) );
 
   assert(pTemp != NULL); 
   fltCfg->blockedInboundTcpPorts = pTemp;
   fltCfg->blockedInboundTcpPorts[num] = port;
   fltCfg->numBlockedInboundTcpPorts++;
}


/// Parses the remainder of the string last operated on by strtok 
/// and converts each octet of the ASCII string IP address to an
/// unsigned integer value.
/// @param ipAddr The destination into which to store the octets
static void ParseRemainderOfStringForIp(unsigned int* ipAddr)
{
   char* pToken;

   pToken = strtok(NULL, ".");
   sscanf(pToken, "%u", &ipAddr[0]);
   pToken = strtok(NULL, ".");
   sscanf(pToken, "%u", &ipAddr[1]);
   pToken = strtok(NULL, ".");
   sscanf(pToken, "%u", &ipAddr[2]);
   pToken = strtok(NULL, "/");
   sscanf(pToken, "%u", &ipAddr[3]);
}


