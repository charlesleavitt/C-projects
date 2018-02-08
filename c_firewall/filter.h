#ifndef __FILTER_H__
#define __FILTER_H__
/// \file filter.h
/// \brief Filters IP packets based on settings in a user supplied
/// configuration file.
/// Author: Charles Leavitt
///

#include <stdbool.h>


/// The type used by the client to store/use a filter instance
typedef void* IpPktFilter;


/// Creates and instance of a IP packet filter
/// @return A pointer to the new instance
IpPktFilter CreateFilter(void);


/// Destroys and instance of an IP packet filter, and frees all
/// of the associated dynamically allocated memory.
/// @param filter The filter instance to destroy
void DestroyFilter(IpPktFilter filter);


/// Configures a newly created filter instance based on the settings
/// in the provided configuration file
/// @param filter The filter instance that is to be configured
/// @param filename The path/filename of the configuration file
/// @return True if successful
bool ConfigureFilter(IpPktFilter filter, char* filename);


/// Determines if an IP packet is allowed or if it should be blocked
/// based on the settings in the specified filter instance
/// @param filter The filter instance that is to be used
/// @param pkt The IP packet that is to be evaluated
/// @return True if the packet is allowed, False if it should be blocked
bool FilterPacket(IpPktFilter filter, unsigned char* pkt);

#endif

