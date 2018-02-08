/// \file firewall.c    Version: 1.8
/// \brief Reads IP packets from a named pipe, examines each packet,
/// and writes allowed packets to an output named pipe.
/// Author: Charles Leavitt, cil9957
///

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>

#include "filter.h"
#define MAX_PKT_LEN 2048

/// Type used to control the mode of the firewall
typedef enum FilterMode_e
{
   MODE_EXIT = 0,
   MODE_BLOCK_ALL = 1,
   MODE_ALLOW_ALL = 2,
   MODE_FILTER = 3
} FilterMode;


/// The input named pipe, "ToFirewall"
static FILE* InPipe = NULL;


/// The output named pipe, "FromFirewall"
static FILE* OutPipe = NULL;


/// Controls the mode of the firewall
volatile FilterMode Mode = MODE_FILTER;


/// The main function that performs the actual packet read, filter, and write.
/// The return value and parameter must match those expected by pthread_create.
/// @param args A pointer to a filter
/// @return Always NULL
static void* FilterThread(void* args);


/// Displays the menu of commands that the user can choose from.
static void DisplayMenu(void);


/// Opens the input and output named files.
/// @return True if successful
static bool OpenPipes(void);


/// Reads a packet from the input name pipe.
/// @param buf Destination buffer to write the packet into
/// @param bufLength The length of the supplied destination buffer
/// @param len The length of the packet
/// @return True if successful
static bool ReadPacket(unsigned char* buf, int bufLength, int* len);

/// usageErr - displays usage error message and exits program
static void usageErr(void) {
    fprintf(stderr, "usage: ./firewall configFileName");
    exit(EXIT_FAILURE);
}

/// The main function. Creates a filter, configures it, launches the
/// filtering thread, handles user input, and cleans up resources when
/// exiting.  The intention is to run this program with a command line
/// argument specifying the configuration file to use.
/// @param argc Number of command line arguments
/// @param argv Command line arguments
/// @return EXIT_SUCCESS or EXIT_FAILURE
int main(int argc, char* argv[])
{
    // Define local variables 
    pthread_t filterThread;
    int rc;
    char input[5];
    int cmd;
    
    // Enforce correct amount of arguments
    if (argc != 2) 
        usageErr();
    
    IpPktFilter filter = CreateFilter();
    
    // Configure filter, if errors in config exit
    if (ConfigureFilter(filter, argv[1]) == false) {
        exit(EXIT_FAILURE);
    }
    
    // Create and run Filter Thread with the configured filter
    rc = pthread_create (&filterThread, NULL, FilterThread, (void*)filter);
    
    if (rc) {
        fprintf(stderr,"Failed to create filter thread\n");
        exit(EXIT_FAILURE);
    }
    
    // Detach the thread so system will clean up it's memory when finished
    pthread_detach(filterThread);

    // Prompt user once
    DisplayMenu();
    
    // start input loop that sets Mode, exit only on "0" from stdin
    while(1) {
        
        // get user input and set the Mode
        if (fgets(input,5,stdin) == NULL) {
            continue;
        }
        sscanf(input, "%d",&cmd);

        if (cmd == MODE_EXIT) {   
            printf("Exiting\n");
            break;
        }
        else if (cmd == MODE_BLOCK_ALL) {
            printf("blocking all packets\n");
            Mode = MODE_BLOCK_ALL;
        }

        else if (cmd == MODE_ALLOW_ALL) {
            printf("allowing all packets\n");
            Mode = MODE_ALLOW_ALL;
        }
        else if (cmd == MODE_FILTER) {
            printf("filtering packets\n");
            Mode = MODE_FILTER;
        }
        printf("> ");
        fflush(stdout);
        fflush(stdin);
    }
    
    // cancel the detached thread to end thread loop and kill thread.
    pthread_cancel(filterThread);
    
    //clean up memory, close pipes
    DestroyFilter(filter);
    fclose(InPipe);
    fclose(OutPipe);
    
    return EXIT_SUCCESS;
}

/// Runs as a thread and handles each packet. It is responsible
/// for reading each packet in its entirety from the input pipe,
/// filtering it, and then writing it to the output pipe. The
/// single void* parameter matches what is expected by pthread.
/// @param args An IpPktFilter
/// @return Always NULL
static void* FilterThread(void* args) {
    // typecast args back into a filter
    IpPktFilter filter = (IpPktFilter) args;
    
    // Create buffer
    unsigned char buffer[MAX_PKT_LEN];
    
    // lenght of a read in packet
    int len; 
    
    // bool switch for alowing packets through firewall
    bool allow = false;
    
    // Start with opening the pipes:
    OpenPipes();
    
    // Loops until thread canceled
    while (1) {
        
        // Read a packet from InPipe
        if ((ReadPacket(buffer,MAX_PKT_LEN,&len) == false)){
            printf("FilterThread: ReadPacket returned false\n");
            continue;
        }
        
        // Check for the current Mode, set boolean accordingly.

        if (Mode == MODE_BLOCK_ALL) {
            allow = false;
        }
        else if (Mode == MODE_ALLOW_ALL) {
            allow = true;
        }
        else if (Mode == MODE_FILTER) {
            allow = FilterPacket(filter, buffer);
        }
        
        // if packet not blocked write to OutPipe
        if (allow == true) {
            
            fwrite(&len, sizeof(int), 1, OutPipe);
            fwrite(buffer, sizeof(unsigned char), len, OutPipe);
            fflush(OutPipe);
        }
    }
    pthread_exit(NULL);
}

/// Print a menu and a prompt to stdout
static void DisplayMenu(void)
{
   printf("\n1. Block All\n");
   printf("2. Allow All\n");
   printf("3. Filter\n");
   printf("0. Exit\n");
   printf("> ");
   fflush(stdout);
   fflush(stdin);
}


/// Open the input and output named pipes that are used for reading
/// and writing packets.
/// @return True if successful
static bool OpenPipes(void)
{

   InPipe = fopen("ToFirewall", "rb");
   if(InPipe == NULL)
   {
      perror("ERROR, failed to open pipe ToFirewall:");
      return false;
   }

   OutPipe = fopen("FromFirewall", "wb");
   if(OutPipe == NULL)
   {
      perror("ERROR, failed to open pipe FromFirewall:");
      return false;
   }

   return true;
}


/// Read an entire IP packet from the input pipe
/// @param buf Destination buffer for storing the packet
/// @param bufLength The length of the supplied destination buffer
/// @param len The length of the packet
/// @return True if a packet was successfully read
static bool ReadPacket(unsigned char* buf, int bufLength, int* len)
{
    // Read in  the lenght of the packet
    if (fread(len, sizeof(int), 1, InPipe) != 1) {
        printf("ReadPacket: bad packet length read\n");
        return false;
    }

    // Ensure the packet length does not exceed buffer size
    if ((*len) > bufLength) {
        printf("ReadPacket: Buffer Overflow prevented\n");
        return false;
    }
    
    unsigned int temp;
    
    // read in the packet with its specified size
    temp = fread(buf, sizeof(unsigned char), *len, InPipe);
    
    // test to ensure entire packet was read into buffer 
    if (temp != (sizeof(unsigned char) *(*len))) {    
        printf("ReadPacket: bad packet read\n");
        return false;
    }
    else
        return true;
}

