/**
* @file load_config.h
*
* @brief 	This header file contains all required definitions and functions
* 			used by the userspace app that sends configuration to module.
*
*/

#ifndef _LOAD_CONFIG_H_
#define _LOAD_CONFIG_H_

////////////////////////////////////////////////////////////////////////
// INCLUDEs
////////////////////////////////////////////////////////////////////////

#define _USER_SPACE_

#include <stdio.h>
#include <sys/stat.h> // To check if config file exist.
#include <stdlib.h>
#include <string.h>

// Initial configuration
#include <arpa/inet.h>
#include "xt_nat64_module_conf.h" // config struct & defaults
#include "xt_nat64_module_comm.h" // config struct & defaults
#include "confuse.h"

// Communication with the module
#include <netlink/netlink.h> 
#include <netlink/socket.h>
#include <netlink/version.h>

// Assert we compile with libnl version >= 3.0
#if !defined(LIBNL_VER_NUM) 
	#error "You MUST install LIBNL library."
#endif
#if LIBNL_VER_NUM < LIBNL_VER(3,0)
	#error "Unsopported LIBNL library version number (< 3.0)."
#endif

////////////////////////////////////////////////////////////////////////
// DEFINITIONS
////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////
// STRUCTURES
////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////
// FUNCTION PROTOTYPES
////////////////////////////////////////////////////////////////////////

void exit_error_conf(cfg_t *cfg);
//~ int validateIP(const char *ipaddr, struct in_addr addr);


#endif
