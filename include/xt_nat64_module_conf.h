/**
 * @file 	xt_nat64_module_conf.h
 *
 * @brief 	Updates the configuration of module, both times when just inserted
 * 			and when a new config is received through a netlink socket.
 *
 */
#ifndef _XT_NAT64_MODULE_CONF_H
#define _XT_NAT64_MODULE_CONF_H

/*
 * Communication with the NAT64 module (using netlink sockets).
 */
//~ #ifndef _LOAD_CONFIG_H_
//~ #ifdef _NF_NAT64_IPV4_POOL_H
#ifdef _USER_SPACE_
//~ #ifndef _NAT64_CONFIG_VALIDATION_H_
//~ #ifndef _NAT64_CONFIG_VALIDATION_H_ || _LOAD_CONFIG_H_
	#include <netinet/in.h>
#else
	#include <linux/in.h>
	#include <linux/in6.h>

#endif

////////////////////////////////////////////////////////////////////////
// DEFAULT VALUES (Communication)
////////////////////////////////////////////////////////////////////////

//#define MY_MSG_TYPE (0x10 + 2)  ///< Netlink socket packet ID, + 2 is arbitrary but is the same for kern/usr

////////////////////////////////////////////////////////////////////////
// DEFAULT VALUES (Configuration)
////////////////////////////////////////////////////////////////////////

// IPv6:
#define IPV6_DEF_PREFIX			"64:ff9b::"
#define IPV6_DEF_MASKBITS   	96
#define IPV6_DEF_MASKBITS_MAX   96
#define IPV6_DEF_MASKBITS_MIN   32
//
#define IPV6_DEF_TCP_POOL_FIRST 1024		// FIXME: Rename to IPV6_DEF_TCP_PORTS_FIRST
#define IPV6_DEF_TCP_POOL_LAST  65535		// 		  Same thing
//
#define IPV6_DEF_UDP_POOL_FIRST 1024		// FIXME: Rename to IPV6_DEF_UDP_PORTS_FIRST
#define IPV6_DEF_UDP_POOL_LAST  65535		// 		  Same thing
// IPv4:
#define IPV4_DEF_NET        "192.168.2.0" 	// FIXME: Rename to IPV4_DEF_POOL_NET
#define IPV4_DEF_MASKBITS   24				// FIXME: Rename to IPV4_DEF_POOL_NET_MASK_BITS
//
#define IPV4_DEF_POOL_FIRST "192.168.2.1"
#define IPV4_DEF_POOL_LAST  "192.168.2.254"
//
#define IPV4_DEF_TCP_POOL_FIRST 1024		// FIXME: Rename to IPV4_DEF_TCP_PORTS_FIRST
#define IPV4_DEF_TCP_POOL_LAST  65535		// 		  Same thing
//
#define IPV4_DEF_UDP_POOL_FIRST 1024		// FIXME: Rename to IPV4_DEF_UDP_PORTS_FIRST
#define IPV4_DEF_UDP_POOL_LAST  65535		// 		  Same thing


////////////////////////////////////////////////////////////////////////
// STRUCTURES
////////////////////////////////////////////////////////////////////////

struct ipv6_prefixes 
{
	struct in6_addr addr;
	unsigned char maskbits;
};


struct config_struct
{
    //// IPv4:
    struct in_addr ipv4_addr_net; 			// FIXME: Rename this to ipv4_pool_net
	unsigned char  ipv4_addr_net_mask_bits; // FIXME: Rename this to ipv4_pool_net_mask_bits
	struct in_addr ipv4_pool_range_first;
	struct in_addr ipv4_pool_range_last;
    //
    unsigned short ipv4_tcp_port_first;
    unsigned short ipv4_tcp_port_last;
    //
    unsigned short ipv4_udp_port_first;
    unsigned short ipv4_udp_port_last;
    
    //// IPv6:
	struct ipv6_prefixes **ipv6_net_prefixes;
	unsigned char 		   ipv6_net_prefixes_qty;
    //
	unsigned short  ipv6_tcp_port_range_first;
	unsigned short  ipv6_tcp_port_range_last;
	//
	unsigned short  ipv6_udp_port_range_first;
    unsigned short  ipv6_udp_port_range_last;   
};


////////////////////////////////////////////////////////////////////////
// FUNCTION PROTOTYPES
////////////////////////////////////////////////////////////////////////

int init_nat_config(struct config_struct *cs);

int update_nat_config(struct config_struct *cst);


#endif /* _XT_NAT64_MODULE_CONF_H */

