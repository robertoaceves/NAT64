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
#define IPV6_DEF_TCP_PORTS_FIRST 1024
#define IPV6_DEF_TCP_PORTS_LAST  65535
//
#define IPV6_DEF_UDP_PORTS_FIRST 1024
#define IPV6_DEF_UDP_PORTS_LAST  65535
// IPv4:
#define IPV4_DEF_POOL_NET	"192.168.2.0"
#define IPV4_DEF_POOL_NET_MASK_BITS   24
//
#define IPV4_DEF_POOL_FIRST "192.168.2.1"
#define IPV4_DEF_POOL_LAST  "192.168.2.254"
//
#define IPV4_DEF_TCP_PORTS_FIRST 1024
#define IPV4_DEF_TCP_PORTS_LAST  65535
//
#define IPV4_DEF_UDP_PORTS_FIRST 1024
#define IPV4_DEF_UDP_PORTS_LAST  65535


////////////////////////////////////////////////////////////////////////
// STRUCTURES
////////////////////////////////////////////////////////////////////////

/**
 * Struct to handle valid IPv6 prefixes specified as configuration parameters.
 */
struct ipv6_prefixes 
{
	struct in6_addr addr;	///< IPv6 prefix
	unsigned char maskbits;	///< Network mask in CIDR format.
};

/**
 * This holds the entire running and valid configuration.
 */
struct config_struct
{
    //// IPv4:
    struct in_addr ipv4_pool_net; 				/**< IPv4 Pool network address. */
	unsigned char  ipv4_pool_net_mask_bits; 	/**< IPv4 Pool network address, in CIDR format. */
	struct in_addr ipv4_pool_range_first;		/**< IPv4 Pool first valid address. */
	struct in_addr ipv4_pool_range_last;		/**< IPv4 Pool last valid address. */
    //
    /// Maybe this should disappear to satisfy requirements about ports handling, as defined in RFC6146. 
    ///@{
    unsigned short ipv4_tcp_port_first;		/**< Valid range of TCP ports. */
    unsigned short ipv4_tcp_port_last;
    //
    unsigned short ipv4_udp_port_first;		/**< Valid range of UDP ports. */
    unsigned short ipv4_udp_port_last;
	///@} 
    
    //// IPv6:
	struct ipv6_prefixes **ipv6_net_prefixes;		/**< Array of valid prefixes. */
	unsigned char 		   ipv6_net_prefixes_qty;	/**< Length of the array. */
    //
    /// Maybe this should disappear to satisfy requirements about ports handling, as defined in RFC6146. 
    ///@{
	unsigned short  ipv6_tcp_port_range_first;		/**< Valid range of TCP ports. */
	unsigned short  ipv6_tcp_port_range_last;
	//
	unsigned short  ipv6_udp_port_range_first;		/**< Valid range of UDP ports. */
    unsigned short  ipv6_udp_port_range_last; 
    ///@} 
};


////////////////////////////////////////////////////////////////////////
// FUNCTION PROTOTYPES
////////////////////////////////////////////////////////////////////////

int init_nat_config(struct config_struct *cs);

int update_nat_config(struct config_struct *cst);


#endif /* _XT_NAT64_MODULE_CONF_H */

