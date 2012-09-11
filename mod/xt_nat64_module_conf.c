#include <linux/inet.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/inetdevice.h>
#include "xt_nat64_module_conf.h"
#include "xt_nat64_module_comm.h"
#include "nf_nat64_ipv4_pool.h"

////////////////////////////////////////////////////////////////////////
// VARIABLES
////////////////////////////////////////////////////////////////////////

/**
 *
 */
struct config_struct cs;


/* IPv4. These are global. Reference using extern, please. */
extern struct in_addr ipv4_pool_net;
extern struct in_addr ipv4_pool_range_first;
extern struct in_addr ipv4_pool_range_last;
extern int ipv4_mask_bits;
extern __be32 ipv4_netmask;	// TODO change data type -> 'in_addr' type. Rob.

/* IPv6. These ones are also global. */
extern char *ipv6_pref_addr_str;
//extern int ipv6_pref_len;	// Var type verified ;). Rob
extern unsigned char ipv6_pref_len;	// Var type verified ;). Rob


/**
 * Default configuration, until it be set up by the user space application.
 *
 * @param cs		Config struct where default values will be dropped.
 */
int init_nat_config(struct config_struct *cs)
{
	struct ipv6_prefixes ip6p;
	
//	int i = 0;
	
	/* IPv4 */
	// Validate IPv4 Pool Network
    if (! in4_pton(IPV4_DEF_NET, -1, (u8 *)&ipv4_pool_net.s_addr, '\x0', NULL)) {
        pr_warning("NAT64: IPv4 pool net in Headers is malformed [%s].", IPV4_DEF_NET);
        return -EINVAL;
    }
	// Validate IPv4 Pool - Netmask
	ipv4_mask_bits = IPV4_DEF_MASKBITS;	// Num. of bits 'on' in the net mask
    if (ipv4_mask_bits > 32 || ipv4_mask_bits < 1) {
        pr_warning("NAT64: IPv4 Pool netmask bits value is invalid [%d].",
                IPV4_DEF_MASKBITS);
        return -EINVAL;
    }
	ipv4_netmask = inet_make_mask(ipv4_mask_bits);
	ipv4_pool_net.s_addr = ipv4_pool_net.s_addr & ipv4_netmask; // For the sake of correctness

	// Validate IPv4 Pool - First and Last addresses .
	if (! in4_pton(IPV4_DEF_POOL_FIRST, -1, (u8 *)&ipv4_pool_range_first.s_addr, '\x0', NULL)) {
        pr_warning("NAT64: IPv4 pool net in Headers is malformed [%s].", IPV4_DEF_POOL_FIRST);
        return -EINVAL;
    }
    if (! in4_pton(IPV4_DEF_POOL_LAST, -1, (u8 *)&ipv4_pool_range_last.s_addr, '\x0', NULL)) {
        pr_warning("NAT64: IPv4 pool net in Headers is malformed [%s].", IPV4_DEF_POOL_LAST);
        return -EINVAL;
    }

	// Assing IPv4 values to config struct.
    (*cs).ipv4_addr_net = ipv4_pool_net;
	(*cs).ipv4_addr_net_mask_bits = ipv4_mask_bits;
	(*cs).ipv4_pool_range_first = ipv4_pool_range_first;
	(*cs).ipv4_pool_range_last = ipv4_pool_range_last;
    //
    (*cs).ipv4_tcp_port_first = IPV4_DEF_TCP_POOL_FIRST;
    (*cs).ipv4_tcp_port_last = IPV4_DEF_TCP_POOL_LAST;
    //
    (*cs).ipv4_udp_port_first = IPV4_DEF_UDP_POOL_FIRST;
    (*cs).ipv4_udp_port_last = IPV4_DEF_UDP_POOL_LAST;


	/* IPv6 */
    // Validate IPv6 prefix
	if (! in6_pton(IPV6_DEF_PREFIX, -1, (u8 *)&(ip6p.addr), '\0', NULL)) {
        pr_warning("NAT64: IPv6 prefix in Headers is malformed [%s].", IPV6_DEF_PREFIX);
        return -EINVAL;
    }
    if (IPV6_DEF_MASKBITS > IPV6_DEF_MASKBITS_MAX || IPV6_DEF_MASKBITS < IPV6_DEF_MASKBITS_MIN)
	{
		pr_warning("NAT64: Bad IPv6 network mask bits value in Headers: %d\n", IPV6_DEF_MASKBITS);
		return -EINVAL;
	}
    ip6p.maskbits = IPV6_DEF_MASKBITS;

    ipv6_pref_len = (unsigned char)IPV6_DEF_MASKBITS; // FIXME: This global variable MUST dissapear, and maybe the next too.	
	ipv6_pref_addr_str = (char *)kmalloc(sizeof(char) * strlen(IPV6_DEF_PREFIX) + 1, GFP_USER);
    strcpy(ipv6_pref_addr_str, IPV6_DEF_PREFIX);	// Default IPv6	Prefix(string)

	
    // Allocate memory for IPv6 prefix
	cs->ipv6_net_prefixes = (struct ipv6_prefixes**) kmalloc(1*sizeof(struct ipv6_prefixes*), GFP_ATOMIC);
	cs->ipv6_net_prefixes[0] = (struct ipv6_prefixes*) kmalloc(sizeof(struct ipv6_prefixes), GFP_ATOMIC);
	// Store values in config struct
	(*(*cs).ipv6_net_prefixes[0]) = ip6p;
	(*cs).ipv6_net_prefixes_qty = 1;
    //
	(*cs).ipv6_tcp_port_range_first = IPV6_DEF_TCP_POOL_FIRST;
	(*cs).ipv6_tcp_port_range_last = IPV6_DEF_TCP_POOL_LAST;
	//
	(*cs).ipv6_udp_port_range_first = IPV6_DEF_UDP_POOL_FIRST;
    (*cs).ipv6_udp_port_range_last = IPV6_DEF_UDP_POOL_LAST;


	pr_debug("NAT64: Initial (default) configuration loaded:");
	pr_debug("NAT64:	using IPv4 pool subnet %pI4/%d (netmask %pI4),",
			  &((*cs).ipv4_addr_net), (*cs).ipv4_addr_net_mask_bits, &ipv4_netmask);
	pr_debug("NAT64:	and IPv6 prefix %pI6c/%d.",
			  &((*cs).ipv6_net_prefixes[0]->addr), (*cs).ipv6_net_prefixes[0]->maskbits);

	return 0; // Alles Klar!
}

/**
 * Update nat64 configuration with data received from the 'load_config'
 * userspace app. It's assumed that this data were validated before
 * being sent.
 * 
 * @param cst	Config struct that arrived from user space.
 */
int update_nat_config(struct config_struct *cst)
{
	unsigned char i = 0;
	unsigned char qty = 0;

	// Copy struct sent by user space app to our config struct.
	cs = (*cst);
	
	//ipv6_pref_len = ipv6_net_prefixes[0]->maskbits; // Default IPv6 Prefix, FIXME: We are taking just the first value
	ipv6_pref_len = 64; // JUST FOR TESTING PURPOSES

	pr_debug("NAT64: Updating configuration:");
	pr_debug("NAT64:	using IPv4 pool subnet %pI4/%d (netmask %pI4),",
			  &(cs.ipv4_addr_net), (cs).ipv4_addr_net_mask_bits, &ipv4_netmask);
	qty = (cs).ipv6_net_prefixes_qty;
	for (i = 0; i < qty; i++)
	{
		pr_debug("NAT64:	and IPv6 prefix %pI6c/%d.",
			  &((cs).ipv6_net_prefixes[i]->addr), (cs).ipv6_net_prefixes[i]->maskbits);
	}

	// Update IPv4 addresses pool
    init_pools(&cs); // Bernardo

	// Should we free cst?
	
	// :)
	return 0; // Alles Klar!
}


//~ char *banner=
//~ "                                   ,----,                       \n"
//~ "         ,--.                    ,/   .`|                 ,--,  \n"
//~ "       ,--.'|   ,---,          ,`   .'  :               ,--.'|  \n"
//~ "   ,--,:  : |  '  .' \\       ;    ;     /  ,---.     ,--,  | :  \n"
//~ ",`--.'`|  ' : /  ;    '.   .'___,/    ,'  /     \\ ,---.'|  : '  \n"
//~ "|   :  :  | |:  :       \\  |    :     |  /    / ' ;   : |  | ;  \n"
//~ ":   |   \\ | ::  |   /\\   \\ ;    |.';  ; .    ' /  |   | : _' |  \n"
//~ "|   : '  '; ||  :  ' ;.   :`----'  |  |'    / ;   :   : |.'  |  \n"
//~ "'   ' ;.    ;|  |  ;/  \\   \\   '   :  ;|   :  \\   |   ' '  ; :  \n"
//~ "|   | | \\   |'  :  | \\  \\ ,'   |   |  ';   |   ``.\\   \\  .'. |  \n"
//~ "'   : |  ; .'|  |  '  '--'     '   :  |'   ;      \\`---`:  | '  \n"
//~ "|   | '`--'  |  :  :           ;   |.' '   |  .\\  |     '  ; |  \n"
//~ "'   : |      |  | ,'           '---'   |   :  ';  :     |  : ;  \n"
//~ ";   |.'      `--''                      \\   \\    /      '  ,/   \n"
//~ "'---'                                    `---`--`       '--'    \n";

//char *banner=
//"                                   ,----,                       \n"
//"         ,--.                    ,/   .`|                 ,--,  \n"
//"       ,--.'|   ,---,          ,`   .'**:               ,--.'|  \n"
//"   ,--,:  :*|  '  .'*\\       ;    ;*****/  ,---.     ,--,  |#:  \n"
//",`--.'`|  '*: /  ;****'.   .'___,/****,'  /     \\ ,---.'|  :#'  \n"
//"|   :**:  |*|:  :*******\\  |    :*****|  /    /#' ;   :#|  |#;  \n"
//":   |***\\ |*::  |***/\\***\\ ;    |.';**; .    '#/  |   |#: _'#|  \n"
//"|   :*'**'; ||  :**' ;.***:`----'  |**|'    /#;   :   :#|.'##|  \n"
//"'   '*;.****;|  |**;/  \\***\\   '   :**;|   :##\\   |   '#'##;#:  \n"
//"|   |*| \\***|'  :**| \\  \\*,'   |   |**';   |###``.\\   \\##.'.#|  \n"
//"'   :*|  ;*.'|  |**'  '--'     '   :**|'   ;######\\`---`:  |#'  \n"
//"|   |*'`--'  |  :**:           ;   |.' '   |##.\\##|     '  ;#|  \n"
//"'   :*|      |  |*,'           '---'   |   :##';##:     |  :#;  \n"
//";   |.'      `--''                      \\   \\####/      '  ,/   \n"
//"'---'                                    `---`--`       '--'    \n";

