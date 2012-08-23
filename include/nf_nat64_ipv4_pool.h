#ifndef _NF_NAT64_IPV4_POOL_H
#define _NF_NAT64_IPV4_POOL_H

#include <linux/slab.h>
#include <linux/inet.h>
#include "xt_nat64_module_conf.h"

struct transport_addr_struct
{
	char *address;
	__be16 port;
	struct list_head list;
};

struct transport_addr_struct *get_udp_transport_addr(void);
struct transport_addr_struct *get_tcp_transport_addr(void);

void return_udp_transpsort_addr(struct transport_addr_struct *transport_addr);
void return_tcp_transport_addr(struct transport_addr_struct *transport_addr);

void init_pools(struct config_struct *cs);


#endif /* _NF_NAT64_IPV4_POOL_H */
