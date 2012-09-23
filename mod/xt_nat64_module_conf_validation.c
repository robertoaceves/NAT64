#include "xt_nat64_module_conf_validation.h"


/**
 * Convertion and validation of IPv6 addresses in the configuration file.
 *
 * @param[in] 	af			Address family: AF_INET[6].
 * @param[in] 	addr_str	Address in string format.
 * @param[out]	addr		Output address in binary format.
 * @return		EXIT_SUCCESS if OK, otherwise EXIT_FAILURE.
 */
int convert_IP_addr(int af, const char *addr_str, void *addr)
{
	switch(af)
	{
		case AF_INET:
			//~ if (inet_pton(af, addr_str, (struct in_addr*)addr) == 0)

			if (! in4_pton(addr_str, -1, (u8 *)addr, '\x0', NULL) )
				return (EXIT_FAILURE);
			break;
		case AF_INET6:
			//~ if (inet_pton(af, addr_str, (struct in6_addr*)addr) == 0)
			if (! in6_pton(addr_str, -1, (u8 *)addr, '\x0', NULL) )
				return (EXIT_FAILURE);
			break;
		default:
			return (EXIT_FAILURE);
	}
	return (EXIT_SUCCESS);
}

/**
 * Convertion and validation of IPv4 addresses in the configuration file.
 *
 * @param[in] 	addr_str	Address in string format.
 * @param[out]	addr		Output address in binary format.
 * @return		EXIT_SUCCESS if OK, otherwise EXIT_FAILURE.
 */
int convert_ipv4_addr(const char *addr_str, struct in_addr *addr)
{
	return convert_IP_addr(AF_INET, addr_str, addr);
}

/**
 * Convertion and validation of IPv6 addresses in the configuration file.
 *
 * @param[in] 	addr_str	Address in string format.
 * @param[out]	addr		Output address in binary format.
 * @return		EXIT_SUCCESS if OK, otherwise EXIT_FAILURE.
 */
int convert_ipv6_addr(const char *addr_str, struct in6_addr *addr)
{
	return convert_IP_addr(AF_INET6, addr_str, addr);
}

/**
 * Validate the network mask in the format '/n'.
 *
 * @param[in] 	netmask_bits	Network mask bits.
 * @return		EXIT_SUCCESS if OK, otherwise EXIT_FAILURE.
 */
int validate_ipv4_netmask_bits(unsigned char netmask_bits)
{
	if (netmask_bits > 32 || netmask_bits < 0)
		return (EXIT_FAILURE);
	
	return (EXIT_SUCCESS);
}

/**
 * Convert the network mask in CIDR format ('/n') to address format.
 *
 * @param[in] 	af		Address Family: AF_INET[6].
 * @param[in] 	bits	Network mask bits, integer value from: /n.
 * @param[out] 	net		Network mask in address format.
 * @return		EXIT_SUCCESS if OK, otherwise EXIT_FAILURE.
 */
int convert_bits_to_netmask(int af, unsigned char bits, void *net)
{

	unsigned char ii = 0;

	switch(af)
	{
		case AF_INET:
			//~ inet_pton(af, "0.0.0.0", (struct in_addr *)net);
			in4_pton("0.0.0.0", -1, (u8 *)net, '\x0', NULL); 
			(*(struct in_addr *)net).s_addr = \
				BROADCAST_ADDR >>(IPV4_NETMASK_BITS_MAX - bits);
			break;
		case AF_INET6:
			//~ inet_pton(af, "::0", (struct in6_addr *)net);
			in6_pton("::0", -1, (u8 *)net, '\x0', NULL);

			for (ii = 0; ii < IPV6_SIZE_UINT32; ii++)
			{
				if (bits <= ii * IPV6_SIZE_UINT32_BITS * 8)
				{
					if (bits == ii * IPV6_SIZE_UINT32_BITS * 8)
						(*(struct in6_addr *)net).s6_addr32[ii] = \
							DONT_CARE;
					else
						(*(struct in6_addr *)net).s6_addr32[ii] = \
							htonl( BROADCAST_ADDR <<(IPV6_NETMASK_BITS_MAX - bits ) );
				}
				else
				{
					(*(struct in6_addr *)net).s6_addr32[ii] = BROADCAST_ADDR;
				}
			}
			break;
		default:
			//~ printf("%s. Error, bad address family.\n", "convert_bits_to_netmask");
			return EXIT_FAILURE;
	}
	
	return EXIT_SUCCESS;	
}

/**
 * Obtain the network address of an IP address.
 *
 * @param[in] 	af			Address Family: AF_INET[6].
 * @param[in] 	ip_addr		IP address.
 * @param[in] 	ip_netmask	Network mask in address format.
 * @param[out] 	ip_net		Network address.
 * @return		EXIT_SUCCESS if OK, otherwise EXIT_FAILURE.
 */
int get_net_addr(int af, void *ip_addr, void *ip_netmask, void *ip_net)
{
	unsigned char ii = 0;

	switch(af)
	{
		case AF_INET:
			(*(struct in_addr *)ip_net).s_addr = \
				(*(struct in_addr *)ip_addr).s_addr & \
				(*(struct in_addr *)ip_netmask).s_addr;
			break;
		
		case AF_INET6:
			for (ii = 0; ii < IPV6_SIZE_UINT32; ii++)
			{
				(*(struct in6_addr *)ip_net).s6_addr32[ii] = \
					(*(struct in6_addr *)ip_addr).s6_addr32[ii] & \
					(*(struct in6_addr *)ip_netmask).s6_addr32[ii];
			}

			break;

		default:
			//~ printf("%s. Error, bad address family.\n", "get_net_addr");
			return EXIT_FAILURE;

	}

	return EXIT_SUCCESS;
}

/**
 * Verify if two IP addresses are different.
 *
 * @param[in] 	af			Address Family: AF_INET[6].
 * @param[in] 	addr_1		First IP address.
 * @param[in] 	addr_2		Second IP address.
 * @return		EXIT_SUCCESS if they are equal, otherwise return EXIT_FAILURE.
 */
int ip_addr_are_diff(int af, void *addr_1, void *addr_2) 
{
	switch (af)
	{
		case AF_INET: 
			if ( 	(*(struct in_addr *)addr_1).s_addr != \
				(*(struct in_addr *)addr_2).s_addr )
			       return EXIT_FAILURE;	       
			break;
		case AF_INET6:
			// TODO: implement me!	
			/*if ( 	(*(struct in_addr *)addr_1).s_addr != \
			  	(*(struct in_addr *)addr_2).s_addr )
			         return EXIT_FAILURE;	       
			 */
			break;
		default:
			//~ printf("%s. Error, bad address family.\n", "ip_addr_are_equal");
			return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

/**
 * Check that first and last pool addresses belongs to the same network.
 *
 * @param[in] 	af			Address Family: AF_INET[6].
 * @param[in] 	network		Pool's network address.
 * @param[in] 	maskbits		Net mask in CIDR format ('/N').
 * @param[in] 	addr_first		First IP address.
 * @param[in] 	addr_last		Last IP address.
 * @return		EXIT_SUCCESS if all they belong to the same net, otherwise return EXIT_FAILURE.
 */
int ip_addr_in_same_net(int af, 
			const void *network, unsigned char maskbits,
	       	const void *addr_first, const void *addr_last)
{
	struct in_addr ipv4_net;
	struct in_addr ipv4_netmask;
	struct in_addr ipv4_first;
	struct in_addr ipv4_last;

	switch (af)
	{
		case AF_INET:
			convert_bits_to_netmask(af, maskbits, &ipv4_netmask);

			get_net_addr(af, (struct in_addr *)network, &ipv4_netmask, &ipv4_net);
			if ( ip_addr_are_diff(af, (struct in_addr *)network, &ipv4_net)  )
				return EXIT_FAILURE;

			get_net_addr(af, (struct in_addr *)addr_first, &ipv4_netmask, &ipv4_first);
			if ( ip_addr_are_diff(af, &ipv4_net, &ipv4_first)  )
				return EXIT_FAILURE;
			
			get_net_addr(af, (struct in_addr *)addr_last, &ipv4_netmask, &ipv4_last);
			if ( ip_addr_are_diff(af, &ipv4_net, &ipv4_last)  )
				return EXIT_FAILURE;

			break;
		case AF_INET6:
			// TODO?: implement  me
			// Is thís necesary?
			//convert_bits_to_netmask(af, ipv6_bits, &ipv6_netmask);
			break;
		default:
			//~ printf("%s. Error, bad address family.\n", "ip_addr_in_same_net");
			return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

/**
 * Validate the IPv4 pool address range.
 *
 * @param[in] 	network		IPv4 pool network address.
 * @param[in] 	maskbits	IPv4 pool network mask bits.
 * @param[in] 	addr_first	First IPv4 pool address available for NAT64 to use.
 * @param[in] 	addr_last	Last IPv4 pool address available for NAT64 to use.
 * @return		EXIT_SUCCESS if OK, otherwise EXIT_FAILURE.
 */
int validate_ipv4_pool_range(	const struct in_addr *network,
								const unsigned char maskbits,
								const struct in_addr *addr_first,
								const struct in_addr *addr_last )
{
	if (addr_first->s_addr > addr_last->s_addr)
		return EXIT_FAILURE;
	
	if ( ip_addr_in_same_net(AF_INET, \
			network, maskbits, \
	       	addr_first, addr_last) == EXIT_FAILURE )
		return EXIT_FAILURE;
	
	return EXIT_SUCCESS;
}	

/**
 * Validates the IPv4 ports range.
 *
 * @param[in] 	port		First IPv4 valid port.
 * @param[in] 	port		Last IPv4 valid port.
 * @return		EXIT_SUCCESS if OK, otherwise EXIT_FAILURE.
 */
int validate_ports_range(unsigned int first, unsigned int last)
{
	if (first < 0 || first > 65535)
		return EXIT_FAILURE;
	if (last < 0 || last > 65535)
		return EXIT_FAILURE;
	if (first > last)
		return EXIT_FAILURE;	
	
	return EXIT_SUCCESS;
}

/**
 * Validate the network mask in the format '/n'.
 *
 * @param[in] 	netmask_bits	Network mask bits.
 * @return		EXIT_SUCCESS if OK, otherwise EXIT_FAILURE.
 */
int validate_ipv6_netmask_bits(unsigned char netmask_bits)
{
	if (netmask_bits > IPV6_DEF_MASKBITS_MAX || netmask_bits < IPV6_DEF_MASKBITS_MIN)
		return (EXIT_FAILURE);
	
	// TODO: Validate values defined on RFC6052
	
	return (EXIT_SUCCESS);
}
