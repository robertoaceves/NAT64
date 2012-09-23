#include "load_config.h"
#include "nat64_config_validation.h"

/**
* Main function of the user app that parses configuration file and sends it to
* NAT64 kernel module.
*
* @param argc	Qty of arguments in command line call.
* @param argv	Array of arguments in command line call.
*/
int main(int argc, char *argv[])
{
	struct stat sb; // To check if config file exist.
	struct in_addr iaddrn, iaddrf, iaddrl;      // To validate IP addresses
    struct in6_addr i6addrf;   			// also
    cfg_t *cfg, *cfg_ipv4, *cfg_ipv6;
	const char *sect_name;
	char *addr_first, *addr_last;
    unsigned char addr_maskbits;
    int port_first, port_last;
    char which[sizeof("ABC")];
    char str[INET_ADDRSTRLEN];
    
    struct config_struct cs;

	struct nl_sock *nls;
	int ret;

	int i = 0;
	struct ipv6_prefixes **ipv6_pref = NULL;
	unsigned char ipv6_pref_qty;
	char ipv6_def_prefix64[sizeof("1111:2222:3333:4444:5555:6666::/128")];
	char *ipv6_buf;  
	char *ipv6_check_addr; 
	char *ipv6_check_maskbits; 

	if (argc != 2)
	{
		printf("Usage: %s <config-file>\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	if ( stat(argv[1], &sb) == -1 )
	{
		printf("Error: Can not open configuration file: %s\n", argv[1]);
		exit(EXIT_FAILURE);
	}

	// Load default configuration values for each config option, just in case 
	// they were not included in the config file.
    cfg_opt_t ipv4_opts[] =
    {
        CFG_STR("ipv4_addr_net", IPV4_DEF_NET, CFGF_NONE), 
        CFG_INT("ipv4_addr_net_mask_bits", IPV4_DEF_MASKBITS, CFGF_NONE), 
        CFG_STR("ipv4_pool_range_first", IPV4_DEF_POOL_FIRST, CFGF_NONE), 
        CFG_STR("ipv4_pool_range_last", IPV4_DEF_POOL_LAST, CFGF_NONE), 
        CFG_INT("ipv4_tcp_port_range_first", IPV4_DEF_TCP_PORTS_FIRST, CFGF_NONE), 
        CFG_INT("ipv4_tcp_port_range_last", IPV4_DEF_TCP_PORTS_LAST, CFGF_NONE), 
        CFG_INT("ipv4_udp_port_range_first", IPV4_DEF_UDP_PORTS_FIRST, CFGF_NONE), 
        CFG_INT("ipv4_udp_port_range_last", IPV4_DEF_UDP_PORTS_LAST, CFGF_NONE), 
        CFG_END()
    };

	// Load default configuration values for each config option, just in case 
	// they were not included in the config file.
	sprintf(ipv6_def_prefix64, "%s/%d", IPV6_DEF_PREFIX, IPV6_DEF_MASKBITS );
	cfg_opt_t ipv6_opts[] =
    {
        CFG_STR_LIST("ipv6_net_prefixes", ipv6_def_prefix64, CFGF_NONE), 
        CFG_INT("ipv6_tcp_port_range_first", IPV6_DEF_TCP_PORTS_FIRST, CFGF_NONE), 
        CFG_INT("ipv6_tcp_port_range_last", IPV6_DEF_TCP_PORTS_LAST, CFGF_NONE), 
        CFG_INT("ipv6_udp_port_range_first", IPV6_DEF_UDP_PORTS_FIRST, CFGF_NONE), 
        CFG_INT("ipv6_udp_port_range_last", IPV6_DEF_UDP_PORTS_LAST, CFGF_NONE), 
		CFG_END()
    };
    // Define two sections in config file
    cfg_opt_t opts[] =
    {
        CFG_SEC("ipv4", ipv4_opts, CFGF_NONE),
        CFG_SEC("ipv6", ipv6_opts, CFGF_NONE),
        CFG_END()
    };

	// Parse config file
    cfg = cfg_init(opts, CFGF_NONE);
    if(cfg_parse(cfg, argv[1]) == CFG_PARSE_ERROR)
	{
		printf("Error parsing configuration file: %s\n", argv[1]);
        exit_error_conf(cfg);
	}

	/*
	 * Loading IPv4 configuration
	 *
	 */
	{
        cfg_ipv4 = cfg_getsec(cfg, "ipv4");

		sect_name = cfg_name(cfg_ipv4);
		printf ("Section: %s\n", sect_name);

		// Validate IPv4 pool address
		addr_first = cfg_getstr(cfg_ipv4, "ipv4_addr_net");
        if ( convert_ipv4_addr(addr_first, &iaddrn) == EXIT_FAILURE )	
		{
			printf("Error: Invalid IPv4 address net: %s\n", addr_first);
			exit_error_conf(cfg);
		}
		// Validate netmask bits
        addr_maskbits = cfg_getint(cfg_ipv4, "ipv4_addr_net_mask_bits");
        if ( validate_ipv4_netmask_bits(addr_maskbits) == EXIT_FAILURE )
        {
            printf("Error: Bad IPv4 network mask bits value: %d\n", addr_maskbits);
			exit_error_conf(cfg);
        }
        // Store values in config struct
		cs.ipv4_addr_net = iaddrn;
        cs.ipv4_addr_net_mask_bits = addr_maskbits;
		printf("\tPool Network: %s/%d\n", addr_first, addr_maskbits);
		
		// Validate pool addresses range
		addr_first = cfg_getstr(cfg_ipv4, "ipv4_pool_range_first");
        addr_last = cfg_getstr(cfg_ipv4, "ipv4_pool_range_last");
		if ( convert_ipv4_addr(addr_first, &iaddrf) == EXIT_FAILURE )	// Validate ipv4 addr
		{
			printf("Error: Malformed ipv4_pool_range_first: %s\n", addr_first);
			exit_error_conf(cfg);
		}
		if ( convert_ipv4_addr(addr_last, &iaddrl) == EXIT_FAILURE  )	// Validate ipv4 addr
		{
			printf("Error: Malformed ipv4_pool_range_last: %s\n", addr_last);
			exit_error_conf(cfg);
		}
		if (  validate_ipv4_pool_range(&iaddrn, addr_maskbits, &iaddrf, &iaddrl) == EXIT_FAILURE )	// Validate that: first < last
		{
			printf("Error: Pool addresses badly defined.\n");
			exit_error_conf(cfg);
		}
		// Store values in config struct
        cs.ipv4_pool_range_first = iaddrf;
        cs.ipv4_pool_range_last = iaddrl;
        inet_ntop(AF_INET, &(iaddrf.s_addr), str, INET_ADDRSTRLEN);
		printf("\t\t- First address: %s\n", str);
        inet_ntop(AF_INET, &(iaddrl.s_addr), str, INET_ADDRSTRLEN);
		printf("\t\t- Last address: %s\n", str);
        
        // Validate port ranges
        port_first = cfg_getint(cfg_ipv4, "ipv4_tcp_port_range_first");
        port_last = cfg_getint(cfg_ipv4, "ipv4_tcp_port_range_last");
        sprintf(which, "TCP");
        if ( validate_ports_range(port_first, port_last) == EXIT_FAILURE )
        {
            //~ printf("Error: Invalid first %s port: %d\n", which, port_first);
            printf("Error: Invalid %s ports range.\n", which);
            exit_error_conf(cfg);
        }
        //~ if (port_last < 0 || port_last > 65535)
        //~ {
            //~ printf("Error: Invalid last %s port: %d\n", which, port_last);
            //~ exit_error_conf(cfg);
        //~ }
        //~ if (port_first > port_last)
        //~ {
            //~ printf("Error: First %s port is greater than last port.\n", which);
            //~ exit_error_conf(cfg);
        //~ }
        cs.ipv4_tcp_port_first = port_first;
        cs.ipv4_tcp_port_last = port_last;
		printf("\t%s pool port range: %d-%d\n", which, port_first, port_last);
		//
        port_first = cfg_getint(cfg_ipv4, "ipv4_udp_port_range_first");
        port_last = cfg_getint(cfg_ipv4, "ipv4_udp_port_range_last");
        sprintf(which, "UDP");
       if ( validate_ports_range(port_first, port_last) == EXIT_FAILURE )
        {
            printf("Error: Invalid %s ports range.\n", which);
            exit_error_conf(cfg);
        }
        //~ if (port_first < 0 || port_first > 65535)
        //~ {
            //~ printf("Error: Invalid first %s port: %d\n", which, port_first);
            //~ exit_error_conf(cfg);
        //~ }
        //~ if (port_last < 0 || port_last > 65535)
        //~ {
            //~ printf("Error: Invalid last %s port: %d\n", which, port_last);
            //~ exit_error_conf(cfg);
        //~ }
        //~ if (port_first > port_last)
        //~ {
            //~ printf("Error: First %s port is greater than last port.\n", which);
            //~ exit_error_conf(cfg);
        //~ }
        cs.ipv4_udp_port_first = port_first;
        cs.ipv4_udp_port_last = port_last;
		printf("\t%s pool port range: %d-%d\n", which, port_first, port_last);
		printf ("\n" );
    }
	
    /*
     * Loading IPv6 configuration
     *
     */
	{
        cfg_ipv6 = cfg_getsec(cfg, "ipv6");

		sect_name = cfg_name(cfg_ipv6);
        
		printf ("Section: %s\n", sect_name );
        
        // Get number of IPv6 prefixes.
        ipv6_pref_qty = cfg_size(cfg_ipv6, "ipv6_net_prefixes"); 
        // Allocate memory for the array of prefixes.
        ipv6_pref = (struct ipv6_prefixes **) malloc(ipv6_pref_qty * sizeof(struct ipv6_prefixes *));
        for(i = 0; i < ipv6_pref_qty; i++)
        {
			// Split prefix and netmask bits
			ipv6_buf = cfg_getnstr(cfg_ipv6, "ipv6_net_prefixes", i);
			ipv6_check_addr = strtok(ipv6_buf, "/");
			ipv6_check_maskbits = strtok(NULL, "/");
			
			// Validate IPv6 addr
			if ( convert_ipv6_addr(ipv6_check_addr, &i6addrf) == EXIT_FAILURE )	
			{
				printf("Error: Invalid IPv6 address net: %s\n", ipv6_check_addr);
				exit_error_conf(cfg);
			}
			// Validate netmask bits
			addr_maskbits = atoi(ipv6_check_maskbits);
			if ( validate_ipv6_netmask_bits(addr_maskbits) == EXIT_FAILURE )
			{
				printf("Error: Bad IPv6 network mask bits value: %d\n", addr_maskbits);
				exit_error_conf(cfg);
			}
			
			// Allocate memory for each IPv6 prefix
			ipv6_pref[i] = (struct ipv6_prefixes *) malloc(sizeof(struct ipv6_prefixes));
			ipv6_pref[i]->addr = (i6addrf);
			ipv6_pref[i]->maskbits = addr_maskbits;
        }
        // Store prefixes in the config struct
        cs.ipv6_net_prefixes = ipv6_pref;
        cs.ipv6_net_prefixes_qty = ipv6_pref_qty;
			
               
        // Validate port ranges
        port_first = cfg_getint(cfg_ipv6, "ipv6_tcp_port_range_first");
        port_last = cfg_getint(cfg_ipv6, "ipv6_tcp_port_range_last");
        sprintf(which, "TCP");
		if ( validate_ports_range(port_first, port_last) == EXIT_FAILURE )
        {
            printf("Error: Invalid %s ports range.\n", which);
            exit_error_conf(cfg);
        }
        //~ if (port_first < 0 || port_first > 65535)
        //~ {
            //~ printf("Error: Invalid first %s port: %d\n", which, port_first);
            //~ exit_error_conf(cfg);
        //~ }
        //~ if (port_last < 0 || port_last > 65535)
        //~ {
            //~ printf("Error: Invalid last %s port: %d\n", which, port_last);
            //~ exit_error_conf(cfg);
        //~ }
        //~ if (port_first > port_last)
        //~ {
            //~ printf("Error: First %s port is greater than last port.\n", which);
            //~ exit_error_conf(cfg);
        //~ }
        cs.ipv6_tcp_port_range_first = port_first;
        cs.ipv6_tcp_port_range_last = port_last;
		printf("\t%s pool port range: %d-%d\n", which, port_first, port_last);
		//
        port_first = cfg_getint(cfg_ipv6, "ipv6_udp_port_range_first");
        port_last = cfg_getint(cfg_ipv6, "ipv6_udp_port_range_last");
        sprintf(which, "UDP");
		if ( validate_ports_range(port_first, port_last) == EXIT_FAILURE )
        {
            printf("Error: Invalid %s ports range.\n", which);
            exit_error_conf(cfg);
        }
        //~ if (port_first < 0 || port_first > 65535)
        //~ {
            //~ printf("Error: Invalid first %s port: %d\n", which, port_first);
            //~ exit_error_conf(cfg);
        //~ }
        //~ if (port_last < 0 || port_last > 65535)
        //~ {
            //~ printf("Error: Invalid last %s port: %d\n", which, port_last);
            //~ exit_error_conf(cfg);
        //~ }
        //~ if (port_first > port_last)
        //~ {
            //~ printf("Error: First %s port is greater than last port.\n", which);
            //~ exit_error_conf(cfg);
        //~ }
        cs.ipv6_udp_port_range_first = port_first;
        cs.ipv6_udp_port_range_last = port_last;
		printf("\t%s pool port range: %d-%d\n", which, port_first, port_last);
        
		printf ("\n" );
    }

	cfg_free(cfg);

    /* We got the configuration structure, now send it to the module
     * using netlink sockets. */

    // Reserve memory for netlink socket
    nls = nl_socket_alloc();
    if (!nls) {
        printf("bad nl_socket_alloc\n");
        return EXIT_FAILURE;
    }

	// Bind and connect the socket to kernel
    ret = nl_connect(nls, NETLINK_USERSOCK);
    if (ret < 0) {
        nl_perror(ret, "nl_connect");
        nl_socket_free(nls);
        return EXIT_FAILURE;
    }

	// Send socket to module
    ret = nl_send_simple(nls, MSG_TYPE_CONF, 0, &(cs), sizeof(cs));
    if (ret < 0) {
        nl_perror(ret, "nl_send_simple");
        printf("Error sending message, is module loaded?\n");
        nl_close(nls);
        nl_socket_free(nls);
        return EXIT_FAILURE;
    } else {        
	    printf("Message sent (%d bytes):\n", ret);
        //print_nat64_run_conf(nrc);
    }
		
    nl_close(nls);
    nl_socket_free(nls);
    
    exit(EXIT_SUCCESS);
}


////////////////////////////////////////////////////////////////////////
// FUNCTIONS
////////////////////////////////////////////////////////////////////////
/**
 * Free resourses for configuration parser if there are errors.
 *
 * @param cfg	Pointer to the allocated configuration structure.
 */
void exit_error_conf(cfg_t *cfg)
{
	cfg_free(cfg);
	exit(EXIT_FAILURE);
}


