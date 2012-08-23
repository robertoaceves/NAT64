#include "load_config.h"


int main(int argc, char *argv[])
{
	struct stat sb; // To check if config file exist.
	struct in_addr iaddrf, iaddrl;      // To validate IP addresses
    struct in6_addr i6addrf;   			// also
    cfg_t *cfg, *cfg_ipv4, *cfg_ipv6;
	const char *sect_name;
	char *addr_first, *addr_last;
    unsigned char addr_maskbits;
    int port_first, port_last;
    char which[sizeof("ABC")];
    
    struct config_struct cs;

	struct nl_sock *nls;
	int ret;

	int i = 0;
	struct ipv6_prefixes **ipv6_pref = NULL;
	unsigned char ipv6_pref_qty;
	char ipv6_def_prefix64[sizeof("1111:2222:3333:4444:5555:6666::/99")];
	char *ipv6_buf;  //[sizeof("1111:2222:3333:4444:5555:6666::/99")];
	char *ipv6_check_addr; // [40]; // 40: maximum string length of an ipv6 addr 
	char *ipv6_check_maskbits; // [sizeof("128")];

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

	sprintf(ipv6_def_prefix64, "%s/%d", IPV6_DEF_PREFIX, IPV6_DEF_MASKBITS );

    cfg_opt_t ipv4_opts[] =
    {
        CFG_STR("ipv4_addr_net", IPV4_DEF_NET, CFGF_NONE), 
        CFG_INT("ipv4_addr_net_mask_bits", IPV4_DEF_MASKBITS, CFGF_NONE), 
        CFG_STR("ipv4_pool_range_first", IPV4_DEF_POOL_FIRST, CFGF_NONE), 
        CFG_STR("ipv4_pool_range_last", IPV4_DEF_POOL_LAST, CFGF_NONE), 
        CFG_INT("ipv4_tcp_port_range_first", IPV4_DEF_TCP_POOL_FIRST, CFGF_NONE), 
        CFG_INT("ipv4_tcp_port_range_last", IPV4_DEF_TCP_POOL_LAST, CFGF_NONE), 
        CFG_INT("ipv4_udp_port_range_first", IPV4_DEF_UDP_POOL_FIRST, CFGF_NONE), 
        CFG_INT("ipv4_udp_port_range_last", IPV4_DEF_UDP_POOL_LAST, CFGF_NONE), 
        CFG_END()
    };
	cfg_opt_t ipv6_opts[] =
    {
        //~ CFG_STR("ipv6_net_prefix", IPV6_DEF_PREFIX, CFGF_NONE), 
        //~ CFG_INT("ipv6_net_mask_bits", IPV6_DEF_MASKBITS, CFGF_NONE), 
        CFG_STR_LIST("ipv6_net_prefixes", ipv6_def_prefix64, CFGF_NONE), 

        CFG_INT("ipv6_tcp_port_range_first", IPV6_DEF_TCP_POOL_FIRST, CFGF_NONE), 
        CFG_INT("ipv6_tcp_port_range_last", IPV6_DEF_TCP_POOL_LAST, CFGF_NONE), 
        CFG_INT("ipv6_udp_port_range_first", IPV6_DEF_UDP_POOL_FIRST, CFGF_NONE), 
        CFG_INT("ipv6_udp_port_range_last", IPV6_DEF_UDP_POOL_LAST, CFGF_NONE), 
		CFG_END()
    };
    cfg_opt_t opts[] =
    {
        CFG_SEC("ipv4", ipv4_opts, CFGF_NONE),
        CFG_SEC("ipv6", ipv6_opts, CFGF_NONE),
        CFG_END()
    };

    cfg = cfg_init(opts, CFGF_NONE);
    if(cfg_parse(cfg, argv[1]) == CFG_PARSE_ERROR)
	{
		printf("Error parsing configuration file: %s\n", argv[1]);
        exit_error_conf(cfg);
	}

	/* Loading IPv4 configuration */
	{
        cfg_ipv4 = cfg_getsec(cfg, "ipv4");

		sect_name = cfg_name(cfg_ipv4);
		printf ("Section: %s\n", sect_name);

		addr_first = cfg_getstr(cfg_ipv4, "ipv4_addr_net");
        if ( inet_aton(addr_first, &iaddrf) == 0 )	// Validate ipv4 addr
		{
			printf("Error: Invalid IPv4 address net: %s\n", addr_first);
			exit_error_conf(cfg);
		}
        addr_maskbits = cfg_getint(cfg_ipv4, "ipv4_addr_net_mask_bits");
        if (addr_maskbits > 32 || addr_maskbits < 0)
        {
            printf("Error: Bad IPv4 network mask bits value: %d\n", addr_maskbits);
			exit_error_conf(cfg);
        }
		cs.ipv4_addr_net = iaddrf;
        cs.ipv4_addr_net_mask_bits = addr_maskbits;
		printf("\tPool Network: %s/%d\n", addr_first, addr_maskbits);
		//
		addr_first = cfg_getstr(cfg_ipv4, "ipv4_pool_range_first");
        addr_last = cfg_getstr(cfg_ipv4, "ipv4_pool_range_last");
		if ( inet_aton(addr_first, &iaddrf) == 0 )	// Validate ipv4 addr
		{
			printf("Error: Malformed ipv4_pool_range_first: %s\n", addr_first);
			exit_error_conf(cfg);
		}
		if ( inet_aton(addr_last, &iaddrl) == 0 )	// Validate ipv4 addr
		{
			printf("Error: Malformed ipv4_pool_range_last: %s\n", addr_last);
			exit_error_conf(cfg);
		}
		if (iaddrf.s_addr > iaddrl.s_addr)	// Validate that: first < last
		{
			printf("Error: First pool address is greater than last pool address.\n");
			exit_error_conf(cfg);
		}
        cs.ipv4_pool_range_first = iaddrf;
        cs.ipv4_pool_range_last = iaddrl;
		printf("\t\t- First address: %s\n", inet_ntoa(iaddrf));
		printf("\t\t- Last address: %s\n", inet_ntoa(iaddrl));
        //
        port_first = cfg_getint(cfg_ipv4, "ipv4_tcp_port_range_first");
        port_last = cfg_getint(cfg_ipv4, "ipv4_tcp_port_range_last");
        sprintf(which, "TCP");
        if (port_first < 0 || port_first > 65535)
        {
            printf("Error: Invalid first %s port: %d\n", which, port_first);
            exit_error_conf(cfg);
        }
        if (port_last < 0 || port_last > 65535)
        {
            printf("Error: Invalid last %s port: %d\n", which, port_last);
            exit_error_conf(cfg);
        }
        if (port_first > port_last)
        {
            printf("Error: First %s port is greater than last port.\n", which);
            exit_error_conf(cfg);
        }
        cs.ipv4_tcp_port_first = port_first;
        cs.ipv4_tcp_port_last = port_last;
		printf("\t%s pool port range: %d-%d\n", which, port_first, port_last);
		//
        port_first = cfg_getint(cfg_ipv4, "ipv4_udp_port_range_first");
        port_last = cfg_getint(cfg_ipv4, "ipv4_udp_port_range_last");
        sprintf(which, "UDP");
        if (port_first < 0 || port_first > 65535)
        {
            printf("Error: Invalid first %s port: %d\n", which, port_first);
            exit_error_conf(cfg);
        }
        if (port_last < 0 || port_last > 65535)
        {
            printf("Error: Invalid last %s port: %d\n", which, port_last);
            exit_error_conf(cfg);
        }
        if (port_first > port_last)
        {
            printf("Error: First %s port is greater than last port.\n", which);
            exit_error_conf(cfg);
        }
        cs.ipv4_udp_port_first = port_first;
        cs.ipv4_udp_port_last = port_last;
		printf("\t%s pool port range: %d-%d\n", which, port_first, port_last);
        
		printf ("\n" );
    }
	
    /* Loading IPv6 configuration */
	{
        cfg_ipv6 = cfg_getsec(cfg, "ipv6");

		sect_name = cfg_name(cfg_ipv6);
        
		printf ("Section: %s\n", sect_name );
		//~ addr_first = cfg_getstr(cfg_ipv6, "ipv6_net_prefix");
        //~ 
        //~ if ( inet_pton(AF_INET6, addr_first, &i6addrf) < 1 )	// Validate ipv6 addr
		//~ {
			//~ printf("Error: Invalid IPv6 address net: %s\n", addr_first);
			//~ exit_error_conf(cfg);
		//~ }
        //~ addr_maskbits = cfg_getint(cfg_ipv6, "ipv6_net_mask_bits");
        //~ if (addr_maskbits > 128 || addr_maskbits < 0)
        //~ {
            //~ printf("Error: Bad IPv6 network mask bits value: %d\n", addr_maskbits);
			//~ exit_error_conf(cfg);
        //~ }
		//~ cs.ipv6_net_prefix = i6addrf;
        //~ cs.ipv6_net_mask_bits = addr_maskbits;
		//~ printf("\tPrefix: %s/%d\n", addr_first, addr_maskbits);
        

        ipv6_pref_qty = cfg_size(cfg_ipv6, "ipv6_net_prefixes"); 
        ipv6_pref = (struct ipv6_prefixes **) malloc(ipv6_pref_qty * sizeof(struct ipv6_prefixes *));
        for(i = 0; i < ipv6_pref_qty; i++)
        {
printf("Hello");
			ipv6_buf = cfg_getnstr(cfg_ipv6, "ipv6_net_prefixes", i);
printf(", %s", ipv6_buf); printf("!\n");
			
			ipv6_check_addr = strtok(ipv6_buf, "/");
printf("prefijo: %s\n", ipv6_check_addr);
			ipv6_check_maskbits = strtok(NULL, "/");
printf("maskbits: %s\n", ipv6_check_maskbits);

printf("Validando prefijos ipv6\n");
						
			if ( inet_pton(AF_INET6, ipv6_check_addr, &i6addrf) < 1 )	// Validate ipv6 addr
			{
				printf("Error: Invalid IPv6 address net: %s\n", ipv6_check_addr);
				exit_error_conf(cfg);
			}
			addr_maskbits = atoi(ipv6_check_maskbits);
			if (addr_maskbits > IPV6_DEF_MASKBITS_MAX || addr_maskbits < IPV6_DEF_MASKBITS_MIN)
			{
				printf("Error: Bad IPv6 network mask bits value: %d\n", addr_maskbits);
				exit_error_conf(cfg);
			}
			
			ipv6_pref[i] = (struct ipv6_prefixes *) malloc(sizeof(struct ipv6_prefixes));
			ipv6_pref[i]->addr = (i6addrf);
			ipv6_pref[i]->maskbits = addr_maskbits;
			
			//~ memset(ipv6_buf, '\0', sizeof(ipv6_buf));
        }
        cs.ipv6_net_prefixes = ipv6_pref;
        cs.ipv6_net_prefixes_qty = ipv6_pref_qty;
			
        
 // return 0; // validate validation      
        
        //
        port_first = cfg_getint(cfg_ipv6, "ipv6_tcp_port_range_first");
        port_last = cfg_getint(cfg_ipv6, "ipv6_tcp_port_range_last");
        sprintf(which, "TCP");
        if (port_first < 0 || port_first > 65535)
        {
            printf("Error: Invalid first %s port: %d\n", which, port_first);
            exit_error_conf(cfg);
        }
        if (port_last < 0 || port_last > 65535)
        {
            printf("Error: Invalid last %s port: %d\n", which, port_last);
            exit_error_conf(cfg);
        }
        if (port_first > port_last)
        {
            printf("Error: First %s port is greater than last port.\n", which);
            exit_error_conf(cfg);
        }
        cs.ipv6_tcp_port_range_first = port_first;
        cs.ipv6_tcp_port_range_last = port_last;
		printf("\t%s pool port range: %d-%d\n", which, port_first, port_last);
		//
        port_first = cfg_getint(cfg_ipv6, "ipv6_udp_port_range_first");
        port_last = cfg_getint(cfg_ipv6, "ipv6_udp_port_range_last");
        sprintf(which, "UDP");
        if (port_first < 0 || port_first > 65535)
        {
            printf("Error: Invalid first %s port: %d\n", which, port_first);
            exit_error_conf(cfg);
        }
        if (port_last < 0 || port_last > 65535)
        {
            printf("Error: Invalid last %s port: %d\n", which, port_last);
            exit_error_conf(cfg);
        }
        if (port_first > port_last)
        {
            printf("Error: First %s port is greater than last port.\n", which);
            exit_error_conf(cfg);
        }
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

	// Bind and connect the socket to a protocol
    ret = nl_connect(nls, NETLINK_USERSOCK);
    if (ret < 0) {
        nl_perror(ret, "nl_connect");
        nl_socket_free(nls);
        return EXIT_FAILURE;
    }

    ret = nl_send_simple(nls, MY_MSG_TYPE, 0, &(cs), sizeof(cs));
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

/* Alternative: Implement this validation in the configuration parser */
int validateIP(const char *ipaddr, struct in_addr addr)
{
	if (inet_aton(ipaddr, &addr) == 0) {
		perror("inet_aton");
		return (EXIT_FAILURE);
	}
	
	printf("%s\n", inet_ntoa(addr));
	return (EXIT_SUCCESS);
}

/* Free resourses for configuration parser if there are errors. */
void exit_error_conf(cfg_t *cfg)
{
	cfg_free(cfg);
	exit(EXIT_FAILURE);
}

