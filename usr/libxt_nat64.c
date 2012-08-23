#include <xtables.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>

#include "xt_nat64.h"
#include "libxt_nat64.h"


 const struct option nat64_tg_opts[] = {
	{.name = "ipsrc", .has_arg = true, .val = '1'},
	{.name = "ipdst", .has_arg = true, .val = '2'},
	{.name = "outdev", .has_arg = true, .val = '3'},
	{NULL},
};

 struct xtables_target nat64_tg4_reg = {
	.version = XTABLES_VERSION,
	.name = "nat64",
	.revision = 0,
	.family = NFPROTO_IPV4,
	.size = XT_ALIGN(sizeof(struct xt_nat64_tginfo)),
	.userspacesize = XT_ALIGN(sizeof(struct xt_nat64_tginfo)),
	.help = nat64_tg_help,
	.parse = nat64_tg4_parse,
	.final_check = nat64_tg_check,
	.print = nat64_tg4_print,
	.save = nat64_tg4_save,
	.extra_opts = nat64_tg_opts,
};

 struct xtables_target nat64_tg6_reg = {
	.version = XTABLES_VERSION,
	.name = "nat64",
	.revision = 0,
	.family = NFPROTO_IPV6,
	.size = XT_ALIGN(sizeof(struct xt_nat64_tginfo)),
	.userspacesize = XT_ALIGN(sizeof(struct xt_nat64_tginfo)),
	.help = nat64_tg_help,
	.parse = nat64_tg6_parse,
	.final_check = nat64_tg_check,
	.print = nat64_tg6_print,
	.save = nat64_tg6_save,
	.extra_opts = nat64_tg_opts,
};


 void nat64_tg4_save(const void *entry, const struct xt_entry_target *target)
{
	const struct xt_nat64_tginfo *info = (const void *)target->data;

	printf("--ipsrc %s ", xtables_ipaddr_to_numeric(&info->ipsrc.in));

	if (info ->flags & XT_NAT64_IP_SRC) {
		printf("--ipsrc %s ", xtables_ipaddr_to_numeric(&info->ipsrc.in));
	}

	if (info->flags & XT_NAT64_IP_DST) {
		printf("--ipdst %s ", xtables_ipaddr_to_numeric(&info->ipdst.in));
	}
}

 void nat64_tg6_save(const void *entry, const struct xt_entry_target *target)
{
	const struct xt_nat64_tginfo *info = (const void *)target->data;

	if (info->flags & XT_NAT64_IPV6_DST) {
		printf("--ipdst %s %s",
				xtables_ip6addr_to_numeric(&info->ip6dst.in6),
				xtables_ip6addr_to_numeric(&info->ip6dst_mask.in6));
	}
}


 void nat64_tg4_print(const void *entry,
		const struct xt_entry_target *target, int numeric)
{
	const struct xt_nat64_tginfo *info = (const void *)target->data;

	if (info->flags & XT_NAT64_IP_SRC) {
		printf("src IP ");

		if (numeric)
			printf("%s ", numeric ?
					xtables_ipaddr_to_numeric(&info->ipsrc.in) :
					xtables_ipaddr_to_anyname(&info->ipsrc.in));
	}

	if (info->flags & XT_NAT64_IP_DST) {
		printf("dst IP ");

		printf("%s ", numeric ?
				xtables_ipaddr_to_numeric(&info->ipdst.in):
				xtables_ipaddr_to_anyname(&info->ipdst.in));
	}
}


 void nat64_tg6_print(const void *entry,
		const struct xt_entry_target *target, int numeric)
{
	const struct xt_nat64_tginfo *info = (const void *)target->data;

	if (info->flags & XT_NAT64_IPV6_DST) {
		printf("dst IP ");

		printf("%s ", numeric ?
				xtables_ip6addr_to_numeric(&info->ip6dst.in6):
				xtables_ip6addr_to_anyname(&info->ip6dst.in6));
	}
}

 int nat64_tg4_parse(int c, char **argv, int invert,
		unsigned int *flags, const void *entry,
		struct xt_entry_target **target)
{
	struct xt_nat64_tginfo *info = (void *)(*target)->data;
	struct in_addr *addrs, mask;
	char out_dev[IFNAMSIZ];
	unsigned char out_dev_mask[IFNAMSIZ];
	unsigned int naddrs;

	switch (c) {
		case '1': /* --ipsrc */
			if (*flags & XT_NAT64_IP_SRC)
				xtables_error(PARAMETER_PROBLEM, "xt_nat64: "
						"Only use \"--ipsrc\" once!");

			*flags |= XT_NAT64_IP_SRC;
			info->flags |= XT_NAT64_IP_SRC;

			if (invert)
				xtables_error(PARAMETER_PROBLEM, "xt_nat64: "
						"I'm sorry, the invert flag isn't available yet");

			xtables_ipparse_any(optarg, &addrs, &mask, &naddrs);

			if (naddrs != 1)
				xtables_error(PARAMETER_PROBLEM,
						"%s does not resolves to exactly "
						"one address", optarg);

			/* Copy the single address */
			memcpy(&info->ipsrc.in, addrs, sizeof(*addrs));
			return true;

		case '2': /* --ipdst */
			if (*flags & XT_NAT64_IP_DST)
				xtables_error(PARAMETER_PROBLEM, "xt_nat64: "
						"Only use \"--ipdst\" once!");

			*flags |= XT_NAT64_IP_DST;
			info->flags |= XT_NAT64_IP_DST;

			if (invert)
				xtables_error(PARAMETER_PROBLEM, "xt_nat64: "
						"I'm sorry, the invert flag isn't available yet");

			xtables_ipparse_any(optarg, &addrs, &mask, &naddrs);

			if (naddrs != 1)
				xtables_error(PARAMETER_PROBLEM,
						"%s does not resolves to exactly "
						"one address", optarg);

			if (addrs == NULL)
				xtables_error(PARAMETER_PROBLEM,
						"Parse error at %s\n", optarg);

			memcpy(&info->ipdst.in, addrs, sizeof(*addrs));
			return true;
		case '3': /* --oudev */
			if (*flags & XT_NAT64_OUT_DEV)
				xtables_error(PARAMETER_PROBLEM, "xt_nat64: "
						"Only use \"--outdev\" once!");

			*flags |= XT_NAT64_OUT_DEV;
			info->flags |= XT_NAT64_OUT_DEV;

			if (invert)
				xtables_error(PARAMETER_PROBLEM, "xt_nat64: "
						"I'm sorry, the invert flag isn't available yet");

			xtables_parse_interface(optarg, out_dev, out_dev_mask);

			if (out_dev == NULL)
				xtables_error(PARAMETER_PROBLEM,
						"Parse error at %s\n", optarg);

			memcpy(&info->out_dev, out_dev, sizeof(char) * IFNAMSIZ);
			memcpy(&info->out_dev_mask, out_dev_mask, sizeof(unsigned char) * IFNAMSIZ);
			return true;

	}
	return false;
}

 int nat64_tg6_parse(int c, char **argv, int invert,
		unsigned int *flags, const void *entry,
		struct xt_entry_target **target)
{
	struct xt_nat64_tginfo *info = (void *)(*target)->data;
	struct in6_addr *addrs, mask;
	char out_dev[IFNAMSIZ];
	unsigned char out_dev_mask[IFNAMSIZ];
	unsigned int naddrs;

	switch(c) {
		case '1': /* --ipsrc */
			xtables_error(PARAMETER_PROBLEM, "xt_nat64: "
					"You can't check for the source!");

			return false;

		case '2': /* --ipdst */
			if (*flags & XT_NAT64_IPV6_DST)
				xtables_error(PARAMETER_PROBLEM, "xt_nat64: "
						"Only use \"--ipdst\" once!");

			*flags |= XT_NAT64_IPV6_DST;
			info->flags |= XT_NAT64_IPV6_DST;

			if (invert)
				xtables_error(PARAMETER_PROBLEM, "xt_nat64: "
						"I'm sorry, the invert flag isn't available yet");

			xtables_ip6parse_any(optarg, &addrs, &mask, &naddrs);

			if (naddrs != 1)
				xtables_error(PARAMETER_PROBLEM,
						"%s does not resolves to exactly "
						"one address", optarg);

			if (addrs == NULL)
				xtables_error(PARAMETER_PROBLEM,
						"Parse error at %s\n", optarg);

			memcpy(&info->ip6dst.in6, addrs, sizeof(*addrs));
			memcpy(&info->ip6dst_mask.in6, &mask, sizeof(mask));
			return true;
		case '3': /* --oudev */
			if (*flags & XT_NAT64_OUT_DEV)
				xtables_error(PARAMETER_PROBLEM, "xt_nat64: "
						"Only use \"--outdev\" once!");

			*flags |= XT_NAT64_OUT_DEV;
			info->flags |= XT_NAT64_OUT_DEV;

			if (invert)
				xtables_error(PARAMETER_PROBLEM, "xt_nat64: "
						"I'm sorry, the invert flag isn't available yet");

			xtables_parse_interface(optarg, out_dev, out_dev_mask);

			if (out_dev == NULL)
				xtables_error(PARAMETER_PROBLEM,
						"Parse error at %s\n", optarg);

			memcpy(&info->out_dev, out_dev, sizeof(char) * IFNAMSIZ);
			memcpy(&info->out_dev_mask, out_dev_mask, sizeof(unsigned char) * IFNAMSIZ);
			return true;
	}

	return false;
}

 void nat64_tg_check(unsigned int flags)
{
	if (flags == 0)
		xtables_error(PARAMETER_PROBLEM, "xt_nat64: You need to "
				"specify at least \"--ipsrc\", \"--ipdst\""
				"or \"--outdev\"");

	if (!(flags | XT_NAT64_IP_DST | XT_NAT64_OUT_DEV))
		xtables_error(PARAMETER_PROBLEM, "xt_nat64: You need to "
				"specify at least \"--outdev\" and \"--ipdst\".");
}


 void nat64_tg_help(void)
{
	printf(
			"nat64 target options:\n"
			"[!] --ipsrc addr target source address of packet\n"
			"[!] --ipdst addr target destination address of packet\n"
			"[!] --outdev dev_name target output device of packet\n"
		  );
}


void _init(void)
{
	xtables_register_target(&nat64_tg4_reg);
	xtables_register_target(&nat64_tg6_reg);
}

