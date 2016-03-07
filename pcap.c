
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_pcap.h"

#include <pcap/pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define ETHER_HEADER_LEN 14

/* If you declare any globals in php_pcap.h uncomment this:
ZEND_DECLARE_MODULE_GLOBALS(pcap)
*/

/* True global resources - no need for thread safety here */
static int le_pcap;
#define le_pcap_name "PCAP resource"

/* {{{ PHP_INI
 */
/* Remove comments and fill if you need to have entries in php.ini
PHP_INI_BEGIN()
    STD_PHP_INI_ENTRY("pcap.global_value",      "42", PHP_INI_ALL, OnUpdateLong, global_value, zend_pcap_globals, pcap_globals)
    STD_PHP_INI_ENTRY("pcap.global_string", "foobar", PHP_INI_ALL, OnUpdateString, global_string, zend_pcap_globals, pcap_globals)
PHP_INI_END()
*/
/* }}} */

static void pcap_destructor_pcap(zend_resource *rsrc)
{       
	pcap_t *ptr = (pcap_t *) rsrc->ptr;

	pcap_close(ptr);
}

#ifdef PHP_WIN32
# define SET_ALIGNED(alignment, decl) __declspec(align(alignment)) decl
#elif HAVE_ATTRIBUTE_ALIGNED
# define SET_ALIGNED(alignment, decl) decl __attribute__ ((__aligned__ (alignment)))
#else
# define SET_ALIGNED(alignment, decl) decl
#endif


/* this is read-only, so it's ok */
SET_ALIGNED(16, static char hexconvtab[]) = "0123456789abcdef";

/* {{{ php_bin2hex
 */
static zend_string *pcap_bin2hex(const unsigned char *old, const size_t oldlen)
{
	zend_string *result;
	size_t i, j;

	result = zend_string_safe_alloc(oldlen, 2 * sizeof(char), 0, 0);

	for (i = j = 0; i < oldlen; i++) {
		ZSTR_VAL(result)[j++] = hexconvtab[old[i] >> 4];
		ZSTR_VAL(result)[j++] = hexconvtab[old[i] & 15];
	}
	ZSTR_VAL(result)[j] = '\0';

	return result;
}

/* {{{ proto string confirm_pcap_compiled(string arg)
   Return a string to confirm that the module is compiled in */
PHP_FUNCTION(pcap_close)
{
	zval	*z_fp;
	pcap_t *fp;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "r", &z_fp) == FAILURE) {
		return;
	}

	if ((fp = (pcap_t *)zend_fetch_resource(Z_RES_P(z_fp), le_pcap_name, le_pcap)) == NULL) {
		RETURN_FALSE;
	}

	pcap_close(fp);

	RETURN_TRUE;
}
/* }}} */

/* {{{ proto string confirm_pcap_compiled(string arg)
   Return a string to confirm that the module is compiled in */
PHP_FUNCTION(pcap_open_offline)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	char *file;
	size_t file_len;
	pcap_t *fp;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &file, &file_len) == FAILURE) {
		return;
	}
	
	if (!(fp = pcap_open_offline(file, errbuf))) {
		/* Error */
		php_error_docref(NULL, E_WARNING, "Problem opening file: %s", errbuf);
		RETURN_FALSE;
	}


	RETURN_RES(zend_register_resource(fp, le_pcap));
}
/* }}} */

/* {{{ proto string confirm_pcap_compiled(string arg)
   Return a string to confirm that the module is compiled in */
PHP_FUNCTION(pcap_filter)
{
	zval	*z_fp;
	pcap_t	*fp;
	char	*str;
	size_t	str_len;
	struct bpf_program bpf; 
	

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "rs", &z_fp, &str, &str_len) == FAILURE) {
		return;
	}

	if ((fp = (pcap_t *)zend_fetch_resource(Z_RES_P(z_fp), le_pcap_name, le_pcap)) == NULL) {
		RETURN_FALSE;
	}

	if (pcap_compile(fp, &bpf, str, 0, PCAP_NETMASK_UNKNOWN) == -1) {
		RETURN_FALSE;
	}

	if (pcap_setfilter(fp, &bpf) == -1) {
		RETURN_FALSE;
	}

	RETURN_TRUE;
}
/* }}} */


/* {{{ proto string confirm_pcap_compiled(string arg)
   Return a string to confirm that the module is compiled in */
PHP_FUNCTION(pcap_geterr)
{
	zval	*z_fp;
	pcap_t	*fp;
	char	*err;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "r", &z_fp) == FAILURE) {
		return;
	}

	if ((fp = (pcap_t *)zend_fetch_resource(Z_RES_P(z_fp), le_pcap_name, le_pcap)) == NULL) {
		RETURN_FALSE;
	}

	err = (char *) pcap_geterr(fp);

	RETURN_STRING(err);
}
/* }}} */


/* {{{ proto string confirm_pcap_compiled(string arg)
   Return a string to confirm that the module is compiled in */
PHP_FUNCTION(pcap_next_raw)
{
	zval		*z_fp;
	pcap_t		*fp;
	int			i;
	const u_char	*p;
	struct pcap_pkthdr hdr;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "r", &z_fp) == FAILURE) {
		return;
	}

	if ((fp = (pcap_t *)zend_fetch_resource(Z_RES_P(z_fp), le_pcap_name, le_pcap)) == NULL) {
		RETURN_FALSE;
	}

	if (!(p = pcap_next(fp, &hdr))) {
		RETURN_FALSE;
	}

	if (p < 0) {
		RETURN_FALSE;
	}

	RETURN_STRINGL(p, hdr.len);
}
/* }}} */

void pcap_ipv4_tcp(zval *ret, struct iphdr *ip, const u_char *p, int *next_hdr)
{
	zval	proto_val;
	char	*data;
	struct tcphdr	*tcp;

	tcp = (struct tcphdr *) (p+*next_hdr);
	array_init(&proto_val);
	add_assoc_string(&proto_val, "header_type", "tcp");
	add_assoc_long(&proto_val, "sport", ntohs(tcp->th_sport));
	add_assoc_long(&proto_val, "dport", ntohs(tcp->th_dport));
	add_assoc_long(&proto_val, "seq", ntohl(tcp->th_seq));
	add_assoc_long(&proto_val, "ack", ntohl(tcp->th_ack));
	add_assoc_long(&proto_val, "res", (tcp->th_x2 << 2));
	add_assoc_long(&proto_val, "offset", tcp->th_off);
	add_assoc_long(&proto_val, "flags", ntohs(tcp->th_flags));
	add_assoc_long(&proto_val, "window", ntohs(tcp->th_win));
	add_assoc_long(&proto_val, "checksum", ntohs(tcp->th_sum));
	add_assoc_long(&proto_val, "urgent", ntohs(tcp->th_urp));
	add_next_index_zval(ret, &proto_val);

	/* XXX: Options not handled! */
	if ((ntohs(ip->tot_len) - (ip->ihl << 2) - (tcp->th_off * 4)) > 0) {
		data = (char *) (p+*next_hdr+(tcp->th_off * 4));
		add_assoc_stringl(ret, "data", data, (ntohs(ip->tot_len)-(ip->ihl << 2)-(tcp->th_off * 4)));
	} else {
		/* Set data to false if we have no data */
		add_assoc_bool(ret, "data", 0);
	}

}


void pcap_ipv4_udp(zval *ret, struct iphdr *ip, const u_char *p, int *next_hdr)
{
	zval	proto_val;
	char	*data;
	struct udphdr	*udp;

	udp = (struct udphdr *) (p+*next_hdr);
	array_init(&proto_val);
	add_assoc_string(&proto_val, "header_type", "udp");
	add_assoc_long(&proto_val, "sport", ntohs(udp->source));
	add_assoc_long(&proto_val, "dport", ntohs(udp->dest));
	add_assoc_long(&proto_val, "len", ntohs(udp->len));
	add_assoc_long(&proto_val, "checksum", ntohs(udp->check));
	add_next_index_zval(ret, &proto_val);
	data = (char *) (p+*next_hdr+8);
	add_assoc_stringl(ret, "data", data, (ntohs(udp->len) - sizeof(struct udphdr)));
}


void pcap_ipv4_vrrp(zval *ret, struct iphdr *ip, const u_char *p, int *next_hdr)
{
	zval	proto_val, ips;
	char	*data;
	struct	vrrp2hdr	*hdr;
	int	i;
	unsigned char	ipaddr[INET_ADDRSTRLEN];

	hdr = (struct vrrp2hdr *) (p+*next_hdr);

	if (2 == hdr->version) {
		array_init(&proto_val);
		array_init(&ips);
		add_assoc_string(&proto_val, "header_type", "vrrp");
		add_assoc_long(&proto_val, "version", hdr->version);
		add_assoc_long(&proto_val, "type", hdr->type);
		add_assoc_long(&proto_val, "rtrid", hdr->rtr_id);
		add_assoc_long(&proto_val, "prio", hdr->priority);
		add_assoc_long(&proto_val, "count", hdr->count);
		add_assoc_long(&proto_val, "auth", hdr->auth);
		add_assoc_long(&proto_val, "advert", hdr->advert);
		add_assoc_long(&proto_val, "checksum", ntohs(hdr->checksum));

		for (i = 0; i < hdr->count; i++) {
			data = (char *) (p+*next_hdr+sizeof(struct vrrp2hdr));
			inet_ntop(AF_INET, data, ipaddr, INET_ADDRSTRLEN);
			add_next_index_string(&ips, ipaddr);
			*next_hdr += 4;
		}

		add_assoc_zval(&proto_val, "ip", &ips);
		data = (char *) (p+*next_hdr+sizeof(struct vrrp2hdr));
		add_assoc_stringl(&proto_val, "authdata", data, 8);
		add_next_index_zval(ret, &proto_val);
	} else {
		/* Not version 2 */
	}
}


void pcap_ipv4_ah(zval *ret, struct iphdr *ip, const u_char *p, int *next_hdr, int *nproto)
{
	zval	proto_val;
	char	*data;
	int	pl_size;
	struct ahhdr	*ah;

	ah = (struct ahhdr *) (p+*next_hdr);

	/* Payload size */
	pl_size = ((ah->len - 2)*12)-sizeof(struct ahhdr);
	*nproto = ah->next;
	data = (char *) (p+*next_hdr+sizeof(struct ahhdr));
	*next_hdr += (ah->len - 2)*12;

	array_init(&proto_val);
	add_assoc_string(&proto_val, "header_type", "ah");
	add_assoc_long(&proto_val, "next", ah->next);
	add_assoc_long(&proto_val, "len", ah->len);
	add_assoc_long(&proto_val, "rsvd", ntohs(ah->rsvd));
	add_assoc_long(&proto_val, "spi", ntohl(ah->spi));
	add_assoc_long(&proto_val, "seq", ntohl(ah->seq));
	add_assoc_stringl(&proto_val, "icv", data, pl_size);
	add_next_index_zval(ret, &proto_val);
}


void pcap_ipv4_ospf(zval *ret, struct iphdr *ip, const u_char *p, int *next_hdr)
{
	zval	proto_val;
	char	*data;
	struct ospfhdr	*ospf;

	ospf = (struct ospfhdr *) (p+*next_hdr);

	array_init(&proto_val);
	add_assoc_string(&proto_val, "header_type", "ospf");
	add_assoc_long(&proto_val, "version", ospf->version);
	add_assoc_long(&proto_val, "type", ospf->type);
	add_assoc_long(&proto_val, "len", ntohs(ospf->len));
	add_assoc_long(&proto_val, "rtrid", ntohl(ospf->rtrid));
	add_assoc_long(&proto_val, "area", ntohl(ospf->area));
	add_assoc_long(&proto_val, "checksum", ntohs(ospf->checksum));
	add_assoc_long(&proto_val, "autype", ntohs(ospf->autype));
	add_assoc_long(&proto_val, "auth", ntohl(ospf->auth));
	add_next_index_zval(ret, &proto_val);
	data = (char *) (p+*next_hdr+sizeof(struct ospfhdr));
	add_assoc_stringl(ret, "data", data, ntohs(ip->tot_len)-(ip->ihl << 2)-sizeof(struct ospfhdr));
}


void pcap_ipv4_gre(zval *ret, struct iphdr *ip, const u_char *p, int *next_hdr, int *nproto)
{
	zval	proto_val;
	struct grehdr	*gre;

	/* XXX: A few of these might add extra payload to the header. Fix this */
	gre = (struct grehdr *) (p+*next_hdr);
	array_init(&proto_val);
	add_assoc_string(&proto_val, "header_type", "gre"); 
	add_assoc_long(&proto_val, "csum", ((ntohs(gre->flags) & 0x8000) >> 15));
	add_assoc_long(&proto_val, "routing", ((ntohs(gre->flags) & 0x4000) >> 14));
	add_assoc_long(&proto_val, "key", ((ntohs(gre->flags) & 0x2000) >> 13));
	add_assoc_long(&proto_val, "seq", ((ntohs(gre->flags) & 0x1000) >> 12));
	add_assoc_long(&proto_val, "ssr", ((ntohs(gre->flags) & 0x0800) >> 11));
	add_assoc_long(&proto_val, "recursion", ((ntohs(gre->flags) & 0x0700) >> 8));
	add_assoc_long(&proto_val, "flags", ((ntohs(gre->flags) & 0x00f8) >> 3));
	add_assoc_long(&proto_val, "version", (ntohs(gre->flags) & 0x0007));
	add_assoc_long(&proto_val, "next", ntohs(gre->next));
	add_next_index_zval(ret, &proto_val);
	*next_hdr += sizeof(struct grehdr);
	*nproto = gre->next;
}



/* {{{ proto string confirm_pcap_compiled(string arg)
   Return a string to confirm that the module is compiled in */
PHP_FUNCTION(pcap_next)
{
	zval	*z_fp, eth_val, ip_val, vlan_val;
	pcap_t	*fp;
	int		i, ip_proto, eth_proto;
	int		next_hdr = 0;
	int		raw = 0;
	char	*data;
	const u_char	*p;
	register const struct ether_header	*eptr;
	struct vlanhdr		*vlan;
	struct pcap_pkthdr	hdr;
	struct iphdr		*ip;
	struct ip6_hdr		*ip6;
	struct mplshdr		*mpls;
	zend_string		*src, *dst;
	unsigned char		ipaddr[INET6_ADDRSTRLEN];

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "r|b", &z_fp, &raw) == FAILURE) {
		return;
	}

	if ((fp = (pcap_t *)zend_fetch_resource(Z_RES_P(z_fp), le_pcap_name, le_pcap)) == NULL) {
		RETURN_FALSE;
	}

	if (!(p = pcap_next(fp, &hdr))) {
		RETURN_FALSE;
	}

	data = (char *) (p+ETHER_HEADER_LEN);

	eptr = (struct ether_header *)p;

	/* Convert MAC addresses to hex */
	src = pcap_bin2hex((char *) eptr->ether_shost, ETHER_ADDR_LEN);
	dst = pcap_bin2hex((char *) eptr->ether_dhost, ETHER_ADDR_LEN);

	array_init(&eth_val);
	array_init(return_value);
	add_assoc_string(&eth_val, "header_type", "ethernet");
	add_assoc_string(&eth_val, "src", ZSTR_VAL(src));
	add_assoc_string(&eth_val, "dst", ZSTR_VAL(dst));
	add_assoc_long(&eth_val, "type", ntohs(eptr->ether_type));
	add_next_index_zval(return_value, &eth_val);

	if (raw) {
		add_assoc_stringl(return_value, "raw", data, (hdr.len-ETHER_HEADER_LEN));
	}

	eth_proto = ntohs(eptr->ether_type);
	next_hdr += ETHER_HEADER_LEN;

ethrestart:
	if (0x0800 == eth_proto) {
		/* IPv4 */
		ip = (struct iphdr *) (p+next_hdr);

		array_init(&ip_val);
		add_assoc_string(&ip_val, "header_type", "ip");
		add_assoc_long(&ip_val, "version", ip->version);
		add_assoc_long(&ip_val, "hlen", (ip->ihl << 2));
		add_assoc_long(&ip_val, "tos", ip->tos);
		add_assoc_long(&ip_val, "len", ntohs(ip->tot_len));
		add_assoc_long(&ip_val, "id", ntohs(ip->id));
		add_assoc_long(&ip_val, "frag_off", ntohs(ip->frag_off));
		add_assoc_long(&ip_val, "ttl", ip->ttl);
		add_assoc_long(&ip_val, "proto", ip->protocol);
		add_assoc_long(&ip_val, "checksum", ntohs(ip->check));
		inet_ntop(AF_INET, &(ip->saddr), ipaddr, INET_ADDRSTRLEN);
		add_assoc_string(&ip_val, "src", ipaddr);
		inet_ntop(AF_INET, &(ip->daddr), ipaddr, INET_ADDRSTRLEN);
		add_assoc_string(&ip_val, "dst", ipaddr); 
		add_next_index_zval(return_value, &ip_val);

		next_hdr += (ip->ihl << 2);
		ip_proto = ip->protocol;
restart:
		switch (ip_proto) {
			case 6:		/* TCP */
				pcap_ipv4_tcp(return_value, ip, p, &next_hdr);
				break;
			case 17:	/* UDP */
				pcap_ipv4_udp(return_value, ip, p, &next_hdr);
				break;
			case 47:	/* IP GRE */
				pcap_ipv4_gre(return_value, ip, p, &next_hdr, &ip_proto);
				goto ethrestart;
			case 51:	/* AH */
				pcap_ipv4_ah(return_value, ip, p, &next_hdr, &ip_proto);
				goto restart;
			case 89:	/* OSPF */
				pcap_ipv4_ospf(return_value, ip, p, &next_hdr);
				break;
			case 112:	/* VRRP */
				pcap_ipv4_vrrp(return_value, ip, p, &next_hdr);
				break;
			default:
				data = (char *)(p+next_hdr);
				add_assoc_stringl(return_value, "data", data, (ntohs(ip->tot_len)-(ip->ihl << 2)));
				break;
		}
		/*   1 ICMP
		 *   2 IGMP
		 *   4 IPIP
		 *  41 IPv6
		 *  43 IPv6 Route
		 *  44 IPv6 Fragment
		 *  47 GRE
		 *  88 EIGRP
		 *  89 OSPF
		 * 115 L2TPv3
		 * 124 ISIS over IPv4
		 * 137 MPLS-in-IP
		 */
	} else if (0x86dd == eth_proto) { 
		/* IPv6 */
		ip6 = (struct ip6_hdr *) (p+next_hdr);

		array_init(&ip_val);
		add_assoc_string(&ip_val, "header_type", "ip6");
		add_assoc_long(&ip_val, "flow", ip6->ip6_ctlun.ip6_un1.ip6_un1_flow);
		add_assoc_long(&ip_val, "plen", ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen));
		add_assoc_long(&ip_val, "next", ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt);
		add_assoc_long(&ip_val, "hlim", ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim);
		add_assoc_long(&ip_val, "vfc", ip6->ip6_ctlun.ip6_un2_vfc);

		/* Convert IPv6 address to string */
		inet_ntop(AF_INET6, &(ip6->ip6_src), ipaddr, INET6_ADDRSTRLEN);
		add_assoc_string(&ip_val, "src", ipaddr);
		inet_ntop(AF_INET6, &(ip6->ip6_dst), ipaddr, INET6_ADDRSTRLEN);
		add_assoc_string(&ip_val, "dst", ipaddr);

		add_next_index_zval(return_value, &ip_val);
		data = (char *) (p+next_hdr+sizeof(struct ip6_hdr));
		add_assoc_stringl(return_value, "data", data, ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen));
	} else if (0x8100 == eth_proto) {
		/* 802.1q */
		vlan = (struct vlanhdr *) (p+next_hdr);
		array_init(&vlan_val);
		add_assoc_string(&vlan_val, "header_type", "vlan");
		add_assoc_long(&vlan_val, "prio", vlan->prio);
		add_assoc_long(&vlan_val, "cfi", vlan->cfi);
		add_assoc_long(&vlan_val, "id", (vlan->id>>4));
		add_assoc_long(&vlan_val, "next", ntohs(vlan->next));
		add_next_index_zval(return_value, &vlan_val);
		next_hdr += sizeof(struct vlanhdr);
		eth_proto = ntohs(vlan->next);
		goto ethrestart;
	} else if (0x888e == eth_proto) {
		/* 802.1x */
	} else if (0x8847 == eth_proto) {
		/* MPLS Unicast */
		do {
			mpls = (struct mplshdr *) (p+next_hdr);
			array_init(&vlan_val);
			add_assoc_string(&vlan_val, "header_type", "mpls");
			add_assoc_long(&vlan_val, "label", ((ntohl(mpls->label) & 0xFFFFF000) >> 12));
			add_assoc_long(&vlan_val, "exp", ((ntohl(mpls->label) & 0x00000E00) >> 9));
			add_assoc_long(&vlan_val, "bottom", ((ntohl(mpls->label) & 0x00000100) >> 8));
			add_assoc_long(&vlan_val, "ttl", (ntohl(mpls->label) & 0x000000FF)); 
			add_next_index_zval(return_value, &vlan_val); 
			next_hdr += sizeof(struct mplshdr);
		} while (!((ntohl(mpls->label) & 0x00000100) >> 8));

		data = (char *) (p+next_hdr);
		if ((*data >> 4) == 4) {
			eth_proto = 0x0800;
		} else if ((*data >> 4) == 6) {
			eth_proto = 0x86dd;
		} else {
			eth_proto = 0xffee;
		}
		goto ethrestart;
	} else {
		add_assoc_stringl(return_value, "data", data, (hdr.len - next_hdr));
	}
}
/* }}} */


/* {{{ php_pcap_init_globals
 */
/* Uncomment this function if you have INI entries
static void php_pcap_init_globals(zend_pcap_globals *pcap_globals)
{
	pcap_globals->global_value = 0;
	pcap_globals->global_string = NULL;
}
*/
/* }}} */

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(pcap)
{
	le_pcap = zend_register_list_destructors_ex(pcap_destructor_pcap, NULL, le_pcap_name, module_number);
	/* If you have INI entries, uncomment these lines
	REGISTER_INI_ENTRIES();
	*/
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(pcap)
{
	/* uncomment this line if you have INI entries
	UNREGISTER_INI_ENTRIES();
	*/
	return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request start */
/* {{{ PHP_RINIT_FUNCTION
 */
PHP_RINIT_FUNCTION(pcap)
{
#if defined(COMPILE_DL_PCAP) && defined(ZTS)
	ZEND_TSRMLS_CACHE_UPDATE();
#endif
	return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request end */
/* {{{ PHP_RSHUTDOWN_FUNCTION
 */
PHP_RSHUTDOWN_FUNCTION(pcap)
{
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(pcap)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "pcap support", "enabled");
	php_info_print_table_end();

	/* Remove comments if you have entries in php.ini
	DISPLAY_INI_ENTRIES();
	*/
}
/* }}} */

/* {{{ pcap_functions[]
 *
 * Every user visible function must have an entry in pcap_functions[].
 */
const zend_function_entry pcap_functions[] = {
	PHP_FE(pcap_close,			NULL)
	PHP_FE(pcap_open_offline,	NULL)
	PHP_FE(pcap_filter,			NULL)
	PHP_FE(pcap_geterr,			NULL)
	PHP_FE(pcap_next_raw,		NULL)
	PHP_FE(pcap_next,			NULL)
	PHP_FE_END	/* Must be the last line in pcap_functions[] */
};
/* }}} */

/* {{{ pcap_module_entry
 */
zend_module_entry pcap_module_entry = {
	STANDARD_MODULE_HEADER,
	"pcap",
	pcap_functions,
	PHP_MINIT(pcap),
	/*PHP_MSHUTDOWN(pcap)*/ NULL,
	/*PHP_RINIT(pcap)*/ NULL,		/* Replace with NULL if there's nothing to do at request start */
	/*PHP_RSHUTDOWN(pcap)*/ NULL,	/* Replace with NULL if there's nothing to do at request end */
	PHP_MINFO(pcap),
	PHP_PCAP_VERSION,
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

#ifdef COMPILE_DL_PCAP
#ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE();
#endif
ZEND_GET_MODULE(pcap)
#endif

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
