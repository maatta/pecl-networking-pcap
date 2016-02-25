
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
#include <netinet/udp.h>
#include <netinet/tcp.h>

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
	zend_string	*err;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "r", &z_fp) == FAILURE) {
		return;
	}

	if ((fp = (pcap_t *)zend_fetch_resource(Z_RES_P(z_fp), le_pcap_name, le_pcap)) == NULL) {
		RETURN_FALSE;
	}

	/* XXX: This is wrong */
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

inline void pcap_ipv4_tcp(zval *ret, struct iphdr *ip, const u_char *p)
{
	zval	proto_val;
	char	*data;
	struct tcphdr	*tcp;

	tcp = (struct tcphdr *) (p+ETHER_HEADER_LEN+(ip->ihl << 2));
	array_init(&proto_val);
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
	add_assoc_zval(ret, "tcp", &proto_val);

	/* XXX: Options not handled! */
	if ((ntohs(ip->tot_len) - (ip->ihl << 2) - (tcp->th_off * 4)) > 0) {
		data = (char *) (p+ETHER_HEADER_LEN+(ip->ihl << 2)+(tcp->th_off * 4));
		add_assoc_stringl(ret, "data", data, (ntohs(ip->tot_len)-(ip->ihl << 2)-(tcp->th_off * 4)));
	} else {
		/* Set data to false if we have no data */
		add_assoc_bool(ret, "data", 0);
	}

}


inline void pcap_ipv4_udp(zval *ret, struct iphdr *ip, const u_char *p)
{
	zval	proto_val;
	char	*data;
	struct udphdr	*udp;

	udp = (struct udphdr *) (p+ETHER_HEADER_LEN+(ip->ihl << 2));
	array_init(&proto_val);
	add_assoc_long(&proto_val, "sport", ntohs(udp->source));
	add_assoc_long(&proto_val, "dport", ntohs(udp->dest));
	add_assoc_long(&proto_val, "len", ntohs(udp->len));
	add_assoc_long(&proto_val, "checksum", ntohs(udp->check));
	add_assoc_zval(ret, "udp", &proto_val);
	data = (char *) (p+ETHER_HEADER_LEN+(ip->ihl << 2)+ntohs(udp->len));
	add_assoc_stringl(ret, "data", data, (ntohs(udp->len) - 8));
}


inline void pcap_ipv4_vrrp(zval *ret, struct iphdr *ip, const u_char *p)
{
	zval	proto_val;
	char	*data;
	struct	vrrp2hdr	*hdr;

	hdr = (struct vrrp2hdr *) (p+ETHER_HEADER_LEN+(ip->ihl << 2));

	if (2 == hdr->version) {
		/* We could parse all IPs and auth data and add to an array maybe ? */
		array_init(&proto_val);
		add_assoc_long(&proto_val, "version", hdr->version);
		add_assoc_long(&proto_val, "type", hdr->type);
		add_assoc_long(&proto_val, "rtrid", hdr->rtr_id);
		add_assoc_long(&proto_val, "prio", hdr->priority);
		add_assoc_long(&proto_val, "count", hdr->count);
		add_assoc_long(&proto_val, "auth", hdr->auth);
		add_assoc_long(&proto_val, "advert", hdr->advert);
		add_assoc_long(&proto_val, "checksum", ntohs(hdr->checksum));
		add_assoc_zval(ret, "vrrp", &proto_val);
		data = (char *) (p+ETHER_HEADER_LEN+(ip->ihl << 2)+8);
		add_assoc_stringl(ret, "data", data, (ntohs(ip->tot_len) - (ip->ihl << 2) - 8));
	} else {
		/* Not version 2 */
	}
}

/* {{{ proto string confirm_pcap_compiled(string arg)
   Return a string to confirm that the module is compiled in */
PHP_FUNCTION(pcap_next)
{
	zval	*z_fp, eth_val, ip_val, proto_val;
	pcap_t	*fp;
	int		i;
	char	*data;
	const u_char	*p;
	register const struct ether_header	*eptr;
	struct pcap_pkthdr	hdr;
	struct iphdr		*ip;
	struct tcphdr		*tcp;
	struct udphdr		*udp;
	zend_string *src, *dst;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "r", &z_fp) == FAILURE) {
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
	add_assoc_string(&eth_val, "src", ZSTR_VAL(src));
	add_assoc_string(&eth_val, "dst", ZSTR_VAL(dst));
	add_assoc_long(&eth_val, "type", __builtin_bswap16(eptr->ether_type));
	add_assoc_zval(return_value, "ethernet", &eth_val);

	if (0x0800 == __builtin_bswap16(eptr->ether_type)) {
		/* IPv4 */
		ip = (struct iphdr *) (p+ETHER_HEADER_LEN);

		array_init(&ip_val);
		add_assoc_long(&ip_val, "version", ip->version);
		add_assoc_long(&ip_val, "hlen", (ip->ihl << 2));
		add_assoc_long(&ip_val, "tos", ip->tos);
		add_assoc_long(&ip_val, "len", ntohs(ip->tot_len));
		add_assoc_long(&ip_val, "id", ntohs(ip->id));
		add_assoc_long(&ip_val, "frag_off", ntohs(ip->frag_off));
		add_assoc_long(&ip_val, "ttl", ip->ttl);
		add_assoc_long(&ip_val, "proto", ip->protocol);
		add_assoc_long(&ip_val, "checksum", ntohs(ip->check));
		add_assoc_long(&ip_val, "saddr", ntohl(ip->saddr));
		add_assoc_long(&ip_val, "daddr", ntohl(ip->daddr)); 
		add_assoc_zval(return_value, "ip", &ip_val);

		switch (ip->protocol) {
			case 6:		/* TCP */
				pcap_ipv4_tcp(return_value, ip, p);
				break;
			case 17:	/* UDP */
				pcap_ipv4_udp(return_value, ip, p);
				break;
			case 112:	/* VRRP */
				pcap_ipv4_vrrp(return_value, ip, p);
				break;
			default:
				data = (char *)(p+ETHER_HEADER_LEN+(ip->ihl << 2));
				add_assoc_stringl(return_value, "data", data, (ntohs(ip->tot_len)-(ip->ihl << 2)));
				break;
		}
		/*   1 ICMP
		 *   2 IGMP
		 *  41 IPv6
		 *  43 IPv6 Route
		 *  44 IPv6 Fragment
		 *  47 GRE
		 *  51 AH
		 *  88 EIGRP
		 *  89 OSPF
		 * 115 L2TPv3
		 * 124 ISIS over IPv4
		 * 137 MPLS-in-IP
		 */
/*	} else if (0x86dd == __builtin_bswap16(eptr->ether_type)) { */
		/* IPv6 */
	} else {
		add_assoc_stringl(return_value, "data", data, (hdr.len - ETHER_HEADER_LEN));
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
	PHP_MSHUTDOWN(pcap),
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
