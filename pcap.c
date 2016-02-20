
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_pcap.h"

#include <pcap/pcap.h>
#include <netinet/if_ether.h>

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
PHP_FUNCTION(pcap_next_raw)
{
	zval		*z_fp;
	pcap_t		*fp;
	int			i;
	const u_char	*p;
	struct pcap_pkthdr hdr;
	char		*packet;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "r", &z_fp) == FAILURE) {
		return;
	}

	if ((fp = (pcap_t *)zend_fetch_resource(Z_RES_P(z_fp), le_pcap_name, le_pcap)) == NULL) {
		RETURN_FALSE;
	}

	if (!(p = pcap_next(fp, &hdr))) {
		RETURN_FALSE;
	}

	packet = (char *)safe_emalloc(1, hdr.len, 0);

	for (i = 0; i < hdr.len; i++) {
		packet[i] = p[i];
	}

	RETURN_STRINGL(packet, hdr.len);

}
/* }}} */

/* {{{ proto string confirm_pcap_compiled(string arg)
   Return a string to confirm that the module is compiled in */
PHP_FUNCTION(pcap_next)
{
	zval	*z_fp, eth_val;
	pcap_t	*fp;
	int		i;
	char	*packet;
	const u_char	*p;
	register const struct ether_header	*eptr;
	struct pcap_pkthdr	hdr;
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

	packet = (char *)safe_emalloc(1, hdr.len, 0);

	for (i = 14; i < hdr.len; i++) {
		packet[(i - 14)] = p[i];
	}

	eptr = (struct ether_header *)p;
	/* Convert MAC addresses to hex */
	src = pcap_bin2hex((char *) eptr->ether_shost, ETHER_ADDR_LEN);
	dst = pcap_bin2hex((char *) eptr->ether_dhost, ETHER_ADDR_LEN);

	array_init(&eth_val);
	array_init(return_value);
	add_assoc_string(&eth_val, "src", ZSTR_VAL(src));
	add_assoc_string(&eth_val, "dst", ZSTR_VAL(dst));
	add_assoc_long(&eth_val, "type", eptr->ether_type);
	add_assoc_zval(return_value, "ethernet", &eth_val);
	add_assoc_stringl(return_value, "data", packet, (hdr.len - 14));

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
