
#ifndef PHP_PCAP_H
#define PHP_PCAP_H

extern zend_module_entry pcap_module_entry;
#define phpext_pcap_ptr &pcap_module_entry

#define PHP_PCAP_VERSION "0.2.0" /* Replace with version number for your extension */

#ifdef PHP_WIN32
#	define PHP_PCAP_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#	define PHP_PCAP_API __attribute__ ((visibility("default")))
#else
#	define PHP_PCAP_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

struct eigrphdr
{
	u_int8_t  version;
	u_int8_t  opcode;
	u_int16_t csum;
	u_int32_t flags;
	u_int32_t seq;
	u_int32_t ack;
	u_int32_t as;
};

struct grehdr
{
	u_int16_t flags;
	u_int16_t next;
};

struct mplshdr
{
	u_int32_t label;
};

struct ospfhdr
{
	u_int8_t  version;
	u_int8_t  type;
	u_int16_t len;
	u_int32_t rtrid;
	u_int32_t area;
	u_int16_t checksum;
	u_int16_t authtype;
	u_int16_t authrsrvd;
	u_int8_t  authkey;
	u_int8_t  authlen;
	u_int16_t authseq;
};

struct vlanhdr
{
	u_int8_t  prio:3;
	u_int8_t  cfi:1;
	u_int16_t id:12;
	u_int16_t next;
};

struct ahhdr
{
	u_int8_t  next;
	u_int8_t  len;
	u_int16_t rsvd;
	u_int32_t spi;
	u_int32_t seq;
};

struct vrrp2hdr
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	u_int8_t  type:4;
	u_int8_t  version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	u_int8_t  version:4;
	u_int8_t  type:4;
#endif
	u_int8_t  rtr_id;
	u_int8_t  priority;
	u_int8_t  count;
	u_int8_t  auth;
	u_int8_t  advert;
	u_int16_t checksum;
};

struct vrrp3hdr
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	u_int8_t  type:4;
	u_int8_t  version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	u_int8_t  version:4;
	u_int8_t  type:4;
#endif
	u_int8_t  virtip;
	u_int8_t  priority;
	u_int8_t  count;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	u_int8_t  rsvd:4;
	u_int16_t advert:12;
#else
#error "Fix this"
#endif
	u_int16_t checksum;
};

/*
  	Declare any global variables you may need between the BEGIN
	and END macros here:

ZEND_BEGIN_MODULE_GLOBALS(pcap)
	zend_long  global_value;
	char *global_string;
ZEND_END_MODULE_GLOBALS(pcap)
*/

/* Always refer to the globals in your function as PCAP_G(variable).
   You are encouraged to rename these macros something shorter, see
   examples in any other php module directory.
*/
#define PCAP_G(v) ZEND_MODULE_GLOBALS_ACCESSOR(pcap, v)

#if defined(ZTS) && defined(COMPILE_DL_PCAP)
ZEND_TSRMLS_CACHE_EXTERN();
#endif

#endif	/* PHP_PCAP_H */

