/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2015 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* Portions Copyright (c) 1995 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#ifndef PROTO_SLAP_H
#define PROTO_SLAP_H

#include <ldap_cdefs.h>
#include "ldap_pvt.h"

#include <event2/event.h>

LDAP_BEGIN_DECL

struct config_args_s;	/* config.h */
struct config_reply_s;	/* config.h */


/*
 * backend.c
 */

LDAP_SLAPD_F (void) backend_connect LDAP_P (( evutil_socket_t s, short what, void *arg ));
LDAP_SLAPD_F (void *) backend_connect_task LDAP_P (( void *ctx, void *arg ));
LDAP_SLAPD_F (void) backend_retry LDAP_P (( Backend *b ));
LDAP_SLAPD_F (Connection *) backend_select LDAP_P (( Operation *op ));
LDAP_SLAPD_F (void) backends_destroy LDAP_P ((void));

/*
 * bconfig.c
 */
LDAP_SLAPD_F (int) slap_loglevel_register LDAP_P (( slap_mask_t m, struct berval *s ));
LDAP_SLAPD_F (int) slap_loglevel_get LDAP_P(( struct berval *s, int *l ));
LDAP_SLAPD_F (int) str2loglevel LDAP_P(( const char *s, int *l ));
LDAP_SLAPD_F (int) loglevel2bvarray LDAP_P(( int l, BerVarray *bva ));
LDAP_SLAPD_F (const char *) loglevel2str LDAP_P(( int l ));
LDAP_SLAPD_F (int) loglevel2bv LDAP_P(( int l, struct berval *bv ));
LDAP_SLAPD_F (int) loglevel_print LDAP_P(( FILE *out ));

/*
 * ch_malloc.c
 */
LDAP_SLAPD_V (BerMemoryFunctions) ch_mfuncs;
LDAP_SLAPD_F (void *) ch_malloc LDAP_P(( ber_len_t size ));
LDAP_SLAPD_F (void *) ch_realloc LDAP_P(( void *block, ber_len_t size ));
LDAP_SLAPD_F (void *) ch_calloc LDAP_P(( ber_len_t nelem, ber_len_t size ));
LDAP_SLAPD_F (char *) ch_strdup LDAP_P(( const char *string ));
LDAP_SLAPD_F (void) ch_free LDAP_P(( void * ));

#ifndef CH_FREE
#undef free
#define free ch_free
#endif

/*
 * bind.c
 */
LDAP_SLAPD_F (int) request_bind LDAP_P(( Connection *c, Operation *op ));
LDAP_SLAPD_F (int) handle_bind_response LDAP_P(( Operation *op, BerElement *ber ));
LDAP_SLAPD_F (int) handle_vc_bind_response LDAP_P(( Operation *op, BerElement *ber ));

/*
 * client.c
 */
LDAP_SLAPD_F (int) request_abandon LDAP_P(( Connection *c, Operation *op ));
LDAP_SLAPD_F (int) request_process LDAP_P(( Connection *c, Operation *op ));
LDAP_SLAPD_F (int) handle_one_request LDAP_P(( Connection *c ));
LDAP_SLAPD_F (void) client_tls_handshake_cb LDAP_P(( evutil_socket_t s, short what, void *arg ));
LDAP_SLAPD_F (Connection *) client_init LDAP_P((
	ber_socket_t s,
	Listener* url,
	const char* peername,
    struct event_base *base,
	int use_tls ));
LDAP_SLAPD_F (void) client_reset LDAP_P(( Connection *c ));
LDAP_SLAPD_F (void) client_destroy LDAP_P(( Connection *c ));
LDAP_SLAPD_F (void) clients_destroy LDAP_P ((void));

/*
 * config.c
 */
LDAP_SLAPD_F (int) read_config LDAP_P(( const char *fname, const char *dir ));
LDAP_SLAPD_F (void) config_destroy LDAP_P ((void));
LDAP_SLAPD_F (char **) slap_str2clist LDAP_P((
	char ***, char *, const char * ));
LDAP_SLAPD_F (int) bverb_to_mask LDAP_P((
	struct berval *bword,  slap_verbmasks *v ));
LDAP_SLAPD_F (int) verb_to_mask LDAP_P((
	const char *word,  slap_verbmasks *v ));
LDAP_SLAPD_F (int) verbs_to_mask LDAP_P((
	int argc, char *argv[], slap_verbmasks *v, slap_mask_t *m ));
LDAP_SLAPD_F (int) mask_to_verbs LDAP_P((
	slap_verbmasks *v, slap_mask_t m, BerVarray *bva ));
LDAP_SLAPD_F (int) mask_to_verbstring LDAP_P((
	slap_verbmasks *v, slap_mask_t m, char delim, struct berval *bv ));
LDAP_SLAPD_F (int) verbstring_to_mask LDAP_P((
	slap_verbmasks *v, char *str, char delim, slap_mask_t *m ));
LDAP_SLAPD_F (int) enum_to_verb LDAP_P((
	slap_verbmasks *v, slap_mask_t m, struct berval *bv ));
LDAP_SLAPD_F (int) slap_verbmasks_init LDAP_P(( slap_verbmasks **vp, slap_verbmasks *v ));
LDAP_SLAPD_F (int) slap_verbmasks_destroy LDAP_P(( slap_verbmasks *v ));
LDAP_SLAPD_F (int) slap_verbmasks_append LDAP_P(( slap_verbmasks **vp,
	slap_mask_t m, struct berval *v, slap_mask_t *ignore ));
LDAP_SLAPD_F (int) slap_tls_get_config LDAP_P((
	LDAP *ld, int opt, char **val ));
LDAP_SLAPD_F (void) bindconf_tls_defaults LDAP_P(( slap_bindconf *bc ));
LDAP_SLAPD_F (int) backend_parse LDAP_P((
	const char *word, Backend *b ));
LDAP_SLAPD_F (int) bindconf_parse LDAP_P((
	const char *word, slap_bindconf *bc ));
LDAP_SLAPD_F (int) bindconf_unparse LDAP_P((
	slap_bindconf *bc, struct berval *bv ));
LDAP_SLAPD_F (int) bindconf_tls_set LDAP_P((
	slap_bindconf *bc, LDAP *ld ));
LDAP_SLAPD_F (void) bindconf_free LDAP_P(( slap_bindconf *bc ));

/*
 * connection.c
 */
LDAP_SLAPD_V (ldap_pvt_thread_mutex_t) clients_mutex;
LDAP_SLAPD_F (void) connection_write_cb LDAP_P(( evutil_socket_t s, short what, void *arg ));
LDAP_SLAPD_F (void) connection_read_cb LDAP_P(( evutil_socket_t s, short what, void *arg ));
LDAP_SLAPD_F (Connection *) connection_init LDAP_P((
	ber_socket_t s,
	const char* peername,
	int use_tls ));
LDAP_SLAPD_F (void) connection_destroy LDAP_P(( Connection *c ));

/*
 * daemon.c
 */
LDAP_SLAPD_F (int) slapd_daemon_init( const char *urls );
LDAP_SLAPD_F (int) slapd_daemon_destroy(void);
LDAP_SLAPD_F (int) slapd_daemon( struct event_base *daemon_base );
LDAP_SLAPD_F (Listener **)	slapd_get_listeners LDAP_P((void));
LDAP_SLAPD_F (void) listeners_reactivate LDAP_P((void));
LDAP_SLAPD_F (struct event_base *) slap_get_base LDAP_P(( ber_socket_t s ));

LDAP_SLAPD_F (void) slap_sig_shutdown LDAP_P(( evutil_socket_t sig, short what, void *arg ));
LDAP_SLAPD_F (void) slap_wake_listener LDAP_P((void));

LDAP_SLAPD_F (void) slap_suspend_listeners LDAP_P((void));
LDAP_SLAPD_F (void) slap_resume_listeners LDAP_P((void));

LDAP_SLAPD_F (void) slapd_clr_writetime LDAP_P((time_t old));
LDAP_SLAPD_F (time_t) slapd_get_writetime LDAP_P((void));

LDAP_SLAPD_V (struct evdns_base *) dnsbase;
LDAP_SLAPD_V (volatile sig_atomic_t) slapd_abrupt_shutdown;
LDAP_SLAPD_V (volatile sig_atomic_t) slapd_shutdown;
LDAP_SLAPD_V (int) slapd_register_slp;
LDAP_SLAPD_V (const char *) slapd_slp_attrs;
LDAP_SLAPD_V (struct runqueue_s) slapd_rq;
LDAP_SLAPD_V (int) slapd_daemon_threads;
LDAP_SLAPD_V (int) slapd_daemon_mask;
#ifdef LDAP_TCP_BUFFER
LDAP_SLAPD_V (int) slapd_tcp_rmem;
LDAP_SLAPD_V (int) slapd_tcp_wmem;
#endif /* LDAP_TCP_BUFFER */

#define bvmatch(bv1, bv2)	( ((bv1)->bv_len == (bv2)->bv_len) && (memcmp((bv1)->bv_val, (bv2)->bv_val, (bv1)->bv_len) == 0) )

/*
 * extended.c
 */
LDAP_SLAPD_V( Avlnode * ) lload_exop_handlers;
LDAP_SLAPD_F (int) exop_handler_cmp LDAP_P(( const void *l, const void *r ));
LDAP_SLAPD_F (int) request_extended LDAP_P(( Connection *c, Operation *op ));
LDAP_SLAPD_F (int) lload_exop_init LDAP_P(( void ));

/*
 * globals.c
 */
LDAP_SLAPD_V( const struct berval ) slap_empty_bv;
LDAP_SLAPD_V( const struct berval ) slap_unknown_bv;
LDAP_SLAPD_V( const struct berval ) slap_true_bv;
LDAP_SLAPD_V( const struct berval ) slap_false_bv;
LDAP_SLAPD_V( struct slap_sync_cookie_s ) slap_sync_cookie;
LDAP_SLAPD_V( void * ) slap_tls_ctx;
LDAP_SLAPD_V( LDAP * ) slap_tls_ld;
LDAP_SLAPD_V( LDAP * ) slap_tls_backend_ld;

/*
 * init.c
 */
LDAP_SLAPD_F (int)	slap_init LDAP_P((int mode, const char* name));
LDAP_SLAPD_F (int)	slap_destroy LDAP_P((void));
LDAP_SLAPD_F (void) slap_counters_init LDAP_P((slap_counters_t *sc));
LDAP_SLAPD_F (void) slap_counters_destroy LDAP_P((slap_counters_t *sc));

LDAP_SLAPD_V (char *)	slap_known_controls[];

/*
 * libevent_support.c
 */
LDAP_SLAPD_F (int) lload_libevent_init LDAP_P((void));
LDAP_SLAPD_F (void) lload_libevent_destroy LDAP_P((void));

/*
 * main.c
 */
LDAP_SLAPD_F (int)
parse_debug_level LDAP_P(( const char *arg, int *levelp, char ***unknowns ));
LDAP_SLAPD_F (int)
parse_syslog_level LDAP_P(( const char *arg, int *levelp ));
LDAP_SLAPD_F (int)
parse_syslog_user LDAP_P(( const char *arg, int *syslogUser ));
LDAP_SLAPD_F (int)
parse_debug_unknowns LDAP_P(( char **unknowns, int *levelp ));

/*
 * operation.c
 */
LDAP_SLAPD_F (const char *) slap_msgtype2str LDAP_P(( ber_tag_t tag ));
LDAP_SLAPD_F (int) operation_upstream_cmp LDAP_P(( const void *l, const void *r ));
LDAP_SLAPD_F (int) operation_client_cmp LDAP_P(( const void *l, const void *r ));
LDAP_SLAPD_F (Operation *) operation_init LDAP_P(( Connection *c, BerElement *ber ));
LDAP_SLAPD_F (void) operation_abandon LDAP_P((Operation *op));
LDAP_SLAPD_F (void) operation_send_reject LDAP_P(( Operation *op, int result, const char *msg, int send_anyway ));
LDAP_SLAPD_F (int) operation_send_reject_locked LDAP_P(( Operation *op, int result, const char *msg, int send_anyway ));
LDAP_SLAPD_F (void) operation_lost_upstream LDAP_P((Operation *op));
LDAP_SLAPD_F (void) operation_destroy_from_client LDAP_P((Operation *op));
LDAP_SLAPD_F (void) operation_destroy_from_upstream LDAP_P((Operation *op));

/*
 * sl_malloc.c
 */
LDAP_SLAPD_F (void *) slap_sl_malloc LDAP_P((
	ber_len_t size, void *ctx ));
LDAP_SLAPD_F (void *) slap_sl_realloc LDAP_P((
	void *block, ber_len_t size, void *ctx ));
LDAP_SLAPD_F (void *) slap_sl_calloc LDAP_P((
	ber_len_t nelem, ber_len_t size, void *ctx ));
LDAP_SLAPD_F (void) slap_sl_free LDAP_P((
	void *, void *ctx ));

LDAP_SLAPD_V (BerMemoryFunctions) slap_sl_mfuncs;

LDAP_SLAPD_F (void) slap_sl_mem_init LDAP_P(( void ));
LDAP_SLAPD_F (void *) slap_sl_mem_create LDAP_P((
						ber_len_t size, int stack, void *ctx, int flag ));
LDAP_SLAPD_F (void) slap_sl_mem_setctx LDAP_P(( void *ctx, void *memctx ));
LDAP_SLAPD_F (void) slap_sl_mem_destroy LDAP_P(( void *key, void *data ));
LDAP_SLAPD_F (void *) slap_sl_context LDAP_P(( void *ptr ));

LDAP_SLAPD_F (int) value_add_one LDAP_P((
	BerVarray *vals,
	struct berval *addval ));

/* assumes (x) > (y) returns 1 if true, 0 otherwise */
#define SLAP_PTRCMP(x, y) ((x) < (y) ? -1 : (x) > (y))

/*
 * upstream.c
 */
LDAP_SLAPD_F (int) forward_final_response LDAP_P(( Operation *op, BerElement *ber ));
LDAP_SLAPD_F (int) forward_response LDAP_P(( Operation *op, BerElement *ber ));
LDAP_SLAPD_F (Connection *) upstream_init LDAP_P((
	ber_socket_t s,
	Backend* b ));
LDAP_SLAPD_F (void) upstream_destroy LDAP_P(( Connection *c ));

/*
 * user.c
 */
#if defined(HAVE_PWD_H) && defined(HAVE_GRP_H)
LDAP_SLAPD_F (void) slap_init_user LDAP_P(( char *username, char *groupname ));
#endif

#ifdef SLAP_ZONE_ALLOC
/*
 * zn_malloc.c
 */
LDAP_SLAPD_F (void *) slap_zn_malloc LDAP_P((ber_len_t, void *));
LDAP_SLAPD_F (void *) slap_zn_realloc LDAP_P((void *, ber_len_t, void *));
LDAP_SLAPD_F (void *) slap_zn_calloc LDAP_P((ber_len_t, ber_len_t, void *));
LDAP_SLAPD_F (void) slap_zn_free LDAP_P((void *, void *));

LDAP_SLAPD_F (void *) slap_zn_mem_create LDAP_P((
							ber_len_t, ber_len_t, ber_len_t, ber_len_t));
LDAP_SLAPD_F (void) slap_zn_mem_destroy LDAP_P((void *));
LDAP_SLAPD_F (int) slap_zn_validate LDAP_P((void *, void *, int));
LDAP_SLAPD_F (int) slap_zn_invalidate LDAP_P((void *, void *));
LDAP_SLAPD_F (int) slap_zh_rlock LDAP_P((void*));
LDAP_SLAPD_F (int) slap_zh_runlock LDAP_P((void*));
LDAP_SLAPD_F (int) slap_zh_wlock LDAP_P((void*));
LDAP_SLAPD_F (int) slap_zh_wunlock LDAP_P((void*));
LDAP_SLAPD_F (int) slap_zn_rlock LDAP_P((void*, void*));
LDAP_SLAPD_F (int) slap_zn_runlock LDAP_P((void*, void*));
LDAP_SLAPD_F (int) slap_zn_wlock LDAP_P((void*, void*));
LDAP_SLAPD_F (int) slap_zn_wunlock LDAP_P((void*, void*));
#endif

LDAP_SLAPD_V (ber_len_t) sockbuf_max_incoming_client;
LDAP_SLAPD_V (ber_len_t) sockbuf_max_incoming_upstream;
LDAP_SLAPD_V (int)		slap_conn_max_pending;
LDAP_SLAPD_V (int)		slap_conn_max_pending_auth;
LDAP_SLAPD_V (int)      slap_conn_max_pdus_per_cycle;

LDAP_SLAPD_V (slap_features_t) slap_features;

LDAP_SLAPD_V (slap_mask_t)	global_allows;
LDAP_SLAPD_V (slap_mask_t)	global_disallows;

LDAP_SLAPD_V (const char) 	Versionstr[];

LDAP_SLAPD_V (int)		global_gentlehup;
LDAP_SLAPD_V (int)		global_idletimeout;

LDAP_SLAPD_V (struct timeval *) lload_timeout_api;
LDAP_SLAPD_V (struct timeval *) lload_timeout_net;
LDAP_SLAPD_V (struct timeval *) lload_write_timeout;

LDAP_SLAPD_V (char *)   global_host;
LDAP_SLAPD_V (int)		lber_debug;
LDAP_SLAPD_V (int)		ldap_syslog;

LDAP_SLAPD_V (slap_counters_t)	slap_counters;

LDAP_SLAPD_V (char *)		slapd_pid_file;
LDAP_SLAPD_V (char *)		slapd_args_file;
LDAP_SLAPD_V (time_t)		starttime;

/* use time(3) -- no mutex */
#define slap_get_time()	time( NULL )

LDAP_SLAPD_V (ldap_pvt_thread_pool_t)     connection_pool;
LDAP_SLAPD_V (int)			connection_pool_max;
LDAP_SLAPD_V (int)			connection_pool_queues;
LDAP_SLAPD_V (int)			slap_tool_thread_max;

#ifdef USE_MP_BIGNUM
# define UI2BVX(bv,ui,ctx) \
	do { \
		char		*val; \
		ber_len_t	len; \
		val = BN_bn2dec(ui); \
		if (val) { \
			len = strlen(val); \
			if ( len > (bv)->bv_len ) { \
				(bv)->bv_val = ber_memrealloc_x( (bv)->bv_val, len + 1, (ctx) ); \
			} \
			AC_MEMCPY((bv)->bv_val, val, len + 1); \
			(bv)->bv_len = len; \
			OPENSSL_free(val); \
		} else { \
			ber_memfree_x( (bv)->bv_val, (ctx) ); \
			BER_BVZERO( (bv) ); \
		} \
	} while ( 0 )

#elif defined( USE_MP_GMP )
/* NOTE: according to the documentation, the result
 * of mpz_sizeinbase() can exceed the length of the
 * string representation of the number by 1
 */
# define UI2BVX(bv,ui,ctx) \
	do { \
		ber_len_t	len = mpz_sizeinbase( (ui), 10 ); \
		if ( len > (bv)->bv_len ) { \
			(bv)->bv_val = ber_memrealloc_x( (bv)->bv_val, len + 1, (ctx) ); \
		} \
		(void)mpz_get_str( (bv)->bv_val, 10, (ui) ); \
		if ( (bv)->bv_val[ len - 1 ] == '\0' ) { \
			len--; \
		} \
		(bv)->bv_len = len; \
	} while ( 0 )

#else
# ifdef USE_MP_LONG_LONG
#  define UI2BV_FORMAT	"%llu"
# elif defined USE_MP_LONG
#  define UI2BV_FORMAT	"%lu"
# elif defined HAVE_LONG_LONG
#  define UI2BV_FORMAT	"%llu"
# else
#  define UI2BV_FORMAT	"%lu"
# endif

# define UI2BVX(bv,ui,ctx) \
	do { \
		char		buf[LDAP_PVT_INTTYPE_CHARS(long)]; \
		ber_len_t	len; \
		len = snprintf( buf, sizeof( buf ), UI2BV_FORMAT, (ui) ); \
		if ( len > (bv)->bv_len ) { \
			(bv)->bv_val = ber_memrealloc_x( (bv)->bv_val, len + 1, (ctx) ); \
		} \
		(bv)->bv_len = len; \
		AC_MEMCPY( (bv)->bv_val, buf, len + 1 ); \
	} while ( 0 )
#endif

#define UI2BV(bv,ui)	UI2BVX(bv,ui,NULL)

LDAP_END_DECL

#endif /* PROTO_SLAP_H */
