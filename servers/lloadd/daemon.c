/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2015 The OpenLDAP Foundation.
 * Portions Copyright 2007 by Howard Chu, Symas Corporation.
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

#include "portable.h"

#include <stdio.h>

#include <ac/ctype.h>
#include <ac/errno.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>
#include <ac/unistd.h>

#include <event2/event.h>
#include <event2/dns.h>
#include <event2/listener.h>

#include "slap.h"
#include "ldap_pvt_thread.h"
#include "lutil.h"

#include "ldap_rq.h"

#ifdef HAVE_TCPD
int allow_severity = LOG_INFO;
int deny_severity = LOG_NOTICE;
#endif /* TCP Wrappers */

#ifdef LDAP_PF_LOCAL
# include <sys/stat.h>
/* this should go in <ldap.h> as soon as it is accepted */
# define LDAPI_MOD_URLEXT		"x-mod"
#endif /* LDAP_PF_LOCAL */

#ifdef LDAP_PF_INET6
int slap_inet4or6 = AF_UNSPEC;
#else /* ! INETv6 */
int slap_inet4or6 = AF_INET;
#endif /* ! INETv6 */

/* globals */
time_t starttime;
struct runqueue_s slapd_rq;

#ifndef SLAPD_MAX_DAEMON_THREADS
#define SLAPD_MAX_DAEMON_THREADS	16
#endif
int slapd_daemon_threads = 1;
int slapd_daemon_mask;

#ifdef LDAP_TCP_BUFFER
int slapd_tcp_rmem;
int slapd_tcp_wmem;
#endif /* LDAP_TCP_BUFFER */

struct event_base *listener_base = NULL;
Listener **slap_listeners = NULL;
static volatile sig_atomic_t listening = 1; /* 0 when slap_listeners closed */
static ldap_pvt_thread_t listener_tid, *daemon_tid;

struct evdns_base *dnsbase;

#ifndef SLAPD_LISTEN_BACKLOG
#define SLAPD_LISTEN_BACKLOG 1024
#endif /* ! SLAPD_LISTEN_BACKLOG */

#define	DAEMON_ID(fd)	(fd & slapd_daemon_mask)

static int emfile;

static time_t chk_writetime;

ldap_pvt_thread_mutex_t operation_mutex;

static volatile int waking;
#ifdef NO_THREADS
#define WAKE_DAEMON(l,w) do { \
    if ((w) && ++waking < 5) { \
        event_active( slap_daemon[l].wakeup_event, EV_WRITE, 0 ); \
    } \
} while (0)
#else /* ! NO_THREADS */
#define WAKE_DAEMON(l,w) do { \
    if (w) { \
        event_active( slap_daemon[l].wakeup_event, EV_WRITE, 0 ); \
    } \
} while (0)
#endif /* ! NO_THREADS */

volatile sig_atomic_t slapd_shutdown = 0;
volatile sig_atomic_t slapd_gentle_shutdown = 0;
volatile sig_atomic_t slapd_abrupt_shutdown = 0;

#ifdef HAVE_WINSOCK
ldap_pvt_thread_mutex_t slapd_ws_mutex;
SOCKET *slapd_ws_sockets;
#define	SD_READ 1
#define	SD_WRITE	2
#define	SD_ACTIVE	4
#define	SD_LISTENER	8
#endif

#ifdef HAVE_TCPD
static ldap_pvt_thread_mutex_t	sd_tcpd_mutex;
#endif /* TCP Wrappers */

typedef struct listener_item {
    struct evconnlistener *listener;
    ber_socket_t fd;
} listener_item;

typedef struct slap_daemon_st {
    ldap_pvt_thread_mutex_t sd_mutex;

    struct event_base *base;
    struct event *wakeup_event;
} slap_daemon_st;

static slap_daemon_st slap_daemon[SLAPD_MAX_DAEMON_THREADS];

static void daemon_wakeup_cb( evutil_socket_t sig, short what, void *arg );

/*
 * Remove the descriptor from daemon control
 */
void
slapd_remove(
	ber_socket_t s,
	Sockbuf *sb,
	int wasactive,
	int wake,
	int locked )
{
	int id = DAEMON_ID(s);

	if ( !locked )
		ldap_pvt_thread_mutex_lock( &slap_daemon[id].sd_mutex );

	if ( sb )
		ber_sockbuf_free(sb);

	/* If we ran out of file descriptors, we dropped a listener from
	 * the select() loop. Now that we're removing a session from our
	 * control, we can try to resume a dropped listener to use.
	 */
	if ( emfile && listening ) {
		int i;
		for ( i = 0; slap_listeners[i] != NULL; i++ ) {
			Listener *lr = slap_listeners[i];

			if ( lr->sl_sd == AC_SOCKET_INVALID ) continue;
			if ( lr->sl_sd == s ) continue;
			if ( lr->sl_mute ) {
				lr->sl_mute = 0;
				emfile--;
				if ( DAEMON_ID(lr->sl_sd) != id )
					WAKE_DAEMON(DAEMON_ID(lr->sl_sd), wake);
				break;
			}
		}
		/* Walked the entire list without enabling anything; emfile
		 * counter is stale. Reset it.
		 */
		if ( slap_listeners[i] == NULL ) emfile = 0;
	}
	ldap_pvt_thread_mutex_unlock( &slap_daemon[id].sd_mutex );
	WAKE_DAEMON(id, wake || slapd_gentle_shutdown == 2);
}

time_t
slapd_get_writetime()
{
	time_t cur;
	ldap_pvt_thread_mutex_lock( &slap_daemon[0].sd_mutex );
	cur = chk_writetime;
	ldap_pvt_thread_mutex_unlock( &slap_daemon[0].sd_mutex );
	return cur;
}

void
slapd_clr_writetime( time_t old )
{
	ldap_pvt_thread_mutex_lock( &slap_daemon[0].sd_mutex );
	if ( chk_writetime == old )
		chk_writetime = 0;
	ldap_pvt_thread_mutex_unlock( &slap_daemon[0].sd_mutex );
}

static void
slapd_close( ber_socket_t s )
{
	Debug( LDAP_DEBUG_CONNS, "daemon: closing %ld\n",
		(long) s, 0, 0 );
	tcp_close( s );
}

static void
slap_free_listener_addresses( struct sockaddr **sal )
{
	struct sockaddr **sap;
	if (sal == NULL) return;
	for (sap = sal; *sap != NULL; sap++) ch_free(*sap);
	ch_free(sal);
}

#if defined(LDAP_PF_LOCAL) || defined(SLAP_X_LISTENER_MOD)
static int
get_url_perms(
	char 	**exts,
	mode_t	*perms,
	int	*crit )
{
	int	i;

	assert( exts != NULL );
	assert( perms != NULL );
	assert( crit != NULL );

	*crit = 0;
	for ( i = 0; exts[ i ]; i++ ) {
		char	*type = exts[ i ];
		int	c = 0;

		if ( type[ 0 ] == '!' ) {
			c = 1;
			type++;
		}

		if ( strncasecmp( type, LDAPI_MOD_URLEXT "=",
			sizeof(LDAPI_MOD_URLEXT "=") - 1 ) == 0 )
		{
			char *value = type + ( sizeof(LDAPI_MOD_URLEXT "=") - 1 );
			mode_t p = 0;
			int j;

			switch (strlen(value)) {
			case 4:
				/* skip leading '0' */
				if ( value[ 0 ] != '0' ) return LDAP_OTHER;
				value++;

			case 3:
				for ( j = 0; j < 3; j++) {
					int	v;

					v = value[ j ] - '0';

					if ( v < 0 || v > 7 ) return LDAP_OTHER;

					p |= v << 3*(2-j);
				}
				break;

			case 10:
				for ( j = 1; j < 10; j++ ) {
					static mode_t	m[] = { 0,
						S_IRUSR, S_IWUSR, S_IXUSR,
						S_IRGRP, S_IWGRP, S_IXGRP,
						S_IROTH, S_IWOTH, S_IXOTH
					};
					static const char	c[] = "-rwxrwxrwx";

					if ( value[ j ] == c[ j ] ) {
						p |= m[ j ];

					} else if ( value[ j ] != '-' ) {
						return LDAP_OTHER;
					}
				}
				break;

			default:
				return LDAP_OTHER;
			}

			*crit = c;
			*perms = p;

			return LDAP_SUCCESS;
		}
	}

	return LDAP_OTHER;
}
#endif /* LDAP_PF_LOCAL || SLAP_X_LISTENER_MOD */

/* port = 0 indicates AF_LOCAL */
static int
slap_get_listener_addresses(
	const char *host,
	unsigned short port,
	struct sockaddr ***sal )
{
	struct sockaddr **sap;

#ifdef LDAP_PF_LOCAL
	if ( port == 0 ) {
		*sal = ch_malloc(2 * sizeof(void *));
		if (*sal == NULL) return -1;

		sap = *sal;
		*sap = ch_malloc(sizeof(struct sockaddr_un));
		if (*sap == NULL) goto errexit;
		sap[1] = NULL;

		if ( strlen(host) >
			(sizeof(((struct sockaddr_un *)*sap)->sun_path) - 1) )
		{
			Debug( LDAP_DEBUG_ANY,
				"daemon: domain socket path (%s) too long in URL",
				host, 0, 0);
			goto errexit;
		}

		(void)memset( (void *)*sap, '\0', sizeof(struct sockaddr_un) );
		(*sap)->sa_family = AF_LOCAL;
		strcpy( ((struct sockaddr_un *)*sap)->sun_path, host );
	} else
#endif /* LDAP_PF_LOCAL */
	{
#ifdef HAVE_GETADDRINFO
		struct addrinfo hints, *res, *sai;
		int n, err;
		char serv[7];

		memset( &hints, '\0', sizeof(hints) );
		hints.ai_flags = AI_PASSIVE;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_family = slap_inet4or6;
		snprintf(serv, sizeof serv, "%d", port);

		if ( (err = getaddrinfo(host, serv, &hints, &res)) ) {
			Debug( LDAP_DEBUG_ANY, "daemon: getaddrinfo() failed: %s\n",
				AC_GAI_STRERROR(err), 0, 0);
			return -1;
		}

		sai = res;
		for (n=2; (sai = sai->ai_next) != NULL; n++) {
			/* EMPTY */ ;
		}
		*sal = ch_calloc(n, sizeof(void *));
		if (*sal == NULL) return -1;

		sap = *sal;
		*sap = NULL;

		for ( sai=res; sai; sai=sai->ai_next ) {
			if( sai->ai_addr == NULL ) {
				Debug( LDAP_DEBUG_ANY, "slap_get_listener_addresses: "
					"getaddrinfo ai_addr is NULL?\n", 0, 0, 0 );
				freeaddrinfo(res);
				goto errexit;
			}

			switch (sai->ai_family) {
#  ifdef LDAP_PF_INET6
			case AF_INET6:
				*sap = ch_malloc(sizeof(struct sockaddr_in6));
				if (*sap == NULL) {
					freeaddrinfo(res);
					goto errexit;
				}
				*(struct sockaddr_in6 *)*sap =
					*((struct sockaddr_in6 *)sai->ai_addr);
				break;
#  endif /* LDAP_PF_INET6 */
			case AF_INET:
				*sap = ch_malloc(sizeof(struct sockaddr_in));
				if (*sap == NULL) {
					freeaddrinfo(res);
					goto errexit;
				}
				*(struct sockaddr_in *)*sap =
					*((struct sockaddr_in *)sai->ai_addr);
				break;
			default:
				*sap = NULL;
				break;
			}

			if (*sap != NULL) {
				(*sap)->sa_family = sai->ai_family;
				sap++;
				*sap = NULL;
			}
		}

		freeaddrinfo(res);

#else /* ! HAVE_GETADDRINFO */
		int i, n = 1;
		struct in_addr in;
		struct hostent *he = NULL;

		if ( host == NULL ) {
			in.s_addr = htonl(INADDR_ANY);

		} else if ( !inet_aton( host, &in ) ) {
			he = gethostbyname( host );
			if( he == NULL ) {
				Debug( LDAP_DEBUG_ANY,
					"daemon: invalid host %s", host, 0, 0);
				return -1;
			}
			for (n = 0; he->h_addr_list[n]; n++) /* empty */;
		}

		*sal = ch_malloc((n+1) * sizeof(void *));
		if (*sal == NULL) return -1;

		sap = *sal;
		for ( i = 0; i<n; i++ ) {
			sap[i] = ch_malloc(sizeof(struct sockaddr_in));
			if (*sap == NULL) goto errexit;

			(void)memset( (void *)sap[i], '\0', sizeof(struct sockaddr_in) );
			sap[i]->sa_family = AF_INET;
			((struct sockaddr_in *)sap[i])->sin_port = htons(port);
			AC_MEMCPY( &((struct sockaddr_in *)sap[i])->sin_addr,
				he ? (struct in_addr *)he->h_addr_list[i] : &in,
				sizeof(struct in_addr) );
		}
		sap[i] = NULL;
#endif /* ! HAVE_GETADDRINFO */
	}

	return 0;

errexit:
	slap_free_listener_addresses(*sal);
	return -1;
}

static int
slap_open_listener(
	const char* url,
	int *listeners,
	int *cur )
{
	int	num, tmp, rc;
	Listener l;
	Listener *li;
	LDAPURLDesc *lud;
	unsigned short port;
	int err, addrlen = 0;
	struct sockaddr **sal = NULL, **psal;
	int socktype = SOCK_STREAM;	/* default to COTS */
	ber_socket_t s;

#if defined(LDAP_PF_LOCAL) || defined(SLAP_X_LISTENER_MOD)
	/*
	 * use safe defaults
	 */
	int	crit = 1;
#endif /* LDAP_PF_LOCAL || SLAP_X_LISTENER_MOD */

	rc = ldap_url_parse( url, &lud );

	if( rc != LDAP_URL_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY,
			"daemon: listen URL \"%s\" parse error=%d\n",
			url, rc, 0 );
		return rc;
	}

	l.sl_url.bv_val = NULL;
	l.sl_mute = 0;
	l.sl_busy = 0;

#ifndef HAVE_TLS
	if( ldap_pvt_url_scheme2tls( lud->lud_scheme ) ) {
		Debug( LDAP_DEBUG_ANY, "daemon: TLS not supported (%s)\n",
			url, 0, 0 );
		ldap_free_urldesc( lud );
		return -1;
	}

	if(! lud->lud_port ) lud->lud_port = LDAP_PORT;

#else /* HAVE_TLS */
	l.sl_is_tls = ldap_pvt_url_scheme2tls( lud->lud_scheme );

	if(! lud->lud_port ) {
		lud->lud_port = l.sl_is_tls ? LDAPS_PORT : LDAP_PORT;
	}
#endif /* HAVE_TLS */

#ifdef LDAP_TCP_BUFFER
	l.sl_tcp_rmem = 0;
	l.sl_tcp_wmem = 0;
#endif /* LDAP_TCP_BUFFER */

	port = (unsigned short) lud->lud_port;

	tmp = ldap_pvt_url_scheme2proto(lud->lud_scheme);
	if ( tmp == LDAP_PROTO_IPC ) {
#ifdef LDAP_PF_LOCAL
		if ( lud->lud_host == NULL || lud->lud_host[0] == '\0' ) {
			err = slap_get_listener_addresses(LDAPI_SOCK, 0, &sal);
		} else {
			err = slap_get_listener_addresses(lud->lud_host, 0, &sal);
		}
#else /* ! LDAP_PF_LOCAL */

		Debug( LDAP_DEBUG_ANY, "daemon: URL scheme not supported: %s",
			url, 0, 0);
		ldap_free_urldesc( lud );
		return -1;
#endif /* ! LDAP_PF_LOCAL */
	} else {
		if( lud->lud_host == NULL || lud->lud_host[0] == '\0'
			|| strcmp(lud->lud_host, "*") == 0 )
		{
			err = slap_get_listener_addresses(NULL, port, &sal);
		} else {
			err = slap_get_listener_addresses(lud->lud_host, port, &sal);
		}
	}

#if defined(LDAP_PF_LOCAL) || defined(SLAP_X_LISTENER_MOD)
	if ( lud->lud_exts ) {
		err = get_url_perms( lud->lud_exts, &l.sl_perms, &crit );
	} else {
		l.sl_perms = S_IRWXU | S_IRWXO;
	}
#endif /* LDAP_PF_LOCAL || SLAP_X_LISTENER_MOD */

	ldap_free_urldesc( lud );
	if ( err ) {
		slap_free_listener_addresses(sal);
		return -1;
	}

	/* If we got more than one address returned, we need to make space
	 * for it in the slap_listeners array.
	 */
	for ( num=0; sal[num]; num++ ) /* empty */;
	if ( num > 1 ) {
		*listeners += num-1;
		slap_listeners = ch_realloc( slap_listeners,
			(*listeners + 1) * sizeof(Listener *) );
	}

	psal = sal;
	while ( *sal != NULL ) {
		char *af;
		switch( (*sal)->sa_family ) {
		case AF_INET:
			af = "IPv4";
			break;
#ifdef LDAP_PF_INET6
		case AF_INET6:
			af = "IPv6";
			break;
#endif /* LDAP_PF_INET6 */
#ifdef LDAP_PF_LOCAL
		case AF_LOCAL:
			af = "Local";
			break;
#endif /* LDAP_PF_LOCAL */
		default:
			sal++;
			continue;
		}

		s = socket( (*sal)->sa_family, socktype, 0);
		if ( s == AC_SOCKET_INVALID ) {
			int err = sock_errno();
			Debug( LDAP_DEBUG_ANY,
				"daemon: %s socket() failed errno=%d (%s)\n",
				af, err, sock_errstr(err) );
			sal++;
			continue;
		}
                ber_pvt_socket_set_nonblock( s, 1 );
		l.sl_sd = s;

#ifdef LDAP_PF_LOCAL
		if ( (*sal)->sa_family == AF_LOCAL ) {
			unlink( ((struct sockaddr_un *)*sal)->sun_path );
		} else
#endif /* LDAP_PF_LOCAL */
		{
#ifdef SO_REUSEADDR
			/* enable address reuse */
			tmp = 1;
			rc = setsockopt( s, SOL_SOCKET, SO_REUSEADDR,
				(char *) &tmp, sizeof(tmp) );
			if ( rc == AC_SOCKET_ERROR ) {
				int err = sock_errno();
				Debug( LDAP_DEBUG_ANY, "lloadd(%ld): "
					"setsockopt(SO_REUSEADDR) failed errno=%d (%s)\n",
					(long) l.sl_sd, err, sock_errstr(err) );
			}
#endif /* SO_REUSEADDR */
		}

		switch( (*sal)->sa_family ) {
		case AF_INET:
			addrlen = sizeof(struct sockaddr_in);
			break;
#ifdef LDAP_PF_INET6
		case AF_INET6:
#ifdef IPV6_V6ONLY
			/* Try to use IPv6 sockets for IPv6 only */
			tmp = 1;
			rc = setsockopt( s , IPPROTO_IPV6, IPV6_V6ONLY,
				(char *) &tmp, sizeof(tmp) );
			if ( rc == AC_SOCKET_ERROR ) {
				int err = sock_errno();
				Debug( LDAP_DEBUG_ANY, "lloadd(%ld): "
					"setsockopt(IPV6_V6ONLY) failed errno=%d (%s)\n",
					(long) l.sl_sd, err, sock_errstr(err) );
			}
#endif /* IPV6_V6ONLY */
			addrlen = sizeof(struct sockaddr_in6);
			break;
#endif /* LDAP_PF_INET6 */

#ifdef LDAP_PF_LOCAL
		case AF_LOCAL:
#ifdef LOCAL_CREDS
			{
				int one = 1;
				setsockopt( s, 0, LOCAL_CREDS, &one, sizeof( one ) );
			}
#endif /* LOCAL_CREDS */

			addrlen = sizeof( struct sockaddr_un );
			break;
#endif /* LDAP_PF_LOCAL */
		}

#ifdef LDAP_PF_LOCAL
		/* create socket with all permissions set for those systems
		 * that honor permissions on sockets (e.g. Linux); typically,
		 * only write is required.  To exploit filesystem permissions,
		 * place the socket in a directory and use directory's
		 * permissions.  Need write perms to the directory to
		 * create/unlink the socket; likely need exec perms to access
		 * the socket (ITS#4709) */
		{
			mode_t old_umask = 0;

			if ( (*sal)->sa_family == AF_LOCAL ) {
				old_umask = umask( 0 );
			}
#endif /* LDAP_PF_LOCAL */
			rc = bind( s, *sal, addrlen );
#ifdef LDAP_PF_LOCAL
			if ( old_umask != 0 ) {
				umask( old_umask );
			}
		}
#endif /* LDAP_PF_LOCAL */
		if ( rc ) {
			err = sock_errno();
			Debug( LDAP_DEBUG_ANY,
				"daemon: bind(%ld) failed errno=%d (%s)\n",
				(long)l.sl_sd, err, sock_errstr( err ) );
			tcp_close( s );
			sal++;
			continue;
		}

		switch ( (*sal)->sa_family ) {
#ifdef LDAP_PF_LOCAL
		case AF_LOCAL: {
			char *path = ((struct sockaddr_un *)*sal)->sun_path;
			l.sl_name.bv_len = strlen(path) + STRLENOF("PATH=");
			l.sl_name.bv_val = ber_memalloc( l.sl_name.bv_len + 1 );
			snprintf( l.sl_name.bv_val, l.sl_name.bv_len + 1,
				"PATH=%s", path );
		} break;
#endif /* LDAP_PF_LOCAL */

		case AF_INET: {
			char addr[INET_ADDRSTRLEN];
			const char *s;
#if defined( HAVE_GETADDRINFO ) && defined( HAVE_INET_NTOP )
			s = inet_ntop( AF_INET, &((struct sockaddr_in *)*sal)->sin_addr,
				addr, sizeof(addr) );
#else /* ! HAVE_GETADDRINFO || ! HAVE_INET_NTOP */
			s = inet_ntoa( ((struct sockaddr_in *) *sal)->sin_addr );
#endif /* ! HAVE_GETADDRINFO || ! HAVE_INET_NTOP */
			if (!s) s = SLAP_STRING_UNKNOWN;
			port = ntohs( ((struct sockaddr_in *)*sal) ->sin_port );
			l.sl_name.bv_val =
				ber_memalloc( sizeof("IP=255.255.255.255:65535") );
			snprintf( l.sl_name.bv_val, sizeof("IP=255.255.255.255:65535"),
				"IP=%s:%d", s, port );
			l.sl_name.bv_len = strlen( l.sl_name.bv_val );
		} break;

#ifdef LDAP_PF_INET6
		case AF_INET6: {
			char addr[INET6_ADDRSTRLEN];
			const char *s;
			s = inet_ntop( AF_INET6, &((struct sockaddr_in6 *)*sal)->sin6_addr,
				addr, sizeof addr);
			if (!s) s = SLAP_STRING_UNKNOWN;
			port = ntohs( ((struct sockaddr_in6 *)*sal)->sin6_port );
			l.sl_name.bv_len = strlen(s) + sizeof("IP=[]:65535");
			l.sl_name.bv_val = ber_memalloc( l.sl_name.bv_len );
			snprintf( l.sl_name.bv_val, l.sl_name.bv_len, "IP=[%s]:%d",
				s, port );
			l.sl_name.bv_len = strlen( l.sl_name.bv_val );
		} break;
#endif /* LDAP_PF_INET6 */

		default:
			Debug( LDAP_DEBUG_ANY, "daemon: unsupported address family (%d)\n",
				(int) (*sal)->sa_family, 0, 0 );
			break;
		}

		AC_MEMCPY(&l.sl_sa, *sal, addrlen);
		ber_str2bv( url, 0, 1, &l.sl_url);
		li = ch_malloc( sizeof( Listener ) );
		*li = l;
		slap_listeners[*cur] = li;
		(*cur)++;
		sal++;
	}

	slap_free_listener_addresses(psal);

	if ( l.sl_url.bv_val == NULL ) {
		Debug( LDAP_DEBUG_TRACE,
			"slap_open_listener: failed on %s\n", url, 0, 0 );
		return -1;
	}

	Debug( LDAP_DEBUG_TRACE, "daemon: listener initialized %s\n",
		l.sl_url.bv_val, 0, 0 );

	return 0;
}

static int daemon_inited = 0;

int
slapd_daemon_init( const char *urls )
{
	int i, j, n, rc;
	char **u;

	Debug( LDAP_DEBUG_ARGS, "daemon_init: %s\n",
		urls ? urls : "<null>", 0, 0 );

    ldap_pvt_thread_mutex_init( &operation_mutex );

#ifdef HAVE_TCPD
	ldap_pvt_thread_mutex_init( &sd_tcpd_mutex );
#endif /* TCP Wrappers */

	daemon_inited = 1;

	if( urls == NULL ) urls = "ldap:///";

	u = ldap_str2charray( urls, " " );

	if( u == NULL || u[0] == NULL ) {
		Debug( LDAP_DEBUG_ANY, "daemon_init: no urls (%s) provided.\n",
			urls, 0, 0 );
		if ( u )
			ldap_charray_free( u );
		return -1;
	}

	for( i=0; u[i] != NULL; i++ ) {
		Debug( LDAP_DEBUG_TRACE, "daemon_init: listen on %s\n",
			u[i], 0, 0 );
	}

	if( i == 0 ) {
		Debug( LDAP_DEBUG_ANY, "daemon_init: no listeners to open (%s)\n",
			urls, 0, 0 );
		ldap_charray_free( u );
		return -1;
	}

	Debug( LDAP_DEBUG_TRACE, "daemon_init: %d listeners to open...\n",
		i, 0, 0 );
	slap_listeners = ch_malloc( (i+1)*sizeof(Listener *) );

	for(n = 0, j = 0; u[n]; n++ ) {
		if ( slap_open_listener( u[n], &i, &j ) ) {
			ldap_charray_free( u );
			return -1;
		}
	}
	slap_listeners[j] = NULL;

	Debug( LDAP_DEBUG_TRACE, "daemon_init: %d listeners opened\n",
		i, 0, 0 );

	ldap_charray_free( u );

	return !i;
}


int
slapd_daemon_destroy( void )
{
	if ( daemon_inited ) {
		int i;

		for ( i=0; i<slapd_daemon_threads; i++ ) {
			ldap_pvt_thread_mutex_destroy( &slap_daemon[i].sd_mutex );
            if ( slap_daemon[i].base ) {
                event_base_free( slap_daemon[i].base );
            }
		}
		daemon_inited = 0;
#ifdef HAVE_TCPD
		ldap_pvt_thread_mutex_destroy( &sd_tcpd_mutex );
#endif /* TCP Wrappers */
	}

	return 0;
}


static void
close_listeners(
	int remove )
{
	int l;

	if ( !listening )
		return;
	listening = 0;

	for ( l = 0; slap_listeners[l] != NULL; l++ ) {
		Listener *lr = slap_listeners[l];

		if ( lr->sl_sd != AC_SOCKET_INVALID ) {
			int s = lr->sl_sd;
			lr->sl_sd = AC_SOCKET_INVALID;
			if ( remove ) slapd_remove( s, NULL, 0, 0, 0 );

#ifdef LDAP_PF_LOCAL
			if ( lr->sl_sa.sa_addr.sa_family == AF_LOCAL ) {
				unlink( lr->sl_sa.sa_un_addr.sun_path );
			}
#endif /* LDAP_PF_LOCAL */

			slapd_close( s );
		}
	}
}

static void
destroy_listeners( void )
{
	Listener *lr, **ll = slap_listeners;

	if ( ll == NULL )
		return;

    ldap_pvt_thread_join( listener_tid, (void *)NULL );

	while ( (lr = *ll++) != NULL ) {
		if ( lr->sl_url.bv_val ) {
			ber_memfree( lr->sl_url.bv_val );
		}

		if ( lr->sl_name.bv_val ) {
			ber_memfree( lr->sl_name.bv_val );
		}

		evconnlistener_free( lr->listener );

		free( lr );
	}

	free( slap_listeners );
	slap_listeners = NULL;

    if ( listener_base ) {
        event_base_free( listener_base );
    }
}

static void
slap_listener(
        struct evconnlistener *listener,
        ber_socket_t s,
        struct sockaddr *a,
        int len,
        void *arg )
{

    Listener *sl = arg;
    Connection *c;
    Sockaddr *from = (Sockaddr *)a;
#ifdef SLAPD_RLOOKUPS
    char hbuf[NI_MAXHOST];
#endif /* SLAPD_RLOOKUPS */

    const char *peeraddr = NULL;
    /* we assume INET6_ADDRSTRLEN > INET_ADDRSTRLEN */
    char addr[INET6_ADDRSTRLEN];
#ifdef LDAP_PF_LOCAL
    char peername[MAXPATHLEN + sizeof("PATH=")];
#ifdef LDAP_PF_LOCAL_SENDMSG
    char peerbuf[8];
    struct berval peerbv = BER_BVNULL;
#endif
#elif defined(LDAP_PF_INET6)
    char peername[sizeof("IP=[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535")];
#else /* ! LDAP_PF_LOCAL && ! LDAP_PF_INET6 */
    char peername[sizeof("IP=255.255.255.255:65336")];
#endif /* LDAP_PF_LOCAL */
    int cflag;
    int tid;

    Debug( LDAP_DEBUG_TRACE,
            ">>> slap_listener(%s)\n",
            sl->sl_url.bv_val, 0, 0 );

    peername[0] = '\0';

    /* Resume the listener FD to allow concurrent-processing of
     * additional incoming connections.
     */
    sl->sl_busy = 0;

    tid = DAEMON_ID(s);

#if defined( SO_KEEPALIVE ) || defined( TCP_NODELAY )
#ifdef LDAP_PF_LOCAL
    /* for IPv4 and IPv6 sockets only */
    if ( from->sa_addr.sa_family != AF_LOCAL )
#endif /* LDAP_PF_LOCAL */
    {
        int rc;
        int tmp;
#ifdef SO_KEEPALIVE
        /* enable keep alives */
        tmp = 1;
        rc = setsockopt( s, SOL_SOCKET, SO_KEEPALIVE,
                (char *) &tmp, sizeof(tmp) );
        if ( rc == AC_SOCKET_ERROR ) {
            int err = sock_errno();
            Debug( LDAP_DEBUG_ANY,
                    "lloadd(%ld): setsockopt(SO_KEEPALIVE) failed "
                    "errno=%d (%s)\n", (long) s, err, sock_errstr(err) );
        }
#endif /* SO_KEEPALIVE */
#ifdef TCP_NODELAY
        /* enable no delay */
        tmp = 1;
        rc = setsockopt( s, IPPROTO_TCP, TCP_NODELAY,
                (char *)&tmp, sizeof(tmp) );
        if ( rc == AC_SOCKET_ERROR ) {
            int err = sock_errno();
            Debug( LDAP_DEBUG_ANY,
                    "lloadd(%ld): setsockopt(TCP_NODELAY) failed "
                    "errno=%d (%s)\n", (long) s, err, sock_errstr(err) );
        }
#endif /* TCP_NODELAY */
    }
#endif /* SO_KEEPALIVE || TCP_NODELAY */

    Debug( LDAP_DEBUG_CONNS,
            "daemon: listen=%ld, new connection on %ld\n",
            (long) sl->sl_sd, (long) s, 0 );

    cflag = 0;
    switch ( from->sa_addr.sa_family ) {
#  ifdef LDAP_PF_LOCAL
        case AF_LOCAL:
            cflag |= CONN_IS_IPC;

            /* FIXME: apparently accept doesn't fill the sun_path member */
            sprintf( peername, "PATH=%s", sl->sl_sa.sa_un_addr.sun_path );
            break;
#endif /* LDAP_PF_LOCAL */

#  ifdef LDAP_PF_INET6
        case AF_INET6:
            if ( IN6_IS_ADDR_V4MAPPED(&from->sa_in6_addr.sin6_addr) ) {
#if defined( HAVE_GETADDRINFO ) && defined( HAVE_INET_NTOP )
                peeraddr = inet_ntop( AF_INET,
                        ((struct in_addr *)&from->sa_in6_addr.sin6_addr.s6_addr[12]),
                        addr, sizeof(addr) );
#else /* ! HAVE_GETADDRINFO || ! HAVE_INET_NTOP */
                peeraddr = inet_ntoa( *((struct in_addr *)
                            &from->sa_in6_addr.sin6_addr.s6_addr[12]) );
#endif /* ! HAVE_GETADDRINFO || ! HAVE_INET_NTOP */
                if ( !peeraddr ) peeraddr = SLAP_STRING_UNKNOWN;
                sprintf( peername, "IP=%s:%d", peeraddr,
                        (unsigned) ntohs( from->sa_in6_addr.sin6_port ) );
            } else {
                peeraddr = inet_ntop( AF_INET6,
                        &from->sa_in6_addr.sin6_addr,
                        addr, sizeof addr );
                if ( !peeraddr ) peeraddr = SLAP_STRING_UNKNOWN;
                sprintf( peername, "IP=[%s]:%d", peeraddr,
                        (unsigned) ntohs( from->sa_in6_addr.sin6_port ) );
            }
            break;
#  endif /* LDAP_PF_INET6 */

        case AF_INET: {
#if defined( HAVE_GETADDRINFO ) && defined( HAVE_INET_NTOP )
                          peeraddr = inet_ntop( AF_INET, &from->sa_in_addr.sin_addr,
                                  addr, sizeof(addr) );
#else /* ! HAVE_GETADDRINFO || ! HAVE_INET_NTOP */
                          peeraddr = inet_ntoa( from->sa_in_addr.sin_addr );
#endif /* ! HAVE_GETADDRINFO || ! HAVE_INET_NTOP */
                          if ( !peeraddr ) peeraddr = SLAP_STRING_UNKNOWN;
                          sprintf( peername, "IP=%s:%d", peeraddr,
                                  (unsigned) ntohs( from->sa_in_addr.sin_port ) );
                      } break;

        default:
		slapd_close(s);
		return;
	}

#ifdef HAVE_TLS
	if ( sl->sl_is_tls ) cflag |= CONN_IS_TLS;
#endif
	c = client_init( s, sl, peername, slap_daemon[tid].base, cflag );

	if ( !c ) {
		Debug( LDAP_DEBUG_ANY,
			"daemon: connection_init(%ld, %s, %s) failed.\n",
			(long) s, peername, sl->sl_name.bv_val );
		slapd_close(s);
	}

	return;
}

static void*
slap_listener_thread(
	void* ctx )
{
    int rc = event_base_dispatch( listener_base );
    Debug( LDAP_DEBUG_ANY, "Listener event loop finished: rc=%d\n", rc, 0, 0 );

    return (void*)NULL;
}

static void
listener_error_cb(
        struct evconnlistener *lev,
        void *arg )
{
    Listener *l = arg;
    int err = EVUTIL_SOCKET_ERROR();

    assert( l->listener == lev );
    if(
#ifdef EMFILE
        err == EMFILE ||
#endif /* EMFILE */
#ifdef ENFILE
        err == ENFILE ||
#endif /* ENFILE */
        0 )
    {
        ldap_pvt_thread_mutex_lock( &slap_daemon[0].sd_mutex );
        emfile++;
        /* Stop listening until an existing session closes */
        l->sl_mute = 1;
        evconnlistener_disable( lev );
        ldap_pvt_thread_mutex_unlock( &slap_daemon[0].sd_mutex );
    } else {
        Debug( LDAP_DEBUG_ANY, "listener_error_cb: "
				"received an error on a listener, shutting down: '%s'\n",
				sock_errstr(err), 0, 0 );
        event_base_loopexit( l->base, NULL );
    }
}

static int
slap_listener_activate( void )
{
    struct evconnlistener *listener;
    int l, rc;

    listener_base = event_base_new();
    if ( !listener_base )
        return -1;

    for ( l = 0; slap_listeners[l] != NULL; l++ ) {
        if ( slap_listeners[l]->sl_sd == AC_SOCKET_INVALID ) continue;

        /* FIXME: TCP-only! */
#ifdef LDAP_TCP_BUFFER
        if ( 1 ) {
            int origsize, size, realsize, rc;
            socklen_t optlen;
            char buf[ SLAP_TEXT_BUFLEN ];

            size = 0;
            if ( slap_listeners[l]->sl_tcp_rmem > 0 ) {
                size = slap_listeners[l]->sl_tcp_rmem;
            } else if ( slapd_tcp_rmem > 0 ) {
                size = slapd_tcp_rmem;
            }

            if ( size > 0 ) {
                optlen = sizeof( origsize );
                rc = getsockopt( slap_listeners[l]->sl_sd,
                        SOL_SOCKET,
                        SO_RCVBUF,
                        (void *)&origsize,
                        &optlen );

                if ( rc ) {
                    int err = sock_errno();
                    Debug( LDAP_DEBUG_ANY,
                            "slap_listener_activate: getsockopt(SO_RCVBUF) failed errno=%d (%s)\n",
                            err, STRERROR(err), 0 );
                }

                optlen = sizeof( size );
                rc = setsockopt( slap_listeners[l]->sl_sd,
                        SOL_SOCKET,
                        SO_RCVBUF,
                        (const void *)&size,
                        optlen );

                if ( rc ) {
                    int err = sock_errno();
                    Debug( LDAP_DEBUG_ANY,
                            "slapd_listener_activate: setsockopt(SO_RCVBUF) failed errno=%d (%s)\n",
                            err, sock_errstr(err), 0 );
                }

                optlen = sizeof( realsize );
                rc = getsockopt( slap_listeners[l]->sl_sd,
                        SOL_SOCKET,
                        SO_RCVBUF,
                        (void *)&realsize,
                        &optlen );

                if ( rc ) {
                    int err = sock_errno();
                    Debug( LDAP_DEBUG_ANY,
                            "slapd_listener_activate: getsockopt(SO_RCVBUF) failed errno=%d (%s)\n",
                            err, sock_errstr(err), 0 );
                }

                snprintf( buf, sizeof( buf ),
                        "url=%s (#%d) RCVBUF original size=%d requested size=%d real size=%d",
                        slap_listeners[l]->sl_url.bv_val, l, origsize, size, realsize );
                Debug( LDAP_DEBUG_ANY,
                        "slapd_listener_activate: %s\n",
                        buf, 0, 0 );
            }

            size = 0;
            if ( slap_listeners[l]->sl_tcp_wmem > 0 ) {
                size = slap_listeners[l]->sl_tcp_wmem;
            } else if ( slapd_tcp_wmem > 0 ) {
                size = slapd_tcp_wmem;
            }

            if ( size > 0 ) {
                optlen = sizeof( origsize );
                rc = getsockopt( slap_listeners[l]->sl_sd,
                        SOL_SOCKET,
                        SO_SNDBUF,
                        (void *)&origsize,
                        &optlen );

                if ( rc ) {
                    int err = sock_errno();
                    Debug( LDAP_DEBUG_ANY,
                            "slapd_listener_activate: getsockopt(SO_SNDBUF) failed errno=%d (%s)\n",
                            err, sock_errstr(err), 0 );
                }

                optlen = sizeof( size );
                rc = setsockopt( slap_listeners[l]->sl_sd,
                        SOL_SOCKET,
                        SO_SNDBUF,
                        (const void *)&size,
                        optlen );

                if ( rc ) {
                    int err = sock_errno();
                    Debug( LDAP_DEBUG_ANY,
                            "slapd_listener_activate: setsockopt(SO_SNDBUF) failed errno=%d (%s)",
                            err, sock_errstr(err), 0 );
                }

                optlen = sizeof( realsize );
                rc = getsockopt( slap_listeners[l]->sl_sd,
                        SOL_SOCKET,
                        SO_SNDBUF,
                        (void *)&realsize,
                        &optlen );

                if ( rc ) {
                    int err = sock_errno();
                    Debug( LDAP_DEBUG_ANY,
                            "slapd_listener_activate: getsockopt(SO_SNDBUF) failed errno=%d (%s)\n",
                            err, sock_errstr(err), 0 );
                }

                snprintf( buf, sizeof( buf ),
                        "url=%s (#%d) SNDBUF original size=%d requested size=%d real size=%d",
                        slap_listeners[l]->sl_url.bv_val, l, origsize, size, realsize );
                Debug( LDAP_DEBUG_ANY,
                        "slapd_listener_activate: %s\n",
                        buf, 0, 0 );
            }
        }
#endif /* LDAP_TCP_BUFFER */

        slap_listeners[l]->sl_busy = 1;
        listener = evconnlistener_new( listener_base,
                slap_listener, slap_listeners[l], LEV_OPT_THREADSAFE,
                SLAPD_LISTEN_BACKLOG, slap_listeners[l]->sl_sd );
        if ( !listener ) {
            int err = sock_errno();

#ifdef LDAP_PF_INET6
            /* If error is EADDRINUSE, we are trying to listen to INADDR_ANY and
             * we are already listening to in6addr_any, then we want to ignore
             * this and continue.
             */
            if ( err == EADDRINUSE ) {
                int i;
                struct sockaddr_in sa = slap_listeners[l]->sl_sa.sa_in_addr;
                struct sockaddr_in6 sa6;

                if ( sa.sin_family == AF_INET &&
                        sa.sin_addr.s_addr == htonl(INADDR_ANY) ) {
                    for ( i = 0 ; i < l; i++ ) {
                        sa6 = slap_listeners[i]->sl_sa.sa_in6_addr;
                        if ( sa6.sin6_family == AF_INET6 &&
                                !memcmp( &sa6.sin6_addr, &in6addr_any,
                                    sizeof(struct in6_addr) ) )
                        {
                            break;
                        }
                    }

                    if ( i < l ) {
                        /* We are already listening to in6addr_any */
                        Debug( LDAP_DEBUG_CONNS,
                                "daemon: Attempt to listen to 0.0.0.0 failed, "
                                "already listening on ::, assuming IPv4 included\n",
                                0, 0, 0 );
                        slapd_close( slap_listeners[l]->sl_sd );
                        slap_listeners[l]->sl_sd = AC_SOCKET_INVALID;
                        continue;
                    }
                }
            }
#endif /* LDAP_PF_INET6 */
            Debug( LDAP_DEBUG_ANY,
                    "daemon: listen(%s, 5) failed errno=%d (%s)\n",
                    slap_listeners[l]->sl_url.bv_val, err,
                    sock_errstr(err) );
            return -1;
        }

        slap_listeners[l]->base = listener_base;
        slap_listeners[l]->listener = listener;
        evconnlistener_set_error_cb( listener, listener_error_cb );
    }


    rc = ldap_pvt_thread_create( &listener_tid, 0,
            slap_listener_thread, slap_listeners[l] );

    if( rc != 0 ) {
        Debug( LDAP_DEBUG_ANY,
                "slap_listener_activate(%d): submit failed (%d)\n",
                slap_listeners[l]->sl_sd, rc, 0 );
    }
    return rc;
}

static void *
slapd_daemon_task(
	void *ptr )
{
    int rc;
    time_t last_idle_check = 0;
    int ebadf = 0;
    int tid = (ldap_pvt_thread_t *) ptr - daemon_tid;
    struct event_base *base = slap_daemon[tid].base;
    struct event *event;

    event = event_new( base, -1, EV_WRITE, daemon_wakeup_cb, ptr );
    if (!event) {
        Debug(LDAP_DEBUG_ANY, "slapd_daemon_task: failed to set up the wakeup event\n", 0, 0, 0 );
        return (void *)-1;
    }
    event_add( event, NULL );
    slap_daemon[tid].wakeup_event = event;


    /* run */
    rc = event_base_dispatch( base );
    Debug( LDAP_DEBUG_ANY, "Daemon %d, event loop finished: rc=%d\n", tid, rc, 0 );

    if ( !slapd_gentle_shutdown ) {
        slapd_abrupt_shutdown = 1;
    }

    return NULL;
}


int
slapd_daemon( struct event_base *daemon_base )
{
    int i, rc;
    Backend *b;
    struct event_base *base;

    assert( daemon_base != NULL );

    dnsbase = evdns_base_new( daemon_base,
            EVDNS_BASE_INITIALIZE_NAMESERVERS | \
            EVDNS_BASE_DISABLE_WHEN_INACTIVE );
    if ( !dnsbase ) {
        Debug( LDAP_DEBUG_ANY, "daemon: failed to set up for async name resolution\n", 0, 0, 0 );
        return -1;
    }

    if ( slapd_daemon_threads > SLAPD_MAX_DAEMON_THREADS )
        slapd_daemon_threads = SLAPD_MAX_DAEMON_THREADS;

    daemon_tid = ch_malloc(slapd_daemon_threads * sizeof(ldap_pvt_thread_t));

    for ( i=0; i<slapd_daemon_threads; i++ )
    {
        base = event_base_new();
        if (!base) {
            Debug(LDAP_DEBUG_ANY, "daemon: failed to acquire event base for an I/O thread\n", 0, 0, 0 );
            return -1;
        }
        slap_daemon[i].base = base;

        ldap_pvt_thread_mutex_init( &slap_daemon[i].sd_mutex );
        /* threads that handle client and upstream sockets */
        rc = ldap_pvt_thread_create( &daemon_tid[i],
                0, slapd_daemon_task, &daemon_tid[i] );

        if ( rc != 0 ) {
            Debug( LDAP_DEBUG_ANY,
                    "listener ldap_pvt_thread_create failed (%d)\n", rc, 0, 0 );
            return rc;
        }
    }

    if ( (rc = slap_listener_activate()) != 0) {
        return rc;
    }

    current_backend = LDAP_CIRCLEQ_FIRST( &backend );
    LDAP_CIRCLEQ_FOREACH( b, &backend, b_next ) {
        struct event *retry_event = evtimer_new( daemon_base, backend_connect, b );

        if ( !retry_event ) {
            Debug( LDAP_DEBUG_ANY, "failed to allocate retry event\n", 0, 0, 0 );
            return -1;
        }
        b->b_retry_event = retry_event;
        b->b_opening++;

        rc = ldap_pvt_thread_pool_submit( &connection_pool, backend_connect_task, b );
        if ( rc ) {
            Debug( LDAP_DEBUG_ANY,
                    "failed to schedule backend connection task (%d)\n",
                    rc, 0, 0 );
            return rc;
        }
    }

    rc = event_base_dispatch( daemon_base );
    Debug( LDAP_DEBUG_ANY, "Main event loop finished: rc=%d\n", rc, 0, 0 );

    /* shutdown */
    event_base_loopexit( listener_base, 0 );
    close_listeners( 0 );

    /* wait for the listener threads to complete */
    destroy_listeners();

    for ( i=0; i<slapd_daemon_threads; i++ )
        ldap_pvt_thread_join( daemon_tid[i], (void *)NULL );

    if ( LogTest( LDAP_DEBUG_ANY )) {
        int t = ldap_pvt_thread_pool_backload( &connection_pool );
        Debug( LDAP_DEBUG_ANY,
                "slapd shutdown: waiting for %d operations/tasks to finish\n",
                t, 0, 0 );
    }
    ldap_pvt_thread_pool_destroy( &connection_pool, 1 );
    backends_destroy();
    evdns_base_free( dnsbase, 0 );

    ch_free( daemon_tid );
    daemon_tid = NULL;

    slapd_daemon_destroy();

    return 0;
}

static void
daemon_wakeup_cb( evutil_socket_t sig, short what, void *arg )
{
    int tid = (ldap_pvt_thread_t *) arg - daemon_tid;

    Debug( LDAP_DEBUG_TRACE, "Daemon thread %d woken up\n", tid, 0, 0 );
    if ( slapd_shutdown ) {
        event_base_loopexit( slap_daemon[tid].base, NULL );
    }
}

void
slap_sig_shutdown( evutil_socket_t sig, short what, void *arg )
{
    struct event_base *daemon_base = arg;
	int save_errno = errno;
	int i;

#if 0
	Debug(LDAP_DEBUG_TRACE, "slap_sig_shutdown: signal %d\n", sig, 0, 0);
#endif

	/*
	 * If the NT Service Manager is controlling the server, we don't
	 * want SIGBREAK to kill the server. For some strange reason,
	 * SIGBREAK is generated when a user logs out.
	 */

#if defined(HAVE_NT_SERVICE_MANAGER) && defined(SIGBREAK)
	if (is_NT_Service && sig == SIGBREAK) {
		/* empty */;
	} else
#endif /* HAVE_NT_SERVICE_MANAGER && SIGBREAK */
#ifdef SIGHUP
	if (sig == SIGHUP && global_gentlehup && slapd_gentle_shutdown == 0) {
		slapd_gentle_shutdown = 1;
	} else
#endif /* SIGHUP */
	{
		slapd_shutdown = 1;
	}

	for (i=0; i<slapd_daemon_threads; i++) {
		WAKE_DAEMON(i,1);
	}
    event_base_loopexit( daemon_base, NULL );

	errno = save_errno;
}


struct event_base *
slap_get_base( ber_socket_t s )
{
    int tid = DAEMON_ID(s);
    return slap_daemon[tid].base;
}

Listener **
slapd_get_listeners( void )
{
	/* Could return array with no listeners if !listening, but current
	 * callers mostly look at the URLs.  E.g. syncrepl uses this to
	 * identify the server, which means it wants the startup arguments.
	 */
	return slap_listeners;
}

/* Reject all incoming requests */
void
slap_suspend_listeners( void )
{
	int i;
	for (i=0; slap_listeners[i]; i++) {
		slap_listeners[i]->sl_mute = 1;
        evconnlistener_disable( slap_listeners[i]->listener );
		listen( slap_listeners[i]->sl_sd, 0 );
	}
}

/* Resume after a suspend */
void
slap_resume_listeners( void )
{
	int i;
	for (i=0; slap_listeners[i]; i++) {
		slap_listeners[i]->sl_mute = 0;
		listen( slap_listeners[i]->sl_sd, SLAPD_LISTEN_BACKLOG );
        evconnlistener_enable( slap_listeners[i]->listener );
	}
}
