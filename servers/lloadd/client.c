/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2017 The OpenLDAP Foundation.
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

#include "portable.h"

#include <ac/socket.h>
#include <ac/errno.h>
#include <ac/string.h>
#include <ac/time.h>
#include <ac/unistd.h>

#include "lutil.h"
#include "slap.h"

static void client_destroy( Connection *c );

static void
client_read_cb( evutil_socket_t s, short what, void *arg )
{
    Connection *c = arg;

    ldap_pvt_thread_mutex_lock( &c->c_mutex );
    Debug( LDAP_DEBUG_CONNS, "client_read_cb: connection %lu ready to read\n", c->c_connid, 0, 0 );
    client_destroy( c );
}

void
client_write_cb( evutil_socket_t s, short what, void *arg )
{
    Connection *c = arg;

    ldap_pvt_thread_mutex_lock( &c->c_write_mutex );
    Debug( LDAP_DEBUG_CONNS, "client_write_cb: have something to write to client %lu\n", c->c_connid, 0, 0 );

    if ( ber_flush( c->c_sb, c->c_pendingber, 1 ) ) {
        int err = sock_errno();
        if ( err != EWOULDBLOCK && err != EAGAIN ) {
            ldap_pvt_thread_mutex_lock( &c->c_mutex );
            ldap_pvt_thread_mutex_unlock( &c->c_write_mutex );
            client_destroy( c );
            return;
        }
        event_add( c->c_write_event, NULL );
    }
    c->c_pendingber = NULL;
    ldap_pvt_thread_mutex_unlock( &c->c_write_mutex );
}

Connection *
client_init(
    ber_socket_t s,
    Listener *listener,
    const char* peername,
    struct event_base *base,
    int flags )
{
    Connection *c;
    struct event *event;

    assert( listener != NULL );

    c = connection_init( s, peername, flags );

    event = event_new( base, s, EV_READ|EV_PERSIST, client_read_cb, c );
    if ( !event ) {
        Debug( LDAP_DEBUG_ANY, "Read event could not be allocated\n", 0, 0, 0 );
        goto fail;
    }
    event_add( event, NULL );
    c->c_read_event = event;

    event = event_new( base, s, EV_WRITE, client_write_cb, c );
    if ( !event ) {
        Debug( LDAP_DEBUG_ANY, "Write event could not be allocated\n", 0, 0, 0 );
        goto fail;
    }
    /* We only register the write event when we have data pending */
    c->c_write_event = event;

    c->c_private = listener;
    ldap_pvt_thread_mutex_unlock( &c->c_mutex );

    return c;
fail:
    if ( c->c_write_event ) {
        event_del( c->c_write_event );
        event_free( c->c_write_event );
    }
    if ( c->c_read_event ) {
        event_del( c->c_read_event );
        event_free( c->c_read_event );
    }
    c->c_struct_state = SLAP_C_UNINITIALIZED;
    connection_destroy( c );
    return NULL;
}

static void
client_destroy( Connection *c )
{
    event_del( c->c_read_event );
    event_free( c->c_read_event );

    event_del( c->c_write_event );
    event_free( c->c_write_event );

    c->c_struct_state = SLAP_C_UNINITIALIZED;
    connection_destroy( c );
}
