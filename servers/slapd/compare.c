/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*
 * Copyright (c) 1995 Regents of the University of Michigan.
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

#include <ac/socket.h>

#include "slap.h"

int
do_compare(
    Connection	*conn,
    Operation	*op
)
{
	char	*ndn;
	Ava	ava;
	Backend	*be;
	int rc = LDAP_SUCCESS;

	Debug( LDAP_DEBUG_TRACE, "do_compare\n", 0, 0, 0 );

	if( op->o_bind_in_progress ) {
		Debug( LDAP_DEBUG_ANY, "do_compare: SASL bind in progress.\n",
			0, 0, 0 );
		send_ldap_result( conn, op, LDAP_SASL_BIND_IN_PROGRESS,
			NULL, "SASL bind in progress", NULL, NULL );
		return LDAP_SASL_BIND_IN_PROGRESS;
	}

	/*
	 * Parse the compare request.  It looks like this:
	 *
	 *	CompareRequest := [APPLICATION 14] SEQUENCE {
	 *		entry	DistinguishedName,
	 *		ava	SEQUENCE {
	 *			type	AttributeType,
	 *			value	AttributeValue
	 *		}
	 *	}
	 */

	if ( ber_scanf( op->o_ber, "{a{ao}}", &ndn, &ava.ava_type,
	    &ava.ava_value ) == LBER_ERROR ) {
		Debug( LDAP_DEBUG_ANY, "ber_scanf failed\n", 0, 0, 0 );
		send_ldap_disconnect( conn, op,
			LDAP_PROTOCOL_ERROR, "decoding error" );
		return -1;
	}

	if( dn_normalize_case( ndn ) == NULL ) {
		Debug( LDAP_DEBUG_ANY, "do_compare: invalid dn (%s)\n", ndn, 0, 0 );
		send_ldap_result( conn, op, rc = LDAP_INVALID_DN_SYNTAX, NULL,
		    "invalid DN", NULL, NULL );
		free( ndn );
		ava_free( &ava, 0 );
		return rc;
	}

	if( ( rc = get_ctrls( conn, op, 1 )) != LDAP_SUCCESS ) {
		free( ndn );
		ava_free( &ava, 0 );
		Debug( LDAP_DEBUG_ANY, "do_compare: get_ctrls failed\n", 0, 0, 0 );
		return rc;
	} 

	value_normalize( ava.ava_value.bv_val, attr_syntax( ava.ava_type ) );

	Debug( LDAP_DEBUG_ARGS, "do_compare: dn (%s) attr (%s) value (%s)\n",
	    ndn, ava.ava_type, ava.ava_value.bv_val );

	Statslog( LDAP_DEBUG_STATS, "conn=%ld op=%d CMP dn=\"%s\" attr=\"%s\"\n",
	    op->o_connid, op->o_opid, ndn, ava.ava_type, 0 );

	/*
	 * We could be serving multiple database backends.  Select the
	 * appropriate one, or send a referral to our "referral server"
	 * if we don't hold it.
	 */
	if ( (be = select_backend( ndn )) == NULL ) {
		free( ndn );
		ava_free( &ava, 0 );

		send_ldap_result( conn, op, rc = LDAP_REFERRAL,
			NULL, NULL, default_referral, NULL );
		return 1;
	}

	/* deref suffix alias if appropriate */
	ndn = suffix_alias( be, ndn );

	if ( be->be_compare ) {
		(*be->be_compare)( be, conn, op, ndn, &ava );
	} else {
		send_ldap_result( conn, op, rc = LDAP_UNWILLING_TO_PERFORM,
			NULL, "Function not implemented", NULL, NULL );
	}

	free( ndn );
	ava_free( &ava, 0 );

	return rc;
}
