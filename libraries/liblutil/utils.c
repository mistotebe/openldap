/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <ac/stdlib.h>
#include <ac/string.h>

#include <lber.h>
#include <lutil.h>
#include <ldap_defaults.h>

char* lutil_progname( const char* name, int argc, char *argv[] )
{
	char *progname;

	if(argc == 0) {
		return ber_strdup( name );
	}

	progname = strrchr ( argv[0], *LDAP_DIRSEP );
	progname = ber_strdup( progname ? &progname[1] : argv[0] );

	return progname;
}

#ifndef HAVE_MKSTEMP
int mkstemp( char * template )
{
	return -1;
}
#endif