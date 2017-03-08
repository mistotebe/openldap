/* config.h - configuration abstraction structure */
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

#ifndef CONFIG_H
#define CONFIG_H

#include<ac/string.h>

LDAP_BEGIN_DECL

typedef struct ConfigTable {
	const char *name;
	const char *what;
	int min_args;
	int max_args;
	int length;
	unsigned int arg_type;
	void *arg_item;
} ConfigTable;

/* search entries are returned according to this order */
typedef enum {
	Cft_Abstract = 0,
	Cft_Global,
	Cft_Module,
	Cft_Schema,
	Cft_Backend,
	Cft_Database,
	Cft_Overlay,
	Cft_Misc	/* backend/overlay defined */
} ConfigType;

#define ARGS_USERLAND	0x00000fff

/* types are enumerated, not a bitmask */
#define ARGS_TYPES	0x0000f000
#define ARG_INT		0x00001000
#define ARG_LONG	0x00002000
#define ARG_BER_LEN_T	0x00003000
#define ARG_ON_OFF	0x00004000
#define ARG_STRING	0x00005000
#define ARG_BERVAL	0x00006000
#define ARG_UINT	0x00008000
#define ARG_ULONG	0x0000a000

#define ARGS_SYNTAX	0xffff0000
#define ARG_IGNORED	0x00080000
#define ARG_PAREN	0x01000000
#define ARG_NONZERO	0x02000000
#define	ARG_NO_INSERT	0x04000000	/* no arbitrary inserting */
#define	ARG_NO_DELETE	0x08000000	/* no runtime deletes */
#define ARG_UNIQUE	0x10000000
#define	ARG_QUOTE	0x20000000	/* wrap with quotes before parsing */
#define ARG_OFFSET	0x40000000
#define ARG_MAGIC	0x80000000

#define ARG_BAD_CONF	0xdead0000	/* overload return values */

struct config_args_s;

typedef int (ConfigDriver)(struct config_args_s *c);

struct config_reply_s {
	int err;
	char msg[SLAP_TEXT_BUFLEN];
};

typedef struct config_args_s {
	int argc;
	char **argv;
	int argv_size;
	char *line;
	char *tline;
	const char *fname;
	int lineno;
	char log[MAXPATHLEN + STRLENOF(": line ") + LDAP_PVT_INTTYPE_CHARS(unsigned long)];
#define cr_msg reply.msg
	ConfigReply reply;
	int depth;
	int valx;	/* multi-valued value index */
	/* parsed first val for simple cases */
	union {
		int v_int;
		unsigned v_uint;
		long v_long;
		size_t v_ulong;
		ber_len_t v_ber_t;
		char *v_string;
		struct berval v_bv;
	} values;
	/* return values for emit mode */
	BerVarray rvalue_vals;
	BerVarray rvalue_nvals;
#define	SLAP_CONFIG_EMIT	0x2000	/* emit instead of set */
#define SLAP_CONFIG_ADD		0x4000	/* config file add vs LDAP add */
	int op;
	int type;	/* ConfigTable.arg_type & ARGS_USERLAND */
	void *ca_private;	/* anything */
	ConfigDriver *cleanup;
	ConfigType table;	/* which config table did we come from */
} ConfigArgs;

#define value_int values.v_int
#define value_uint values.v_uint
#define value_long values.v_long
#define value_ulong values.v_ulong
#define value_ber_t values.v_ber_t
#define value_string values.v_string
#define value_bv values.v_bv

int config_fp_parse_line(ConfigArgs *c);

int config_del_vals(ConfigTable *cf, ConfigArgs *c);
int config_get_vals(ConfigTable *ct, ConfigArgs *c);
int config_add_vals(ConfigTable *ct, ConfigArgs *c);

void init_config_argv( ConfigArgs *c );
int init_config_attrs(ConfigTable *ct);
void config_parse_ldif( ConfigArgs *c );
int config_parse_vals(ConfigTable *ct, ConfigArgs *c, int valx);
int config_parse_add(ConfigTable *ct, ConfigArgs *c, int valx);
int read_config_file(const char *fname, int depth, ConfigArgs *cf,
	ConfigTable *cft );

ConfigTable * config_find_keyword(ConfigTable *ct, ConfigArgs *c);

Listener *config_check_my_url(const char *url, LDAPURLDesc *lud);
int config_shadow( ConfigArgs *c, slap_mask_t flag );
#define	config_slurp_shadow(c)	config_shadow((c), SLAP_DBFLAG_SLURP_SHADOW)
#define	config_sync_shadow(c)	config_shadow((c), SLAP_DBFLAG_SYNC_SHADOW)

	/* Make sure we don't exceed the bits reserved for userland */
#define	config_check_userland(last) \
	assert( ( ( (last) - 1 ) & ARGS_USERLAND ) == ( (last) - 1 ) );

LDAP_SLAPD_V (slap_verbmasks *) slap_ldap_response_code;
extern int slap_ldap_response_code_register( struct berval *bv, int err );

LDAP_SLAPD_V (ConfigTable) olcDatabaseDummy[];

LDAP_END_DECL

#endif /* CONFIG_H */
