/*
 * mod_mono.c
 * 
 * Authors:
 * 	Daniel Lopez Ridruejo
 * 	Gonzalo Paniagua Javier
 *      Marek Habersack
 *
 * Copyright (c) 2002 Daniel Lopez Ridruejo
 *           (c) 2002-2006 Novell, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifdef HAVE_CONFIG_H
#include "mod_mono_config.h"
#endif

/* uncomment this to get tons of messages in the log */
/* or use --enable-debug with configure */
/* #define DEBUG */
#ifndef DEBUG_LEVEL
#define DEBUG_LEVEL 0
#endif

#include "mod_mono.h"

DEFINE_MODULE (mono_module);

/* Configuration pool. Cleared on restart. */
static apr_pool_t *pconf;

typedef struct per_dir_config {
	char *location;
	char *alias;
} per_dir_config;

enum {
	FORK_NONE,
	FORK_INPROCESS,
	FORK_ATTEMPTED,
	FORK_FAILED,
	FORK_SUCCEEDED
};

typedef enum {
	AUTORESTART_MODE_INVALID,
	AUTORESTART_MODE_NONE,
	AUTORESTART_MODE_TIME,
	AUTORESTART_MODE_REQUESTS,
} auto_restart_mode;

typedef struct {
	uint32_t handled_requests;
	time_t start_time;
	char restart_issued;
} dashboard_data;

typedef struct xsp_data {
	char is_default;
	char *alias;
	char *filename;
	char *umask_value;
	char *run_xsp;
	char *executable_path;
	char *path;
	char *server_path;
	char *applications;
	char *wapidir;
	char *document_root;
	char *appconfig_file;
	char *appconfig_dir;
	char *listen_port;
	char *listen_address;
	char *max_cpu_time;
	char *max_memory;
	char *debug;
	char *flushOnWrite;
	char *env_vars;
	char status; /* One of the FORK_* in the enum above.
		      * Don't care if run_xsp is "false" */
	char is_virtual; /* is the server virtual? */
	char *start_attempts;
	char *start_wait_time;

	/* auto-restart stuff */
	auto_restart_mode restart_mode;
	uint32_t restart_requests;
	uint32_t restart_time;

#ifndef APACHE13
	apr_shm_t *dashboard_shm;
	dashboard_data *dashboard;
	apr_global_mutex_t *dashboard_mutex;
	char dashboard_mutex_initialized_in_child;
	char *dashboard_file;
	char *dashboard_lock_file;
#endif
} xsp_data;

typedef struct {
	int nservers;
	xsp_data *servers;
	char auto_app;
	char auto_app_set;
} module_cfg;

typedef struct {
	uint32_t client_block_buffer_size;
	char *client_block_buffer;
} request_data;

#ifndef APACHE13
typedef struct {
	char *name;
	apr_lockmech_e sym;
	char available;
} lock_mechanism;

#define LOCK_MECH(name) {#name, APR_LOCK_ ## name, APR_HAS_ ## name ## _SERIALIZE}
  
static lock_mechanism lockMechanisms [] = {
	LOCK_MECH (FCNTL),
	LOCK_MECH (FLOCK),
	LOCK_MECH (SYSVSEM),
	LOCK_MECH (PROC_PTHREAD),
	LOCK_MECH (POSIXSEM),
	{"DEFAULT", APR_LOCK_DEFAULT, 1},
	{NULL, 0, 0}
};
#endif

static int send_table (apr_pool_t *pool, apr_table_t *table, apr_socket_t *sock);
static void start_xsp (module_cfg *config, int is_restart, char *alias);
static apr_status_t terminate_xsp2 (void *data, char *alias, int for_restart, int lock_held);

#ifndef APACHE13
static apr_lockmech_e
get_apr_locking_mechanism ()
{
	char *name = getenv ("MOD_MONO_LOCKING_MECHANISM");
	int i = 0;

	DEBUG_PRINT (0, "Requested locking mechanism name: %s", name);
	if (!name)
		return APR_LOCK_DEFAULT;
	while (lockMechanisms [i].name) {
		if (!strncasecmp (name, lockMechanisms [i].name, strlen (lockMechanisms [i].name))) {
			if (lockMechanisms [i].available) {
				DEBUG_PRINT (1, "Using configured lock mechanism: %s", lockMechanisms [i].name);
				return lockMechanisms [i].sym;
			} else {
				ap_log_error (APLOG_MARK, APLOG_ALERT, STATUS_AND_SERVER,
					      "Locking mechanism '%s' is unavailable for this platform. Using the default one.",
					      lockMechanisms [i].name);
				return APR_LOCK_DEFAULT;
			}
		}
		i++;
	}

	ap_log_error (APLOG_MARK, APLOG_ALERT, STATUS_AND_SERVER,
		      "No locking mechanism matching '%s' has been found for this platform. Using the default one.",
		      name);
	return APR_LOCK_DEFAULT;
}
#endif

/* */
static int
search_for_alias (const char *alias, module_cfg *config)
{
	/* 'alias' may be NULL to search for the default XSP */
	int i;
	xsp_data *xsp;

	for (i = 0; i < config->nservers; i++) {
		xsp = &config->servers [i];
		if ((alias == NULL || !strcmp (alias, "default")) && xsp->is_default)
			return i;

		if (alias != NULL && !strcmp (alias, xsp->alias))
			return i;
	}

	return -1;
}

static const char *
set_alias (cmd_parms *cmd, void *mconfig, const char *alias)
{
	per_dir_config *config = mconfig;
	module_cfg *sconfig;

	sconfig = ap_get_module_config (cmd->server->module_config, &mono_module);
	config->alias = (char *) alias;
	if (search_for_alias (alias, sconfig) == -1) {
		char *err = apr_pstrcat (cmd->pool, "Server alias '", alias, ", not found.", NULL);
		return err;
	}

	return NULL;
}

static const char *
set_auto_application (cmd_parms *cmd, void *mconfig, const char *value)
{
	module_cfg *sconfig;

	sconfig = ap_get_module_config (cmd->server->module_config, &mono_module);
	if (!strcasecmp (value, "disabled")) {
		if (sconfig->auto_app_set && sconfig->auto_app != FALSE)
			return apr_pstrdup (cmd->pool, "Conflicting values for MonoAutoApplication.");

		sconfig->auto_app = FALSE;
		/* TODO: Copiar de 'XXGLOBAL' a 'default' */
	} else if (!strcasecmp (value, "enabled")) {
		if (sconfig->auto_app_set && sconfig->auto_app != TRUE)
			return apr_pstrdup (cmd->pool, "Conflicting values for MonoAutoApplication.");

		sconfig->auto_app = TRUE;
	} else {
		return apr_pstrdup (cmd->pool, "Invalid value. Must be 'enabled' or 'disabled'");
	}

	sconfig->auto_app_set = TRUE;
	return NULL;
}


static unsigned long
parse_restart_time (const char *t)
{
	uint32_t time_spec [4] = {0, 0, 0, 0};
	int parsed;

	parsed = sscanf (t, "%u:%u:%u:%u",
			 &time_spec [0],
			 &time_spec [1],
			 &time_spec [2],
			 &time_spec [3]);
	switch (parsed) {
		case 1:
			DEBUG_PRINT (1, "Auto-restart will happen after: %u days (%us)",
				     time_spec [0],
				     time_spec [0] * 86400);
			return time_spec [0] * 86400;
		case 2:
			DEBUG_PRINT (1, "Auto-restart will happen after: %u days, %u hours (%us)",
				     time_spec [0], time_spec [1],
				     (time_spec [0] * 86400) + (time_spec [1] * 3600));
			return (time_spec [0] * 86400) + (time_spec [1] * 3600);
		case 3:
			DEBUG_PRINT (1, "Auto-restart will happen after: %u days, %u hours, %u minutes (%us)",
				     time_spec [0], time_spec [1], time_spec [2],
				     (time_spec [0] * 86400) + (time_spec [1] * 3600) + (time_spec [2] * 60));
			return (time_spec [0] * 86400) + (time_spec [1] * 3600) + (time_spec [2] * 60);
		case 4:
			DEBUG_PRINT (1, "Auto-restart will happen: %u days, %u hours, %u minutes, %u seconds (%us)",
				     time_spec [0], time_spec [1], time_spec [2], time_spec [3],
				     (time_spec [0] * 86400) + (time_spec [1] * 3600) + (time_spec [2] * 60) + time_spec [3]);
			return (time_spec [0] * 86400) + (time_spec [1] * 3600) + (time_spec [2] * 60) + time_spec [3];
		default:
			return 0;
	}
}

static void
get_restart_mode (xsp_data *xsp, const char *value)
{
	unsigned long val = 0;
	if (xsp == NULL)
		return;

	switch (xsp->restart_mode) {
		case AUTORESTART_MODE_REQUESTS:
			ap_log_error (APLOG_MARK, APLOG_NOTICE, STATUS_AND_SERVER,
				      "Backend '%s' auto-restart mode %s enabled",
				      xsp->alias ? xsp->alias : "default", "REQUESTS");
			if (value)
				val = (unsigned long)strtol (value, NULL, 0);
			if (val == 0 || val > UINT_MAX || (val == ULONG_MAX && errno == ERANGE))
				val = DEFAULT_RESTART_REQUESTS;
			ap_log_error (APLOG_MARK, APLOG_NOTICE, STATUS_AND_SERVER,
				      "Auto-restart will happen after %u requests made to the backend",
				      (uint32_t)val);
			xsp->restart_requests = (uint32_t)val;
			break;

		case AUTORESTART_MODE_TIME:
			ap_log_error (APLOG_MARK, APLOG_NOTICE, STATUS_AND_SERVER,
				      "Backend '%s' auto-restart mode %s enabled",
				      xsp->alias ? xsp->alias : "default", "TIME");
			if (value)
				val = parse_restart_time (value);
			if (val == 0 || val > UINT_MAX || (val == ULONG_MAX && errno == ERANGE))
				val = DEFAULT_RESTART_TIME;
			ap_log_error (APLOG_MARK, APLOG_NOTICE, STATUS_AND_SERVER,
				      "Auto-restart will happen after %u seconds of the backend uptime",
				      (uint32_t)val);
			xsp->restart_time = (uint32_t)val;
			break;

		default:
			break;
	}
}

inline static uid_t
apache_get_userid ()
{
#ifdef HAVE_UNIXD
	return unixd_config.user_id;
#else
	return ap_user_id;
#endif
}

inline static gid_t
apache_get_groupid ()
{
#ifdef HAVE_UNIXD
	return unixd_config.group_id;
#else
	return ap_group_id;
#endif
}

inline static char *
apache_get_username ()
{
#ifdef HAVE_UNIXD
	return unixd_config.user_name;
#else
	return ap_user_name;
#endif
}

#ifndef APACHE13
static void
ensure_dashboard_initialized (module_cfg *config, xsp_data *xsp, apr_pool_t *p)
{
	apr_status_t rv;
	mode_t old_umask;
#if defined (APR_HAS_USER)
	apr_uid_t cur_uid;
	apr_gid_t cur_gid;
	int switch_back_to_root = 0;

	if (apache_get_userid () == -1 || apache_get_groupid () == -1) {
		ap_log_error (APLOG_MARK, APLOG_CRIT, STATUS_AND_SERVER,
			      "The unix daemon module not initialized yet. Please make sure that "
			      "your mod_mono module is loaded after the User/Group directives have "
			      "been parsed. Not initializing the dashboard.");
		return;
	}
#endif

	if (!xsp->dashboard_shm) {
		DEBUG_PRINT (1, "removing dashboard file '%s' as root", xsp->dashboard_file);
		if (unlink (xsp->dashboard_file) == -1 && errno != ENOENT) {
			ap_log_error (APLOG_MARK, APLOG_CRIT, STATUS_AND_SERVER,
				      "Failed to remove dashboard file '%s', further actions impossible. %s",
				      xsp->dashboard_file, strerror (errno));
			return;
		}
	}
	
#if defined (APR_HAS_USER)
	if (apr_uid_current (&cur_uid, &cur_gid, p) == APR_SUCCESS && cur_uid == 0) {
		DEBUG_PRINT (2, "Temporarily switching to target uid/gid");
		switch_back_to_root = 1;
		if (setegid (apache_get_groupid ()) == -1)
			ap_log_error (APLOG_MARK, APLOG_ALERT, STATUS_AND_SERVER,
				      "setegid: unable to set effective group id to %u. %s",
				      (unsigned)apache_get_groupid (), strerror (errno));
		
		if (seteuid (apache_get_userid ()) == -1)
			ap_log_error (APLOG_MARK, APLOG_ALERT, STATUS_AND_SERVER,
				      "seteuid: unable to set effective user id to %u. %s",
				      (unsigned)apache_get_userid (), strerror (errno));
	}
#endif

	if (!xsp->dashboard_mutex) {
		DEBUG_PRINT (1, "creating dashboard mutex = %s", xsp->dashboard_lock_file);
		rv = apr_global_mutex_create (&xsp->dashboard_mutex, xsp->dashboard_lock_file,
					      get_apr_locking_mechanism (), p);
		if (rv != APR_SUCCESS) {
			ap_log_error (APLOG_MARK, APLOG_CRIT, STATCODE_AND_SERVER (rv),
				      "Failed to create mutex '%s'", xsp->dashboard_lock_file);
			goto restore_creds;
		}

#if defined (AP_NEED_SET_MUTEX_PERMS) && defined (HAVE_UNIXD)
		DEBUG_PRINT (1, "Setting mutex permissions for %s", xsp->dashboard_lock_file);
		rv = unixd_set_global_mutex_perms (xsp->dashboard_mutex);
		if (rv != APR_SUCCESS) {
			ap_log_error (APLOG_MARK, APLOG_CRIT, STATCODE_AND_SERVER (rv),
				      "Failed to set mutex permissions for %s",
				      xsp->dashboard_lock_file);
			goto restore_creds;
		}
#endif
	}

	if (!xsp->dashboard_shm) {
		rv = apr_shm_attach (&xsp->dashboard_shm, xsp->dashboard_file, p);
		if (rv != APR_SUCCESS) {
			DEBUG_PRINT (1, "creating dashboard '%s'", xsp->dashboard_file);
			
			old_umask = umask (0077);
			rv = apr_shm_create (&xsp->dashboard_shm, sizeof (dashboard_data), xsp->dashboard_file, p);
			umask (old_umask);
			if (rv != APR_SUCCESS) {
				ap_log_error (APLOG_MARK, APLOG_CRIT, STATCODE_AND_SERVER (rv),
					      "Failed to create shared memory segment for backend '%s'",
					      xsp->alias);
				goto restore_creds;
			} else {
				rv = apr_shm_attach (&xsp->dashboard_shm, xsp->dashboard_file, p);
				if (rv != APR_SUCCESS) {
					ap_log_error (APLOG_MARK, APLOG_CRIT, STATCODE_AND_SERVER (rv),
						      "Failed to attach to the dashboard '%s'",
						      xsp->dashboard_file);
					return;
				}
          
				xsp->dashboard = apr_shm_baseaddr_get (xsp->dashboard_shm);
				xsp->dashboard->start_time = time (NULL);
				xsp->dashboard->handled_requests = 0;
				xsp->dashboard->restart_issued = 0;
				goto restore_creds;
			}
		}
	}

	xsp->dashboard = apr_shm_baseaddr_get (xsp->dashboard_shm);

  restore_creds:
#if defined (APR_HAS_USER) && !defined (WIN32)
	if (switch_back_to_root) {
		DEBUG_PRINT (2, "Switching back to root");
		if (seteuid (0) == -1)
			ap_log_error (APLOG_MARK, APLOG_ALERT, STATUS_AND_SERVER,
				      "seteuid: cannot switch the effective user id back to root. %s",
				      strerror (errno));
		if (setegid (0) == -1)
			ap_log_error (APLOG_MARK, APLOG_ALERT, STATUS_AND_SERVER,
				      "setegid: cannot switch the effective group id back to root. %s",
				      strerror (errno));
	}
#endif
}
#endif

static int
add_xsp_server (apr_pool_t *pool, const char *alias, module_cfg *config, int is_default, int is_virtual)
{
	xsp_data *server;
	xsp_data *servers;
	int nservers;
	int i;
#ifndef APACHE13
	char num [8];
#endif
	
	i = search_for_alias (alias, config);
	if (i >= 0)
		return i;

	server = apr_pcalloc (pool, sizeof (xsp_data));
	
	server->is_default = is_default;
	server->alias = apr_pstrdup (pool, alias);
	server->filename = NULL;
	server->umask_value = NULL;
	server->run_xsp = "True";
	/* (Obsolete) server->executable_path = EXECUTABLE_PATH; */
	server->path = NULL;
	server->server_path = MODMONO_SERVER_PATH;
	server->applications = NULL;
	server->wapidir = WAPIDIR;
	server->document_root = DOCUMENT_ROOT;
	server->appconfig_file = APPCONFIG_FILE;
	if (is_default)
		server->appconfig_dir = APPCONFIG_DIR;

	server->listen_port = NULL;
	server->listen_address = NULL;
	server->max_cpu_time = NULL;
	server->max_memory = NULL;
	server->debug = NULL;
	server->env_vars = NULL;
	server->status = FORK_NONE;
	server->is_virtual = is_virtual;
	server->start_attempts = "3";
	server->start_wait_time = "2";

#ifndef APACHE13
	apr_snprintf (num, sizeof (num), "%u", (unsigned)config->nservers + 1);
	server->dashboard_file = apr_pstrcat (pool,
					      DASHBOARD_FILE,
					      "_",
					      alias == NULL ? "default" : alias,
					      "_",
					      num,
					      NULL);
	server->dashboard_lock_file = apr_pstrcat (pool, server->dashboard_file, ".lock", NULL);
	server->dashboard_shm = NULL;
	server->dashboard = NULL;
	server->dashboard_mutex = NULL;
	server->dashboard_mutex_initialized_in_child = 0;
	server->restart_mode = AUTORESTART_MODE_INVALID;
	server->restart_requests = 0;
	server->restart_time = 0;

	ensure_dashboard_initialized (config, server, pool);
#endif
	
	nservers = config->nservers + 1;
	servers = config->servers;
	config->servers = apr_pcalloc (pool, sizeof (xsp_data) * nservers);
	if (config->nservers > 0)
		memcpy (config->servers, servers, sizeof (xsp_data) * config->nservers);

	memcpy (&config->servers [config->nservers], server, sizeof (xsp_data));
	config->nservers = nservers;
  
	return config->nservers - 1;
}

static int
handle_restart_config (char *ptr, unsigned long offset, const char *value)
{
	xsp_data *xsp = (xsp_data*)ptr;
	
	if (offset == APR_OFFSETOF (xsp_data, restart_mode)) {
		if (!strncasecmp (value, "REQUESTS", 8)) {
			xsp->restart_mode = AUTORESTART_MODE_REQUESTS;
			xsp->restart_requests = DEFAULT_RESTART_REQUESTS;
		} else if (!strncasecmp (value, "TIME", 4)) {
			xsp->restart_mode = AUTORESTART_MODE_TIME;
			xsp->restart_time = DEFAULT_RESTART_TIME;
		} else if (!strncasecmp (value, "NONE", 4))
			xsp->restart_mode = AUTORESTART_MODE_NONE;
		else
			xsp->restart_mode = AUTORESTART_MODE_INVALID;
		return 1;
	}

	if ((offset == APR_OFFSETOF (xsp_data, restart_requests)) ||
	    (offset == APR_OFFSETOF (xsp_data, restart_time))) {
		get_restart_mode (xsp, value);
		return 1;
	}

	return 0;
}

static const char *
store_config_xsp (cmd_parms *cmd, void *notused, const char *first, const char *second)
{
	const char *alias;
	const char *value;
	char *prev_value = NULL;
	char *new_value;
	int idx;
	module_cfg *config;
	char *ptr;
	unsigned long offset;
	int is_default;
	
	offset = (unsigned long) cmd->info;
	DEBUG_PRINT (1, "store_config %lu '%s' '%s'", offset, first, second);
	config = ap_get_module_config (cmd->server->module_config, &mono_module);
	if (second == NULL) {
		if (config->auto_app) {
			idx = search_for_alias ("XXGLOBAL", config);
			value = first;
			ptr = (char *) &config->servers [idx];
			
			/* special handling for restart fields */
			if (handle_restart_config (ptr, offset, value))
				return NULL;
			ptr += offset;
			
			/* MonoApplications/AddMonoApplications are accumulative */
			if (offset == APR_OFFSETOF (xsp_data, applications))
				prev_value = *((char **) ptr);

			if (prev_value != NULL) {
				new_value = apr_pstrcat (cmd->pool, prev_value, ",", value, NULL);
			} else {
				new_value = apr_pstrdup (cmd->pool, value);
			}

			*((char **) ptr) = new_value;
			return NULL;
		}
		alias = "default";
		if (cmd->server->is_virtual)
			alias = cmd->server->server_hostname;
		value = first;
		is_default = 1;
	} else {
		if (!strcmp (first, "XXGLOBAL"))
			return apr_pstrdup (cmd->pool, "XXGLOBAL is a reserved application identifier.");
		alias = first;
		value = second;
		is_default = (!strcmp (alias, "default"));
	}

	/* Disable autoapp if there's any other application. MonoDebug is excluded. */
	if (!config->auto_app_set)
		config->auto_app = FALSE;

	idx = search_for_alias (alias, config);
	if (idx == -1)
		idx = add_xsp_server (cmd->pool, alias, config, is_default, cmd->server->is_virtual);

	ptr = (char *) &config->servers [idx];
  
	/* special handling for restart fields */
	if (handle_restart_config (ptr, offset, value))
		return NULL;
	
	ptr += offset;
	/* MonoApplications/AddMonoApplications are accumulative */
	if (offset == APR_OFFSETOF (xsp_data, applications))
		prev_value = *((char **) ptr);

	if (prev_value != NULL) {
		new_value = apr_pstrcat (cmd->pool, prev_value, ",", value, NULL);
	} else {
		new_value = apr_pstrdup (cmd->pool, value);
	}

	*((char **) ptr) = new_value;
	DEBUG_PRINT (1, "store_config end: %s", new_value);
	return NULL;
}

static void *
merge_config (apr_pool_t *p, void *base_conf, void *new_conf)
{
	module_cfg *base_module = (module_cfg *) base_conf;
	module_cfg *new_module = (module_cfg *) new_conf;
	xsp_data *base_config;
	xsp_data *new_config;
	int nservers;

	if (new_module->nservers == 0)
		return new_module;
	
	base_config = base_module->servers;
	new_config = new_module->servers;
	nservers = base_module->nservers + new_module->nservers;

	/* FIXME: error out on duplicate aliases. */
	base_module->servers = apr_pcalloc (p, sizeof (xsp_data) * nservers);
	memcpy (base_module->servers, base_config, sizeof (xsp_data) * base_module->nservers);
	memcpy (&base_module->servers [base_module->nservers], new_config, new_module->nservers * sizeof (xsp_data));
	base_module->nservers = nservers;
	DEBUG_PRINT (1, "Total mod-mono-servers to spawn so far: %d", nservers);
	return new_module;
}

static void *
create_dir_config (apr_pool_t *p, char *dirspec)
{
	per_dir_config *cfg;

	DEBUG_PRINT (1, "creating dir config for %s", dirspec);

	cfg = apr_pcalloc (p, sizeof (per_dir_config));
	if (dirspec != NULL)
		cfg->location = apr_pstrdup (p, dirspec);

	return cfg;
}

static char *
get_default_global_socket_name (apr_pool_t *pool, const char *base)
{
	return apr_pstrcat (pool, base, "_", "global", NULL);
}

static void *
create_mono_server_config (apr_pool_t *p, server_rec *s)
{
	module_cfg *server;

	DEBUG_PRINT (0, "creating mono server config");
	server = apr_pcalloc (p, sizeof (module_cfg));
	server->auto_app = TRUE;
	server->auto_app_set = FALSE;
	
	add_xsp_server (p, "XXGLOBAL", server, FALSE, FALSE);
	server->servers [0].filename = get_default_global_socket_name (p, SOCKET_FILE);
	return server;
}

static void
request_send_response_from_memory (request_rec *r, char *byteArray, int size, int doFlush)
{
#ifdef APACHE13
	if (r->sent_bodyct == 0)
		ap_send_http_header (r);
#endif

	ap_rwrite (byteArray, size, r);
	if (doFlush) {
		DEBUG_PRINT (0, "flushing");
		ap_rflush (r);
	}
}

static void
request_send_response_string (request_rec *r, char *byteArray)
{
	request_send_response_from_memory (r, byteArray, strlen (byteArray), 0);
}

/* Not connection because actual port will vary depending on Apache configuration */
static int
request_get_server_port (request_rec *r)
{
	return ap_get_server_port (r);
}

static int
connection_get_remote_port (conn_rec *c)
{ 
#ifdef APACHE13
	return  ntohs (c->remote_addr.sin_port);
#elif defined(APACHE22)
	return c->remote_addr->port;
#else
	apr_port_t port;
	apr_sockaddr_port_get (&port, c->remote_addr);
	return port;
#endif
  
}

static int
connection_get_local_port (request_rec *r)
{
#ifdef APACHE13  
	return ap_get_server_port (r);
#elif defined(APACHE22)
	return r->connection->local_addr->port;
#else
	apr_port_t port;
	apr_sockaddr_port_get (&port, r->connection->local_addr);
	return port;  
#endif
}

static const char *
connection_get_remote_name (request_rec *r)
{
#ifdef APACHE13
	return ap_get_remote_host (r->connection, r->per_dir_config, REMOTE_NAME);
#else
	return ap_get_remote_host (r->connection, r->per_dir_config, REMOTE_NAME, NULL);
#endif
}

/* Do nothing
 * This does a kind of final flush which is not what we want.
 * It caused bug 60117.
 static void
 connection_flush (request_rec *r)
 {
 #ifdef APACHE13
 ap_rflush (r);
 #else
 ap_flush_conn (r->connection);
 #endif
 }
*/

static void
set_response_header (request_rec *r,
		     const char *name,
		     const char *value)
{
	if (!strcasecmp (name,"Content-Type")) {
		r->content_type = value;
	} else {
		apr_table_addn (r->headers_out, name, value);
	}
}

static int
setup_client_block (request_rec *r)
{
	if (r->read_length)
		return APR_SUCCESS;

	return ap_setup_client_block (r, REQUEST_CHUNKED_DECHUNK);
}

static int
write_data (apr_socket_t *sock, const void *str, apr_size_t size)
{
	apr_size_t prevsize = size;
	apr_status_t statcode;
  
	if ((statcode = apr_socket_send (sock, str, &size)) != APR_SUCCESS) {
		ap_log_error (APLOG_MARK, APLOG_ERR, STATCODE_AND_SERVER (statcode), "write_data failed");
		return -1;
	}
  
	return (prevsize == size) ? size : -1;
}

static int
read_data (apr_socket_t *sock, void *ptr, apr_size_t size)
{
	apr_status_t statcode;
  
	if ((statcode = apr_socket_recv (sock, ptr, &size)) != APR_SUCCESS) {
		ap_log_error (APLOG_MARK, APLOG_ERR, STATCODE_AND_SERVER (statcode), "read_data failed");
		return -1;
	}
  
	return size;
}

static char *
read_data_string (apr_pool_t *pool, apr_socket_t *sock, char **ptr, int32_t *size)
{
	int l, count;
	char *buf;
	apr_status_t result;

	if (read_data (sock, &l, sizeof (int32_t)) == -1)
		return NULL;

	l = INT_FROM_LE (l);
	buf = apr_pcalloc (pool, l + 1);
	count = l;
	while (count > 0) {
		result = read_data (sock, buf + l - count, count);
		if (result == -1)
			return NULL;

		count -= result;
	}

	if (ptr)
		*ptr = buf;

	if (size)
		*size = l;

	return buf;
}

static int
send_entire_file (request_rec *r, const char *filename, int *result)
{
#ifdef APACHE2
#  ifdef APR_LARGEFILE 
#      define MODMONO_LARGE APR_LARGEFILE
#  else
#      define MODMONO_LARGE 0
#  endif
	apr_file_t *file;
	apr_status_t st;
	apr_finfo_t info;
	apr_size_t nbytes;
	const apr_int32_t flags = APR_READ | APR_SENDFILE_ENABLED | MODMONO_LARGE;

	st = apr_file_open (&file, filename, flags, APR_OS_DEFAULT, r->pool);
	if (st != APR_SUCCESS) {
		DEBUG_PRINT (1, "file_open FAILED");
		*result = HTTP_FORBIDDEN; 
		return -1;
	}

	st = apr_file_info_get (&info, APR_FINFO_SIZE, file);
	if (st != APR_SUCCESS) {
		DEBUG_PRINT (1, "info_get FAILED");
		*result = HTTP_FORBIDDEN; 
		return -1;
	}

	st = ap_send_fd (file, r, 0, info.size, &nbytes);
	apr_file_close (file);
	if (nbytes < 0) {
		DEBUG_PRINT (1, "SEND FAILED");
		*result = HTTP_INTERNAL_SERVER_ERROR;
		return -1;
	}

	return 0;
#else
	FILE *fp;

	fp = fopen (filename, "rb");
	if (fp == NULL) {
		DEBUG_PRINT (1, "file_open FAILED");
		*result = HTTP_FORBIDDEN; 
		return -1;
	}

	if (ap_send_fd (fp, r) < 0) {
		fclose (fp);
		*result = HTTP_INTERNAL_SERVER_ERROR;
		return -1;
	}
		
	fclose (fp);
	return 0;
#endif
}

static int
send_response_headers (request_rec *r, apr_socket_t *sock)
{
	char *str;
	int32_t size;
	int pos, len;
	char *name;
	char *value;

	if (read_data_string (r->pool, sock, &str, &size) == NULL) {
		ap_log_error (APLOG_MARK, APLOG_ERR, STATUS_AND_SERVER, "failed to read data string");
		return -1;
	}
  
	DEBUG_PRINT (2, "Headers length: %d", size);
	pos = 0;
	while (size > 0) {
		name = &str [pos];
		len = strlen (name);
		pos += len + 1;
		size -= len + 1;
		value = &str [pos];
		len = strlen (value);
		pos += len + 1;
		size -= len + 1;
		set_response_header (r, name, value);
	}

	return 0;
}

static void
remove_http_vars (apr_table_t *table)
{
	const apr_array_header_t *elts;
	const apr_table_entry_t *t_elt;
	const apr_table_entry_t *t_end;

	elts = apr_table_elts (table);
	if (elts->nelts == 0)
		return;

	t_elt = (const apr_table_entry_t *) (elts->elts);
	t_end = t_elt + elts->nelts;

	do {
		if (!strncmp (t_elt->key, "HTTP_", 5)) {
			apr_table_setn (table, t_elt->key, NULL);
		}
		t_elt++;
	} while (t_elt < t_end);
}

static char *
get_client_block_buffer (request_rec *r, uint32_t requested_size, uint32_t *actual_size)
{
	request_data *rd = ap_get_module_config (r->request_config, &mono_module);

	if (rd == NULL)	{
		rd = apr_pcalloc (r->pool, sizeof (request_data));
		ap_set_module_config (r->request_config, &mono_module, rd);
	}

	if (requested_size > 1024 * 1024)
		requested_size = 1024 * 1024;

	if (requested_size > rd->client_block_buffer_size) {
		rd->client_block_buffer = apr_pcalloc (r->pool, requested_size);
		rd->client_block_buffer_size = requested_size;
	}

	*actual_size = requested_size;
	return rd->client_block_buffer;
}

static int
do_command (int command, apr_socket_t *sock, request_rec *r, int *result, int doFlush)
{
	int32_t size;
	char *str;
	const char *cstr;
	int32_t i;
	uint32_t actual_size;
	int status = 0;
	apr_pool_t *temp_pool;
	char *error_message = NULL;

	if (command < 0 || command >= LAST_COMMAND) {
		ap_log_error (APLOG_MARK, APLOG_ERR, STATUS_AND_SERVER,
			      "Unknown command: %d", command);
		*result = HTTP_INTERNAL_SERVER_ERROR;
		return FALSE;
	}

	DEBUG_PRINT (2, "Command received: %s", cmdNames [command]);
	*result = OK;
	switch (command) {
		case SEND_FROM_MEMORY:
			apr_pool_create (&temp_pool, r->pool);
			if (read_data_string (temp_pool, sock, &str, &size) == NULL) {
				error_message = "failed to read data for SEND_FROM_MEMORY command";
				status = -1;
				apr_pool_destroy (temp_pool);
				break;
			}
			request_send_response_from_memory (r, str, size, doFlush);
			apr_pool_destroy (temp_pool);
			break;
		case GET_SERVER_VARIABLES:
			ap_add_cgi_vars (r);
			ap_add_common_vars (r);
			remove_http_vars (r->subprocess_env);
			cstr = apr_table_get (r->subprocess_env, "HTTPS");
			if (cstr != NULL && !strcmp (cstr, "on"))
				apr_table_add (r->subprocess_env, "SERVER_PORT_SECURE", "True");
			if (!send_table (r->pool, r->subprocess_env, sock)) {
				error_message = "failed to send server variables";
				status = -1;
			} else
				status = 0;
			break;
		case SET_RESPONSE_HEADERS:
			status = send_response_headers (r, sock);
			if (status < 0)
				error_message = "failed to send response headers";
			break;
		case GET_LOCAL_PORT:
			i = connection_get_local_port (r);
			i = LE_FROM_INT (i);
			status = write_data (sock, &i, sizeof (int32_t));
			if (status < 0)
				error_message = "failed to get local port";
			break;
		case CLOSE:
			return FALSE;
			break;
		case SHOULD_CLIENT_BLOCK:
			size = ap_should_client_block (r);
			size = LE_FROM_INT (size);
			status = write_data (sock, &size, sizeof (int32_t));
			if (status < 0)
				error_message = "failed to send the 'should block' flag";
			break;
		case SETUP_CLIENT_BLOCK:
			if (setup_client_block (r) != APR_SUCCESS) {
				size = LE_FROM_INT (-1);
				status = write_data (sock, &size, sizeof (int32_t));
				if (status < 0)
					error_message = "failed to setup client block (data size)";
				break;
			}

			size = LE_FROM_INT (0);
			status = write_data (sock, &size, sizeof (int32_t));
			if (status < 0)
				error_message = "failed to setup client block (data)";
			break;
		case GET_CLIENT_BLOCK:
			status = read_data (sock, &i, sizeof (int32_t));
			if (status == -1)
				break;

			i = INT_FROM_LE (i);
			if (i < 0) {
				DEBUG_PRINT (2, "xsp sent us size == %d: not processing", i);
				abort();
			}
			str = get_client_block_buffer (r, (uint32_t) i, &actual_size);
			i = ap_get_client_block (r, str, actual_size);
			i = LE_FROM_INT (i);
			status = write_data (sock, &i, sizeof (int32_t));
			if (status < 0)
				error_message = "failed to get client block (data size)";
			i = INT_FROM_LE (i);
			if (i == -1)
				break;
			status = write_data (sock, str, i);
			if (status < 0)
				error_message = "failed to get client block (data)";
			break;
		case SET_STATUS:
			status = read_data (sock, &i, sizeof (int32_t));
			if (status == -1) {
				error_message = "failed to set status (data size)";
				break;
			}
    
			if (read_data_string (r->pool, sock, &str, NULL) == NULL) {
				error_message = "failed to set status (data)";
				status = -1;
				break;
			}
			r->status = INT_FROM_LE (i);
			r->status_line = str;
			break;
		case DECLINE_REQUEST:
			*result = DECLINED;
			return FALSE;
		case IS_CONNECTED:
			*result = (r->connection->aborted ? 0 : 1);
			status = write_data (sock, result, sizeof (int32_t));
			if (status < 0)
				error_message = "failed to check if the backend is connected";
			break;
		case MYNOT_FOUND:
			ap_log_error (APLOG_MARK, APLOG_ERR, STATUS_AND_SERVER,
				      "No application found for %s", r->uri);

			ap_log_error (APLOG_MARK, APLOG_ERR, STATUS_AND_SERVER,
				      "Host header was %s",
				      apr_table_get (r->headers_in, "host"));

			*result = HTTP_NOT_FOUND;
			return FALSE;
		case SEND_FILE:
			if (read_data_string (r->pool, sock, &str, NULL) == NULL) {
				error_message = "failed to send file (file name)";
				status = -1;
				break;
			}
			status = send_entire_file (r, str, result);
			if (status == -1)
				error_message = "failed to send file (file data)";
			break;
		default:
			error_message = "unknown command";
			status = -1;
			break;
	}

	if (status == -1) {
		ap_log_error (APLOG_MARK, APLOG_ERR, STATUS_AND_SERVER,
			      "command failed: %s",
			      error_message ? error_message : "unknown error");
		*result = HTTP_INTERNAL_SERVER_ERROR;
		return FALSE;
	}

	return TRUE;
}

#ifndef APACHE2
static apr_status_t
apr_sockaddr_info_get (apr_sockaddr_t **sa, const char *hostname,
		       int family, int port, int flags, apr_pool_t *p)
{
	struct addrinfo hints, *list;
	int error;
	struct sockaddr_in *addr;

	if (port < 0 || port > 65535)
		return EINVAL;

	memset (&hints, 0, sizeof (hints));
	hints.ai_family = family;
	hints.ai_socktype = SOCK_STREAM;
	error = getaddrinfo (hostname, NULL, &hints, &list);
	if (error != 0) {
		ap_log_error (APLOG_MARK, APLOG_ERR, STATUS_AND_SERVER,
			      "mod_mono: getaddrinfo failed (%s) hostname: '%s' port: '%d'.",
			      strerror (error), hostname, port);

		return error;
	}

	*sa = apr_pcalloc (p, sizeof (apr_sockaddr_t));
	(*sa)->pool = p;
	(*sa)->addrlen = list->ai_addrlen;
	(*sa)->addr = apr_pcalloc (p, list->ai_addrlen);
	memcpy ((*sa)->addr, list->ai_addr, list->ai_addrlen);
	addr = (struct sockaddr_in *) (*sa)->addr;
	addr->sin_port = htons (port);

	freeaddrinfo (list);

	return APR_SUCCESS;
}

static apr_status_t
apr_socket_connect (apr_socket_t *sock, apr_sockaddr_t *sa)
{
	int sock_fd;

	apr_os_sock_get (&sock_fd, sock);
	if (connect (sock_fd, sa->addr, sa->addrlen) != 0)
		return errno;

	return APR_SUCCESS;
}

static apr_status_t
apr_socket_send (apr_socket_t *sock, const char *buf, apr_size_t *len)
{
	int result;
	int total;

	total = 0;
	do {
		result = write (sock->fd, buf + total, (*len) - total);
		if (result >= 0)
			total += result;
	} while ((result >= 0 && total < *len) || (result == -1 && errno == EINTR));

	return (total == *len) ? 0 : -1;
}

static apr_status_t
apr_socket_recv (apr_socket_t *sock, char *buf, apr_size_t *len)
{
	int result;
	int total;
	apr_os_sock_t sock_fd;

	apr_os_sock_get (&sock_fd, sock);
	total = 0;
	do {
		result = read (sock_fd, buf + total, (*len) - total);
		if (result >= 0)
			total += result;
	} while ((result > 0 && total < *len) || (result == -1 && errno == EINTR));

	return (total == *len) ? 0 : -1;
}

static void
apr_sleep (long t)
{
	struct timeval tv;

	tv.tv_usec = t % 1000000;
	tv.tv_sec = t / 1000000;
	select (0, NULL, NULL, NULL, &tv);
}
#elif !defined (HAVE_APR_SOCKET_CONNECT)
/* libapr-0 <= 0.9.3 (or 0.9.2?) */
#	define apr_socket_connect apr_connect
#endif

static char *
get_default_socket_name (apr_pool_t *pool, const char *alias, const char *base)
{
	return apr_pstrcat (pool, base, "_", alias == NULL ? "default" : alias, NULL);
}

static apr_status_t 
try_connect (xsp_data *conf, apr_socket_t **sock, apr_pool_t *pool)
{
	char *error;
	struct sockaddr_un unix_address;
	struct sockaddr *ptradd;
	char *fn = NULL;
	char *la = NULL;
	int err;

	if (conf->listen_port == NULL) {
		apr_os_sock_t sock_fd;

		apr_os_sock_get (&sock_fd, *sock);
		unix_address.sun_family = PF_UNIX;
		if (conf->filename != NULL)
			fn = conf->filename;
		else
			fn = get_default_socket_name (pool, conf->alias, SOCKET_FILE);

		DEBUG_PRINT (1, "Socket file name %s", fn);
		memcpy (unix_address.sun_path, fn, strlen (fn) + 1);
		ptradd = (struct sockaddr *) &unix_address;
		if (connect (sock_fd, ptradd, sizeof (unix_address)) != -1)
			return APR_SUCCESS;
	} else {
		apr_status_t rv;
		apr_sockaddr_t *sa;

		la = conf->listen_address ? conf->listen_address : LISTEN_ADDRESS;
		rv = apr_sockaddr_info_get (&sa, la, APR_INET,
					    atoi (conf->listen_port), 0, pool);

		if (rv != APR_SUCCESS) {
			ap_log_error (APLOG_MARK, APLOG_ERR, STATUS_AND_SERVER,
				      "mod_mono: error in address ('%s') or port ('%s').",
				      la, conf->listen_port);
			return -2;
		}

		rv = apr_socket_connect (*sock, sa);
		if (rv == APR_SUCCESS)
			return APR_SUCCESS;
		errno = rv;
	}

	err = errno;
	switch (err) {
		case ENOENT:
		case ECONNREFUSED:
			return -1; /* Can try to launch mod-mono-server */
		case EPERM:
			error = strerror (err);
			if (conf->listen_port == NULL)
				ap_log_error (APLOG_MARK, APLOG_ERR, STATUS_AND_SERVER,
					      "mod_mono: file %s exists, but wrong permissions.", fn);
			else
				ap_log_error (APLOG_MARK, APLOG_ERR, STATUS_AND_SERVER,
					      "mod_mono: no permission to listen on %s.",
					      conf->listen_port);


			apr_socket_close (*sock);
			return -2; /* Unrecoverable */
		default:
			error = strerror (err);
			if (conf->listen_port == NULL)
				ap_log_error (APLOG_MARK, APLOG_ERR, STATUS_AND_SERVER,
					      "mod_mono: connect error (%s). File: %s",
					      error, fn);
			else
				ap_log_error (APLOG_MARK, APLOG_ERR, STATUS_AND_SERVER,
					      "mod_mono: connect error (%s). Address: %s Port: %s",
					      error, la, conf->listen_port);


			apr_socket_close (*sock);
			return -2; /* Unrecoverable */
	}
}

static char *
get_directory (apr_pool_t *pool, const char *filepath)
{
	char *sep;
	char *result;

	sep = strrchr ((char *) filepath, '/');
	if (sep == NULL || sep == filepath)
		return "/";
	
	result = apr_pcalloc (pool, sep - filepath + 1);
	strncpy (result, filepath, sep - filepath);
	return result;
}

#ifdef HAVE_SETENV
#	define SETENV(pool, name, value) setenv (name, value, 1)
#else
#	ifdef HAVE_PUTENV
#	define SETENV(pool, name, value) setenv_to_putenv (pool, name, value)
static int
setenv_to_putenv (apr_pool_t *pool, char *name, char *value)
{
	char *arg;

	arg = apr_pcalloc (pool, strlen (name) + strlen (value) + 2);
	sprintf (arg, "%s=%s", name, value);
	return putenv (arg);
}

#	else
#	error No setenv or putenv found!
#endif
#endif

static void
set_environment_variables (apr_pool_t *pool, char *environment_variables)
{
	char *tmp;
	char *name;
	char *value;

	/* were any environment_variables specified? */
	if (environment_variables == NULL)
		return;

	name = environment_variables;
	tmp = strchr (environment_variables, '=');
	while (tmp != NULL) {
		*tmp = '\0';
		value = tmp + 1;
		tmp = strchr (value, ';');
		if (tmp != NULL)
			*tmp = '\0';

		SETENV (pool, name, value);
		if (tmp == NULL)
			break;

		name = tmp + 1;
		tmp = strchr (name, '=');
	}
}

static void
set_process_limits2 (int resource, int max, char *name) {
	struct rlimit limit;

	if (max > 0) {
#ifdef HAVE_SETRLIMIT
		/* We don't want SIGXCPU */
		limit.rlim_cur = max;
		limit.rlim_max = max;
		DEBUG_PRINT (1, "Setting %s limit to %d", name, max);
		if (setrlimit (resource, &limit) == -1) {
			if (errno == EPERM)
				ap_log_error (APLOG_MARK, APLOG_ERR, STATUS_AND_SERVER,
					      "Failed to set %s process limit on mod-mono-server to %d: The value is greater than an existing hard limit", name, max);
			else
				ap_log_error (APLOG_MARK, APLOG_ERR, STATUS_AND_SERVER,
					      "Failed to set %s process limit on mod-mono-server to %d.", name, max);
		}
#else
		ap_log_error (APLOG_MARK, APLOG_ERR, STATUS_AND_SERVER,
			      "Setting %s process limit is not supported on this platform.", name);
#endif
	}
}

static void
set_process_limits (int max_cpu_time, int max_memory)
{
#ifndef HAVE_SETRLIMIT
#define RLIMIT_CPU 0
#define RLIMIT_DATA 0
#endif
	set_process_limits2 (RLIMIT_CPU, max_cpu_time, "CPU time");
	set_process_limits2 (RLIMIT_DATA, max_memory, "memory (data segment)");
}

static void
fork_mod_mono_server (apr_pool_t *pool, xsp_data *config)
{
	pid_t pid;
	int i;
	const int MAXARGS = 21;
	char *argv [MAXARGS];
	int argi;
	char *path;
	char *tmp;
	char *serverdir;
	char *wapidir;
	int max_memory = 0;
	int max_cpu_time = 0;
	int status;
	char is_master;
#if defined (APR_HAS_USER)
	apr_uid_t cur_uid;
	apr_gid_t cur_gid;

	if (apache_get_userid () == -1 || apache_get_groupid () == -1) {
		ap_log_error (APLOG_MARK, APLOG_CRIT, STATUS_AND_SERVER,
			      "The unix daemon module not initialized yet. Please make sure that "
			      "your mod_mono module is loaded after the User/Group directives have "
			      "been parsed. Not forking the backend.");
		return;
	}
#endif
  
	/* Running mod-mono-server not requested */
	if (!strcasecmp (config->run_xsp, "false")) {
		DEBUG_PRINT (1, "Not running mod-mono-server: %s", config->run_xsp);
		ap_log_error (APLOG_MARK, APLOG_DEBUG, STATUS_AND_SERVER,
			      "Not running mod-mono-server.exe");
		return;
	}

	is_master = (0 == strcmp ("XXGLOBAL", config->alias));
	/*
	 * At least one of MonoApplications, MonoApplicationsConfigFile or
	 * MonoApplicationsConfigDir must be specified, except for the 'global'
	 * instance that will be used to create applications on demand.
	 */
	DEBUG_PRINT (1, "Applications: %s", config->applications);
	DEBUG_PRINT (1, "Config file: %s", config->appconfig_file);
	DEBUG_PRINT (1, "Config dir.: %s", config->appconfig_dir);
	if (!is_master && config->applications == NULL && config->appconfig_file == NULL &&
	    config->appconfig_dir == NULL) {
		ap_log_error (APLOG_MARK, APLOG_ERR,
			      STATUS_AND_SERVER,
			      "Not running mod-mono-server.exe because no MonoApplications, "
			      "MonoApplicationsConfigFile or MonoApplicationConfigDir specified.");
		return;
	}

	/* Only one of MonoUnixSocket and MonoListenPort. */
	DEBUG_PRINT (1, "Listen port: %s", config->listen_port);
	if (config->listen_port != NULL && config->filename != NULL) {
		ap_log_error (APLOG_MARK, APLOG_ERR, STATUS_AND_SERVER,
			      "Not running mod-mono-server.exe because both MonoUnixSocket and "
			      "MonoListenPort specified.");
		return;
	}

	/* MonoListenAddress must be used together with MonoListenPort */
	DEBUG_PRINT (1, "Listen address: %s", config->listen_address);
	if (config->listen_port == NULL && config->listen_address != NULL) {
		ap_log_error (APLOG_MARK, APLOG_ERR, STATUS_AND_SERVER,
			      "Not running mod-mono-server.exe because MonoListenAddress "
			      "is present and there is no MonoListenPort.");
		return;
	}

	if (config->max_memory != NULL)
		max_memory = atoi (config->max_memory);

	if (config->max_cpu_time != NULL)
		max_cpu_time = atoi (config->max_cpu_time);

	set_environment_variables (pool, config->env_vars);

	pid = fork ();
	if (pid > 0) {
		wait (&status);
		return;
	}

	/* Double fork to prevent defunct/zombie processes */
	pid = fork ();
	if (pid > 0)
		exit (0);

	setsid ();
	chdir ("/");

#if defined (APR_HAS_USER)
	/*
	 * Make sure the backend runs with proper uid/gid if we're forking
	 * from the module postconfig handler.
	 */
	if (apr_uid_current (&cur_uid, &cur_gid, pool) == APR_SUCCESS && cur_uid == 0) {
		DEBUG_PRINT (2, "switching forked process group to %u", (unsigned)apache_get_groupid ());
		if (setgid (apache_get_groupid ()) == -1)
			ap_log_error (APLOG_MARK, APLOG_ALERT, STATUS_AND_SERVER,
				      "setgid: unable to set group id to %u. %s",
				      (unsigned)apache_get_groupid (), strerror (errno));

		DEBUG_PRINT (2, "switching forked process user to %s", apache_get_username ());
		if (setuid (apache_get_userid ()) == -1)
			ap_log_error (APLOG_MARK, APLOG_ALERT, STATUS_AND_SERVER,
				      "setuid: unable to set user id to %u. %s",
				      (unsigned)apache_get_userid (), strerror (errno));
	}
#endif
  
	if (config->umask_value == NULL)
		umask (0077);
	else {
		unsigned int uval;
		if (sscanf(config->umask_value, "%o", &uval) != 1) {
			DEBUG_PRINT (1, "umask conversion to octal failed");
			uval = 0077;
		}
		DEBUG_PRINT (1, "setting umask to %o", uval);
		umask (uval);
	}
	DEBUG_PRINT (1, "child started");

#ifdef DEBUG
	dup2 (2, 1);
#endif
	for (i = getdtablesize () - 1; i >= 3; i--)
		close (i);

	set_process_limits (max_cpu_time, max_memory);
	tmp = getenv ("PATH");
	DEBUG_PRINT (1, "PATH: %s", tmp);
	if (tmp == NULL)
		tmp = "";

	serverdir = get_directory (pool, config->server_path);
	DEBUG_PRINT (1, "serverdir: %s", serverdir);
	path = apr_pcalloc (pool, strlen (tmp) + strlen (serverdir) + 2);
	sprintf (path, "%s:%s", serverdir, tmp);

	DEBUG_PRINT (1, "PATH after: %s", path);
	SETENV (pool, "PATH", path);
	if (config->path != NULL)
		SETENV (pool, "MONO_PATH", config->path);
	wapidir = apr_pcalloc (pool, strlen (config->wapidir) + 5 + 2);
	sprintf (wapidir, "%s/%s", config->wapidir, ".wapi");
	mkdir (wapidir, 0700);
	if (chmod (wapidir, 0700) != 0 && (errno == EPERM || errno == EACCES)) {
		ap_log_error (APLOG_MARK, APLOG_ERR, STATUS_AND_SERVER,
			      "%s: %s", wapidir, strerror (errno));
		exit (1);
	}

	SETENV (pool, "MONO_SHARED_DIR", config->wapidir);
	if (config->debug && !strcasecmp (config->debug, "True"))
		SETENV (pool, "MONO_OPTIONS", "--debug");

	memset (argv, 0, sizeof (char *) * MAXARGS);
	argi = 0;
	argv [argi++] = config->server_path;
	if (config->listen_port != NULL) {
		char *la;

		la = config->listen_address;
		la = la ? la : LISTEN_ADDRESS;
		argv [argi++] = "--address";
		argv [argi++] = la;
		argv [argi++] = "--port";
		argv [argi++] = config->listen_port;
	} else {
		char *fn;

		fn = config->filename;
		if (fn == NULL)
			fn = get_default_socket_name (pool, config->alias, SOCKET_FILE);

		argv [argi++] = "--filename";
		argv [argi++] = fn;
	}

	if (config->applications != NULL) {
		argv [argi++] = "--applications";
		argv [argi++] = config->applications;
	}

	argv [argi++] = "--nonstop";
	if (config->document_root != NULL) {
		argv [argi++] = "--root";
		argv [argi++] = config->document_root;
	}

	if (config->appconfig_file != NULL) {
		argv [argi++] = "--appconfigfile";
		argv [argi++] = config->appconfig_file;
	}

	if (config->appconfig_dir != NULL) {
		argv [argi++] = "--appconfigdir";
		argv [argi++] = config->appconfig_dir;
	}

	if (is_master)
		argv [argi++] = "--master";
	/*
	 * The last element in the argv array must always be NULL
	 * to terminate the array for execv().
	 *
	 * Any new argi++'s that are added here must also increase
	 * the maxargs argument at the top of this method to prevent
	 * array out-of-bounds. 
	 */

	ap_log_error (APLOG_MARK, APLOG_DEBUG, STATUS_AND_SERVER,
		      "running '%s %s %s %s %s %s %s %s %s %s %s %s %s'",
		      argv [0], argv [1], argv [2], argv [3], argv [4],
		      argv [5], argv [6], argv [7], argv [8], 
		      argv [9], argv [10], argv [11], argv [12]);

	execv (argv [0], argv);
	ap_log_error (APLOG_MARK, APLOG_ERR, STATUS_AND_SERVER,
		      "Failed running '%s %s %s %s %s %s %s %s %s %s %s %s %s'. Reason: %s",
		      argv [0], argv [1], argv [2], argv [3], argv [4],
		      argv [5], argv [6], argv [7], argv [8],
		      argv [9], argv [10], argv [11], argv [12],
		      strerror (errno));
	exit (1);
}

static apr_status_t
setup_socket (apr_socket_t **sock, xsp_data *conf, apr_pool_t *pool)
{
	apr_status_t rv;
	int family, proto;

	family = (conf->listen_port != NULL) ? AF_UNSPEC : PF_UNIX;
	/* APR_PROTO_TCP = 6 */
	proto = (family == AF_UNSPEC) ? 6 : 0;
#ifdef APACHE2
	rv = APR_SOCKET_CREATE (sock, family, SOCK_STREAM, proto, pool);
#else
	(*sock)->fd = ap_psocket (pool, family, SOCK_STREAM, 0);
	(*sock)->pool = pool;
	rv = ((*sock)->fd != -1) ? APR_SUCCESS : -1;
#endif
	if (rv != APR_SUCCESS) {
		int err= errno;
		ap_log_error (APLOG_MARK, APLOG_ERR, STATUS_AND_SERVER,
			      "mod_mono: error creating socket: %d %s", err, strerror (err));
		return rv;
	}

	rv = try_connect (conf, sock, pool);
	DEBUG_PRINT (1, "try_connect: %d", (int) rv);
	return rv;
}

static int
write_string_to_buffer (char *buffer, int offset, const char *str)
{
	int tmp;
	int le;

	buffer += offset;
	tmp = (str != NULL) ? strlen (str) : 0;
	le = LE_FROM_INT (tmp);
	memcpy (buffer, &le, sizeof (int32_t));
	if (tmp > 0) {
		buffer += sizeof (int32_t);
		memcpy (buffer, str, tmp);
	}

	return tmp + sizeof (int32_t);
}

static int32_t
get_table_send_size (apr_table_t *table)
{
	const apr_array_header_t *elts;
	const apr_table_entry_t *t_elt;
	const apr_table_entry_t *t_end;
	int32_t size;

	elts = apr_table_elts (table);
	if (elts->nelts == 0)
		return sizeof (int32_t);

	size = sizeof (int32_t);
	t_elt = (const apr_table_entry_t *) (elts->elts);
	t_end = t_elt + elts->nelts;

	do {
		if (t_elt->val != NULL) {
			size += sizeof (int32_t) * 2;
			size += strlen (t_elt->key);
			size += strlen (t_elt->val);
		}
		t_elt++;
	} while (t_elt < t_end);

	return size;
}

static int32_t
write_table_to_buffer (char *buffer, apr_table_t *table)
{
	const apr_array_header_t *elts;
	const apr_table_entry_t *t_elt;
	const apr_table_entry_t *t_end;
	char *ptr;
	int32_t count = 0;

	elts = apr_table_elts (table);
	if (elts->nelts == 0) { /* size is sizeof (int32_t) */
		int32_t *i32 = (int32_t *) buffer;
		*i32 = 0;
		return sizeof (int32_t);
	}

	ptr = buffer;
	/* the count is set after the loop */
	ptr += sizeof (int32_t);
	t_elt = (const apr_table_entry_t *) (elts->elts);
	t_end = t_elt + elts->nelts;

	do {
		if (t_elt->val != NULL) {
			DEBUG_PRINT (3, "%s: %s", t_elt->key, t_elt->val);
			ptr += write_string_to_buffer (ptr, 0, t_elt->key);
			ptr += write_string_to_buffer (ptr, 0, t_elt->val);
			count++;
		}

		t_elt++;
	} while (t_elt < t_end);

	count = LE_FROM_INT (count);
	memcpy (buffer, &count, sizeof (int32_t));
	return (ptr - buffer);
}

static int
send_table (apr_pool_t *pool, apr_table_t *table, apr_socket_t *sock)
{
	char *buffer;
	int32_t size;

	size = get_table_send_size (table);
	buffer = apr_pcalloc (pool, size);
	write_table_to_buffer (buffer, table);
	return (write_data (sock, buffer, size) == size);
}

static int
send_initial_data (request_rec *r, apr_socket_t *sock, char auto_app)
{
	int i;
	char *str, *ptr;
	int size;
	server_rec *s = r->server;

	DEBUG_PRINT (2, "Send init1");
	size = 1;
	size += ((r->method != NULL) ? strlen (r->method) : 0) + sizeof (int32_t);
	if (s != NULL)
		size += ((s->is_virtual && s->server_hostname != NULL) ? strlen (s->server_hostname) : 0) + sizeof (int32_t);
	else
		size += sizeof (int32_t);
	size += ((r->uri != NULL) ? strlen (r->uri) : 0) + sizeof (int32_t);
	size += ((r->args != NULL) ? strlen (r->args) : 0) + sizeof (int32_t);
	size += ((r->protocol != NULL) ? strlen (r->protocol) : 0) + sizeof (int32_t);
	size += strlen (r->connection->local_ip) + sizeof (int32_t);
	size += sizeof (int32_t);
	size += strlen (r->connection->remote_ip) + sizeof (int32_t);
	size += sizeof (int32_t);
	size += strlen (connection_get_remote_name (r)) + sizeof (int32_t);
	size += get_table_send_size (r->headers_in);
	size++; /* byte. TRUE->auto_app, FALSE: configured application */
	if (auto_app != FALSE) {
		if (r->filename != NULL) {
			size += strlen (r->filename) + sizeof (int32_t);
		} else {
			auto_app = FALSE;
		}
	}

	ptr = str = apr_pcalloc (r->pool, size);
	*ptr++ = 7; /* version. Keep in sync with ModMonoRequest. */
	ptr += write_string_to_buffer (ptr, 0, r->method);
	if (s != NULL)
		ptr += write_string_to_buffer (ptr, 0, (s->is_virtual ? s->server_hostname : NULL));
	else
		ptr += write_string_to_buffer (ptr, 0, NULL);
	ptr += write_string_to_buffer (ptr, 0, r->uri);
	ptr += write_string_to_buffer (ptr, 0, r->args);
	ptr += write_string_to_buffer (ptr, 0, r->protocol);

	ptr += write_string_to_buffer (ptr, 0, r->connection->local_ip);
	i = request_get_server_port (r);
	i = LE_FROM_INT (i);
	memcpy (ptr, &i, sizeof (int32_t));
	ptr += sizeof (int32_t);
	ptr += write_string_to_buffer (ptr, 0, r->connection->remote_ip);
	i = connection_get_remote_port (r->connection);
	i = LE_FROM_INT (i);
	memcpy (ptr, &i, sizeof (int32_t));
	ptr += sizeof (int32_t);
	ptr += write_string_to_buffer (ptr, 0, connection_get_remote_name (r));
	ptr += write_table_to_buffer (ptr, r->headers_in);
	*ptr++ = auto_app;
	if (auto_app != FALSE)
		ptr += write_string_to_buffer (ptr, 0, r->filename);

	if (write_data (sock, str, size) != size)
		return -1;

	return 0;
}

static int
mono_execute_request (request_rec *r, char auto_app)
{
	apr_socket_t *sock;
	apr_status_t rv;
#ifndef APACHE13
	apr_status_t rv2;
#endif
	int command = -1;
	int result = FALSE;
	apr_status_t input;
	int status = 0;
	module_cfg *config;
	per_dir_config *dir_config = NULL;
	int idx;
	xsp_data *conf;
	int connect_attempts;
	int start_wait_time;
	char *socket_name = NULL;
  
	config = ap_get_module_config (r->server->module_config, &mono_module);
	DEBUG_PRINT (2, "config = 0x%lx", (uint64_t) config);
	if (r->per_dir_config != NULL)
		dir_config = ap_get_module_config (r->per_dir_config, &mono_module);

	DEBUG_PRINT (2, "dir_config = 0x%lx", (uint64_t) dir_config);
	if (dir_config != NULL && dir_config->alias != NULL)
		idx = search_for_alias (dir_config->alias, config);
	else
		idx = search_for_alias (NULL, config);

	DEBUG_PRINT (2, "idx = %d", idx);
	
	if (idx < 0) {
		DEBUG_PRINT (2, "Alias not found. Checking for auto-applications.");
		if (config->auto_app)
			idx = search_for_alias ("XXGLOBAL", config);

		if (idx == -1) {
			DEBUG_PRINT (2, "Global config not found. Finishing request.");
			return HTTP_INTERNAL_SERVER_ERROR;
		}
	}

#ifdef APACHE13
	sock = apr_pcalloc (r->pool, sizeof (apr_socket_t));
#endif
	conf = &config->servers [idx];
	
	if (conf->filename != NULL)
		socket_name = conf->filename;
	else
		socket_name = get_default_socket_name (r->pool, conf->alias, SOCKET_FILE);
	
	connect_attempts = atoi (conf->start_attempts);
	start_wait_time = atoi (conf->start_wait_time);
	if (connect_attempts < 0)
		connect_attempts = 3;
	if (start_wait_time < 2)
		start_wait_time = 2;

#ifndef APACHE13
	ensure_dashboard_initialized (config, conf, pconf);
	if (conf->dashboard_mutex && !conf->dashboard_mutex_initialized_in_child) {
		/* Avoiding to call apr_global_mutex_child_init is a hack since in certain
		 * conditions it may lead to apache deadlock. Since we don't know the exact cause
		 * and usually it is not necessary to use the environment variable to work around
		 * the apr's default locking mechanism, we skip the call in case the envvar is
		 * used.
		 */
		if (!getenv ("MOD_MONO_LOCKING_MECHANISM")) {
			rv = apr_global_mutex_child_init (&conf->dashboard_mutex, conf->dashboard_lock_file, pconf);
		} else {
			DEBUG_PRINT (0, "Skipping apr_global_mutex_child_init on '%s'", conf->dashboard_lock_file);
			rv = APR_SUCCESS;
		}
		if (rv != APR_SUCCESS) {
			ap_log_error (APLOG_MARK, APLOG_CRIT, STATCODE_AND_SERVER (rv),
				      "Failed to initialize the dashboard mutex '%s' in child process",
				      conf->dashboard_lock_file);
			/* continue despite the error, the init doesn't have to be necessary on this platform */
		} else
			conf->dashboard_mutex_initialized_in_child = 1;
	}
#endif
	
	rv = -1; /* avoid a warning about uninitialized value */
	while (connect_attempts--) {
		rv = setup_socket (&sock, conf, r->pool);
		DEBUG_PRINT (2, "After setup_socket");
		// Note that rv's value after the loop ends is important.
		if (rv != APR_SUCCESS) {
			if (rv != -1)
				return HTTP_SERVICE_UNAVAILABLE;
			DEBUG_PRINT (2, "No backend found, will start a new copy.");

#ifndef APACHE13
			if (conf->dashboard_mutex)
				rv2 = apr_global_mutex_lock (conf->dashboard_mutex);
			else
				rv2 = APR_SUCCESS;
			DEBUG_PRINT (1, "Acquiring the %s lock for backend start", conf->dashboard_lock_file);
      
			if (rv2 != APR_SUCCESS) {
				ap_log_error (APLOG_MARK, APLOG_CRIT, STATCODE_AND_SERVER (rv2),
					      "Failed to acquire %s lock, cannot continue starting new process",
					      conf->dashboard_lock_file);
				return HTTP_SERVICE_UNAVAILABLE;
			}
#endif
			
			if (socket_name != NULL && unlink (socket_name) < 0 && errno != ENOENT)
				ap_log_error (APLOG_MARK, APLOG_ALERT, STATUS_AND_SERVER,
					      "Could not remove stale socket %s. %s. Further requests will probably fail.",
					      socket_name, strerror (errno));
			start_xsp (config, 0, conf->alias);
			/* give some time for warm-up */
			DEBUG_PRINT (2, "Started new backend, sleeping %us to let it configure", (unsigned)start_wait_time);
			apr_sleep (apr_time_from_sec (start_wait_time));
#ifndef APACHE13
			if (conf->dashboard_mutex) {
				rv2 = apr_global_mutex_unlock (conf->dashboard_mutex);
				if (rv2 != APR_SUCCESS)
					ap_log_error (APLOG_MARK, APLOG_ALERT, STATCODE_AND_SERVER (rv2),
						      "Failed to release %s lock, the process may deadlock!",
						      conf->dashboard_lock_file);

			}
#endif
		} else
			break; /* connected */
	}
	
	if (rv != APR_SUCCESS) {
		/* Failed to connect to mod-mono-server after several attempts. */
		ap_log_error (APLOG_MARK, APLOG_ERR, STATUS_AND_SERVER,
			      "Failed to connect to mod-mono-server after several attempts to spawn the process.");
		return HTTP_SERVICE_UNAVAILABLE;
	}
  
	DEBUG_PRINT (2, "Sending init data");
	if (send_initial_data (r, sock, auto_app) != 0) {
		ap_log_error (APLOG_MARK, APLOG_ALERT, STATUS_AND_SERVER,
			      "Failed to send initial data. %s", strerror (errno));
		apr_socket_close (sock);
		return HTTP_SERVICE_UNAVAILABLE;
	}
	
	DEBUG_PRINT (2, "Loop");
	do {
		input = read_data (sock, (char *) &command, sizeof (int32_t));
		if (input == sizeof (int32_t)) {
			int doFlush = conf->flushOnWrite && (strcasecmp (conf->flushOnWrite, "True") == 0);
			
			command = INT_FROM_LE (command);
			result = do_command (command, sock, r, &status, doFlush);
		}
	} while (input == sizeof (int32_t) && result == TRUE);

	apr_socket_close (sock);
	if (input != sizeof (int32_t)) {
		ap_log_error (APLOG_MARK, APLOG_ERR, STATUS_AND_SERVER,
			      "Command stream corrupted, last command was %d", command);
		status = HTTP_INTERNAL_SERVER_ERROR;
	}

#ifndef APACHE13
	if (conf->restart_mode > AUTORESTART_MODE_NONE) {
		int do_restart = 0;
		
		DEBUG_PRINT (2, "Auto-restart enabled for '%s', checking if restart required", conf->alias);

		ensure_dashboard_initialized (config, conf, pconf);
		if (!conf->dashboard_mutex)
			return status;

		rv = apr_global_mutex_lock (conf->dashboard_mutex);
		DEBUG_PRINT (1, "Acquired the %s lock for backend auto-restart check", conf->dashboard_lock_file);
		
		if (rv != APR_SUCCESS) {
			ap_log_error (APLOG_MARK, APLOG_CRIT, STATCODE_AND_SERVER (rv),
				      "Failed to acquire %s lock, cannot continue auto-restart check",
				      conf->dashboard_lock_file);
			return status;
		}
		
		if (conf->restart_mode == AUTORESTART_MODE_REQUESTS) {
			conf->dashboard->handled_requests++;
			if (conf->dashboard->handled_requests > conf->restart_requests) {
				DEBUG_PRINT (0, "More than %u requests served (%u), restart required",
					     conf->restart_requests, conf->dashboard->handled_requests);
				do_restart = 1;
			} else {
				DEBUG_PRINT (0, "Backend %s has %u requests left before auto-restart",
					     conf->alias, conf->restart_requests - conf->dashboard->handled_requests);
			}
		} else if (conf->restart_mode == AUTORESTART_MODE_TIME) {
			time_t now = time (NULL);
			if (now - conf->dashboard->start_time > conf->restart_time) {
				DEBUG_PRINT (0, "Backend uptime exceeded %us, restart required", conf->restart_time);
				do_restart = 1;
			} else {
				DEBUG_PRINT (0, "Backend %s has %us left before auto-restart",
					     conf->alias, (uint32_t)(conf->restart_time - (now - conf->dashboard->start_time)));
			}
		}

		if (do_restart && !conf->dashboard->restart_issued) {
			/* we just need to stop it, it will be started at the next request */
			DEBUG_PRINT (0, "Stopping the backend '%s', it will be started at the next request",
				     conf->alias);
			ap_log_error (APLOG_MARK, APLOG_ALERT, STATCODE_AND_SERVER (rv),
				      "Requesting termination of %s mod-mono-server for restart...",
				      conf->alias);
			conf->dashboard->restart_issued = 1;
			terminate_xsp2 (r->server, conf->alias, 1, 1);
		}
		
		rv = apr_global_mutex_unlock (conf->dashboard_mutex);
		if (rv != APR_SUCCESS)
			ap_log_error (APLOG_MARK, APLOG_ALERT, STATCODE_AND_SERVER (rv),
				      "Failed to release %s lock after auto-restart check, the process may deadlock!",
				      conf->dashboard_lock_file);
	}
#endif
	
	DEBUG_PRINT (2, "Done. Status: %d", status);
	return status;
}

/*
  static const char *known_extensions4 [] = { "aspx", "asmx", "ashx", "asax", "ascx", "soap", NULL };
*/
/*
 * TRUE -> we know about this file
 * FALSE -> decline processing
 */
/*
  static int
  check_file_extension (char *filename)
  {
  int len;
  char *ext;
  const char **extensions;

  if (filename == NULL)
  return FALSE;

  len = strlen (filename);
  if (len <= 4)
  return FALSE;

  ext = strrchr (filename, '.');
  if (ext == NULL)
  return FALSE;

  switch (filename - ext + len - 1) {
  case 3:
  * Check for xxx/Trace.axd *
  if (len >=10 && !strcmp ("axd", ext + 1))
  return !strncmp ("/Trace", ext - 6, 6);
  return !strcmp ("rem", ext + 1);
  case 4:
  extensions = (const char **) known_extensions4;
  while (*extensions != NULL) {
  if (!strcmp (*extensions, ext + 1))
  return TRUE;
  extensions++;
  }
  break;
  case 5:
  return !strcmp ("config", ext + 1);
  }

  return FALSE;
  }
*/

/* 
 * Compute real path directory and all the directories above that up to the first filesystem
 * change */

static int
mono_handler (request_rec *r)
{
	module_cfg *config;

	if (r->handler != NULL && !strcmp (r->handler, "mono")) {
		DEBUG_PRINT (1, "handler: %s", r->handler);
		return mono_execute_request (r, FALSE);
	}

	if (!r->content_type || strcmp (r->content_type, "application/x-asp-net"))
		return DECLINED;

	config = ap_get_module_config (r->server->module_config, &mono_module);
	if (!config->auto_app)
		return DECLINED;

	/*
	  if (FALSE == check_file_extension (r->filename))
	  return DECLINED;
	*/

	/* Handle on-demand created applications */
	return mono_execute_request (r, TRUE);
}

/*
 * It is assumed that this function is called with the dashboard mutex held. This is not required when calling it from the module
 * init handler, as there's only one process running at that time.
 */
static void
start_xsp (module_cfg *config, int is_restart, char *alias)
{
	/* 'alias' may be NULL to start all XSPs */
	apr_socket_t *sock;
	apr_status_t rv;
	char *termstr = "";
	xsp_data *xsp;
	int i;

	/*****
	 * NOTE: we might be trying to start the same mod-mono-server in several
	 * different apache child processes. xsp->status tries to help avoiding this
	 * and mod-mono-server uses a lock that checks for same command line, same
	 * user...
	 *****/
	for (i = 0; i < config->nservers; i++) {
		xsp = &config->servers [i];
		if (xsp->run_xsp && !strcasecmp (xsp->run_xsp, "false"))
			continue;

		if (xsp->status != FORK_NONE)
			continue;
		
		/* If alias isn't null, skip XSPs that don't have that alias. */
		if (alias != NULL && strcmp (xsp->alias, alias))
			continue;

		if (!strcmp ("XXGLOBAL", xsp->alias) && config->auto_app == FALSE)
			continue;

#ifdef APACHE13
		sock = apr_pcalloc (pconf, sizeof (apr_socket_t));
#endif
		rv = setup_socket (&sock, xsp, pconf);

		if (rv == APR_SUCCESS) {
			/* connected */
			DEBUG_PRINT (0, "connected %s", xsp->alias);
			if (is_restart) {
				write_data (sock, termstr, 1);
				apr_socket_close (sock);
				apr_sleep (apr_time_from_sec (2));
				i--;
				continue; /* Wait for the previous to die */
			}
			apr_socket_close (sock);
			xsp->status = FORK_SUCCEEDED;
		} else {
			apr_socket_close (sock);
			/* need fork */
			xsp->status = FORK_INPROCESS;
			DEBUG_PRINT (0, "forking %s", xsp->alias);
			fork_mod_mono_server (pconf, xsp);
			xsp->status = FORK_SUCCEEDED;
#ifndef APACHE13
			if (xsp->dashboard) {
				xsp->dashboard->start_time = time (NULL);
				xsp->dashboard->handled_requests = 0;
				xsp->dashboard->restart_issued = 0;
			}
#endif
		}
	}
}

static apr_status_t
terminate_xsp2 (void *data, char *alias, int for_restart, int lock_held)
{
	/* alias may be NULL to terminate all XSPs */
	server_rec *server;
	module_cfg *config;
	apr_socket_t *sock;
	apr_status_t rv;
	char *termstr = "";
	xsp_data *xsp;
	int i;
#ifndef APACHE13
	int release_lock = 0;
#endif
	
	DEBUG_PRINT (0, "Terminate XSP");
	server = (server_rec *) data;
	config = ap_get_module_config (server->module_config, &mono_module);

	for (i = 0; i < config->nservers; i++) {
		xsp = &config->servers [i];
		if (xsp->run_xsp && !strcasecmp (xsp->run_xsp, "false"))
			continue;

		/* If alias isn't null, skip XSPs that don't have that alias. */
		if (alias != NULL && strcmp(xsp->alias, alias))
			continue;
		
#ifdef APACHE13
		sock = apr_pcalloc (pconf, sizeof (apr_socket_t));
#endif
		rv = setup_socket (&sock, xsp, pconf);
		if (rv == APR_SUCCESS) {
			write_data (sock, termstr, 1);
			apr_socket_close (sock);
		}

		if (xsp->listen_port == NULL) {
			char *fn = xsp->filename;

			if (fn == NULL)
				fn = get_default_socket_name (pconf, xsp->alias, SOCKET_FILE);

			remove (fn); /* Don't bother checking error */
		}

#ifndef APACHE13
		/* destroy the dashboard */     
		if (!for_restart && xsp->dashboard_shm) {
			DEBUG_PRINT (0, "Destroying dashboard for %s", xsp->alias);
			if (!lock_held && xsp->dashboard_mutex) {
				rv = apr_global_mutex_lock (xsp->dashboard_mutex);
				if (rv != APR_SUCCESS)
					ap_log_error (APLOG_MARK, APLOG_ALERT, STATCODE_AND_SERVER (rv),
						      "Failed to acquire dashboard lock before destroying the dashboard");
				else
					release_lock = 1;
			}
			
			if (xsp->dashboard_shm) { // it might've been released while we had been waiting
						  // for the lock
				rv = apr_shm_detach (xsp->dashboard_shm);
				if (rv != APR_SUCCESS)
					ap_log_error (APLOG_MARK, APLOG_WARNING, STATCODE_AND_SERVER (rv),
						      "Failed to detach from the '%s' shared memory dashboard",
						      xsp->dashboard_file);
				
				rv = apr_shm_destroy (xsp->dashboard_shm);
				if (rv != APR_SUCCESS)
					ap_log_error (APLOG_MARK, APLOG_WARNING, STATCODE_AND_SERVER (rv),
						      "Failed to destroy the '%s' shared memory dashboard",
						      xsp->dashboard_file);
			}
			
			if (release_lock) {
				rv = apr_global_mutex_unlock (xsp->dashboard_mutex);
				if (rv != APR_SUCCESS)
					ap_log_error (APLOG_MARK, APLOG_WARNING, STATCODE_AND_SERVER (rv),
						      "Failed to release dashboard lock after destroying the dashboard");
			}
			
			xsp->dashboard_shm = NULL;
			xsp->dashboard = NULL;
		}

		if (!for_restart && xsp->dashboard_mutex) {
			DEBUG_PRINT (0, "Destroying dasboard mutex %s", xsp->dashboard_lock_file);
			rv = apr_global_mutex_destroy (xsp->dashboard_mutex);
			if (rv != APR_SUCCESS)
				ap_log_error (APLOG_MARK, APLOG_WARNING, STATCODE_AND_SERVER (rv),
					      "Failed to destroy the dashboard mutex '%s'",
					      xsp->dashboard_lock_file);
			else
				xsp->dashboard_mutex = NULL;
		}
		
		xsp->status = FORK_NONE;
#endif
	}
	
	apr_sleep (apr_time_from_sec (1));
	return APR_SUCCESS;
}

static apr_status_t
terminate_xsp (void *data)
{
	DEBUG_PRINT (0, "Cleaning up for shutdown");
	return terminate_xsp2(data, NULL, 0, 0);
}

static int
mono_control_panel_handler (request_rec *r)
{
	module_cfg *config;
	apr_uri_t *uri;
	xsp_data *xsp;
	int i;
	char *buffer;
#ifndef APACHE13
	apr_status_t rv;
#endif
	
	if (strcmp (r->handler, "mono-ctrl"))
		return DECLINED;

	DEBUG_PRINT (1, "control panel handler: %s", r->handler);

	config = ap_get_module_config (r->server->module_config, &mono_module);
	
	set_response_header (r, "Content-Type", "text/html");

	request_send_response_string (r, "<html><body>\n");
	request_send_response_string (r, "<h1 style=\"text-align: center;\">mod_mono Control Panel</h1>\n");
	
	uri = &r->parsed_uri;
	if (!uri->query || !strcmp (uri->query, "")) {
		/* No query string -> Emit links for configuration commands. */
		request_send_response_string (r, "<ul style=\"text-align: center;\">\n");
		request_send_response_string (r, "<li><a href=\"?restart=ALL\">Restart all mod-mono-server processes</a></li>\n");

		for (i = 0; i < config->nservers; i++) {
			xsp = &config->servers [i];
			if (xsp->run_xsp && !strcasecmp (xsp->run_xsp, "false"))
				continue;

			buffer = apr_psprintf (r->pool, "<li>%s: <a href=\"?restart=%s\">"
					       "Restart Server</a>", xsp->alias, xsp->alias);
			request_send_response_string(r, buffer);

#ifndef APACHE13
			ensure_dashboard_initialized (config, xsp, pconf);
			if (xsp->dashboard_mutex) {
				rv = apr_global_mutex_lock (xsp->dashboard_mutex);
				if (rv == APR_SUCCESS) {
					if (xsp->restart_mode == AUTORESTART_MODE_REQUESTS) {
						buffer = apr_psprintf (r->pool, " [%d requests served; limit: %d]",
								       xsp->dashboard->handled_requests, xsp->restart_requests);
						request_send_response_string(r, buffer);
					} else if (xsp->restart_mode == AUTORESTART_MODE_TIME) {
						buffer = apr_psprintf (r->pool, " [%ds time running; limit: %ds]",
								       (int)(time(NULL) - xsp->dashboard->start_time), (int)xsp->restart_time);
						request_send_response_string(r, buffer);
					}

					rv = apr_global_mutex_unlock (xsp->dashboard_mutex);
					if (rv != APR_SUCCESS)
						ap_log_error (APLOG_MARK, APLOG_ALERT, STATCODE_AND_SERVER (rv),
							      "Failed to release %s lock after mono-ctrl output, the process may deadlock!",
							      xsp->dashboard_lock_file);
				}
			}
#endif
			
			request_send_response_string(r, "</li>\n");
		}
		
		request_send_response_string (r, "</ul>\n");
	} else {
		if (uri->query && !strncmp (uri->query, "restart=", 8)) {
			/* Restart the mod-mono-server processes */
			char *alias = uri->query + 8; /* +8 == .Substring(8) */
			if (!strcmp (alias, "ALL"))
				alias = NULL;
			terminate_xsp2 (r->server, alias, 1, 0); 
			start_xsp (config, 1, alias);
			request_send_response_string (r, "<div style=\"text-align: center;\">mod-mono-server processes restarted.</div><br>\n");
		} else {
			/* Invalid command. */
			request_send_response_string (r, "<div style=\"text-align: center;\">Invalid query string command.</div>\n");
		}
	
		request_send_response_string (r, "<div style=\"text-align: center;\"><a href=\"?\">Return to Control Panel</a></div>\n");
	}
	
	request_send_response_string(r, "</body></html>\n");

	DEBUG_PRINT (2, "Done.");
	return OK;
}

#ifdef APACHE13
static void
mono_init_handler (server_rec *s, pool *p)
{
#if defined (APR_HAS_USER) && !defined (WIN32)
	module_cfg *config;
#endif
  
	if (ap_standalone && ap_restart_time == 0)
		return;

	DEBUG_PRINT (0, "Initializing handler");
	ap_add_version_component ("mod_mono/" VERSION);
	pconf = p;
	ap_register_cleanup (p, s, (void (*)(void *)) terminate_xsp, ap_null_cleanup);
  
#if defined (APR_HAS_USER) && !defined (WIN32)
	config = ap_get_module_config (s->module_config, &mono_module);
	start_xsp (config, 0, NULL);
#endif
}
#else
static int
mono_init_handler (apr_pool_t *p,
		   apr_pool_t *plog,
		   apr_pool_t *ptemp,
		   server_rec *s)
{
	void *data;
	const char *userdata_key = "mono_module_init";
#if defined (APR_HAS_USER) && !defined (WIN32)
	module_cfg *config;
#endif
  
	/*
	 * mono_init_handler() will be called twice, and if it's a DSO then all
	 * static data from the first call will be lost. Only set up our static
	 * data on the second call.
	 */
	apr_pool_userdata_get (&data, userdata_key, s->process->pool);
	if (!data) {
		apr_pool_userdata_set ((const void *) 1, userdata_key,
				       apr_pool_cleanup_null, s->process->pool);
		return OK;
	}

	DEBUG_PRINT (0, "Initializing handler");
	ap_add_version_component (p, "mod_mono/" VERSION);
	pconf = s->process->pconf;
	apr_pool_cleanup_register (pconf, s, terminate_xsp, apr_pool_cleanup_null);

#if defined (APR_HAS_USER) && !defined (WIN32)
	config = ap_get_module_config (s->module_config, &mono_module);
	start_xsp (config, 0, NULL);
#endif
  
	return OK;
}
#endif

#if !defined (APR_HAS_USER) || defined (WIN32)
void
mono_child_init (
#ifdef APACHE2
	apr_pool_t *p, server_rec *s
#else
	server_rec *s, apr_pool_t *p
#endif
)
{
	module_cfg *config;
	
	DEBUG_PRINT (0, "Mono Child Init");
	config = ap_get_module_config (s->module_config, &mono_module);
	start_xsp (config, 0, NULL);
}
#endif

#ifdef APACHE13
static const handler_rec mono_handlers [] = {
	{ "mono", mono_handler },
	{ "application/x-asp-net", mono_handler },
	{ "mono-ctrl", mono_control_panel_handler },
	{ NULL, NULL }
};
#else
static void
mono_register_hooks (apr_pool_t * p)
{
	ap_hook_handler (mono_handler, NULL, NULL, APR_HOOK_FIRST);
	ap_hook_handler (mono_control_panel_handler, NULL, NULL, APR_HOOK_FIRST);
	ap_hook_post_config (mono_init_handler, NULL, NULL, APR_HOOK_MIDDLE);
#if !defined (APR_HAS_USER) || defined (WIN32)
	ap_hook_child_init (mono_child_init, NULL, NULL, APR_HOOK_MIDDLE);
#endif
}
#endif

static const command_rec mono_cmds [] = {
	MAKE_CMD12 (MonoUnixUmask, umask_value,
		    "Value of the file mode creation mask (see umask(2))"
		    "Default: 0077"
	),
	MAKE_CMD12 (MonoUnixSocket, filename,
		    "Named pipe file name. Mutually exclusive with MonoListenPort. "
		    "Default: /tmp/mod_mono_server"
	),

	MAKE_CMD12 (MonoListenPort, listen_port,
		    "TCP port on which mod-mono-server should listen/is listening on. Mutually "
		    "exclusive with MonoUnixSocket. "
		    "When this options is specified, "
		    "mod-mono-server and mod_mono will use a TCP socket for communication. "
		    "Default: none"
	),

	MAKE_CMD12 (MonoListenAddress, listen_address,
		    "IP address where mod-mono-server should listen/is listening on. Can "
		    "only be used when MonoListenPort is specified."
		    "Default: \"127.0.0.1\""
	),

	MAKE_CMD12 (MonoRunXSP, run_xsp,
		    "It can be False or True. If it is True, asks the module to "
		    "start mod-mono-server.exe if it's not already there. Default: True"
	),

	MAKE_CMD12 (MonoXSPStartAttempts, start_attempts,
		    "Number of attempts to make when a backend is found to be dead. "
		    "Cannot be less than 0. Default: 3"),

	MAKE_CMD12 (MonoXSPStartWaitTime, start_wait_time,
		    "Number of seconds to wait for the backend to come up. Cannot be less "
		    "than 2. Default: 2"),

	MAKE_CMD12 (MonoExecutablePath, executable_path,
		    "(Obsolete) If MonoRunXSP is True, this is the full path where mono is located. "
		    "Default: /usr/bin/mono"
	),

	MAKE_CMD12 (MonoPath, path,
		    "If MonoRunXSP is True, this will be the content of MONO_PATH "
		    "environment variable. Default: \"\""
	),

	MAKE_CMD12 (MonoServerPath, server_path,
		    "If MonoRunXSP is True, this is the full path to the mod-mono-server script. "
		    "Default: " MODMONO_SERVER_PATH
	),

	MAKE_CMD12 (MonoApplications, applications,
		    "Comma separated list with virtual directories and real directories. "
		    "One ASP.NET application will be created for each pair. Default: \"\" "
	),

	MAKE_CMD12 (MonoWapiDir, wapidir,
		    "The directory where mono runtime will create the '.wapi' directory "
		    "used to emulate windows I/O. It's used to set MONO_SHARED_DIR. "
		    "Default value: \"/tmp\""
	),

	MAKE_CMD12 (MonoDocumentRootDir, document_root,
		    "The argument passed in --root argument to mod-mono-server. "
		    "This tells mod-mono-server to change the directory to the "
		    "value specified before doing anything else. Default: /"
	),

	MAKE_CMD12 (MonoApplicationsConfigFile, appconfig_file,
		    "Adds application definitions from the  XML configuration file. "
		    "See Appendix C for details on the file format. "
		    "Default value: \"\""
	),

	MAKE_CMD12 (MonoApplicationsConfigDir, appconfig_dir,
		    "Adds application definitions from all XML files found in the "
		    "specified directory DIR. Files must have '.webapp' extension. "
		    "Default value: \"\""
	),

#ifndef HAVE_SETRLIMIT
	MAKE_CMD12 (MonoMaxMemory, max_memory,
		    "If MonoRunXSP is True, the maximum size of the process's data segment "
		    "(data size) in bytes allowed for the spawned mono process. It will "
		    "be restarted when the limit is reached.  .. but your system doesn't "
		    "support setrlimit. Sorry, this feature will not be available. "
		    "Default value: system default"
	),
#else
	MAKE_CMD12 (MonoMaxMemory, max_memory,
		    "If MonoRunXSP is True, the maximum size of the process's data "
		    "segment (data size) in bytes allowed "
		    "for the spawned mono process. It will be restarted when the limit "
		    "is reached."
		    " Default value: system default"
	),
#endif

#ifndef HAVE_SETRLIMIT
	MAKE_CMD12 (MonoMaxCPUTime, max_cpu_time,
		    "If MonoRunXSP is True, CPU time limit in seconds allowed for "
		    "the spawned mono process. Beyond that, it will be restarted."
		    ".. but your system doesn't support setrlimit. Sorry, this feature "
		    "will not be available."
		    " Default value: system default"
	),
#else
	MAKE_CMD12 (MonoMaxCPUTime, max_cpu_time,
		    "If MonoRunXSP is True, CPU time limit in seconds allowed for "
		    "the spawned mono process. Beyond that, it will be restarted."
		    " Default value: system default"
	),
#endif
	MAKE_CMD12 (MonoDebug, debug,
		    "If MonoDebug is true, mono will be run in debug mode."
		    " Default value: False"
	),

	MAKE_CMD12 (MonoSetEnv, env_vars,
		    "A string of name=value pairs separated by semicolons."
		    "For each pair, setenv(name, value) is called before running "
		    "mod-mono-server."
		    " Default value: Default: \"\""
	),

	MAKE_CMD_ITERATE2 (AddMonoApplications, applications,
			   "Appends an application."
	),

	MAKE_CMD_ACCESS (MonoSetServerAlias, set_alias,
			 "Uses the server named by this alias inside this Directory/Location."
	),
	MAKE_CMD1 (MonoAutoApplication, set_auto_application,
		   "Disables automatic creation of applications. "
		   "Default value: 'Disabled' if there's any other application for the server. "
		   "'Enabled' otherwise."
	),
	MAKE_CMD12 (MonoAutoRestartMode, restart_mode,
		    "Set the auto-restart mode for the backend(s). Three modes are available: "
		    "None - do not auto-restart, Requests - restart after a configured number of "
		    "requests served, Time - restart after the backend has been up for the specified "
		    "period of time. Default value: None"),
	MAKE_CMD12 (MonoAutoRestartRequests, restart_requests,
		    "Number of requests for a backend to serve before auto-restarting. The value here "
		    "is taken into account only when MonoAutoRestartMode is set to Requests. "
		    "Default value: 10000"),
	MAKE_CMD12 (MonoAutoRestartTime, restart_time,
		    "Time after which the backend should be auto-restarted. The time format is: "
		    "DD[:HH[:MM[:SS]]]. Default value: 00:12:00:00"),
	MAKE_CMD12 (MonoFlushOnWrite, flushOnWrite,
		    "If MonoFlushOnWrite is true, mod_mono will flush the Apache output buffers on "
		    "every write. Note that Apache2 supports a notion of output filters, which will be "
		    "invoked on every write if this option is set to true. This may have a severe impact "
		    "on your application performance. "
		    "Default: False"),
	{ NULL }
};

#ifdef APACHE13
module MODULE_VAR_EXPORT mono_module =
{
	STANDARD_MODULE_STUFF,
	mono_init_handler,		/* initializer */
	create_dir_config,		/* dir config creater */
	NULL,			/* dir merger --- default is to override */
	create_mono_server_config,	/* server config */
	merge_config,		/* merge server configs */
	mono_cmds,			/* command table */
	mono_handlers,		/* handlers */
	NULL,                       /* filename translation */
	NULL,                       /* check_user_id */
	NULL,                       /* check auth */
	NULL,                       /* check access */
	NULL,                       /* type_checker */
	NULL,			/* fixups */
	NULL,                       /* logger */
	NULL,                       /* header parser */
#if !defined (APR_HAS_USER) || defined (WIN32)
	mono_child_init,		/* child_init */
#endif
	NULL,                       /* child_exit */
	NULL                        /* post read-request */
};
#else
module AP_MODULE_DECLARE_DATA mono_module = {
	STANDARD20_MODULE_STUFF,
	create_dir_config,		/* dir config creater */
	NULL,				/* dir merger --- default is to override */
	create_mono_server_config,	/* server config */
	merge_config,			/* merge server configs */
	mono_cmds,			/* command apr_table_t */
	mono_register_hooks		/* register hooks */
};
#endif

