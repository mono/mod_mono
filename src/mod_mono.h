/*
 * mod_mono.h
 *
 * Authors:
 *	Daniel Lopez Ridruejo
 *	Gonzalo Paniagua Javier
 *      Marek Habersack
 *
 * Copyright (c) 2002 Daniel Lopez Ridruejo
 *           (c) 2002-2009 Novell, Inc.
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
#ifndef __MOD_MONO_H
#define __MOD_MONO_H

#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifndef WIN32
#include <sys/select.h>
#include <sys/un.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include "httpd.h"
#include "http_core.h"
#include "http_log.h"
#include "http_config.h"

#if !defined (WIN32) && !defined (OS2) && !defined (BEOS) && !defined (NETWARE)
#define HAVE_UNIXD
#include "unixd.h"
#endif

/* KEEP IN SYNC WITH ModMonoRequest!! */
#define PROTOCOL_VERSION 9

#define STATCODE_AND_SERVER(__code__) __code__, NULL
#include <http_protocol.h>
#include <http_request.h>
#include <util_script.h>
#include <apr_version.h>
#include <apr_strings.h>
#include <apr_support.h>
#include <apr_shm.h>

#if APR_MAJOR_VERSION <= 0
#define APR_SOCKET_CREATE(sock, family, type, protocol, pool) apr_socket_create (sock, family, type, pool)
#else
#define APR_SOCKET_CREATE(sock, family, type, protocol, pool) apr_socket_create (sock, family, type, protocol, pool)
#endif

#define STATUS_AND_SERVER STATCODE_AND_SERVER (0)

/* Some defaults */
#ifndef MONO_PREFIX
#define MONO_PREFIX "/usr"
#endif

#ifdef WIN32
#define DIRECTORY_SEPARATOR	"\\"
#else
#define DIRECTORY_SEPARATOR	"/"
#endif

#define MODMONO_SERVER_BASEPATH MONO_PREFIX "/bin/mod-mono-server"
#define MONO_DEFAULT_FRAMEWORK  "2.0"
#define MODMONO_SERVER_PATH	MODMONO_SERVER_BASEPATH "2"
#define WAPIDIR			"/tmp"
#define DOCUMENT_ROOT		NULL
#define APPCONFIG_FILE		NULL
#define APPCONFIG_DIR		NULL
#define SOCKET_FILE		"/tmp/mod_mono_server"
#define LISTEN_ADDRESS		"127.0.0.1"
#define DASHBOARD_FILE		"/tmp/mod_mono_dashboard"
#define GLOBAL_SERVER_NAME	"XXGLOBAL"
#define MAX_ACTIVE_REQUESTS	150
#define MAX_WAITING_REQUESTS	150
#define START_ATTEMPTS		3
#define START_WAIT_TIME		2

#ifndef DEFAULT_RESTART_REQUESTS
#define DEFAULT_RESTART_REQUESTS 10000
#endif

#ifndef DEFAULT_RESTART_TIME
#define DEFAULT_RESTART_TIME 43200
#endif

/* Converts every int sent into little endian */
#ifdef MODMONO_BIGENDIAN
#define INT_FROM_LE(val) LE_FROM_INT (val)
#define LE_FROM_INT(val)	((uint32_t) ( \
    (((uint32_t) (val) & (uint32_t) 0x000000ffU) << 24) | \
    (((uint32_t) (val) & (uint32_t) 0x0000ff00U) <<  8) | \
    (((uint32_t) (val) & (uint32_t) 0x00ff0000U) >>  8) | \
    (((uint32_t) (val) & (uint32_t) 0xff000000U) >> 24)))

#else
#define LE_FROM_INT(val) val
#define INT_FROM_LE(val) val
#endif

/* Commands */
enum Cmd {
	FIRST_COMMAND,
	SEND_FROM_MEMORY = 0,
	GET_SERVER_VARIABLES,
	SET_RESPONSE_HEADERS,
	GET_LOCAL_PORT,
	CLOSE,
	SHOULD_CLIENT_BLOCK,
	SETUP_CLIENT_BLOCK,
	GET_CLIENT_BLOCK,
	SET_STATUS,
	DECLINE_REQUEST,
	MYNOT_FOUND, /* apache 1.3 already defines NOT_FOUND */
	IS_CONNECTED,
	SEND_FILE,
	SET_CONFIGURATION,
	LAST_COMMAND
};

static char *cmdNames [] = {
	"SEND_FROM_MEMORY",
	"GET_SERVER_VARIABLES",
	"SET_RESPONSE_HEADERS",
	"GET_LOCAL_PORT",
	"CLOSE",
	"SHOULD_CLIENT_BLOCK",
	"SETUP_CLIENT_BLOCK",
	"GET_CLIENT_BLOCK",
	"SET_STATUS",
	"DECLINE_REQUEST",
	"NOT_FOUND",
	"IS_CONNECTED",
	"SEND_FILE",
	"SET_CONFIGURATION"
};

/* Module definition */
#define DEFINE_MODULE(x) module AP_MODULE_DECLARE_DATA x

/* Directives */
#define MAKE_CMD_ACCESS(name, function_name, description) \
	AP_INIT_TAKE1 (#name, function_name, NULL, ACCESS_CONF, description)

#define MAKE_CMD1(name, function_name, description) \
	AP_INIT_TAKE1 (#name, function_name, NULL, RSRC_CONF, description)

#define MAKE_CMD12(name, field_name, description) \
	AP_INIT_TAKE12 (#name, store_config_xsp, \
	(void *) APR_OFFSETOF (xsp_data, field_name), RSRC_CONF, description)

#define MAKE_CMD_ITERATE2(name, field_name, description) \
	AP_INIT_ITERATE2 (#name, store_config_xsp, \
	(void *) APR_OFFSETOF (xsp_data, field_name), RSRC_CONF, description)

#ifndef AF_UNSPEC
#define AF_UNSPEC 0
#endif

/* Debugging */
#ifdef DEBUG
#define DEBUG_PRINT(a,...) \
	if (a >= DEBUG_LEVEL) { \
		errno = 0; \
		ap_log_error (APLOG_MARK, APLOG_WARNING, STATUS_AND_SERVER, \
				__VA_ARGS__); \
	}
#else
#define DEBUG_PRINT dummy_print
static void
dummy_print (int a, ...)
{
}
#endif /* DEBUG */

#endif /* __MOD_MONO_H */

