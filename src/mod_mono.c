/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2002 Daniel Lopez Ridruejo.
 *           (c) 2002 Ximian, Inc.
 *           All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by 
 *        Daniel Lopez Ridruejo (daniel@rawbyte.com) and
 *        Ximian Inc. (http://www.ximian.com)"
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The name "mod_mono" must not be used to endorse or promote products 
 *    derived from this software without prior written permission. For written
 *    permission, please contact daniel@rawbyte.com.
 *
 * 5. Products derived from this software may not be called "mod_mono",
 *    nor may "mod_mono" appear in their name, without prior written
 *    permission of Daniel Lopez Ridruejo and Ximian Inc.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL DANIEL LOPEZ RIDRUEJO OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 */

#include <httpd.h>
#include <http_core.h>
#include <http_protocol.h>
#include <http_config.h>
#include <http_log.h>
#include <mono/jit/jit.h>
#include <mono/metadata/appdomain.h>
#include <mono/metadata/debug-helpers.h>
#include <mod_mono_config.h>

#define MODMONO_MAGIC_TYPE "application/x-httpd-mono"

module AP_MODULE_DECLARE_DATA mono_module;

#define EXPOSE_REQUEST_FIELD_STRING_GET(funcname, fieldname) static MonoString * funcname (request_rec *r) {  return mono_string_new(mono_domain_get(), r->fieldname);}

#define EXPOSE_REQUEST_FIELD_STRING_SET(funcname, fieldname) static void funcname (request_rec *r, MonoString *value) { r->fieldname = (char *)apr_pstrdup(r->pool, (const char *)mono_string_to_utf8(value));}

#define EXPOSE_REQUEST_FIELD_INT_GET(funcname, fieldname) static int funcname (request_rec *r) {  return r->fieldname; }
#define EXPOSE_REQUEST_FIELD_INT_SET(funcname, fieldname) static void funcname (request_rec *r, int value) { r->fieldname = value; }

#define EXPOSE_CONNECTION_FIELD_STRING_GET(funcname, fieldname) static MonoString * funcname (conn_rec *c) {  return mono_string_new(mono_domain_get(), c->fieldname);}


EXPOSE_REQUEST_FIELD_STRING_GET(mono_apache_request_get_request, the_request);
EXPOSE_REQUEST_FIELD_STRING_GET(mono_apache_request_get_protocol, protocol);
EXPOSE_REQUEST_FIELD_STRING_GET(mono_apache_request_get_hostname, hostname);
EXPOSE_REQUEST_FIELD_STRING_GET(mono_apache_request_get_status_line, status_line);
EXPOSE_REQUEST_FIELD_STRING_SET(mono_apache_request_set_status_line, status_line);
EXPOSE_REQUEST_FIELD_STRING_GET(mono_apache_request_get_method, method);
EXPOSE_REQUEST_FIELD_STRING_GET(mono_apache_request_get_range, range);
EXPOSE_REQUEST_FIELD_STRING_GET(mono_apache_request_get_content_type, content_type);
EXPOSE_REQUEST_FIELD_STRING_GET(mono_apache_request_get_handler, handler);
EXPOSE_REQUEST_FIELD_STRING_GET(mono_apache_request_get_content_encoding, content_encoding);
EXPOSE_REQUEST_FIELD_STRING_GET(mono_apache_request_get_user, user);
EXPOSE_REQUEST_FIELD_STRING_GET(mono_apache_request_get_auth_type, ap_auth_type);
EXPOSE_REQUEST_FIELD_STRING_GET(mono_apache_request_get_unparsed_uri, unparsed_uri);
EXPOSE_REQUEST_FIELD_STRING_GET(mono_apache_request_get_uri, uri);
EXPOSE_REQUEST_FIELD_STRING_GET(mono_apache_request_get_filename, filename);
EXPOSE_REQUEST_FIELD_STRING_GET(mono_apache_request_get_canonical_filename, canonical_filename);
EXPOSE_REQUEST_FIELD_STRING_GET(mono_apache_request_get_path_info, path_info);
EXPOSE_REQUEST_FIELD_STRING_GET(mono_apache_request_get_args, args);

EXPOSE_REQUEST_FIELD_INT_GET(mono_apache_request_get_status_code, status);
EXPOSE_REQUEST_FIELD_INT_SET(mono_apache_request_set_status_code, status);

EXPOSE_CONNECTION_FIELD_STRING_GET(mono_apache_connection_get_remote_address, remote_ip);
EXPOSE_CONNECTION_FIELD_STRING_GET(mono_apache_connection_get_local_address, local_ip);

typedef struct {
  const char *virtual;
  const char *app_base_dir;
} modmono_server_rec;

static int alias_matches_managed(MonoString *uri, MonoString *alias_fakename) {
  return alias_matches(mono_string_to_utf8(uri),
		       mono_string_to_utf8(alias_fakename));
}

/* From mod_alias */
static int alias_matches(const char *uri, const char *alias_fakename)
{
  const char *aliasp= alias_fakename , *urip = uri;
  while (*aliasp) {
    if (*aliasp == '/') {
      /* any number of '/' in the alias matches any number in
       * the supplied URI, but there must be at least one...
       */
      if (*urip != '/')
	return 0;

      do {
	++aliasp;
      } while (*aliasp == '/');
      do {
	++urip;
      } while (*urip == '/');
    }
    else {
      /* Other characters are compared literally */
      if (*urip++ != *aliasp++)
	return 0;
    }
  }

  /* Check last alias path component matched all the way */

  if (aliasp[-1] != '/' && *urip != '\0' && *urip != '/')
    return 0;
  /* Return number of characters from URI which matched (may be
   * greater than length of alias, since we may have matched
   * doubled slashes)
   */

  return urip - uri;
}


static MonoObject *ApacheApplicationHost;

/* For now we only allow one application domain */
static const char *modmono_application_directive(cmd_parms *cmd, void *config,
						 const char *virtual, const char *app_base_dir)
{
  modmono_server_rec *server_rec = (modmono_server_rec *)
    ap_get_module_config(cmd->server->module_config,
			 &mono_module);
  /* TODO: Check they are sensible, they exist, etc. */
  server_rec->virtual = virtual;
  server_rec->app_base_dir = app_base_dir;
  return NULL;
}


static void *create_modmono_server_config(apr_pool_t *p, server_rec *s)
{
  modmono_server_rec *new_config = (modmono_server_rec *)
  apr_pcalloc(p, sizeof(*new_config));
  return new_config;
}



static void mono_apache_request_send_response_from_memory (request_rec *r, MonoArray* byteArray, int size)
{
  ap_rwrite((const void*)mono_array_to_lparray(byteArray), size, r);
}

/*Not connection because actual port will vary depending on Apache configuration*/
static guint16 mono_apache_request_get_server_port (request_rec *r) {
  return (guint16)ap_get_server_port(r);
}

static guint16 mono_apache_connection_get_remote_port (conn_rec *c) {
  apr_port_t port;
  apr_sockaddr_port_get(&port, c->remote_addr);
  return (guint16)port;
}

static guint16 mono_apache_connection_get_local_port (conn_rec *c) {
  apr_port_t port;
  apr_sockaddr_port_get(&port, c->local_addr);
  return (guint16)port;
}
static MonoString *mono_apache_connection_get_remote_name (request_rec *r) {
  return mono_string_new(mono_domain_get(),  ap_get_remote_host(r->connection, r->per_dir_config,
                                              REMOTE_NAME, NULL));
}

static void mono_apache_connection_flush (conn_rec *c) {
  ap_flush_conn(c);
}

static void mono_apache_request_set_response_header(request_rec *r, MonoString *header_name, MonoString *header_value) {
  char *name = mono_string_to_utf8(header_name);
  char *value = mono_string_to_utf8(header_value);
  /* Is there a more efficient way to do this w/o breaking encapsulation at HttpWorkerRequest level?. 
   Apache requires content_type to be set and will insert content type header itself later on.
   -- daniel
  */
  if (!strcmp(name,"Content-Type")) {
    r->content_type = value;
  } else {
    apr_table_setn(r->headers_out, name, value);
  }
}

static MonoString *mono_apache_request_get_request_header(request_rec *r, MonoString *header_name) {
    char *header = apr_table_get(r->headers_in, mono_string_to_utf8(header_name));
    return header ? mono_string_new(mono_domain_get(),header) : NULL;
}

static conn_rec *mono_apache_request_get_connection (request_rec *r) {
  return r->connection;
}

static void mono_apache_connection_close (conn_rec *c) {
  ap_lingering_close(c);
}

static MonoString *mono_apache_request_get_server_variable(request_rec *r, MonoString *name) {
  return mono_string_new(mono_domain_get(), apr_table_get(r->subprocess_env, mono_string_to_utf8(name)));
}

static MonoString *mono_apache_request_get_path_translated(request_rec *r) {
  return mono_string_new(mono_domain_get(), ap_make_dirstr_parent(r->pool, r->filename));
}

static MonoString *mono_apache_request_get_query_string(request_rec *r) {
  return mono_string_new(mono_domain_get(), r->parsed_uri.query ? r->parsed_uri.query : "");
}

static int mono_apache_should_client_block( request_rec *r ) {
  return  r->read_length || ap_should_client_block(r);
}

static int mono_apache_setup_client_block( request_rec *r ) {
  if (r->read_length) {
    return APR_SUCCESS;
  } else {
    return ap_setup_client_block(r, REQUEST_CHUNKED_ERROR);
  }
}

static int mono_apache_get_client_block( request_rec *r, MonoArray *byteArray, apr_size_t size ) {
  return ap_get_client_block(r, (char *)mono_array_to_lparray(byteArray), size);
}

void register_wrappers () {
  mono_add_internal_call("Apache.Web.Request::GetHttpVersionInternal", mono_apache_request_get_protocol);
  mono_add_internal_call("Apache.Web.Request::GetHttpVerbNameInternal", mono_apache_request_get_method);
  mono_add_internal_call("Apache.Web.Request::SendResponseFromMemoryInternal", mono_apache_request_send_response_from_memory);
  mono_add_internal_call("Apache.Web.Request::GetConnectionInternal", mono_apache_request_get_connection);
  mono_add_internal_call("Apache.Web.Request::GetPathInfoInternal", mono_apache_request_get_path_info);
  mono_add_internal_call("Apache.Web.Request::GetServerVariableInternal", mono_apache_request_get_server_variable);
  mono_add_internal_call("Apache.Web.Request::GetAppPathTranslatedInternal", mono_apache_request_get_path_translated);
  mono_add_internal_call("Apache.Web.Request::GetServerPortInternal", mono_apache_request_get_server_port);
  mono_add_internal_call("Apache.Web.Request::SetResponseHeaderInternal", mono_apache_request_set_response_header);
  mono_add_internal_call("Apache.Web.Request::GetRequestHeaderInternal", mono_apache_request_get_request_header);
  mono_add_internal_call("Apache.Web.Request::GetFileNameInternal", mono_apache_request_get_filename);
  mono_add_internal_call("Apache.Web.Request::GetUriInternal", mono_apache_request_get_uri);
  mono_add_internal_call("Apache.Web.Request::GetQueryStringInternal", mono_apache_request_get_query_string);
  mono_add_internal_call("Apache.Web.Request::GetRemoteAddressInternal", mono_apache_connection_get_remote_address);
  mono_add_internal_call("Apache.Web.Request::GetLocalAddressInternal", mono_apache_connection_get_local_address);
  mono_add_internal_call("Apache.Web.Request::GetRemotePortInternal", mono_apache_connection_get_remote_port);
  mono_add_internal_call("Apache.Web.Request::GetLocalPortInternal", mono_apache_connection_get_local_port);
  mono_add_internal_call("Apache.Web.Request::GetRemoteNameInternal", mono_apache_connection_get_remote_name);
  mono_add_internal_call("Apache.Web.Request::FlushInternal", mono_apache_connection_flush);
  mono_add_internal_call("Apache.Web.Request::CloseInternal", mono_apache_connection_close);
  mono_add_internal_call("Apache.Web.Request::ShouldClientBlockInternal", mono_apache_should_client_block);
  mono_add_internal_call("Apache.Web.Request::SetupClientBlockInternal", mono_apache_setup_client_block);
  mono_add_internal_call("Apache.Web.Request::GetClientBlockInternal", mono_apache_get_client_block);
  mono_add_internal_call("Apache.Web.Request::SetStatusLineInternal", mono_apache_request_set_status_line);
  mono_add_internal_call("Apache.Web.Request::SetStatusCodeInternal", mono_apache_request_set_status_code);
  mono_add_internal_call("Apache.Web.Request::AliasMatches", alias_matches_managed);
}

static MonoObject *
modmono_create_application_host (MonoDomain *domain, MonoAssembly *assembly,
				 const char *virtual, const char *app_base_dir)
{
  MonoMethodDesc *desc;
  MonoClass *class;
  MonoMethod *method;
  gpointer params[2];

  class = mono_class_from_name (assembly->image, "Apache.Web", "ApacheApplicationHost");
  if (class == NULL)
    return NULL;

  desc = mono_method_desc_new ("::CreateApplicationHost(string,string)", 0);
  method = mono_method_desc_search_in_class (desc, class);
  params[0] = mono_string_new (domain, virtual); 
  params[1] = mono_string_new (domain, app_base_dir); 
  return mono_runtime_invoke (method, NULL, params, NULL);
}

static MonoAssembly *
modmono_assembly_setup (MonoDomain *domain, char *app_base_dir) {
  MonoAssembly *assembly;
  gchar *path;
  gchar *with_extension;
  MonoAssemblyName aname;
  
  aname.name = "ModMono.dll";
  /* Specifying NULL base dir means it will look in path */
  if ((assembly = (MonoAssembly *)mono_assembly_load (&aname, NULL, NULL)) == NULL) {
    return NULL;
  }

  domain->entry_assembly = assembly;
  domain->setup->application_base = mono_string_new (domain, app_base_dir);
  path = g_build_path (app_base_dir, assembly->aname.name, NULL);
  with_extension = g_strconcat (path, ".exe.config", NULL);
  domain->setup->configuration_file = mono_string_new (domain, with_extension);
  g_free (with_extension);
  g_free (path);
  return assembly;
}

static int
create_application_host (request_rec *r)
{
  MonoDomain *domain;
  MonoAssembly *assembly;
  gchar *str;
  modmono_server_rec *server_conf;
  const char *app_base_dir;
  int retval = 5;
  int result;
  
  server_conf = ap_get_module_config(r->server->module_config, &mono_module);
  app_base_dir = server_conf->app_base_dir;
  if (app_base_dir == NULL) {
    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, NULL, "mod_mono: No MonoApplication directive found");
    return HTTP_INTERNAL_SERVER_ERROR;
  }
  register_wrappers();
  mono_config_parse (NULL);
  domain = mono_jit_init (app_base_dir);
  mono_thread_attach(domain);

  if (domain == NULL) {
    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, NULL, "mod_mono: Could not initialize domain");
    return HTTP_INTERNAL_SERVER_ERROR;
  }
  assembly = modmono_assembly_setup(domain, app_base_dir);
  if (assembly == NULL) {
    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, NULL, "mod_mono: Could not initialize ModMono.dll. Is it in your path?", app_base_dir);
    return HTTP_INTERNAL_SERVER_ERROR;
  }

  ApacheApplicationHost = modmono_create_application_host (domain, assembly, server_conf->virtual, app_base_dir);
  if (ApacheApplicationHost == NULL) {
    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, NULL, "mod_mono: Could not create ApacheApplicationHost");
    return HTTP_INTERNAL_SERVER_ERROR;
  }

  return OK;
}


int modmono_handler (request_rec* r) {
  modmono_server_rec *server_conf = ap_get_module_config(r->server->module_config, &mono_module);
  int l = alias_matches(r->uri, server_conf->virtual);
  char *path;
  /* Does the request match the application virtual path? */
  if (server_conf->virtual == NULL || l == 0) {
    return DECLINED;
  } else {
    path =  apr_pstrcat(r->pool, server_conf->app_base_dir, r->uri + l, NULL);
    r->filename = ap_server_root_relative(r->pool, path);
    if (ApacheApplicationHost == NULL) { /* TODO: locking */
      int res;
      res = create_application_host (r);
      if (res != OK)
	return res;
    }
    
    return modmono_request_handler(r);
  }
}

int modmono_execute_request(MonoObject *ApacheApplicationHost, request_rec *r) {
  MonoClass *class;
  gpointer args [1];
  gchar *cwd;
  MonoClass *klass;
  modmono_server_rec *server_conf;
  int i;

  /* We cannot use mono_method_desc_search_in_class because the class is a transparent proxy.
     The right way is to use mono_object_get_virtual_method, but that function was fixed post 0.20
     For now, search the method in the real object (klass) and call the remoting ones (class)
   */
  klass = ((MonoTransparentProxy *)ApacheApplicationHost)->klass;
  for (i = 0; i < klass->vtable_size; ++i) {
    if (!strcmp(klass->vtable[i]->name,"ProcessRequest")) break;
  }

  /* xxx Hack because of the tmp*.dll files, which are created in the current current directory.*/
  cwd = g_malloc(APR_PATH_MAX);
  getcwd(cwd, APR_PATH_MAX);
  if(cwd == NULL) {
    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, NULL, "mod_mono: Could not get current working directory");
    return HTTP_INTERNAL_SERVER_ERROR;
  }
  server_conf = ap_get_module_config(r->server->module_config, &mono_module);
  chdir (server_conf->app_base_dir); 
  args[0] = &r;
  mono_runtime_invoke (klass->vtable[i], ApacheApplicationHost, args, NULL);
  chdir(cwd);
  g_free(cwd);
  return OK;

}

int modmono_request_handler (request_rec* r) {
  MonoDomain *domain;
  gchar *str;
  const char *file;
  int retval = 5;
  int result;
  
  if (ApacheApplicationHost == NULL) {
    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, NULL, "mod_mono: cannot get ApacheApplicationHost");
    return HTTP_INTERNAL_SERVER_ERROR;
  }

  result = modmono_execute_request(ApacheApplicationHost, r);
  /*mono_jit_cleanup(domain); Goes in infinite loop*/
  return result;
}


static int modmono_init_handler (apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp,
			  server_rec *s) {
  ap_add_version_component(p, "mod_mono/" VERSION );  
  return OK;
}

static void register_modmono_hooks(apr_pool_t * p)
{
  ap_hook_handler(modmono_handler, NULL, NULL, APR_HOOK_FIRST);
  ap_hook_post_config(modmono_init_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

static const command_rec modmono_cmds[] =
  {
    AP_INIT_TAKE2("MonoApplication", modmono_application_directive, NULL, RSRC_CONF,
                  "Create a Mono Application. The first argument is the virtual path and the second the directory on disk."),
    NULL
  };


module AP_MODULE_DECLARE_DATA mono_module =
  {
    STANDARD20_MODULE_STUFF,
    NULL,             /* dir config creater */
    NULL,              /* dir merger --- default is to override */
    create_modmono_server_config,      /* server config */
    NULL,                          /* merge server configs */
    modmono_cmds,                      /* command apr_table_t */
    register_modmono_hooks                 /* register hooks */
  };

