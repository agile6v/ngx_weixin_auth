/*
 *  Copyright (C) agile6v
 */

#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#if NGX_HAVE_SHA1
#include "ngx_sha1.h"
#endif

typedef struct {
    ngx_flag_t                  enable;
    ngx_str_t                   token;
    ngx_http_handler_pt         original_handler;
} ngx_http_weixin_auth_loc_conf_t;

static ngx_int_t ngx_http_weixin_auth(ngx_http_request_t *r);
static ngx_int_t ngx_http_weixin_auth_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_weixin_auth_access_handler(ngx_http_request_t *r);
static void *ngx_http_weixin_auth_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_weixin_auth_merge_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_command_t ngx_http_weixin_auth_module_commands[] = {

    { ngx_string("weixin_auth"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_weixin_auth_loc_conf_t, enable),
      NULL },
      
    { ngx_string("weixin_auth_token"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_weixin_auth_loc_conf_t, token),
      NULL },

      ngx_null_command
};

static ngx_http_module_t  ngx_http_weixin_auth_module_ctx = {
    NULL,                                       /* preconfiguration */
    NULL,                                       /* postconfiguration */
    NULL,                                       /* create main configuration */
    NULL,                                       /* init main configuration */
    NULL,                                       /* create server configuration */
    NULL,                                       /* merge server configuration */
    ngx_http_weixin_auth_create_loc_conf,       /* create location configuration */
    ngx_http_weixin_auth_merge_conf,            /* merge location configuration */
};

ngx_module_t  ngx_http_weixin_auth_module = {
    NGX_MODULE_V1,
    &ngx_http_weixin_auth_module_ctx,       /* module context */
    ngx_http_weixin_auth_module_commands,   /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_http_weixin_auth_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_weixin_auth_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_weixin_auth_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    
    conf->enable = NGX_CONF_UNSET;
    
    return conf;
}

static char *
ngx_http_weixin_auth_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_weixin_auth_loc_conf_t *prev = parent;
    ngx_http_weixin_auth_loc_conf_t *conf = child;
    ngx_http_core_loc_conf_t        *clcf;
    
    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_str_value(conf->token, prev->token, "token");
    
    if (conf->enable) {
    
        clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
        if (clcf->handler != NULL) {
            conf->original_handler = clcf->handler;
            clcf->handler = ngx_http_weixin_auth_access_handler;
        } else {
            clcf->handler = ngx_http_weixin_auth_handler;
        }
    }

    return NGX_CONF_OK;
}

static ngx_int_t 
ngx_http_weixin_auth_access_handler(ngx_http_request_t *r)
{
    ngx_int_t                        rc;
    ngx_http_weixin_auth_loc_conf_t *auth_conf;
    
    auth_conf = ngx_http_get_module_loc_conf(r, ngx_http_weixin_auth_module);

    if (r->method & NGX_HTTP_POST) {
    
        rc = ngx_http_weixin_auth(r);
        if (rc != NGX_OK && rc != NGX_DECLINED) {
            return rc;
        }
        
        if (rc == NGX_DECLINED) {
            return NGX_HTTP_FORBIDDEN;
        }
        
        return auth_conf->original_handler(r);
    }
    
    if (r->method & NGX_HTTP_GET) {
        return ngx_http_weixin_auth_handler(r);
    }
    
    return NGX_DECLINED;
}

static ngx_int_t 
ngx_http_weixin_auth_handler(ngx_http_request_t *r)
{
    ngx_buf_t       *b;
    ngx_chain_t      out;
    ngx_int_t        rc;
    ngx_str_t        echostr;
    
    if (!(r->method & NGX_HTTP_GET)) {
        return NGX_DECLINED;
    }
    
    if (!r->args.len) {
        return NGX_DECLINED;
    }
   
    if (ngx_http_arg(r, (u_char *) "echostr", 7, &echostr) != NGX_OK) {
        return NGX_DECLINED;
    }
    
    rc = ngx_http_weixin_auth(r);
    if (rc != NGX_OK && rc != NGX_DECLINED) {
        return rc;
    }
    
    if (rc == NGX_DECLINED) {
        return NGX_HTTP_FORBIDDEN;
    }
    
    b = ngx_create_temp_buf(r->pool, echostr.len);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    b->last = ngx_cpymem(b->last, echostr.data, echostr.len);
    b->last_buf = 1;
    
    out.buf = b;
    out.next = NULL;
    
    r->headers_out.status = NGX_HTTP_OK;
    ngx_str_set(&r->headers_out.content_type, "text/plain");
    r->headers_out.content_length_n = echostr.len;
    
    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }
    
    return ngx_http_output_filter(r, &out);
}

static ngx_int_t 
ngx_http_weixin_auth(ngx_http_request_t *r)
{
    u_char     *p;
    ngx_int_t   rc;
    ngx_str_t   signature, str, array_str[3], tmp;
    ngx_sha1_t  sha;
    u_char      sha_buf[SHA_DIGEST_LENGTH];
    u_char      sha_buf_str[SHA_DIGEST_LENGTH + SHA_DIGEST_LENGTH];
    ngx_http_weixin_auth_loc_conf_t *auth_conf;
    
    auth_conf = ngx_http_get_module_loc_conf(r, ngx_http_weixin_auth_module);
    
    if (ngx_http_arg(r, (u_char *) "signature", 9, &signature) != NGX_OK) {
        return NGX_DECLINED;
    }
    
    if (ngx_http_arg(r, (u_char *) "timestamp", 9, &array_str[0]) != NGX_OK) {
        return NGX_DECLINED;
    }
    
    if (ngx_http_arg(r, (u_char *) "nonce", 5, &array_str[1]) != NGX_OK) {
        return NGX_DECLINED;
    }
    
    if (signature.len != SHA_DIGEST_LENGTH * 2) {
        return NGX_DECLINED;
    }
    
    array_str[2] = auth_conf->token;
    
    //  token¡¢timestamp¡¢nonce
    if (ngx_memn2cmp(array_str[0].data, array_str[1].data, array_str[0].len, array_str[1].len) > 0) {
        tmp = array_str[0];
        array_str[0] = array_str[1];
        array_str[1] = tmp;
    }
    
    if (ngx_memn2cmp(array_str[1].data, array_str[2].data, array_str[1].len, array_str[2].len) > 0) {
        tmp = array_str[1];
        array_str[1] = array_str[2];
        array_str[2] = tmp;
    }

    if (ngx_memn2cmp(array_str[0].data, array_str[1].data, array_str[0].len, array_str[1].len) > 0) {
        tmp = array_str[0];
        array_str[0] = array_str[1];
        array_str[1] = tmp;
    }
    
    str.len = array_str[0].len + array_str[1].len + array_str[2].len;
    str.data = ngx_pcalloc(r->pool, str.len + 1);
    if (str.data == NULL) {
        return NGX_ERROR;
    }
    
    p = str.data;
    p = ngx_cpymem(p, array_str[0].data, array_str[0].len);
    p = ngx_cpymem(p, array_str[1].data, array_str[1].len);
    p = ngx_cpymem(p, array_str[2].data, array_str[2].len);
    p = '\0';
    
    ngx_sha1_init(&sha);
    ngx_sha1_update(&sha, str.data, str.len);
    ngx_sha1_final(sha_buf, &sha);
    
    p = ngx_hex_dump(sha_buf_str, sha_buf, SHA_DIGEST_LENGTH);
    p = '\0';
    
    rc = ngx_memcmp(sha_buf_str, signature.data, SHA_DIGEST_LENGTH * 2);
    if (rc != 0) {
        return NGX_DECLINED;
    }
    
    return NGX_OK;
}
