#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct ngx_http_hello_loc_conf_t
{
  ngx_flag_t connection_so_keepalive;
	ngx_int_t connection_tcp_keepidle;
	ngx_int_t connection_tcp_keepintvl;
	ngx_int_t connection_tcp_keepcnt;
}ngx_http_hello_loc_conf_t;

static ngx_int_t ngx_http_hello_filter_init(ngx_conf_t *cf);

static void *ngx_http_hello_filter_create_loc_conf(ngx_conf_t *cf);

//自定义函数
static char *ngx_http_hello_connection_so_keepalive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_hello_connection_tcp_keepidle(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_hello_connection_tcp_keepintvl(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_hello_connection_tcp_keepcnt(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t ngx_http_hello_filter_commands[] = {
    { ngx_string("connection_so_keepalive"),
        NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_NOARGS|NGX_CONF_TAKE1|NGX_CONF_FLAG,
        ngx_http_hello_connection_so_keepalive,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },
    { ngx_string("connection_tcp_keepidle"),
         NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
         ngx_http_hello_connection_tcp_keepidle,
         NGX_HTTP_LOC_CONF_OFFSET,
         0,
         NULL },
    { ngx_string("connection_tcp_keepintvl"),
          NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
          ngx_http_hello_connection_tcp_keepintvl,
          NGX_HTTP_LOC_CONF_OFFSET,
          0,
          NULL },
    { ngx_string("connection_tcp_keepcnt"),
           NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
           ngx_http_hello_connection_tcp_keepcnt,
           NGX_HTTP_LOC_CONF_OFFSET,
           0,
           NULL },
        ngx_null_command
};

static ngx_http_module_t ngx_http_hello_filter_module_ctx = {
        NULL,                          /* preconfiguration */
        ngx_http_hello_filter_init,    /* postconfiguration */

        NULL,                          /* create main configuration */
        NULL,                          /* init main configuration */

        NULL,  /* create server configuration */
        NULL,                          /* merge server configuration */

        ngx_http_hello_filter_create_loc_conf, /* create location configuration */
        NULL                            /* merge location configuration */
};


ngx_module_t ngx_http_hello_filter_module = {
        NGX_MODULE_V1,
        &ngx_http_hello_filter_module_ctx,    /* module context */
        ngx_http_hello_filter_commands,       /* module directives */
        NGX_HTTP_MODULE,               /* module type */
        NULL,                          /* init master */
        NULL,                          /* init module */
        NULL,                          /* init process */
        NULL,                          /* init thread */
        NULL,                          /* exit thread */
        NULL,                          /* exit process */
        NULL,                          /* exit master */
        NGX_MODULE_V1_PADDING
};

static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;

static void *ngx_http_hello_filter_create_loc_conf(ngx_conf_t *cf)
{
  ngx_conf_log_error(NGX_LOG_DEBUG_HTTP, cf, 0,
             "hello body filter create loc configure");
  ngx_http_hello_loc_conf_t* local_conf = NULL;
  local_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_hello_loc_conf_t));
  if (local_conf == NULL)
  {
    return NULL;
  }

  local_conf->connection_so_keepalive = NGX_CONF_UNSET;
	local_conf->connection_tcp_keepidle = NGX_CONF_UNSET;
	local_conf->connection_tcp_keepintvl = NGX_CONF_UNSET;
	local_conf->connection_tcp_keepcnt = NGX_CONF_UNSET;

  return local_conf;
}

//设置参数
static char *
ngx_http_hello_connection_so_keepalive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_conf_log_error(NGX_LOG_DEBUG_HTTP, cf, 0,
             "hello body filter set connection keepalive");
  ngx_http_hello_loc_conf_t *flcf = conf;
  ngx_str_t        *value;
  value = cf->args->elts;
  if(cf->args->nelts <= 1)
  {
          flcf->connection_so_keepalive = 0;
  }
  else if (ngx_strcasecmp(value[1].data, (u_char *) "on") == 0) {
    flcf->connection_so_keepalive = 1;
  } else if (ngx_strcasecmp(value[1].data, (u_char *) "off") == 0) {
    flcf->connection_so_keepalive = 0;
  } else {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "invalid value \"%s\" in \"%s\" directive, "
                    "it must be \"on\" or \"off\"",
                    value[1].data, cmd->name.data);
    return NGX_CONF_ERROR;
  }
  return NGX_CONF_OK;
}

static char *
ngx_http_hello_connection_tcp_keepidle(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_conf_log_error(NGX_LOG_DEBUG_HTTP, cf, 0,
             "hello body filter set connection tcp keepidle");

  ngx_http_hello_loc_conf_t *flcf = conf;
  ngx_str_t        *value;
  ngx_conf_post_t  *post;
  ngx_int_t        np = flcf->connection_tcp_keepidle;

  if (np != NGX_CONF_UNSET) {
     return "is duplicate";
  }

  value = cf->args->elts;
  np = ngx_atoi(value[1].data, value[1].len);
  if (np == NGX_ERROR) {
     return "invalid number";
  }
  flcf->connection_tcp_keepidle = np;

  if (cmd->post) {
     post = cmd->post;
     return post->post_handler(cf, post, &np);
  }

  return NGX_CONF_OK;
}

static char *
ngx_http_hello_connection_tcp_keepintvl(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_conf_log_error(NGX_LOG_DEBUG_HTTP, cf, 0,
             "hello body filter set connection tcp keepintvl");

  ngx_http_hello_loc_conf_t *flcf = conf;
  ngx_str_t        *value;
  ngx_conf_post_t  *post;
  ngx_int_t        np = flcf->connection_tcp_keepintvl;

  if (np != NGX_CONF_UNSET) {
     return "is duplicate";
  }

  value = cf->args->elts;
  np = ngx_atoi(value[1].data, value[1].len);
  if (np == NGX_ERROR) {
     return "invalid number";
  }
  flcf->connection_tcp_keepintvl = np;

  if (cmd->post) {
     post = cmd->post;
     return post->post_handler(cf, post, &np);
  }

  return NGX_CONF_OK;
}

static char *
ngx_http_hello_connection_tcp_keepcnt(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_conf_log_error(NGX_LOG_DEBUG_HTTP, cf, 0,
             "hello body filter set connection tcp keepcnt");

  ngx_http_hello_loc_conf_t *flcf = conf;
  ngx_str_t        *value;
  ngx_conf_post_t  *post;
  ngx_int_t        np = flcf->connection_tcp_keepcnt;

  if (np != NGX_CONF_UNSET) {
     return "is duplicate";
  }

  value = cf->args->elts;
  np = ngx_atoi(value[1].data, value[1].len);
  if (np == NGX_ERROR) {
     return "invalid number";
  }
  flcf->connection_tcp_keepcnt = np;

  if (cmd->post) {
     post = cmd->post;
     return post->post_handler(cf, post, &np);
  }

  return NGX_CONF_OK;
}

//功能函数
static void ngx_http_hello_connection_set_keepalive_param(ngx_http_request_t *r)
{
  ngx_http_hello_loc_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_hello_filter_module);
  ngx_connection_t  *c = r->connection;
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
	           "hello socket set keepalive fd:%d", c->fd);

	ngx_int_t keepalive = 1; // 开启keepalive属性
	ngx_int_t keepidle = 2; // 如该连接在60秒内没有任何数据往来,则进行探测
	ngx_int_t keepinterval = 2; // 探测时发包的时间间隔为5 秒
	ngx_int_t keepcount = 2; // 探测尝试的次数.如果第1次探测包就收到响应了,则后2次的不再发.

	if(conf == NULL)
	{
		ngx_log_debug(NGX_LOG_DEBUG_HTTP, c->log, 0,
		           "hello socket set keepalive conf == NULL");
	}else
	{
		if(conf->connection_so_keepalive != NGX_CONF_UNSET)
			keepalive = conf->connection_so_keepalive;
		if(conf->connection_tcp_keepidle != NGX_CONF_UNSET)
			keepidle = conf->connection_tcp_keepidle;
		if(conf->connection_tcp_keepintvl != NGX_CONF_UNSET)
			keepinterval = conf->connection_tcp_keepintvl;
		if(conf->connection_tcp_keepcnt != NGX_CONF_UNSET)
			keepcount = conf->connection_tcp_keepcnt;

		ngx_log_debug4(NGX_LOG_DEBUG_HTTP, c->log, 0,
			           "hello socket set keepalive param: keepalive:%d idle:%d interval:%d count:%d",
                 keepalive,keepidle,keepinterval,keepcount);
	}
  

	int ret = setsockopt(c->fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&keepalive , sizeof(keepalive ));
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
	           "hello socket set keepalive SO_KEEPALIVE:%d",ret);
	ret = setsockopt(c->fd, SOL_TCP, TCP_KEEPIDLE, (void*)&keepidle , sizeof(keepidle ));
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
	           "hello socket set keepalive TCP_KEEPIDLE:%d",ret);
	ret = setsockopt(c->fd, SOL_TCP, TCP_KEEPINTVL, (void *)&keepinterval , sizeof(keepinterval ));
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
	           "hello socket set keepalive TCP_KEEPINTVL:%d",ret);
	ret = setsockopt(c->fd, SOL_TCP, TCP_KEEPCNT, (void *)&keepcount , sizeof(keepcount ));
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
	           "hello socket set keepalive TCP_KEEPCNT:%d",ret);
  if(ret == 0)
  {
    socklen_t len = sizeof(ngx_int_t);
    ret = getsockopt(c->fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&keepalive , &len);
    ret = getsockopt(c->fd, SOL_TCP, TCP_KEEPIDLE, (void *)&keepidle , &len);
    ret = getsockopt(c->fd, SOL_TCP, TCP_KEEPINTVL, (void *)&keepinterval , &len);
    ret = getsockopt(c->fd, SOL_TCP, TCP_KEEPCNT, (void *)&keepcount , &len);

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, c->log, 0,
                 "hello socket get keepalive param: keepalive:%d idle:%d interval:%d count:%d",
                 keepalive,keepidle,keepinterval,keepcount);
  }
}

static ngx_int_t ngx_http_hello_connection_get_keepalive(ngx_connection_t  *c)
{
    ngx_int_t keepalive = 0;
    socklen_t len = sizeof(ngx_int_t);
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "hello connection get keepalive");

    int ret = getsockopt(c->fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&keepalive , &len);
    if(ret ==0)
    {
      return keepalive;
    }else{
      ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
             "hello socket get keepalive SO_KEEPALIVE:%d errno:%d",ret,errno);
      return 0;
    }
}

static ngx_int_t ngx_hello_check_event(ngx_connection_t *c)
{
    int                n;
    char               buf[1];
    ngx_err_t            err;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "hello keepalive check event");


    if (c->close) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "hello keepalive check close");
        goto close;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "hello keepalive check recv...");

    n = recv(c->fd, buf, 1, MSG_PEEK);
    err = ngx_socket_errno;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "hello keepalive check recv:%d %d",n,err);
    if (n == -1) {
        if(err == NGX_EAGAIN)
        {
            return NGX_EAGAIN;
        }
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "hello keepalive check recv errno:%d",err);
        return NGX_ERROR;
    }
    else if(n == 0)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "hello keepalive check recv n == 0");
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "hello keepalive check recv n == %d",n);
    return NGX_OK;
close:
    return NGX_ERROR;
}

static ngx_int_t
ngx_http_hello_check_broken_connection(ngx_http_request_t *r)
{
    int                  n;
    char                 buf[1];
    ngx_err_t            err;
    ngx_connection_t     *c;
    ngx_http_upstream_t  *u;
    ngx_event_t *ev;

    c = r->connection;
    u = r->upstream;

    if (c->error) {
        return NGX_ERROR;
    }

    ev = c->write;
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                   "hello http check client, write event:%d, \"%V\"",
                   ev->write, &r->uri);

    n = recv(c->fd, buf, 1, MSG_PEEK);

    err = ngx_socket_errno;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, err,
                   "hello http recv(): %d %d", n,err);

    if (n > 0) {
        return NGX_OK;
    }

    if (n == -1) {
        if (err == NGX_EAGAIN) {
                return NGX_EAGAIN;
        }

        ev->error = 1;

    } else { /* n == 0 */
        err = 0;
    }

    ev->eof = 1;
    c->error = 1;

    if (!u->cacheable && u->peer.connection) {
        ngx_log_error(NGX_LOG_INFO, c->log, err,
                      "hello client prematurely closed connection, "
                      "so upstream connection is closed too");
        return NGX_HTTP_CLIENT_CLOSED_REQUEST;
    }

    ngx_log_error(NGX_LOG_INFO, c->log, err,
                  "hello client prematurely closed connection");

    if (u->peer.connection == NULL) {
        return NGX_HTTP_CLIENT_CLOSED_REQUEST;
    }
    return NGX_ERROR;
}


static ngx_int_t ngx_http_hello_filter_check_connect(ngx_http_request_t *r)
{
  return ngx_http_hello_check_broken_connection(r);
  return ngx_hello_check_event(r->connection);
}

static ngx_int_t
ngx_http_hello_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
  ngx_int_t  rc;
  ngx_http_hello_loc_conf_t *conf;
  conf = ngx_http_get_module_loc_conf(r, ngx_http_hello_filter_module);

  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
             "hello body filter check: %d", conf->connection_so_keepalive);

  if(conf->connection_so_keepalive == 1)
  {
    if(ngx_http_hello_connection_get_keepalive(r->connection) != 1)
    {
      ngx_http_hello_connection_set_keepalive_param(r);
    }
    rc = ngx_http_hello_filter_check_connect(r);
    if(rc != NGX_OK && rc != NGX_EAGAIN)
    {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "hello filter check :%d",rc);
            return NGX_ERROR;
    }
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "hello body filter check ok: %d", rc);
  }
  rc = ngx_http_next_body_filter(r,in);
  return rc;
}

static ngx_int_t
ngx_http_hello_filter_init(ngx_conf_t *cf)
{
  ngx_conf_log_error(NGX_LOG_DEBUG_HTTP, cf, 0,
             "hello body filter init");

  ngx_http_next_body_filter = ngx_http_top_body_filter;
  ngx_http_top_body_filter = ngx_http_hello_body_filter;

  return NGX_OK;
}