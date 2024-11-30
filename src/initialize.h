#ifndef _INITIALIZE_H_
#define _INITIALIZE_H_

#include <httpd.h>

int dims_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s);
void dims_child_init(apr_pool_t *p, server_rec *s);
void dims_register_hooks(apr_pool_t *p);

#endif