
#include "mod_dims.h"
#include "handler.h"
#include "directives.h"
#include "module.h"

void 
dims_register_hooks(apr_pool_t *p)
{
    ap_hook_post_config(dims_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(dims_child_init, NULL, NULL,APR_HOOK_MIDDLE); 
    ap_hook_handler(dims_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA dims_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,                   /* dir config creater */
    NULL,                   /* dir merger --- default is to override */
    dims_create_config,     /* server config */
    NULL,                   /* merge server config */
    dims_directives,        /* command apr_table_t */
    dims_register_hooks     /* register hooks */
};