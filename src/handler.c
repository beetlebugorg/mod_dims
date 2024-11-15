
#include <httpd.h>
#include <util_md5.h>
#include <scoreboard.h>
#include <apr.h>
#include <apr_hash.h>

#include "mod_dims.h"
#include "handler.h"
#include "configuration.h"
#include "request.h"
#include "module.h"
#include "encryption.h"
#include "status.h"

// Called by Apache httpd per request.
apr_status_t 
dims_handler(request_rec *r) 
{
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "URI: %s ARGS: %s", r->uri, r->args);

    if(strcmp(r->handler, "dims-status") == 0) {
        return status_handler(r);
    }

    if (!(strcmp(r->handler, "dims3") == 0 || strcmp(r->handler, "dims4") == 0)) {
        return DECLINED;
    }

    if ((strcmp(r->handler, "dims3") == 0)) {
        return dims_handle_dims3(r);
    } else if (strcmp(r->handler, "dims4") == 0) {
        return dims_handle_dims4(r);
    }

    return DECLINED;
}
