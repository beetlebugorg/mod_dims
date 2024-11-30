#ifndef _STATUS_H_
#define _STATUS_H_

#include <httpd.h>
#include <apr.h>

apr_status_t status_handler(request_rec *r);

#endif