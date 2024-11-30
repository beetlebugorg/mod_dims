
#include <apr.h>
#include <MagickWand/MagickWand.h>

#include "request.h"
#include "mod_dims.h"
#include "curl.h"

/* Converts a hex character to its integer value */
static char from_hex(char ch) {
    return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
}

/* Converts an integer value to its hex character*/
static char to_hex(char code) {
    static char hex[] = "0123456789abcdef";
    return hex[code & 15];
}

void 
lock_share(CURL *handle, 
           curl_lock_data data, 
           curl_lock_access access, 
           void *userptr)
{
    dims_curl_rec *locks = (dims_curl_rec *) userptr;       

    switch(data) {
        case CURL_LOCK_DATA_DNS:
            apr_thread_mutex_lock(locks->dns_mutex);
            break;
        default:
            apr_thread_mutex_lock(locks->share_mutex);
    }
}

void 
unlock_share(CURL *handle, 
             curl_lock_data data, 
             void *userptr) 
{
    dims_curl_rec *locks = (dims_curl_rec *) userptr;       

    switch(data) {
        case CURL_LOCK_DATA_DNS:
            apr_thread_mutex_unlock(locks->dns_mutex);
            break;
        default:
            apr_thread_mutex_unlock(locks->share_mutex);
    }
}

static int
dims_curl_debug_cb(
    CURL *handle,
    curl_infotype type,
    char *data,
    size_t size,
    void *clientp)
{
    dims_request_rec *d = (dims_request_rec *) clientp;
    switch(type) {
        case CURLINFO_HEADER_OUT:
            ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, d->r, "Curl request header data: %s ", data);
            break;
        default:
            break;
    }

    return 0;
}

/**
 * dims_write_image_cb - Appends image data chunk to an existing buffer.
 *
 * @chunk: Pointer to the incoming data chunk.
 * @size: The number of elements in the data chunk.
 * @bytes_size: Size of each element in bytes.
 * @data: Pointer to the image data structure (dims_image_data_t).
 *
 * This function writes a given image data chunk into an existing dynamically 
 * allocated buffer, reallocating memory as needed.
 *
 * Returns: The number of bytes successfully appended to the buffer, or 0 on failure.
 */
size_t
dims_write_image_cb(void *chunk, size_t size, size_t bytes_size, void *data)
{
    ap_assert(data != NULL);
    ap_assert(chunk != NULL);

    // Prevent overflow ('size' is always 1 but just in case)
    if (size != 1 && bytes_size > SIZE_MAX / size) {
        return 0; 
    }

    dims_image_data_t *image = (dims_image_data_t *) data;
    size_t chunk_size = size * bytes_size;

    // Allocate more memory if needed.
    if(image->used + chunk_size > image->size) {
        size_t new_size = (image->used + chunk_size) * 2;
        char *new_data = (char *)realloc(image->data, new_size);
        if (new_data == NULL) {
            return 0;
        }

        image->data = new_data;
        image->size = new_size;
    }

    memcpy(&(image->data[image->used]), chunk, chunk_size);
    image->used += chunk_size;

    return chunk_size;
}

CURLcode
dims_curl(dims_request_rec *d, const char *url, dims_image_data_t *source_image)
{
    CURL *curl_handle;
    CURLcode code;

    dims_image_data_t image_data;
    image_data.data = NULL;
    image_data.size = 0;
    image_data.used = 0;

    curl_handle = curl_easy_init();
    curl_easy_setopt(curl_handle, CURLOPT_URL, url);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, dims_write_image_cb);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *) &image_data);
    curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT_MS, d->config->download_timeout);
    curl_easy_setopt(curl_handle, CURLOPT_NOSIGNAL, 1);
    curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl_handle, CURLOPT_DEBUGFUNCTION, dims_curl_debug_cb);
    curl_easy_setopt(curl_handle, CURLOPT_DEBUGDATA, d);

    /* Set the user agent to dims/<version> */
    if (d->config->user_agent_override != NULL) {
        curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, d->config->user_agent_override);
    } else {
        char *dims_useragent = apr_psprintf(d->r->pool, "mod_dims/%s", MODULE_VERSION);
        curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, dims_useragent);
    }

    /* The curl shared handle allows this process to share DNS cache
     * and prevents the DNS cache from going away after every request.
     */
    void *shared_locks = NULL;
    apr_pool_userdata_get((void *) &shared_locks, DIMS_CURL_SHARED_KEY, d->r->server->process->pool);
    if (shared_locks) {
        dims_curl_rec *locks = (dims_curl_rec *) shared_locks;
        curl_easy_setopt(curl_handle, CURLOPT_SHARE, locks->share);
    }

    code = curl_easy_perform(curl_handle);

    // Grab cache headers using curl_easy_headers()
    struct curl_header *header = NULL;
    CURLHcode header_code = curl_easy_header(curl_handle, "cache-control", 0, CURLH_HEADER, -1, &header);
    if (CURLHE_OK == header_code) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, d->r, "Cache-Control: %s", header->value);
        source_image->cache_control = apr_pstrdup(d->pool, header->value);

        // Parse the Cache-Control header to extract "max-age" if present
        char *cache_control = source_image->cache_control;
        char *saveptr;
        char *directive = strtok_r(cache_control, ",", &saveptr);

        while (directive != NULL) {
            // Trim leading spaces
            while (*directive == ' ') {
                directive++;
            }

            // Check if the directive is "max-age"
            if (strncmp(directive, "max-age=", 8) == 0) {
                d->source_image->max_age = atol(directive + 8);
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, d->r, "Max-Age: %d", d->source_image->max_age);
                break;  // Exit loop once max-age is found
            }

            // Get the next directive
            directive = strtok_r(NULL, ",", &saveptr);
        }
    }

    header_code = curl_easy_header(curl_handle, "edge-control", 0, CURLH_HEADER, -1, &header);
    if (CURLHE_OK == header_code) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, d->r, "Edge-Control: %s", header->value);
        source_image->edge_control = apr_pstrdup(d->pool, header->value);
    }

    header_code = curl_easy_header(curl_handle, "last-modified", 0, CURLH_HEADER, -1, &header);
    if (CURLHE_OK == header_code) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, d->r, "Last-Modified: %s", header->value);
        source_image->last_modified = apr_pstrdup(d->pool, header->value);
    }

    header_code = curl_easy_header(curl_handle, "etag", 0, CURLH_HEADER, -1, &header);
    if (CURLHE_OK == header_code) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, d->r, "ETag: %s", header->value);
        source_image->etag = apr_pstrdup(d->pool, header->value);
    }

    curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &source_image->response_code);
    curl_easy_cleanup(curl_handle);

    if (source_image->response_code == 200) {
        source_image->data = apr_pmemdup(d->pool, image_data.data, image_data.used);
        source_image->size = image_data.used;
        source_image->used = image_data.used;
    }

    free(image_data.data);

    return code;
}

static apr_status_t
dims_curl_cleanup(void *data) {
    dims_curl_rec *locks = (dims_curl_rec *) data;

    curl_share_cleanup(locks->share);
    curl_global_cleanup();

    apr_thread_mutex_destroy(locks->share_mutex);
    apr_thread_mutex_destroy(locks->dns_mutex);

    apr_pool_userdata_set(NULL, DIMS_CURL_SHARED_KEY, NULL, locks->s->process->pool);
}

void 
dims_curl_init(apr_pool_t *p, server_rec *s) {
    curl_global_init(CURL_GLOBAL_ALL);

    dims_curl_rec *locks = (dims_curl_rec *) apr_pcalloc(p, sizeof(dims_curl_rec));

    locks->s = s;
    locks->share = curl_share_init(); 

    apr_thread_mutex_create(&locks->share_mutex, APR_THREAD_MUTEX_DEFAULT, p);
    apr_thread_mutex_create(&locks->dns_mutex, APR_THREAD_MUTEX_DEFAULT, p);

    curl_share_setopt(locks->share, CURLSHOPT_LOCKFUNC, lock_share); 
    curl_share_setopt(locks->share, CURLSHOPT_UNLOCKFUNC, unlock_share); 
    curl_share_setopt(locks->share, CURLSHOPT_USERDATA, (void *) locks); 
    curl_share_setopt(locks->share, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS);

    /* We have to associate our handle/locks with the process->pool otherwise
     * we won't be able to get at it from the remote_fetch_image function.  This
     * pool doesn't seem to go away when the child process goes away so we
     * have to register the clean up method below.
     */
    apr_pool_userdata_set(locks, DIMS_CURL_SHARED_KEY, NULL, s->process->pool);

    /* Register cleanup with the 'p' pool so we can clean up the locks and
     * shared curl handle when this process dies.
     */
    apr_pool_cleanup_register(p, locks, dims_curl_cleanup, dims_curl_cleanup);
}