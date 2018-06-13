/**
 * @file
 * @brief Test the smtp-client library.
 * @author James Humphrey (mail@somnisoft.com)
 * @version 0.99
 *
 * This smtp-client testing framework has 100% branch coverage on POSIX
 * systems. It requires a Postfix SMTP server that supports all of the
 * connection security and authentication methods. These functional tests
 * also require the user to manually check and ensure that the destination
 * addresses received all of the test emails.
 *
 * This software has been placed into the public domain using CC0.
 *
 * @section test_seams_countdown_global
 *
 * The test harnesses control most of the test seams through the use of
 * global counter values.
 *
 * Setting a global counter to -1 will make the test seam function operate
 * as it normally would. If set to a positive value, the value will continue
 * to decrement every time the function gets called. When the counter reaches
 * 0, the test seam will force the function to return an error value.
 *
 * For example, initially setting the counter to 0 will force the test seam
 * to return an error condition the first time it gets called. Setting the
 * value to 1 initially will force the test seam to return an error condition
 * on the second time it gets called.
 */
#ifndef SMTP_TEST_H
#define SMTP_TEST_H

#include <sys/socket.h>
#include <sys/types.h>

#include "../src/smtp.h"

#ifdef SMTP_OPENSSL
# include <openssl/bio.h>
# include <openssl/err.h>
# include <openssl/ssl.h>
# include <openssl/x509.h>
# include <openssl/x509v3.h>
#endif /* SMTP_OPENSSL */

struct smtp_command;
struct str_getdelimfd;

/**
 * Maximum size of an RFC 2822 date string.
 *
 * Also defined in @ref smtp.c. Redefined here because the unit tests
 * need to use this max size when calling the @ref smtp_date_rfc_2822 function.
 */
#define SMTP_DATE_MAX_SZ 32

ssize_t
smtp_base64_decode(const char *const buf,
                   unsigned char **decode);

char *
smtp_base64_encode(const char *const buf,
                   ssize_t buflen);

char *
smtp_bin2hex(const unsigned char *const s,
             size_t slen);

int
smtp_str_getdelimfd(struct str_getdelimfd *const gdfd);

void
smtp_str_getdelimfd_free(struct str_getdelimfd *const gdfd);

char *
smtp_strdup(const char *s);

char *
smtp_str_replace(const char *const search,
            const char *const replace,
            const char *const s);

size_t
smtp_strnlen(const char *s,
             size_t maxlen);

char *
smtp_chunk_split(const char *const s,
                 int chunklen,
                 const char *const end);

char *
smtp_ffile_get_contents(FILE *stream,
                        size_t *bytes_read);

char *
smtp_file_get_contents(const char *const filename,
                       size_t *bytes_read);

int
smtp_parse_cmd_line(char *const line,
                    struct smtp_command *const cmd);

int
smtp_date_rfc_2822(char *const date);

int
smtp_address_validate_email(const char *const email);

int
smtp_address_validate_name(const char *const name);

int
smtp_attachment_validate_name(const char *const name);

int
smtp_header_key_validate(const char *const key);

int
smtp_header_value_validate(const char *const value);

/* test seams */

BIO *
smtp_test_seam_bio_new_socket(int sock,
                              int close_flag);

int
smtp_test_seam_bio_should_retry(BIO *bio);

void *
smtp_test_seam_calloc(size_t nelem,
                      size_t elsize);

int
smtp_test_seam_close(int fildes);

int
smtp_test_seam_connect(int socket,
                       const struct sockaddr *address,
                       socklen_t address_len);

unsigned long
smtp_test_seam_err_peek_error(void);

int
smtp_test_seam_fclose(FILE *stream);

int
smtp_test_seam_ferror(FILE *stream);

struct tm *
smtp_test_seam_gmtime_r(const time_t *timep,
                        struct tm *result);

unsigned char *
smtp_test_seam_hmac(const EVP_MD *evp_md,
                    const void *key,
                    int key_len,
                    const unsigned char *d,
                    int n,
                    unsigned char *md,
                    unsigned int *md_len);

struct tm *
smtp_test_seam_localtime_r(const time_t *timep,
                           struct tm *result);

void *
smtp_test_seam_malloc(size_t size);

time_t
smtp_test_seam_mktime(struct tm *timeptr);


void *
smtp_test_seam_realloc(void *ptr,
                       size_t size);

ssize_t
smtp_test_seam_recv(int socket,
                    void *buffer,
                    size_t length,
                    int flags);

int
smtp_test_seam_select(int nfds,
                      fd_set *readfds,
                      fd_set *writefds,
                      fd_set *errorfds,
                      struct timeval *timeout);

ssize_t
smtp_test_seam_send(int socket,
                    const void *buffer,
                    size_t length,
                    int flags);

int
smtp_test_seam_socket(int domain,
                      int type,
                      int protocol);

int
smtp_test_seam_ssl_connect(SSL *ssl);

SSL_CTX *
smtp_test_seam_ssl_ctx_new(const SSL_METHOD *method);

int
smtp_test_seam_ssl_do_handshake(SSL *ssl);

X509 *
smtp_test_seam_ssl_get_peer_certificate(const SSL *ssl);

SSL *
smtp_test_seam_ssl_new(SSL_CTX *ctx);

int
smtp_test_seam_ssl_read(SSL *ssl,
                        void *buf,
                        int num);

int
smtp_test_seam_ssl_write(SSL *ssl,
                         const void *buf,
                         int num);

int
smtp_test_seam_sprintf(char *s,
                       const char *format, ...);

time_t
smtp_test_seam_time(time_t *tloc);

/**
 * Counter for @ref smtp_test_seam_bio_new_socket.
 *
 * See @ref test_seams_countdown_global for more details.
 */
int g_smtp_test_err_bio_new_socket_ctr;

/**
 * Counter for @ref smtp_test_seam_bio_should_retry.
 *
 * See @ref test_seams_countdown_global for more details.
 */
int g_smtp_test_err_bio_should_retry_ctr;

/**
 * Counter for @ref smtp_test_seam_calloc.
 *
 * See @ref test_seams_countdown_global for more details.
 */
int g_smtp_test_err_calloc_ctr;

/**
 * Counter for @ref smtp_test_seam_close.
 *
 * See @ref test_seams_countdown_global for more details.
 */
int g_smtp_test_err_close_ctr;

/**
 * Counter for @ref smtp_test_seam_connect.
 *
 * See @ref test_seams_countdown_global for more details.
 */
int g_smtp_test_err_connect_ctr;

/**
 * Counter for @ref smtp_test_seam_err_peek_error.
 *
 * See @ref test_seams_countdown_global for more details.
 */
int g_smtp_test_err_err_peek_error_ctr;

/**
 * Counter for @ref smtp_test_seam_fclose.
 *
 * See @ref test_seams_countdown_global for more details.
 */
int g_smtp_test_err_fclose_ctr;

/**
 * Counter for @ref smtp_test_seam_ferror.
 *
 * See @ref test_seams_countdown_global for more details.
 */
int g_smtp_test_err_ferror_ctr;

/**
 * Counter for @ref smtp_test_seam_gmtime_r.
 *
 * See @ref test_seams_countdown_global for more details.
 */
int g_smtp_test_err_gmtime_r_ctr;

/**
 * Counter for @ref smtp_test_seam_hmac.
 *
 * See @ref test_seams_countdown_global for more details.
 */
int g_smtp_test_err_hmac_ctr;

/**
 * Counter for @ref smtp_test_seam_localtime_r.
 *
 * See @ref test_seams_countdown_global for more details.
 */
int g_smtp_test_err_localtime_r_ctr;

/**
 * Counter for @ref smtp_test_seam_malloc.
 *
 * See @ref test_seams_countdown_global for more details.
 */
int g_smtp_test_err_malloc_ctr;

/**
 * Counter for @ref smtp_test_seam_mktime.
 *
 * See @ref test_seams_countdown_global for more details.
 */
int g_smtp_test_err_mktime_ctr;

/**
 * Counter for @ref smtp_test_seam_realloc.
 *
 * See @ref test_seams_countdown_global for more details.
 */
int g_smtp_test_err_realloc_ctr;

/**
 * Counter for @ref smtp_test_seam_recv.
 *
 * See @ref test_seams_countdown_global for more details.
 */
int g_smtp_test_err_recv_ctr;

/**
 * Set the received bytes in recv() and SSL_read() to this value if it
 * contains a null-terminated string at least one bytes long.
 *
 * This makes it easier to inject a bad server response for testing the
 * smtp-client handling of those bad responses.
 *
 * See @ref test_seams_countdown_global for more details.
 */
char g_smtp_test_err_recv_bytes[90];

/**
 * Counter for @ref smtp_test_seam_select.
 *
 * See @ref test_seams_countdown_global for more details.
 */
int g_smtp_test_err_select_ctr;

/**
 * Counter for @ref smtp_test_seam_send.
 *
 * See @ref test_seams_countdown_global for more details.
 */
int g_smtp_test_err_send_ctr;

/**
 * Counter for @ref smtp_test_seam_socket.
 *
 * See @ref test_seams_countdown_global for more details.
 */
int g_smtp_test_err_socket_ctr;

/**
 * Counter for @ref smtp_test_seam_ssl_connect.
 *
 * See @ref test_seams_countdown_global for more details.
 */
int g_smtp_test_err_ssl_connect_ctr;

/**
 * Counter for @ref smtp_test_seam_ssl_ctx_new.
 *
 * See @ref test_seams_countdown_global for more details.
 */
int g_smtp_test_err_ssl_ctx_new_ctr;

/**
 * Counter for @ref smtp_test_seam_ssl_do_handshake.
 *
 * See @ref test_seams_countdown_global for more details.
 */
int g_smtp_test_err_ssl_do_handshake_ctr;

/**
 * Counter for @ref smtp_test_seam_ssl_get_peer_certificate.
 *
 * See @ref test_seams_countdown_global for more details.
 */
int g_smtp_test_err_ssl_get_peer_certificate_ctr;

/**
 * Counter for @ref smtp_test_seam_ssl_new.
 *
 * See @ref test_seams_countdown_global for more details.
 */
int g_smtp_test_err_ssl_new_ctr;

/**
 * Counter for @ref smtp_test_seam_ssl_read.
 *
 * See @ref test_seams_countdown_global for more details.
 */
int g_smtp_test_err_ssl_read_ctr;

/**
 * Counter for @ref smtp_test_seam_ssl_write.
 *
 * See @ref test_seams_countdown_global for more details.
 */
int g_smtp_test_err_ssl_write_ctr;

/**
 * Counter for @ref smtp_test_seam_sprintf.
 *
 * See @ref test_seams_countdown_global for more details.
 */
int g_smtp_test_err_sprintf_ctr;

/**
 * Value to force the sprintf() function to return.
 *
 * This value will only get returned if @ref g_smtp_test_err_sprintf_ctr has
 * a value of 0.
 */
int g_smtp_test_err_sprintf_rc;

/**
 * Indicates if the time() function should return a custom value.
 *
 * This can get set to one of two values:
 *   -  0 - The time() function will operate normally.
 *   - !0 - The time() function will return the value specified in
 *          @ref g_smtp_test_time_ret_value.
 */
int g_smtp_test_time_custom_ret;

/**
 * Value to force the time() function to return.
 *
 * This value will only get returned if @ref g_smtp_test_time_custom_ret has
 * a positive value.
 */
time_t g_smtp_test_time_ret_value;

#endif /* SMTP_TEST_H */

