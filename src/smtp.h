/**
 * @file
 * @brief SMTP client library.
 * @author James Humphrey (mail@somnisoft.com)
 * @version 0.99
 *
 * This SMTP client library allows the user to send emails to an SMTP server.
 * The user can include custom headers and MIME attachments.
 *
 * This software has been placed into the public domain using CC0.
 */
#ifndef SMTP_H
#define SMTP_H

#include <sys/types.h>
#include <stddef.h>
#include <stdio.h>

/**
 * Status codes indicating the success or failure from calling any of the
 * SMTP library functions. This code gets returned by all functions in this
 * header.
 */
enum smtp_status_code{
  /**
   * Successful operation completed.
   */
  SMTP_STATUS_OK,

  /**
   * Memory allocation failed.
   */
  SMTP_STATUS_NOMEM,

  /**
   * Failed to connect to the mail server.
   */
  SMTP_STATUS_CONNECT,

  /**
   * Failed to handshake or negotiate a TLS connection with the server.
   */
  SMTP_STATUS_HANDSHAKE,

  /**
   * Failed to authenticate with the given credentials.
   */
  SMTP_STATUS_AUTH,

  /**
   * Failed to send bytes to the server.
   */
  SMTP_STATUS_SEND,

  /**
   * Failed to receive bytes from the server.
   */
  SMTP_STATUS_RECV,

  /**
   * Failed to properly close a connection.
   */
  SMTP_STATUS_CLOSE,

  /**
   * SMTP server sent back an unexpected status code.
   */
  SMTP_STATUS_SERVER_RESPONSE,

  /**
   * Invalid parameter.
   */
  SMTP_STATUS_PARAM,

  /**
   * Failed to open or read a local file.
   */
  SMTP_STATUS_FILE,

  /**
   * Failed to get the local date and time.
   */
  SMTP_STATUS_DATE,

  /**
   * Indicates the last status code in the enumeration, useful for
   * bounds checking. Not a valid status code.
   */
  SMTP_STATUS__LAST
};

/**
 * Address source and destination types.
 */
enum smtp_address_type{
  /**
   * From address.
   */
  SMTP_ADDRESS_FROM,

  /**
   * To address.
   */
  SMTP_ADDRESS_TO,

  /**
   * Copy address.
   */
  SMTP_ADDRESS_CC,

  /**
   * Blind copy address.
   *
   * Recipients should not see any of the BCC addresses when they receive
   * their email. However, some SMTP server implementations may copy this
   * information into the mail header, so do not assume that this will
   * always get hidden. If the BCC addresses must not get shown to the
   * receivers, then send one separate email to each BCC party and add
   * the TO and CC addresses manually as a header property using
   * @ref smtp_header_add instead of as an address using
   * @ref smtp_address_add.
   */
  SMTP_ADDRESS_BCC
};

/**
 * Connect to the SMTP server using either an unencrypted socket or
 * TLS encryption.
 */
enum smtp_connection_security{
#ifdef SMTP_OPENSSL
  /**
   * First connect without encryption, then negotiate an encrypted connection
   * by issuing a STARTTLS command.
   */
  SMTP_SECURITY_STARTTLS,

  /**
   * Use TLS when initially connecting to server.
   *
   * @deprecated SMTP clients should not use this connection type unless
   *             connecting to a legacy SMTP server which requires it.
   *             Instead, use @ref SMTP_SECURITY_STARTTLS if possible.
   */
  SMTP_SECURITY_TLS,
#endif /* SMTP_OPENSSL */

  /**
   * Do not use TLS encryption. Not recommended unless connecting to the
   * SMTP server locally.
   */
  SMTP_SECURITY_NONE
};

/**
 * List of supported methods for authenticating a mail user account on
 * the server.
 */
enum smtp_authentication_method{
#ifdef SMTP_OPENSSL
  /**
   * Use HMAC-MD5.
   */
  SMTP_AUTH_CRAM_MD5,
#endif /* SMTP_OPENSSL */
  /**
   * No authentication required.
   *
   * Some servers support this option if connecting locally.
   */
  SMTP_AUTH_NONE,

  /**
   * Authenticate using base64 user and password.
   */
  SMTP_AUTH_PLAIN,

  /**
   * Another base64 authentication method, similar to SMTP_AUTH_PLAIN.
   */
  SMTP_AUTH_LOGIN
};

/**
 * Special flags defining certain behaviors for the SMTP client context.
 */
enum smtp_flag{
  /**
   * Print client and server communication on stderr.
   */
  SMTP_DEBUG          = 1 << 0,

  /**
   * Do not verify TLS certificate.
   *
   * By default, the TLS handshake function will check if a certificate
   * has expired or if using a self-signed certificate. Either of those
   * conditions will cause the connection to fail. This option allows the
   * connection to proceed even if those checks fail.
   */
  SMTP_NO_CERT_VERIFY = 1 << 1
};

struct smtp;

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

enum smtp_status_code
smtp_open(const char *const server,
          const char *const port,
          enum smtp_connection_security connection_security,
          enum smtp_flag flags,
          const char *const cafile,
          struct smtp **smtp);

enum smtp_status_code
smtp_auth(struct smtp *const smtp,
          enum smtp_authentication_method auth_method,
          const char *const user,
          const char *const pass);

enum smtp_status_code
smtp_mail(struct smtp *const smtp,
          const char *const body);

enum smtp_status_code
smtp_close(struct smtp *smtp);

enum smtp_status_code
smtp_status_code_get(const struct smtp *const smtp);

enum smtp_status_code
smtp_status_code_set(struct smtp *const smtp,
                     enum smtp_status_code new_status_code);

const char *
smtp_status_code_errstr(enum smtp_status_code status_code);

enum smtp_status_code
smtp_header_add(struct smtp *const smtp,
                const char *const key,
                const char *const value);

void smtp_header_clear_all(struct smtp *const smtp);

enum smtp_status_code
smtp_address_add(struct smtp *const smtp,
                 enum smtp_address_type type,
                 const char *const email,
                 const char *const name);

void smtp_address_clear_all(struct smtp *const smtp);

enum smtp_status_code
smtp_attachment_add_path(struct smtp *const smtp,
                         const char *const name,
                         const char *const path);

enum smtp_status_code
smtp_attachment_add_fp(struct smtp *const smtp,
                       const char *const name,
                       FILE *fp);

enum smtp_status_code
smtp_attachment_add_mem(struct smtp *const smtp,
                        const char *const name,
                        const void *const data,
                        ssize_t datasz);

void smtp_attachment_clear_all(struct smtp *const smtp);


/*
 * The SMTP_INTERNAL DEFINE section contains definitions that get used
 * internally by the SMTP client library.
 */
#ifdef SMTP_INTERNAL_DEFINE
/**
 * SMTP codes returned by the server and parsed by the client.
 */
enum smtp_result_code{
  /**
   * Client error code which does not get set by the server.
   */
  SMTP_INTERNAL_ERROR =  -1,

  /**
   * Returned when ready to begin processing next step.
   */
  SMTP_READY          = 220,

  /**
   * Returned in response to QUIT.
   */
  SMTP_CLOSE          = 221,

  /**
   * Returned if client successfully authenticates.
   */
  SMTP_AUTH_SUCCESS   = 235,

  /**
   * Returned when some commands successfully complete.
   */
  SMTP_DONE           = 250,

  /**
   * Returned for some multi-line authentication mechanisms which indicates
   * the next stage in the authentication step
   */
  SMTP_AUTH_CONTINUE  = 334,

  /**
   * Returned in response to DATA.
   */
  SMTP_BEGIN_MAIL     = 354
};

/**
 * Used for parsing out the responses from the SMTP server.
 *
 * For example, if the server sends back '250-STARTTLS', then code would
 * get set to 250, more would get set to 1, and text would get set to STARTTLS.
 */
struct smtp_command{
  /**
   * Result code converted to an integer.
   */
  enum smtp_result_code code;

  /**
   * Indicates if more server commands follow.
   *
   * This will get set to 1 if the fourth character in the response line
   * contains a '-', otherwise this will get set to 0.
   */
  int more;

  /**
   * The text shown after the status code.
   */
  const char *text;
};

/**
 * Return codes for the getdelim interface which allows the caller to check
 * if more delimited lines can get processed.
 */
enum str_getdelim_retcode{
  /**
   * An error occurred during the getdelim processing.
   */
  STRING_GETDELIMFD_ERROR = -1,

  /**
   * Found a new line and can process more lines in the next call.
   */
  STRING_GETDELIMFD_NEXT  =  0,

  /**
   * Found a new line and unable to read any more lines at this time.
   */
  STRING_GETDELIMFD_DONE  =  1
};

/**
 * Data structure for read buffer and line parsing.
 *
 * It assists with getting and parsing the server response lines.
 */
struct str_getdelimfd{
  /**
   * Read buffer which may include bytes past the delimiter.
   */
  char *_buf;

  /**
   * Number of allocated bytes in the read buffer.
   */
  size_t _bufsz;

  /**
   * Number of stored bytes in the read buffer.
   */
  size_t _buf_len;

  /**
   * Character delimiter used for determining line separation.
   */
  int delim;

  /**
   * Current line containing the text up to the delimiter.
   */
  char *line;

  /**
   * Number of stored bytes in the line buffer.
   */
  size_t line_len;

  /**
   * Function pointer to a custom read function for the
   * @ref smtp_str_getdelimfd interface.
   *
   * This function prototype has similar semantics to the read function.
   * The @p gdfd parameter allows the custom function to pull the user_data
   * info from the @ref str_getdelimfd struct which can contain file pointer,
   * socket connection, etc.
   */
  ssize_t (*getdelimfd_read)(struct str_getdelimfd *const gdfd,
                             void *buf,
                             size_t count);

  /**
   * User data which gets sent to the read handler function.
   */
  void *user_data;
};

#endif /* SMTP_INTERNAL_DEFINE */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* SMTP_H */

