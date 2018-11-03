/**
 * @file
 * @brief SMTP client library.
 * @author James Humphrey (mail@somnisoft.com)
 * @version 1.00
 *
 * This SMTP client library allows the user to send emails to an SMTP server.
 * The user can include custom headers and MIME attachments.
 *
 * This software has been placed into the public domain using CC0.
 */

/**
 * @mainpage smtp-client
 *
 * This section contains documentation generated directly from the source
 * code.
 *
 * To view the repository details, visit the main smtp-client page at
 * <a href='https://www.somnisoft.com/smtp-client'>
 * www.somnisoft.com/smtp-client
 * </a>.
 */

#if defined(_WIN32) || defined(WIN32)
# define SMTP_IS_WINDOWS
#endif /* SMTP_IS_WINDOWS */

#ifdef SMTP_IS_WINDOWS
# include <winsock2.h>
# include <ws2tcpip.h>
#else /* POSIX */
/**
 * Need to define this on some POSIX systems in order to get access to the
 * getaddrinfo and localtime_r functions.
 */
# define _POSIX_C_SOURCE 200112L
# include <netinet/in.h>
# include <sys/select.h>
# include <sys/socket.h>
# include <netdb.h>
# include <unistd.h>
#endif /* SMTP_IS_WINDOWS */

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#ifdef SMTP_OPENSSL
# include <openssl/bio.h>
# include <openssl/err.h>
# include <openssl/ssl.h>
# include <openssl/x509.h>
# include <openssl/x509v3.h>
#endif /* SMTP_OPENSSL */

/**
 * Get access to the @ref smtp_result_code and @ref smtp_command definitions.
 */
#define SMTP_INTERNAL_DEFINE

#include "smtp.h"

/*
 * The SMTP_TEST converts some library routines into special test seams which
 * allows the test program to control whether they fail. For example, we can
 * control when malloc() fails under certain conditions with an out of
 * memory condition.
 */
#ifdef SMTP_TEST
/**
 * Declare extern linkage on some functions so we can redefine their behavior
 * in the external test suite.
 */
# define SMTP_LINKAGE extern
# include "../test/seams.h"
#else /* !(SMTP_TEST) */
/**
 * When not testing, all functions should have static linkage except for those
 * in the header.
 */
# define SMTP_LINKAGE static
#endif /* SMTP_TEST */

/**
 * Increment the read buffer size by this amount if the delimiter
 * has not been found.
 */
#define SMTP_GETDELIM_READ_SZ 1000

/**
 * Stores source and destination email addresses.
 */
struct smtp_address{
  /**
   * Specify from, to, cc, bcc.
   */
  enum smtp_address_type type;

  /**
   * Email address without any special formatting.
   *
   * For example: mail@example.com
   */
  char *email;

  /**
   * Description of the email address.
   */
  char *name;
};

/**
 * Attachment data which gets placed in the MIME email section.
 */
struct smtp_attachment{
  /**
   * File name of the attachment.
   */
  char *name;

  /**
   * Base64-encoded file data.
   */
  char *b64_data;
};

/**
 * List of email headers to send before the mail body.
 */
struct smtp_header{
  /**
   * Header name which will get sorted alphabetically in the header list.
   */
  char *key;

  /**
   * Content of the corresponding header key.
   */
  char *value;
};

/**
 * Main data structure that holds the SMTP client context.
 */
struct smtp{
  /**
   * Bitwise list of flags controlling the behavior of this SMTP client.
   */
  enum smtp_flag flags;

  /**
   * Standard network socket connection.
   */
  int sock;

  /**
   * Read buffer and line parsing structure.
   */
  struct str_getdelimfd gdfd;

  /**
   * List of headers to print before the mail body.
   */
  struct smtp_header *header_list;

  /**
   * Number of headers in header_list.
   */
  size_t num_headers;

  /**
   * List of from, to, cc, and bcc email addresses.
   */
  struct smtp_address *address_list;

  /**
   * Number of addresses in address_list.
   */
  size_t num_address;

  /**
   * List of attachments to send.
   */
  struct smtp_attachment *attachment_list;

  /**
   * Number of attachments in attachment_list.
   */
  size_t num_attachment;

  /**
   * Status code indicating success/failure.
   *
   * This code gets returned by most of the header functions.
   */
  enum smtp_status_code status_code;

  /**
   * Timeout in seconds to wait before returning with an error.
   *
   * This applies to both writing to and reading from a network socket.
   */
  long timeout_sec;

  /**
   * Indicates if this context has an active TLS connection.
   *   - Set to 0 if TLS connection inactive.
   *   - Set to 1 if TLS connection currently active.
   */
  int tls_on;

  /**
   * Path to certificate file if using self-signed or untrusted certificate
   * not in the default key store.
   */
  const char *cafile;

#ifdef SMTP_OPENSSL
  /**
   * OpenSSL TLS object.
   */
  SSL *tls;

  /**
   * OpenSSL TLS context.
   */
  SSL_CTX *tls_ctx;

  /**
   * OpenSSL TLS I/O abstraction.
   */
  BIO *tls_bio;
#endif /* SMTP_OPENSSL */
};

/**
 * Wait until more data has been made available on the socket read end.
 *
 * @param[in] smtp SMTP client context.
 * @retval  0 If data available to read on the socket.
 * @retval -1 If the connection times out before any data appears on the
 *            socket.
 */
static int
smtp_str_getdelimfd_read_timeout(struct smtp *const smtp){
  fd_set readfds;
  struct timeval timeout;
  int sel_rc;

  FD_ZERO(&readfds);
  FD_SET(smtp->sock, &readfds);
  timeout.tv_sec  = smtp->timeout_sec;
  timeout.tv_usec = 0;
  sel_rc = select(smtp->sock + 1, &readfds, NULL, NULL, &timeout);
  if(sel_rc < 1){
    return smtp_status_code_set(smtp, SMTP_STATUS_RECV);
  }
  return smtp->status_code;
}

/**
 * This function gets called by the @ref smtp_str_getdelimfd interface when it
 * needs to read in more data.
 *
 * It reads using either the plain socket connection if encryption not
 * enabled, or it reads using OpenSSL if it has an active TLS connection.
 *
 * @param[in]  gdfd  See @ref str_getdelimfd.
 * @param[out] buf   Pointer to buffer for storing bytes read.
 * @param[in]  count Maximum number of bytes to try reading.
 * @retval >=0 Number of bytes read.
 * @retval -1  Failed to read from the socket.
 */
static long
smtp_str_getdelimfd_read(struct str_getdelimfd *const gdfd,
                         void *buf,
                         size_t count){
  struct smtp *smtp;
  long bytes_read;

  smtp = gdfd->user_data;

  if(smtp_str_getdelimfd_read_timeout(smtp) != SMTP_STATUS_OK){
    return -1;
  }

  bytes_read = 0;
  if(smtp->tls_on){
#ifdef SMTP_OPENSSL
    do{
      bytes_read = SSL_read(smtp->tls, buf, count);
    } while(bytes_read <= 0 && BIO_should_retry(smtp->tls_bio));
#endif /* SMTP_OPENSSL */
  }
  else{
    bytes_read = recv(smtp->sock, buf, count, 0);
  }
  return bytes_read;
}

/**
 * Find and return the location of the delimiter character in the
 * search buffer.
 *
 * This function gets used by the main socket parsing function which
 * continually reads from the socket and expands the buffer until it
 * encounters the expected delimiter. This function provides the logic
 * to check for the delimiter character in order to simplify the code
 * in the main parse function.
 *
 * @param[in]  buf       Search buffer used to find the delimiter.
 * @param[in]  buf_len   Number of bytes to search for in buf.
 * @param[in]  delim     The delimiter to search for in buf.
 * @param[out] delim_pos If delimiter found in buf, return the delimiter
 *                       position in this parameter.
 * @retval 1 If the delimiter character found.
 * @retval 0 If the delimiter character not found.
 */
static int
smtp_str_getdelimfd_search_delim(const char *const buf,
                                 size_t buf_len,
                                 int delim,
                                 size_t *const delim_pos){
  size_t i;

  *delim_pos = 0;
  for(i = 0; i < buf_len; i++){
    if(buf[i] == delim){
      *delim_pos = i;
      return 1;
    }
  }
  return 0;
}

/**
 * Set the internal line buffer to the number of bytes specified.
 *
 * @param[in] gdfd     See @ref str_getdelimfd.
 * @param[in] copy_len Number of bytes to copy to the internal line buffer.
 * @retval  0 Successfully allocated and copied data over to the new
 *            line buffer.
 * @retval -1 Failed to allocate memory for the new line buffer.
 */
static int
smtp_str_getdelimfd_set_line_and_buf(struct str_getdelimfd *const gdfd,
                                     size_t copy_len){
  if(gdfd->line){
    free(gdfd->line);
  }
  if((gdfd->line = calloc(1, copy_len + 1)) == NULL){
    return -1;
  }
  memcpy(gdfd->line, gdfd->_buf, copy_len);
  gdfd->line_len = copy_len;
  memmove(gdfd->_buf, gdfd->_buf + copy_len + 1, gdfd->_buf_len - copy_len);
  if(gdfd->_buf_len != 0){
    gdfd->_buf_len -= copy_len + 1;
  }
  return 0;
}

/**
 * Free memory in the @ref str_getdelimfd data structure.
 *
 * @param[in] gdfd Frees memory stored in this socket parsing structure.
 */
SMTP_LINKAGE void
smtp_str_getdelimfd_free(struct str_getdelimfd *const gdfd){
  free(gdfd->_buf);
  free(gdfd->line);
  gdfd->_buf = NULL;
  gdfd->_bufsz = 0;
  gdfd->_buf_len = 0;
  gdfd->line = NULL;
  gdfd->line_len = 0;
}

/**
 * Read and parse a delimited string using a custom socket read function.
 *
 * This interface handles all of the logic for expanding the buffer,
 * parsing the delimiter in the buffer, and returning each "line"
 * to the caller for handling.
 *
 * @param[in] gdfd See @ref str_getdelimfd.
 * @return @ref str_getdelim_retcode.
 */
SMTP_LINKAGE enum str_getdelim_retcode
smtp_str_getdelimfd(struct str_getdelimfd *const gdfd){
  size_t delim_pos;
  long bytes_read;
  void *read_buf_ptr;
  char *buf_new;
  size_t buf_sz_remaining;
  size_t buf_sz_new;

  if(gdfd->getdelimfd_read == NULL){
    return STRING_GETDELIMFD_ERROR;
  }

  bytes_read = -1;

  while(1){
    if(smtp_str_getdelimfd_search_delim(gdfd->_buf,
                                        gdfd->_buf_len,
                                        gdfd->delim,
                                        &delim_pos)){
      if(smtp_str_getdelimfd_set_line_and_buf(gdfd, delim_pos) < 0){
        smtp_str_getdelimfd_free(gdfd);
        return STRING_GETDELIMFD_ERROR;
      }
      return STRING_GETDELIMFD_NEXT;
    }else if(bytes_read == 0){
      if(smtp_str_getdelimfd_set_line_and_buf(gdfd, gdfd->_buf_len) < 0){
        smtp_str_getdelimfd_free(gdfd);
        return STRING_GETDELIMFD_ERROR;
      }
      return STRING_GETDELIMFD_DONE;
    }

    buf_sz_remaining = gdfd->_bufsz - gdfd->_buf_len;
    if(buf_sz_remaining < SMTP_GETDELIM_READ_SZ){
      buf_sz_new = buf_sz_remaining + SMTP_GETDELIM_READ_SZ;
      buf_new = realloc(gdfd->_buf, buf_sz_new);
      if(buf_new == NULL){
        smtp_str_getdelimfd_free(gdfd);
        return STRING_GETDELIMFD_ERROR;
      }
      gdfd->_buf = buf_new;
      gdfd->_bufsz = buf_sz_new;
    }
    read_buf_ptr = gdfd->_buf + gdfd->_buf_len;
    bytes_read = (*gdfd->getdelimfd_read)(gdfd,
                                          read_buf_ptr,
                                          SMTP_GETDELIM_READ_SZ);
    if(bytes_read < 0){
      smtp_str_getdelimfd_free(gdfd);
      return STRING_GETDELIMFD_ERROR;
    }
    gdfd->_buf_len += bytes_read;
  }
}

/**
 * Copy a string and get the pointer to the end of the copied buffer.
 *
 * This function behaves similar to POSIX stpcpy(), useful for
 * concatenating multiple strings onto a buffer. It always adds a
 * null-terminated byte at the end of the string.
 *
 * @param[in] s1 Destination buffer.
 * @param[in] s2 Null-terminated source string to copy to @p s1.
 * @return Pointer to location in @p s1 after the last copied byte.
 */
SMTP_LINKAGE char *
smtp_stpcpy(char *s1,
            const char *s2){
  size_t i;

  i = 0;
  do{
    s1[i] = s2[i];
  } while(s2[i++] != '\0');
  return &s1[i-1];
}

/**
 * Copy a string into a new dynamically allocated buffer.
 *
 * Returns a dynamically allocated string, with the same contents as the
 * input string. The caller must free the returned string when finished.
 *
 * @param[in] s String to duplicate.
 * @retval char* Pointer to a new dynamically allocated string duplicated
 *               from @p s.
 * @retval NULL  Failed to allocate memory for the new duplicate string.
 */
SMTP_LINKAGE char *
smtp_strdup(const char *s){
  char *dup;
  size_t dup_len;

  dup_len = strlen(s) + 1;
  if((dup = malloc(dup_len)) != NULL){
    memcpy(dup, s, dup_len);
  }
  return dup;
}

/**
 * Search for all substrings in a string and replace each instance with a
 * replacement string.
 *
 * @param[in] search  Substring to search for in @p s.
 * @param[in] replace Replace each instance of the search string with this.
 * @param[in] s       Null-terminated string to search and replace.
 * @retval char* A dynamically allocated string with the replaced instances
 *               as described above. The caller must free the allocated
 *               memory when finished.
 * @retval NULL  Memory allocation failure.
 */
SMTP_LINKAGE char *
smtp_str_replace(const char *const search,
                 const char *const replace,
                 const char *const s){
  size_t search_len;
  size_t replace_len;
  size_t slen;
  size_t s_idx;
  int found_matches;
  char *snew;
  size_t snew_len;
  size_t snew_sz;
  char *stmp;

  search_len    = strlen(search);
  replace_len   = strlen(replace);
  slen          = strlen(s);
  s_idx         = 0;
  found_matches = 0;
  snew          = NULL;
  snew_len      = 0;
  snew_sz       = 0;

  if(s[0] == '\0'){
    return smtp_strdup("");
  }
  else if(search_len < 1){
    return smtp_strdup(s);
  }

  while(s[s_idx]){
    if(strncmp(&s[s_idx], search, search_len) == 0){
      if(snew_len + replace_len + 1 >= snew_sz){
        snew_sz += snew_sz + slen + replace_len + 1;
        if((stmp = realloc(snew, snew_sz)) == NULL){
          free(snew);
          return NULL;
        }
        snew = stmp;
      }
      memcpy(&snew[snew_len], replace, replace_len);
      snew_len += replace_len;
      s_idx += search_len;
      found_matches += 1;
    }
    else{
      if(snew_len + 1 >= snew_sz){
        snew_sz += snew_sz + slen + snew_len + 1;
        if((stmp = realloc(snew, snew_sz)) == NULL){
          free(snew);
          return NULL;
        }
        snew = stmp;
      }
      snew[snew_len] = s[s_idx];
      s_idx += 1;
      snew_len += 1;
    }
  }
  snew[snew_len] = '\0';

  return snew;
}

/**
 * Lookup table used to encode data into base64.
 *
 * Base64 encoding takes six bits of data and encodes those bits using this
 * table. Since 2^6 = 64, this array has 64 entries which maps directly from
 * the 6 bit value into the corresponding array value.
 */
static unsigned char g_base64_encode_table[] = {
  'A','B','C','D','E','F','G','H','I','J',
  'K','L','M','N','O','P','Q','R','S','T',
  'U','V','W','X','Y','Z',
  'a','b','c','d','e','f','g','h','i','j',
  'k','l','m','n','o','p','q','r','s','t',
  'u','v','w','x','y','z',
  '0','1','2','3','4','5','6','7','8','9',
  '+','/'
};

/**
 * Encode a single block of binary data into base64.
 *
 * @param[in]  buf          Buffer with data to encode.
 * @param[in]  buf_block_sz Number of bytes in buf to encode (min 1, max 3).
 * @param[out] b64          Pointer to buffer with at least 4 bytes for
 *                          storing the base64 encoded result.
 */
static void
smtp_base64_encode_block(const char *const buf,
                         size_t buf_block_sz,
                         char *const b64){
  unsigned char inb[3] = {0};
  unsigned char in_idx[4] = {0};
  char outb[5] = {'=', '=', '=', '=', '\0'};
  size_t i;

  memcpy(inb, buf, buf_block_sz);

  in_idx[0] = ((inb[0] >> 2))                         & 0x3F;
  in_idx[1] = ((inb[0] << 4) | ((inb[1] >> 4) & 0xF)) & 0x3F;
  in_idx[2] = ((inb[1] << 2) | ((inb[2] >> 6) & 0x3)) & 0x3F;
  in_idx[3] = ((inb[2]     ))                         & 0x3F;
  for(i = 0; i < 4; i++){
    if(i < buf_block_sz + 1){
      outb[i] = g_base64_encode_table[in_idx[i]];
    }
    b64[i] = outb[i];
  }
}

/**
 * Encode binary data into a base64 string.
 *
 * @param[in] buf    Binary data to encode in base64.
 * @param[in] buflen Number of bytes in the @p buf parameter.
 * @retval char* Dynamically allocated base64 encoded string. The caller
 *               must free this string when finished.
 * @retval NULL  Memory allocation failure.
 */
SMTP_LINKAGE char *
smtp_base64_encode(const char *const buf,
                   long buflen){
  char *b64;
  size_t b64_sz;
  size_t buf_i;
  size_t b64_i;
  size_t remaining_block_sz;
  size_t buf_block_sz;

  if(buflen < 0){
    buflen = strlen(buf);
  }

  /*
   * base64 size expands by 33%
   * +1 to round integer division up
   * +2 for '=' padding
   * +1 null terminator
   */
  b64_sz = (4 * buflen / 3) + 1 + 2 + 1;
  if((b64 = calloc(1, b64_sz)) == NULL){
    return NULL;
  }

  if(buflen == 0){
    return b64;
  }

  buf_i = 0;
  b64_i = 0;
  remaining_block_sz = buflen;
  while(remaining_block_sz > 0){
    if(remaining_block_sz >= 3){
      buf_block_sz = 3;
    }
    else{
      buf_block_sz = remaining_block_sz;
    }

    smtp_base64_encode_block(&buf[buf_i], buf_block_sz, &b64[b64_i]);
    if(buf_block_sz < 3){
      break;
    }

    buf_i += 3;
    b64_i += 4;
    remaining_block_sz -= 3;
  }

  return b64;
}

#ifdef SMTP_OPENSSL
/**
 * Lookup table used to decode base64 data.
 *
 * For base64 encoding, every six bits have been encoded using only the ASCII
 * characters from @ref g_base64_encode_table. This table has entries which
 * allow the reversal of that process. It has 128 entries which map over to
 * the index value from the encoding table. If an indexing result ends up
 * with -1 during the decoding process, then that indicates an invalid base64
 * character in the encoded data.
 */
static signed char
g_base64_decode_table[] = {
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1,
  62,                                     /*   +   */
  -1, -1, -1,
  63,                                     /*   /   */
  52, 53, 54, 55, 56, 57, 58, 59, 60, 61, /* 0 - 9 */
  -1, -1, -1, -1, -1, -1, -1,
   0,  1,  2,  3,  4,  5,  6,  7,  8,  9, /* A - J */
  10, 11, 12, 13, 14, 15, 16, 17, 18, 19, /* K - T */
  20, 21, 22, 23, 24, 25,                 /* U - Z */
  -1, -1, -1, -1, -1, -1,
  26, 27, 28, 29, 30, 31, 32, 33, 34, 35, /* a - j */
  36, 37, 38, 39, 40, 41, 42, 43, 44, 45, /* k - t */
  46, 47, 48, 49, 50, 51,                 /* u - z */
  -1, -1, -1, -1, -1
};

/**
 * Decodes a base64 block of up to four bytes at a time.
 *
 * @param[in]  buf    Buffer containing bytes to decode.
 * @param[out] decode Buffer for storing base64 decoded bytes.
 * @retval >0 Length of the decoded block.
 * @retval -1 If the block contains invalid base64 data.
 */
static int
smtp_base64_decode_block(const unsigned char *const buf,
                         unsigned char *const decode){
  int decode_block_len;
  size_t i;
  signed char decode_table[4];
  unsigned char outb[3];

  decode_block_len = 0;
  for(i = 0; i < 4; i++){
    if(buf[i] == '='){
      decode_table[i] = 0;
      continue;
    }
    decode_table[i] = g_base64_decode_table[buf[i]];
    if(decode_table[i] < 0){
      return -1;
    }
  }

  outb[0] = ((decode_table[0] << 2) & 0xFC) | ((decode_table[1] >> 4) & 0x03);
  outb[1] = ((decode_table[1] << 4) & 0xF0) | ((decode_table[2] >> 2) & 0x0F);
  outb[2] = ((decode_table[2] << 6) & 0xC0) | ((decode_table[3]     ) & 0x3F);

  decode[0] = outb[0];
  decode_block_len += 1;

  if(buf[2] == '='){
    decode[1] = '\0';
  }
  else{
    decode[1] = outb[1];
    decode_block_len += 1;
  }

  if(buf[3] == '='){
    decode[2] = '\0';
  }
  else{
    decode[2] = outb[2];
    decode_block_len += 1;
  }

  return decode_block_len;
}

/**
 * Decode a base64 string.
 *
 * The decode parameter will get dynamically allocated by this function
 * if it successfully completes. Therefore, the caller must free the decode
 * parameter after use.
 *
 * @param[in]  buf    Null-terminated base64 string.
 * @param[out] decode Pointer to buffer which will get dynamically allocated
 *                    and will contain the decoded binary data. This parameter
 *                    will get set to NULL if the memory allocation fails.
 * @retval >=0 Length of the data stored in the decode parameter.
 * @retval -1  Memory allocation failure or invalid base64 byte sequences.
 */
SMTP_LINKAGE long
smtp_base64_decode(const char *const buf,
                   unsigned char **decode){
  size_t buf_len;
  size_t buf_i;
  unsigned char *b64_decode;
  long decode_len;
  int decode_block_len;

  *decode = NULL;

  buf_len = strlen(buf);
  if(buf_len % 4 != 0){
    return -1;
  }

  if((b64_decode = calloc(1, buf_len + 1)) == NULL){
    return -1;
  }

  decode_len = 0;
  for(buf_i = 0; buf_i < buf_len; buf_i += 4){
    if((decode_block_len = smtp_base64_decode_block(
                             (const unsigned char*)&buf[buf_i],
                             &b64_decode[decode_len])) < 0){
      free(b64_decode);
      return -1;
    }
    decode_len += decode_block_len;
  }
  *decode = b64_decode;
  return decode_len;
}

/**
 * Convert binary data to lowercase hexadecimal representation.
 *
 * @param[in] s    Buffer containing binary data to convert.
 * @param[in] slen Number of bytes in @p s.
 * @retval char* Dynamically allocated string consisting of a hexadecimal
 *               representation of binary data in @p s. The caller must free
 *               this memory when finished.
 * @retval NULL  Memory allocation or encoding error.
 */
SMTP_LINKAGE char *
smtp_bin2hex(const unsigned char *const s,
             size_t slen){
  char *snew;
  size_t alloc_sz;
  size_t i;
  size_t j;
  unsigned hex;
  int rc;

  alloc_sz = slen * 2 + 1;
  if((snew = malloc(alloc_sz)) == NULL){
    return NULL;
  }

  for(i = 0, j = 0; i < slen; i++, j += 2){
    hex = s[i];
    rc = sprintf(&snew[j], "%02x", hex);
    if(rc < 0 || (size_t)rc >= 3){
      free(snew);
      return NULL;
    }
  }
  snew[j] = '\0';

  return snew;
}
#endif /* SMTP_OPENSSL */

/**
 * Get the length in bytes of a UTF-8 character.
 *
 * This consists of a very simple check and assumes the user provides a valid
 * UTF-8 byte sequence. It gets the length from the first byte in the sequence
 * and does not validate any other bytes in the character sequence or any other
 * bits in the first byte of the character sequence.
 *
 * @param[in] c The first byte in a valid UTF-8 character sequence.
 * @retval >0 Number of bytes for the current UTF-8 character sequence.
 * @retval -1 Invalid byte sequence.
 */
SMTP_LINKAGE int
smtp_utf8_charlen(unsigned char c){
  if((c & 0x80) == 0){         /* 0XXXXXXX */
    return 1;
  }
  else if((c & 0xE0) == 0xC0){ /* 110XXXXX */
    return 2;
  }
  else if((c & 0xF0) == 0xE0){ /* 1110XXXX */
    return 3;
  }
  else if((c & 0xF8) == 0xF0){ /* 11110XXX */
    return 4;
  }
  else{                        /* invalid  */
    return -1;
  }
}

/**
 * Check if a string contains non-ASCII UTF-8 characters.
 *
 * Uses the simple algorithm from @ref smtp_utf8_charlen to check for
 * non-ASCII UTF-8 characters.
 *
 * @param[in] s UTF-8 string.
 * @retval 1 String contains non-ASCII UTF-8 characters.
 * @retval 0 String contains only ASCII characters.
 */
SMTP_LINKAGE int
smtp_str_has_nonascii_utf8(const char *const s){
  int i;
  int charlen;

  for(i = 0; s[i]; i++){
    charlen = smtp_utf8_charlen(s[i]);
    if(charlen != 1){
      return 1;
    }
  }
  return 0;
}

/**
 * Get the number of bytes in a UTF-8 string, or a shorter count if
 * the string exceeds a maximum specified length.
 *
 * See @p maxlen for more information on multi-byte parsing.
 *
 * @param[in] s      Null-terminated UTF-8 string.
 * @param[in] maxlen Do not check more than @p maxlen bytes of string @p s
 *                   except if in the middle of a multi-byte character.
 * @retval strlen(s) If length of s has less bytes than maxlen or the same
 *                   number of bytes as maxlen. See @p maxlen for more details.
 * @retval maxlen    If length of s has more bytes than maxlen.
 * @retval -1        If @p s contains an invalid UTF-8 byte sequence.
 */
SMTP_LINKAGE long
smtp_strnlen_utf8(const char *s,
                  size_t maxlen){
  size_t i;
  int utf8_i;
  int utf8_len;

  for(i = 0; *s && i < maxlen; i += utf8_len){
    utf8_len = smtp_utf8_charlen(*s);
    if(utf8_len < 0){
      return -1;
    }

    for(utf8_i = 0; utf8_i < utf8_len; utf8_i++){
      if(!*s){
        return -1;
      }
      s += 1;
    }
  }
  return i;
}

/**
 * Get the offset of the next whitespace block to process folding.
 *
 * If a string does not have whitespace before @p maxlen, then the index
 * will get returned past @p maxlen. Also returns the index of NULL character
 * if that fits within the next block. The caller must check for the NULL
 * index to indicate the last block. It will skip past any leading whitespace
 * even if that means going over maxlen.
 *
 * Examples:
 * @ref smtp_fold_whitespace_get_offset ("Subject: Test WS", 1/2/8/9/10/13) -> 8
 * @ref smtp_fold_whitespace_get_offset ("Subject: Test WS", 14/15) -> 13
 * @ref smtp_fold_whitespace_get_offset ("Subject: Test WS", 17/18) -> 16
 *
 * @param[in] s      String to get offset from.
 * @param[in] maxlen Number of bytes for each line in the string (soft limit).
 * @return Index in @p s.
 */
SMTP_LINKAGE size_t
smtp_fold_whitespace_get_offset(const char *const s,
                                unsigned int maxlen){
  size_t i;
  size_t offset_i;

  i = 0;
  offset_i = 0;

  while(s[i] == ' ' || s[i] == '\t'){
    i += 1;
  }

  while(s[i]){
    if(s[i] == ' ' || s[i] == '\t'){
      do{
        i += 1;
      } while(s[i] == ' ' || s[i] == '\t');
      i -= 1;
      if(i < maxlen || !offset_i){
        offset_i = i;
      }
      else{
        break;
      }
    }
    i += 1;
  }

  if(!offset_i || i < maxlen){
    offset_i = i;
  }

  return offset_i;
}

/**
 * Email header lines should have no more than 78 characters and must
 * not be more than 998 characters.
 */
#define SMTP_LINE_MAX 78

/**
 * Fold a line at whitespace characters.
 *
 * This function tries to keep the total number of characters per line under
 * @p maxlen, but does not guarantee this. For really long text with no
 * whitespace, the line will still extend beyond @p maxlen and possibly
 * beyond the RFC limit as defined in @ref SMTP_LINE_MAX. This is by design
 * and intended to keep the algorithm simpler to implement. Users sending
 * long headers with no space characters should not assume that will work,
 * but modern email systems may correctly process those headers anyways.
 *
 * Lines get folded by adding a [CR][LF] and then two space characters on the
 * beginning of the next line. For example, this Subject line:
 *
 * Subject: Email[WS][WS]Header
 *
 * Would get folded like this (assuming a small @p maxlen):
 *
 * Subject: Email[WS][CR][LF]
 * [WS][WS]Header
 *
 * @param[in] s      String to fold.
 * @param[in] maxlen Number of bytes for each line in the string (soft limit).
 *                   The minimum value of this parameter is 3 and it will get
 *                   forced to 3 if the provided value is less.
 * @retval char* Pointer to an allocated string with the contents split into
 *               separate lines. The caller must free this memory when done.
 * @retval NULL  Memory allocation failed.
 */
SMTP_LINKAGE char *
smtp_fold_whitespace(const char *const s,
                     unsigned int maxlen){
  const char *const SMTP_LINE_FOLD_STR = "\r\n ";
  size_t end_slen;
  size_t s_i;
  size_t buf_i;
  size_t bufsz;
  size_t ws_offset;
  char *buf;
  char *buf_new;

  if(maxlen < 3){
    maxlen = 3;
  }

  end_slen = strlen(SMTP_LINE_FOLD_STR);

  s_i = 0;
  buf_i = 0;
  bufsz = 0;
  buf = NULL;

  while(1){
    ws_offset = smtp_fold_whitespace_get_offset(&s[s_i], maxlen - 2);

    bufsz += ws_offset + end_slen + 1;
    buf_new = realloc(buf, bufsz);
    if(buf_new == NULL){
      free(buf);
      return NULL;
    }
    buf = buf_new;
    memcpy(&buf[buf_i], &s[s_i], ws_offset);
    buf[buf_i + ws_offset] = '\0';

    if(s[s_i + ws_offset] == '\0'){
      break;
    }

    buf_i += ws_offset;
    strcat(&buf[buf_i], SMTP_LINE_FOLD_STR);
    buf_i += end_slen;

    /*                 WS */
    s_i += ws_offset + 1;
  }
  return buf;
}

/**
 * Splits a string into smaller chunks separated by a terminating string.
 *
 * @param[in] s        The string to chunk.
 * @param[in] chunklen Number of bytes for each chunk in the string.
 * @param[in] end      Terminating string placed at the end of each chunk.
 * @retval char* Pointer to an allocated string with the contents split into
 *               separate chunks. The caller must free this memory when done.
 * @retval NULL  Memory allocation failure.
 */
SMTP_LINKAGE char *
smtp_chunk_split(const char *const s,
                 int chunklen,
                 const char *const end){
  char *snew;
  size_t bodylen;
  size_t endlen;
  size_t snewlen;
  size_t chunk_i;
  size_t snew_i;
  size_t body_i;
  long body_copy_len;

  if(chunklen < 1){
    errno = EINVAL;
    return NULL;
  }

  bodylen = strlen(s);
  endlen = strlen(end);

  if(bodylen < 1){
    return smtp_strdup(end);
  }

  snewlen = bodylen + (endlen + 1) * (bodylen / chunklen + 1) + 1;

  if((snew = calloc(1, snewlen)) == NULL){
    return NULL;
  }

  body_i = 0;
  snew_i = 0;
  for(chunk_i = 0; chunk_i < bodylen / chunklen + 1; chunk_i++){
    body_copy_len = smtp_strnlen_utf8(&s[body_i], chunklen);
    if(body_copy_len < 0){
      free(snew);
      errno = EINVAL;
      return NULL;
    }
    memcpy(&snew[snew_i], &s[body_i], body_copy_len);
    snew_i += body_copy_len;
    if(s[body_i] == '\0'){
      snew_i += 1;
    }
    body_i += body_copy_len;

    if(endlen > 0){
      memcpy(&snew[snew_i], end, endlen);
    }
    snew_i += endlen;
  }

  return snew;
}

/**
 * Read the entire contents of a file stream and store the data into a
 * dynamically allocated buffer.
 *
 * @param[in]  stream     File stream already opened by the caller.
 * @param[out] bytes_read Number of bytes stored in the return buffer.
 * @retval char* A dynamically allocated buffer which contains the entire
 *               contents of @p stream. The caller must free this memory
 *               when done.
 * @retval NULL Memory allocation or file read error.
 */
SMTP_LINKAGE char *
smtp_ffile_get_contents(FILE *stream,
                        size_t *bytes_read){
  char *read_buf;
  size_t bufsz;
  char *new_buf;
  size_t bytes_read_loop;
  const size_t BUFSZ_INCREMENT = 512;

  read_buf = NULL;
  bufsz = 0;

  if(bytes_read){
    *bytes_read = 0;
  }

  do{
    if((new_buf = realloc(read_buf, bufsz + BUFSZ_INCREMENT)) == NULL){
      free(read_buf);
      return NULL;
    }
    read_buf = new_buf;
    bufsz += BUFSZ_INCREMENT;

    bytes_read_loop = fread(&read_buf[bufsz - BUFSZ_INCREMENT],
                            sizeof(char),
                            BUFSZ_INCREMENT,
                            stream);
    if(bytes_read){
      *bytes_read += bytes_read_loop;
    }
    if(ferror(stream)){
      free(read_buf);
      return NULL;
    }
  } while(!feof(stream));

  return read_buf;
}

/**
 * Read the entire contents of a file from a given path, and store the data
 * into a dynamically allocated buffer.
 *
 * @param[in]  filename   Path of file to open and read from.
 * @param[out] bytes_read Number of bytes stored in the return buffer.
 * @retval char* A dynamically allocated buffer which has the contents of
 *         the file at @p filename. The caller must free this memory when
 *         done.
 * @retval NULL Memory allocation or file read error.
 */
SMTP_LINKAGE char *
smtp_file_get_contents(const char *const filename,
                       size_t *bytes_read){
  FILE *fp;
  char *read_buf;

  if((fp = fopen(filename, "r")) == NULL){
    return NULL;
  }

  read_buf = smtp_ffile_get_contents(fp, bytes_read);

  if(fclose(fp) == EOF){
    free(read_buf);
    read_buf = NULL;
  }

  return read_buf;
}

/**
 * Parse a server response line into the @ref smtp_command data structure.
 *
 * @param[in]  line Server response string.
 * @param[out] cmd  Structure containing the server response data broken up
 *                  into its separate components.
 * @return See @ref smtp_result_code.
 */
SMTP_LINKAGE int
smtp_parse_cmd_line(char *const line,
                    struct smtp_command *const cmd){
  char *ep;
  char code_str[4];
  size_t line_len;

  line_len = strlen(line);
  if(line_len < 5){
    cmd->code = SMTP_INTERNAL_ERROR;
    cmd->more = 0;
    cmd->text = line;
    return cmd->code;
  }

  cmd->text = &line[4];

  memcpy(code_str, line, 3);
  code_str[3] = '\0';
  cmd->code = strtoul(code_str, &ep, 10);
  if(*ep != '\0'){
    cmd->code = SMTP_INTERNAL_ERROR;
  }
  cmd->more = line[3] == '-' ? 1 : 0;
  return cmd->code;
}

/**
 * Prints communication between the client and server to stderr only if
 * the debug flag has been set.
 *
 * @param[in] smtp   SMTP client context.
 * @param[in] prefix Print this prefix before the main debug line text.
 * @param[in] str    Debug text to print out.
 */
static void
smtp_puts_dbg(struct smtp *const smtp,
              const char *const prefix,
              const char *const str){
  char *sdup;
  size_t i;

  if(smtp->flags & SMTP_DEBUG){
    if((sdup = smtp_strdup(str)) == NULL){
      return;
    }

    /* Remove carriage return and newline when printing to stderr. */
    for(i = 0; sdup[i]; i++){
      if(sdup[i] == '\r' || sdup[i] == '\n'){
        sdup[i] = ' ';
      }
    }

    if(fprintf(stderr, "[smtp %s]: %s\n", prefix, sdup) < 0){
      /* Do not care if this fails. */
    }
    free(sdup);
  }
}

/**
 * Read a server response line.
 *
 * @param[in] smtp SMTP client context.
 * @return @ref str_getdelim_retcode.
 */
static enum str_getdelim_retcode
smtp_getline(struct smtp *const smtp){
  enum str_getdelim_retcode rc;

  errno = 0;
  rc = smtp_str_getdelimfd(&smtp->gdfd);
  if(errno == ENOMEM){
    smtp_status_code_set(smtp, SMTP_STATUS_NOMEM);
    return rc;
  }
  else if(rc == STRING_GETDELIMFD_ERROR){
    smtp_status_code_set(smtp, SMTP_STATUS_RECV);
    return STRING_GETDELIMFD_ERROR;
  }

  if(smtp->gdfd.line_len > 0){
    /* Remove the carriage-return character ('\r'). */
    smtp->gdfd.line[smtp->gdfd.line_len - 1] = '\0';
    smtp_puts_dbg(smtp, "Server", smtp->gdfd.line);
  }
  return rc;
}

/**
 * Loop through all of the server response lines until the last line, and
 * then return the status code from the last response line.
 *
 * @param[in] smtp SMTP client context.
 * @return @ref smtp_result_code.
 */
static int
smtp_read_and_parse_code(struct smtp *const smtp){
  struct smtp_command cmd;
  enum str_getdelim_retcode rc;

  do{
    rc = smtp_getline(smtp);
    if(rc == STRING_GETDELIMFD_ERROR){
      return SMTP_INTERNAL_ERROR;
    }

    smtp_parse_cmd_line(smtp->gdfd.line, &cmd);
  }while (rc != STRING_GETDELIMFD_DONE && cmd.more);

  return cmd.code;
}

/**
 * Send data to the SMTP server.
 *
 * Writes a buffer of length len into either the unencrypted TCP socket or
 * the TLS encrypted socket, depending on the current underlying mode of
 * the socket.
 *
 * @param[in] smtp SMTP client context.
 * @param[in] buf Data to send to the SMTP server.
 * @param[in] len Number of bytes in buf.
 * @return @ref smtp_status_code.
 */
static int
smtp_write(struct smtp *const smtp,
           const char *const buf,
           size_t len){
  smtp_puts_dbg(smtp, "Client", buf);

  if(smtp->tls_on){
#ifdef SMTP_OPENSSL
    if(SSL_write(smtp->tls, buf, len) <= 0){
      return smtp_status_code_set(smtp, SMTP_STATUS_SEND);
    }
#endif /* SMTP_OPENSSL */
  }
  else{
    if(send(smtp->sock, buf, len, 0) < 0){
      return smtp_status_code_set(smtp, SMTP_STATUS_SEND);
    }
  }

  return smtp->status_code;
}

/**
 * Send a null-terminated string to the SMTP server.
 *
 * @param[in] smtp SMTP client context.
 * @param[in] s    Null-terminated string to send to the SMTP server.
 * @return See @ref smtp_status_code and @ref smtp_write.
 */
static int
smtp_puts(struct smtp *const smtp,
          const char *const s){
  return smtp_write(smtp, s, strlen(s));
}

/**
 * Same as @ref smtp_puts except this function also appends the line
 * terminating carriage return and newline bytes at the end of the string.
 *
 * @param[in] smtp SMTP client context.
 * @param[in] s    Null-terminated string to send to the SMTP server.
 * @return See @ref smtp_status_code and @ref smtp_puts.
 */
static int
smtp_puts_terminate(struct smtp *const smtp,
                    const char *const s){
  int rc;
  char *line;
  char *concat;

  if((line = malloc(strlen(s) + 3)) == NULL){
    return smtp_status_code_set(smtp, SMTP_STATUS_NOMEM);
  }
  concat = smtp_stpcpy(line, s);
  smtp_stpcpy(concat, "\r\n");
  rc = smtp_puts(smtp, line);
  free(line);
  return rc;
}

/**
 * Connect to the server using a standard TCP socket.
 *
 * This function handles the server name lookup to get an IP address
 * for the server, and then to connect to that IP using a normal TCP
 * connection.
 *
 * @param[in] smtp   SMTP client context.
 * @param[in] server Mail server name or IP address.
 * @param[in] port   Mail server port number.
 * @retval  0 Successfully connected to server.
 * @retval -1 Failed to connect to server.
 */
static int
smtp_connect(struct smtp *const smtp,
             const char *const server,
             const char *const port){
  struct addrinfo hints;
  struct addrinfo *res0;
  struct addrinfo *res;

  /*
   * Windows requires initializing the socket library before we call any
   * socket functions.
   */
#ifdef SMTP_IS_WINDOWS
  /* Windows global network socket data structure. */
  WSADATA wsa_data;
  if(WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0){
    return -1;
  }
#endif /* SMTP_IS_WINDOWS */

  memset(&hints, 0, sizeof(hints));
  hints.ai_family   = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags    = 0;
  hints.ai_protocol = IPPROTO_TCP;

  if(getaddrinfo(server, port, &hints, &res0) != 0){
    return -1;
  }

  for(res = res0; res; res = res->ai_next){
    smtp->sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if(smtp->sock < 0){
      continue;
    }

    if(connect(smtp->sock, res->ai_addr, res->ai_addrlen) < 0){
#ifdef SMTP_IS_WINDOWS
      closesocket(smtp->sock);
#else /* POSIX */
      close(smtp->sock);
#endif /* SMTP_IS_WINDOWS */
      smtp->sock = -1;
    }
    else{
      break;
    }
  }

  freeaddrinfo(res0);
  if(smtp->sock < 0){
    return -1;
  }

  return 0;
}

#ifdef SMTP_OPENSSL
/**
 * Initialize the TLS library and establish a TLS handshake with the server
 * over the existing socket connection.
 *
 * @param[in] smtp   SMTP client context.
 * @param[in] server Server name or IP address.
 * @retval  0 Successfully established a TLS connection with the server.
 * @retval -1 Failed to establish a TLS connection with the server.
 */
static int
smtp_tls_init(struct smtp *const smtp,
              const char *const server){
  X509 *X509_cert_peer;

  /* Do not need to check the return value since this always returns 1. */
  SSL_library_init();

  SSL_load_error_strings();
  ERR_load_BIO_strings();
  OpenSSL_add_all_algorithms();

  if((smtp->tls_ctx = SSL_CTX_new(SSLv23_client_method())) == NULL){
    return -1;
  }

  /* Disable SSLv2, SSLv3, and TLSv1.0. */
  SSL_CTX_set_options(smtp->tls_ctx,
                      SSL_OP_NO_SSLv2 |
                      SSL_OP_NO_SSLv3 |
                      SSL_OP_NO_TLSv1);

  SSL_CTX_set_mode(smtp->tls_ctx, SSL_MODE_AUTO_RETRY);
  if((smtp->flags & SMTP_NO_CERT_VERIFY) == 0){
    SSL_CTX_set_verify(smtp->tls_ctx, SSL_VERIFY_PEER, NULL);
  }

  /*
   * Set the path to the user-provided CA file or use the default cert paths
   * if not provided.
   */
  if(smtp->cafile){
    if(SSL_CTX_load_verify_locations(smtp->tls_ctx, smtp->cafile, NULL) != 1){
      SSL_CTX_free(smtp->tls_ctx);
      return -1;
    }
  }
  else{
    X509_STORE_set_default_paths(SSL_CTX_get_cert_store(smtp->tls_ctx));
    if(ERR_peek_error() != 0){
      SSL_CTX_free(smtp->tls_ctx);
      return -1;
    }
  }

  if((smtp->tls = SSL_new(smtp->tls_ctx)) == NULL){
    SSL_CTX_free(smtp->tls_ctx);
    return -1;
  }

  if((smtp->tls_bio = BIO_new_socket(smtp->sock, 0)) == NULL){
    SSL_CTX_free(smtp->tls_ctx);
    SSL_free(smtp->tls);
    return -1;
  }

  SSL_set_bio(smtp->tls, smtp->tls_bio, smtp->tls_bio);
  SSL_set_connect_state(smtp->tls);
  if(SSL_connect(smtp->tls) != 1){
    SSL_CTX_free(smtp->tls_ctx);
    SSL_free(smtp->tls);
    return -1;
  }

  if(SSL_do_handshake(smtp->tls) != 1){
    SSL_CTX_free(smtp->tls_ctx);
    SSL_free(smtp->tls);
    return -1;
  }

  /* Verify matching subject in certificate. */
  if((smtp->flags & SMTP_NO_CERT_VERIFY) == 0){
    if((X509_cert_peer = SSL_get_peer_certificate(smtp->tls)) == NULL){
      SSL_CTX_free(smtp->tls_ctx);
      SSL_free(smtp->tls);
      return -1;
    }
    if(X509_check_host(X509_cert_peer, server, 0, 0, NULL) != 1){
      SSL_CTX_free(smtp->tls_ctx);
      SSL_free(smtp->tls);
      return -1;
    }
    X509_free(X509_cert_peer);
  }

  smtp->tls_on = 1;
  return 0;
}
#endif /* SMTP_OPENSSL */

/**
 * Send the EHLO command and parse through the responses.
 *
 * Ignores all of the server extensions that get returned. If a server
 * doesn't support an extension we need, then we should receive an error
 * later on when we try to use that extension.
 *
 * @param[in] smtp SMTP client context.
 * @return @ref smtp_status_code.
 */
static int
smtp_ehlo(struct smtp *const smtp){
  if(smtp_puts(smtp, "EHLO smtp\r\n") != SMTP_STATUS_OK){
    return smtp->status_code;
  }

  smtp_read_and_parse_code(smtp);
  return smtp->status_code;
}

/**
 * Authenticate using the PLAIN method.
 *
 *   1. Set the text to the following format: "\0<user>\0<password>",
 *      or as shown in the format string: "\0%s\0%s", email, password.
 *   2. Base64 encode the text from (1).
 *   3. Send the constructed auth text from (2) to the server:
 *      "AUTH PLAIN <b64>\r\n".
 *
 * @param[in] smtp SMTP client context.
 * @param[in] user SMTP account user name.
 * @param[in] pass SMTP account password.
 * @retval  0 Successfully authenticated.
 * @retval -1 Failed to authenticate.
 */
static int
smtp_auth_plain(struct smtp *const smtp,
                const char *const user,
                const char *const pass){
  size_t user_len;
  size_t pass_len;
  char *login_str;
  int login_len;
  char *login_b64;
  char *login_send;
  char *concat;

  /* (1) */
  user_len = strlen(user);
  pass_len = strlen(pass);
  login_len = 1 + user_len + 1 + pass_len;
  if((login_str = malloc(login_len)) == NULL){
    return -1;
  }
  login_str[0] = '\0';
  memcpy(&login_str[1], user, user_len);
  login_str[1 + user_len] = '\0';
  memcpy(&login_str[1 + user_len + 1], pass, pass_len);

  /* (2) */
  login_b64 = smtp_base64_encode(login_str, login_len);
  free(login_str);
  if(login_b64 == NULL){
    return -1;
  }

  /* (3) */
  if((login_send = malloc(strlen(login_b64) + 14)) == NULL){
    free(login_b64);
    return -1;
  }
  concat = smtp_stpcpy(login_send, "AUTH PLAIN ");
  concat = smtp_stpcpy(concat, login_b64);
  smtp_stpcpy(concat, "\r\n");

  free(login_b64);
  smtp_puts(smtp, login_send);
  free(login_send);
  if(smtp->status_code != SMTP_STATUS_OK){
    return -1;
  }

  if(smtp_read_and_parse_code(smtp) != SMTP_AUTH_SUCCESS){
    return -1;
  }
  return 0;
}

/**
 * Authenticate using the LOGIN method.
 *
 *   1. Base64 encode the user name.
 *   2. Send string from (1) as part of the login:
 *      "AUTH LOGIN <b64_username>\r\n".
 *   3. Base64 encode the password and send that by itself on a separate
 *      line: "<b64_password>\r\n".
 *
 * @param[in] smtp SMTP client context.
 * @param[in] user SMTP account user name.
 * @param[in] pass SMTP account password.
 * @retval  0 Successfully authenticated.
 * @retval -1 Failed to authenticate.
 */
static int
smtp_auth_login(struct smtp *const smtp,
                const char *const user,
                const char *const pass){
  char *b64_user;
  char *b64_pass;
  char *login_str;
  char *concat;

  /* (1) */
  if((b64_user = smtp_base64_encode(user, -1)) == NULL){
    return -1;
  }

  /* (2) */
  if((login_str = malloc(strlen(b64_user) + 14)) == NULL){
    free(b64_user);
    return -1;
  }
  concat = smtp_stpcpy(login_str, "AUTH LOGIN ");
  concat = smtp_stpcpy(concat, b64_user);
  smtp_stpcpy(concat, "\r\n");

  free(b64_user);
  smtp_puts(smtp, login_str);
  free(login_str);
  if(smtp->status_code != SMTP_STATUS_OK){
     return -1;
   }

  if(smtp_read_and_parse_code(smtp) != SMTP_AUTH_CONTINUE){
    return -1;
  }

  /* (3) */
  if((b64_pass = smtp_base64_encode(pass, -1)) == NULL){
    return -1;
  }
  smtp_puts_terminate(smtp, b64_pass);
  free(b64_pass);
  if(smtp->status_code != SMTP_STATUS_OK){
    return -1;
  }

  if(smtp_read_and_parse_code(smtp) != SMTP_AUTH_SUCCESS){
    return -1;
  }
  return 0;
}

#ifdef SMTP_OPENSSL
/**
 * Authenticate using the CRAM-MD5 method.
 *
 *   1. Send "AUTH CRAM-MD5\r\n" to the server.
 *   2. Decode the base64 challenge response from the server.
 *   3. Do an MD5 HMAC on (2) using the account password as the key.
 *   4. Convert the binary data in (3) to lowercase hex characters.
 *   5. Construct the string: "<user> <(4)>".
 *   6. Encode (5) into base64 format.
 *   7. Send the final string from (6) to the server and check the response.
 *
 * @param[in] smtp SMTP client context.
 * @param[in] user SMTP account user name.
 * @param[in] pass SMTP account password.
 * @retval  0 Successfully authenticated.
 * @retval -1 Failed to authenticate.
 */
static int
smtp_auth_cram_md5(struct smtp *const smtp,
                   const char *const user,
                   const char *const pass){
  struct smtp_command cmd;
  unsigned char *challenge_decoded;
  long challenge_decoded_len;
  const char *key;
  int key_len;
  unsigned char hmac[EVP_MAX_MD_SIZE];
  unsigned int hmac_len;
  unsigned char *hmac_ret;
  char *challenge_hex;
  char *auth_concat;
  char *concat;
  size_t auth_concat_len;
  char *b64_auth;

  /* (1) */
  if(smtp_puts(smtp, "AUTH CRAM-MD5\r\n") != SMTP_STATUS_OK){
    return -1;
  }
  if(smtp_getline(smtp) == STRING_GETDELIMFD_ERROR){
    return -1;
  }
  if(smtp_parse_cmd_line(smtp->gdfd.line, &cmd) != SMTP_AUTH_CONTINUE){
    return -1;
  }

  /* (2) */
  challenge_decoded_len = smtp_base64_decode(cmd.text, &challenge_decoded);
  if(challenge_decoded_len < 0){
    return -1;
  }

  /* (3) */
  key = pass;
  key_len = strlen(pass);
  hmac_ret = HMAC(EVP_md5(),
                  key, key_len,
                  challenge_decoded, challenge_decoded_len,
                  hmac, &hmac_len);
  free(challenge_decoded);
  if(hmac_ret == NULL){
    return -1;
  }

  /* (4) */
  challenge_hex = smtp_bin2hex(hmac, hmac_len);
  if(challenge_hex == NULL){
    return -1;
  }

  /* (5) */
  auth_concat_len = strlen(user) + 1 + strlen(challenge_hex) + 1;
  if((auth_concat = malloc(auth_concat_len)) == NULL){
    free(challenge_hex);
    return -1;
  }
  concat = smtp_stpcpy(auth_concat, user);
  concat = smtp_stpcpy(concat, " ");
  smtp_stpcpy(concat, challenge_hex);
  free(challenge_hex);

  /* (6) */
  b64_auth = smtp_base64_encode(auth_concat, auth_concat_len - 1);
  free(auth_concat);
  if(b64_auth == NULL){
    return -1;
  }

  /* (7) */
  smtp_puts_terminate(smtp, b64_auth);
  free(b64_auth);
  if(smtp->status_code != SMTP_STATUS_OK){
    return -1;
  }

  if(smtp_read_and_parse_code(smtp) != SMTP_AUTH_SUCCESS){
    return -1;
  }
  return 0;
}
#endif /* SMTP_OPENSSL */

/**
 * Set the timeout for the next socket read operation.
 *
 * @param[in] smtp    SMTP client context.
 * @param[in] seconds Timeout in seconds.
 */
static void
smtp_set_read_timeout(struct smtp *const smtp,
                 long seconds){
  smtp->timeout_sec = seconds;
}

/**
 * Perform a handshake with the SMTP server which includes optionally
 * setting up TLS and sending the EHLO greeting.
 *
 * At this point, the client has already connected to the SMTP server
 * through its socket connection. In this function, the client will:
 *   1. Optionally convert the connection to TLS (SMTP_SECURITY_TLS).
 *   2. Read the initial server greeting.
 *   3. Send an EHLO to the server.
 *   4. Optionally initiate STARTTLS and resend the EHLO
 *      (SMTP_SECURITY_STARTTLS).
 *
 * @param[in] smtp                SMTP client context.
 * @param[in] server              Server name or IP address.
 * @param[in] connection_security See @ref smtp_connection_security.
 * @return @ref smtp_status_code.
 */
static int
smtp_initiate_handshake(struct smtp *const smtp,
                        const char *const server,
                        enum smtp_connection_security connection_security){
  /* Eliminate unused warnings if not using SMTP_OPENSSL. */
  (void)server;
  (void)connection_security;

  /* (1) */
#ifdef SMTP_OPENSSL
  if(connection_security == SMTP_SECURITY_TLS){
    if(smtp_tls_init(smtp, server) < 0){
      return smtp_status_code_set(smtp, SMTP_STATUS_HANDSHAKE);
    }
  }
#endif /* SMTP_OPENSSL */

  /* (2) */
  /* Get initial 220 message - 5 minute timeout. */
  smtp_set_read_timeout(smtp, 60 * 5);
  if(smtp_getline(smtp) == STRING_GETDELIMFD_ERROR){
    return smtp->status_code;
  }

  /* (3) */
  if(smtp_ehlo(smtp) != SMTP_STATUS_OK){
    return smtp->status_code;
  }

  /* (4) */
#ifdef SMTP_OPENSSL
  if(connection_security == SMTP_SECURITY_STARTTLS){
    if(smtp_puts(smtp, "STARTTLS\r\n") != SMTP_STATUS_OK){
      return smtp->status_code;
    }
    if(smtp_read_and_parse_code(smtp) != SMTP_READY){
      return smtp_status_code_set(smtp, SMTP_STATUS_HANDSHAKE);
    }
    if(smtp_tls_init(smtp, server) < 0){
      return smtp_status_code_set(smtp, SMTP_STATUS_HANDSHAKE);
    }
    if(smtp_ehlo(smtp) != SMTP_STATUS_OK){
      return smtp->status_code;
    }
  }
#endif /* SMTP_OPENSSL */

  return smtp->status_code;
}

/**
   Maximum size of an RFC 2822 date string.

   @verbatim
   Thu, 21 May 1998 05:33:29 -0700
   12345678901234567890123456789012
           10        20        30 32 (bytes)
   @endverbatim

   Add more bytes to the 32 maximum size to silence compiler warning on the
   computed UTF offset.
 */
#define SMTP_DATE_MAX_SZ (32 + 5)

/**
 * Convert the time into an RFC 2822 formatted string.
 *
 * Example date format:
 * Thu, 21 May 1998 05:33:29 -0700
 *
 * @param[out] date Buffer that has at least SMTP_DATE_MAX_SZ bytes.
 * @retval  0 Successfully copied the current date to the buffer.
 * @retval -1 Failed to establish the current date or an output
 *            format error occurred.
 */
SMTP_LINKAGE int
smtp_date_rfc_2822(char *const date){
  time_t t;
  time_t t_local;
  time_t t_utc;
  struct tm tm_local;
  struct tm tm_utc;
  long offset_utc;
  int rc;

  const char weekday_abbreviation[7][4] = {
    "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
  };

  const char month_abbreviation[12][4] = {
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
  };

  if((t = time(NULL)) == (time_t)(-1)){
    return -1;
  }

#ifdef SMTP_IS_WINDOWS
  if(localtime_s(&tm_local, &t) ||
     gmtime_s(&tm_utc, &t)){
    return -1;
  }
#else /* POSIX */
  /* Not defined if system does not have localtime_r or gmtime_r. */
# ifdef SMTP_TIME_NO_REENTRANT
  struct tm *tm;

  /* localtime() not thread-safe. */
  if((tm = localtime(&t)) == NULL){
    return -1;
  }
  memcpy(&tm_local, tm, sizeof(tm_local));

  /* gmtime() not thread-safe. */
  if((tm = gmtime(&t)) == NULL){
    return -1;
  }
  memcpy(&tm_utc, tm, sizeof(tm_utc));
# else /* Reentrant versions: localtime_r() and gmtime_r(). */
  if(localtime_r(&t, &tm_local) == NULL ||
     gmtime_r(&t, &tm_utc) == NULL){
    return -1;
  }
# endif /* SMTP_TIME_NO_REENTRANT */
#endif /* SMTP_IS_WINDOWS */

  if((t_local = mktime(&tm_local)) == (time_t)(-1)){
    return -1;
  }

  if((t_utc = mktime(&tm_utc)) == (time_t)(-1)){
    return -1;
  }

  /*
   * After computing the offset, it will contain a maximum of 4 digits.
   * For example, PST time zone will have an offset of -800 which will get
   * formatted as -0800 in the sprintf call below.
   */
  offset_utc = difftime(t_local, t_utc);
  offset_utc = offset_utc / 60 / 60 * 100;

  rc = sprintf(date,
               "%s, %02d %s %d %02d:%02d:%02d %0+5ld",
               weekday_abbreviation[tm_local.tm_wday],
               tm_local.tm_mday,
               month_abbreviation[tm_local.tm_mon],
               tm_local.tm_year + 1900,
               tm_local.tm_hour,
               tm_local.tm_min,
               tm_local.tm_sec, /* 0 - 60 (leap second) */
               offset_utc);

  if(rc + 1 != SMTP_DATE_MAX_SZ - 5){ /* See @ref SMTP_DATE_MAX_SZ for -5. */
    return -1;
  }

  return 0;
}

/**
 * Minimum length of buffer required to hold the MIME boundary test:
 * mimeXXXXXXXXXX
 * 123456789012345
 * 1       10   15 bytes
 */
#define SMTP_MIME_BOUNDARY_LEN 15

/**
 * Generate the MIME boundary text field and store it in a user-supplied
 * buffer.
 *
 * For example:
 * mimeXXXXXXXXXX
 * where each X gets set to a pseudo-random uppercase ASCII character.
 *
 * This uses a simple pseudo-random number generator since we only care
 * about preventing accidental boundary collisions.
 *
 * @param[out] boundary Buffer that has at least SMTP_MIME_BOUNDARY_LEN bytes.
 */
static void
smtp_gen_mime_boundary(char *const boundary){
  size_t i;

  strcpy(boundary, "mime");
  srand(time(NULL));
  for(i = 4; i < SMTP_MIME_BOUNDARY_LEN - 1; i++){
    /* Modulo bias okay since we only need to prevent accidental collision. */
    boundary[i] = rand() % 26 + 'A';
  }
  boundary[SMTP_MIME_BOUNDARY_LEN - 1] = '\0';
}

/**
 * Print the MIME header and the MIME section containing the email body.
 *
 * @param[in] smtp     SMTP client context.
 * @param[in] boundary MIME boundary text.
 * @param[in] body     Email body text.
 * @return @ref smtp_status_code.
 */
static int
smtp_print_mime_header_and_body(struct smtp *const smtp,
                                const char *const boundary,
                                const char *const body){
  char *data_double_dot;
  size_t bufsz;
  char *data_header_and_body;
  char *concat;

  /*
   * Insert an extra dot for each line that begins with a dot. This will
   * prevent data in the body parameter from prematurely ending the DATA
   * segment.
   */
  if((data_double_dot = smtp_str_replace("\r\n.", "\r\n..", body)) == NULL){
    return smtp_status_code_set(smtp, SMTP_STATUS_NOMEM);
  }

  bufsz = strlen(data_double_dot) + 1000;
  if((data_header_and_body = malloc(bufsz)) == NULL){
    free(data_double_dot);
    return smtp_status_code_set(smtp, SMTP_STATUS_NOMEM);
  }

  concat = smtp_stpcpy(data_header_and_body,
                       "MIME-Version: 1.0\r\n"
                       "Content-Type: multipart/mixed; boundary=");
  concat = smtp_stpcpy(concat,
                       boundary);
  concat = smtp_stpcpy(concat,
                       "\r\n"
                       "\r\n"
                       "Multipart MIME message.\r\n"
                       "--");
  concat = smtp_stpcpy(concat,
                       boundary);
  concat = smtp_stpcpy(concat,
                       "\r\n"
                       "Content-Type: text/plain; charset=\"UTF-8\"\r\n"
                       "\r\n");
  concat = smtp_stpcpy(concat,
                       data_double_dot);
  smtp_stpcpy(concat,
              "\r\n"
              "\r\n");

  free(data_double_dot);
  smtp_puts(smtp, data_header_and_body);
  free(data_header_and_body);
  return smtp->status_code;
}

/**
 * Print a MIME section containing an attachment.
 *
 * @param[in] smtp       SMTP client context.
 * @param[in] boundary   MIME boundary text.
 * @param[in] attachment @ref smtp_attachment.
 * @return @ref smtp_status_code.
 */
static int
smtp_print_mime_attachment(struct smtp *const smtp,
                           const char *const boundary,
                           const struct smtp_attachment *const attachment){
  size_t bufsz;
  char *mime_attach_text;
  char *concat;

  bufsz = SMTP_MIME_BOUNDARY_LEN       +
          strlen(attachment->name)     +
          strlen(attachment->b64_data) +
          1000;
  if((mime_attach_text = malloc(bufsz)) == NULL){
    return smtp_status_code_set(smtp, SMTP_STATUS_NOMEM);
  }

  concat = smtp_stpcpy(mime_attach_text,
                       "--");
  concat = smtp_stpcpy(concat,
                       boundary);
  concat = smtp_stpcpy(concat,
                       "\r\n"
                       "Content-Type: application/octet-stream\r\n"
                       "Content-Disposition: attachment; filename=\"");
  concat = smtp_stpcpy(concat,
                       attachment->name);
  concat = smtp_stpcpy(concat,
                       "\"\r\n"
                       "Content-Transfer-Encoding: base64\r\n"
                       "\r\n");
  concat = smtp_stpcpy(concat,
                       attachment->b64_data);
  smtp_stpcpy(concat,
              "\r\n"
              "\r\n");
  smtp_puts(smtp, mime_attach_text);
  free(mime_attach_text);
  return smtp->status_code;
}

/**
 * Prints double hyphen on both sides of the MIME boundary which indicates
 * the end of the MIME sections.
 *
 * @param[in] smtp     SMTP client context.
 * @param[in] boundary MIME boundary text.
 * @return See @ref smtp_status_code and @ref smtp_puts.
 */
static int
smtp_print_mime_end(struct smtp *const smtp,
                    const char *const boundary){
  char *concat;
  char mime_end[2 + SMTP_MIME_BOUNDARY_LEN + 4 + 1];

  concat = smtp_stpcpy(mime_end, "--");
  concat = smtp_stpcpy(concat, boundary);
  smtp_stpcpy(concat, "--\r\n");
  return smtp_puts(smtp, mime_end);
}

/**
 * Send the main email body to the SMTP server.
 *
 * This includes the MIME sections for the email body and attachments.
 *
 * @param[in] smtp SMTP client context.
 * @param[in] body Null-terminated string to send in the email body.
 * @return @ref smtp_status_code.
 */
static int
smtp_print_mime_email(struct smtp *const smtp,
                      const char *const body){
  char boundary[SMTP_MIME_BOUNDARY_LEN];
  size_t i;
  struct smtp_attachment *attachment;

  smtp_gen_mime_boundary(boundary);

  if(smtp_print_mime_header_and_body(smtp, boundary, body) != SMTP_STATUS_OK){
    return smtp->status_code;
  }

  for(i = 0; i < smtp->num_attachment; i++){
    attachment = &smtp->attachment_list[i];
    if(smtp_print_mime_attachment(smtp,
                                  boundary,
                                  attachment) != SMTP_STATUS_OK){
      return smtp->status_code;
    }
  }

  return smtp_print_mime_end(smtp, boundary);
}

/**
 * Convert a header into an RFC 5322 formatted string and send it to the
 * SMTP server.
 *
 * This will adding proper line wrapping and indentation for long
 * header lines.
 *
 * @param[in] smtp   SMTP client context.
 * @param[in] header See @ref smtp_header.
 * @return @ref smtp_status_code.
 */
static int
smtp_print_header(struct smtp *const smtp,
                  const struct smtp_header *const header){
  size_t concat_len;
  char *header_concat;
  char *concat;
  char *header_fmt;

  if(header->value == NULL){
    return smtp->status_code;
  }

  concat_len = strlen(header->key) + 2 + strlen(header->value) + 1;
  if((header_concat = malloc(concat_len)) == NULL){
    return smtp_status_code_set(smtp, SMTP_STATUS_NOMEM);
  }
  concat = smtp_stpcpy(header_concat, header->key);
  concat = smtp_stpcpy(concat, ": ");
  smtp_stpcpy(concat, header->value);

  header_fmt = smtp_fold_whitespace(header_concat, SMTP_LINE_MAX);
  free(header_concat);
  if(header_fmt == NULL){
    return smtp_status_code_set(smtp, SMTP_STATUS_NOMEM);
  }

  smtp_puts_terminate(smtp, header_fmt);
  free(header_fmt);
  return smtp->status_code;
}

/**
 * Take a FROM, TO, and CC address and add it into the email header list.
 *
 * The following example shows what the final header might look like when
 * the client sends an email to two CC addresses:
 * Cc: mail1@example.com, mail2@example.com
 *
 * @param[in] smtp         SMTP client context.
 * @param[in] address_type @ref smtp_address_type.
 * @param[in] key          Header key value, for example, To From Cc.
 * @return @ref smtp_status_code.
 */
static int
smtp_append_address_to_header(struct smtp *const smtp,
                              enum smtp_address_type address_type,
                              const char *const key){
  size_t i;
  size_t num_address_in_header;
  size_t header_value_sz;
  size_t name_slen;
  size_t email_slen;
  size_t concat_len;
  struct smtp_address *address;
  char *header_value;
  char *header_value_new;
  char *concat;

  num_address_in_header = 0;
  header_value_sz = 0;
  header_value = NULL;
  concat_len = 0;
  for(i = 0; i < smtp->num_address; i++){
    address = &smtp->address_list[i];
    if(address->type == address_type){
      name_slen = 0;
      if(address->name){
        name_slen = strlen(address->name);
      }

      email_slen = strlen(address->email);
      /*                ', "'      NAME     '" <'      EMAIL     >  \0 */
      header_value_sz +=  3  +  name_slen  +  3  +  email_slen + 1 + 1;
      if((header_value_new = realloc(header_value,
                                     header_value_sz)) == NULL){
        free(header_value);
        return smtp_status_code_set(smtp, SMTP_STATUS_NOMEM);
      }
      header_value = header_value_new;
      concat = header_value + concat_len;
      if(num_address_in_header > 0){
        concat = smtp_stpcpy(concat, ", ");
      }

      if(name_slen){
        concat = smtp_stpcpy(concat, "\"");
        concat = smtp_stpcpy(concat, address->name);
        concat = smtp_stpcpy(concat, "\" ");
      }
      concat = smtp_stpcpy(concat, "<");
      concat = smtp_stpcpy(concat, address->email);
      concat = smtp_stpcpy(concat, ">");
      num_address_in_header += 1;
      concat_len = concat - header_value;
    }
  }

  if(header_value){
    smtp_header_add(smtp, key, header_value);
    free(header_value);
  }
  return smtp->status_code;
}

/**
 * Send envelope MAIL FROM or RCPT TO header address.
 *
 * Examples:
 * MAIL FROM:<mail@example.com>
 * RCPT TO:<mail@example.com>
 *
 * @param[in] smtp    SMTP client context.
 * @param[in] header  Either "MAIL FROM" or "RCPT TO".
 * @param[in] address @ref smtp_address -> email field.
 * @return @ref smtp_status_code.
 */
static int
smtp_mail_envelope_header(struct smtp *const smtp,
                          const char *const header,
                          const struct smtp_address *const address){
  const char *const SMTPUTF8 = " SMTPUTF8";
  size_t bufsz;
  char *envelope_address;
  char *concat;
  const char *smtputf8_opt;

  bufsz = 14 + strlen(address->email) + strlen(SMTPUTF8) + 1;
  if((envelope_address = malloc(bufsz)) == NULL){
    return smtp_status_code_set(smtp, SMTP_STATUS_NOMEM);
  }

  smtputf8_opt = "";
  if(smtp_str_has_nonascii_utf8(address->email)){
    smtputf8_opt = SMTPUTF8;
  }

  concat = smtp_stpcpy(envelope_address, header);
  concat = smtp_stpcpy(concat, ":<");
  concat = smtp_stpcpy(concat, address->email);
  concat = smtp_stpcpy(concat, ">");
  concat = smtp_stpcpy(concat, smtputf8_opt);
  smtp_stpcpy(concat, "\r\n");
  smtp_puts(smtp, envelope_address);
  free(envelope_address);

  if(smtp->status_code != SMTP_STATUS_OK){
    return smtp->status_code;
  }
  smtp_read_and_parse_code(smtp);
  return smtp->status_code;
}

/**
 * Comparison function for qsort which sorts headers alphabetically based
 * on the key.
 *
 * @param[in] v1 The first @ref smtp_header to compare.
 * @param[in] v2 The second @ref smtp_header to compare.
 * @retval  0 If the keys match.
 * @retval !0 If the keys do not match.
 */
static int
smtp_header_cmp(const void *v1,
                const void *v2){
  const struct smtp_header *header1;
  const struct smtp_header *header2;

  header1 = v1;
  header2 = v2;
  return strcmp(header1->key, header2->key);
}

/**
 * Search function used by bsearch which allows the caller to check for
 * headers with existing keys.
 *
 * @param v1 String to search for in the list.
 * @param v2 The @ref smtp_header to compare.
 * @retval  0 If the keys match.
 * @retval !0 If the keys do not match.
 */
static int
smtp_header_cmp_key(const void *const v1,
                    const void *const v2){
  const char *key;
  const struct smtp_header *header2;

  key = v1;
  header2 = v2;
  return strcmp(key, header2->key);
}

/**
 * Determine if the header key has already been defined in this context.
 *
 * @param[in] smtp SMTP client context.
 * @param[in] key  Header key value to search for.
 * @retval 1 If the header already exists in this context.
 * @retval 0 If the header does not exist in this context.
 */
static int
smtp_header_exists(const struct smtp *const smtp,
                   const char *const key){
  if(bsearch(key,
             smtp->header_list,
             smtp->num_headers,
             sizeof(*smtp->address_list),
             smtp_header_cmp_key) == NULL){
    return 0;
  }
  return 1;
}

/**
 * Validate characters in the email header key.
 *
 * Must consist only of printable US-ASCII characters except colon.
 *
 * @param[in] key Header key to validate.
 * @retval  0 Successful validation.
 * @retval -1 Failed to validate.
 */
SMTP_LINKAGE int
smtp_header_key_validate(const char *const key){
  unsigned c;
  size_t i;
  size_t keylen;

  keylen = strlen(key);
  if(keylen < 1){
    return -1;
  }

  for(i = 0; i < keylen; i++){
    c = key[i];
    if(c <= ' ' || c > 126 || c == ':'){
      return -1;
    }
  }

  return 0;
}

/**
 * Validate characters in the email header contents.
 *
 * Must consist only of printable character, space, or horizontal tab.
 *
 * @param[in] value Header value to validate.
 * @retval  0 Successful validation.
 * @retval -1 Failed to validate.
 */
SMTP_LINKAGE int
smtp_header_value_validate(const char *const value){
  size_t i;
  unsigned char c;

  for(i = 0; value[i]; i++){
    c = value[i];
    if((c < ' ' || c > 126) &&
        c != '\t' &&
        c < 0x80){ /* Allow UTF-8 byte sequence. */
      return -1;
    }
  }
  return 0;
}

/**
 * Validate characters in the email address.
 *
 * The email address must consist only of printable characters excluding
 * the angle brackets (<) and (>).
 *
 * @param[in] email The email address of the party.
 * @retval  0 Successful validation.
 * @retval -1 Failed to validate.
 */
SMTP_LINKAGE int
smtp_address_validate_email(const char *const email){
  size_t i;
  unsigned char c;

  for(i = 0; email[i]; i++){
    c = email[i];
    if(c <= ' ' || c == 127 ||
       c == '<' || c == '>'){
      return -1;
    }
  }
  return 0;
}

/**
 * Validate characters in the email name.
 *
 * Email user name must consist only of printable characters, excluding the
 * double quote character.
 *
 * @param[in] name Email name to validate.
 * @retval  0 Successful validation.
 * @retval -1 Failed to validate.
 */
SMTP_LINKAGE int
smtp_address_validate_name(const char *const name){
  size_t i;
  unsigned char c;

  for(i = 0; name[i]; i++){
    c = name[i];
    if(c < ' ' || c == 127 || c == '\"'){
      return -1;
    }
  }
  return 0;
}

/**
 * Validate characters in the attachment file name.
 *
 * Must consist only of printable characters or the space character ( ), and
 * excluding the quote characters (') and (").
 *
 * @param[in] name Filename of the attachment shown to recipients.
 * @retval  0 Successful validation.
 * @retval -1 Failed to validate.
 */
SMTP_LINKAGE int
smtp_attachment_validate_name(const char *const name){
  size_t i;
  unsigned c;

  for(i = 0; name[i]; i++){
    c = name[i];
    if(c < ' ' || c == 127 ||
       c == '\'' || c == '\"'){
      return -1;
    }
  }
  return 0;
}

/**
 * Special flag value for the SMTP context used to determine if the initial
 * memory allocation failed to create the context.
 */
#define SMTP_FLAG_INVALID_MEMORY (enum smtp_flag)(0xFFFFFFFF)

/**
 * This error structure used for the single error case where we cannot
 * initially allocate memory. This makes it easier to propagate any
 * error codes when calling the other header functions because the
 * caller will always get a valid SMTP structure returned.
 */
static struct smtp smtp_error = {
  SMTP_FLAG_INVALID_MEMORY, /* flags                        */
  0,                        /* sock                         */
  {                         /* gdfd                         */
    NULL,                   /* _buf                         */
    0,                      /* _bufsz                       */
    0,                      /* _buf_len                     */
    0,                      /* delim                        */
    NULL,                   /* line                         */
    0,                      /* line_len                     */
    NULL,                   /* getdelimfd_read              */
    NULL                    /* user_data                    */
  },                        /* gdfd                         */
  NULL,                     /* header_list                  */
  0,                        /* num_headers                  */
  NULL,                     /* address_list                 */
  0,                        /* num_address                  */
  NULL,                     /* attachment_list              */
  0,                        /* num_attachment               */
  SMTP_STATUS_NOMEM,        /* smtp_status_code status_code */
  0,                        /* timeout_sec                  */
  0,                        /* tls_on                       */
  NULL                      /* cafile                       */
#ifdef SMTP_OPENSSL
  ,
  NULL,                     /* tls                          */
  NULL,                     /* tls_ctx                      */
  NULL                      /* tls_bio                      */
#endif /* SMTP_OPENSSL */
};


/**
 * Open a connection to an SMTP server and return the context.
 *
 * After successfully connecting and performing a handshake with the
 * SMTP server, this function will return an SMTP client context which
 * the calling program can use in the other API function calls. The
 * caller must always use this function prior to any other smtp-client
 * library function.
 *
 * This function always returns a valid SMTP client context even if
 * the server connection or memory allocation fails. However, the error
 * status will continue to propagate to any further function calls for
 * the SMTP context while in this failure mode.
 *
 * This function will ignore the SIGPIPE signal. Applications that require a
 * handler for that signal should set it up after calling this function.
 *
 * @param[in]  server              Server name or IP address.
 * @param[in]  port                Server port number.
 * @param[in]  connection_security See @ref smtp_connection_security.
 * @param[in]  flags               See @ref smtp_flag.
 * @param[in]  cafile              Path to certificate file, or NULL to use
 *                                 certificates in the default path.
 * @param[out] smtp                Pointer to a new SMTP context which will
 *                                 always have a valid state even if memory
 *                                 allocation fails. When finished, the caller
 *                                 must free this context using
 *                                 @ref smtp_close.
 * @return @ref smtp_status_code.
 */
enum smtp_status_code
smtp_open(const char *const server,
          const char *const port,
          enum smtp_connection_security connection_security,
          enum smtp_flag flags,
          const char *const cafile,
          struct smtp **smtp){
  struct smtp *snew;

  if((snew = calloc(1, sizeof(**smtp))) == NULL){
    *smtp = &smtp_error;
    return smtp_status_code_get(*smtp);
  }
  *smtp = snew;

  snew->flags = flags;
  snew->cafile = cafile;

#ifndef SMTP_IS_WINDOWS
  signal(SIGPIPE, SIG_IGN);
#endif /* !(SMTP_IS_WINDOWS) */

  if(smtp_connect(snew, server, port) < 0){
    return smtp_status_code_set(*smtp, SMTP_STATUS_CONNECT);
  }

  /* All other gdfd fields already set to NULL from the snew calloc. */
  snew->gdfd.delim           = '\n';
  snew->gdfd.getdelimfd_read = smtp_str_getdelimfd_read;
  snew->gdfd.user_data       = snew;

  if(smtp_initiate_handshake(snew,
                             server,
                             connection_security) != SMTP_STATUS_OK){
    return smtp_status_code_set(*smtp, SMTP_STATUS_HANDSHAKE);
  }

  return snew->status_code;
}

/**
 * Authenticate the user using one of the methods listed in
 * @ref smtp_authentication_method.
 *
 * @param[in] smtp        SMTP client context.
 * @param[in] auth_method See @ref smtp_authentication_method.
 * @param[in] user        Server authentication user name.
 * @param[in] pass        Server authentication user password.
 * @return @ref smtp_status_code.
 */
enum smtp_status_code
smtp_auth(struct smtp *const smtp,
          enum smtp_authentication_method auth_method,
          const char *const user,
          const char *const pass){
  int auth_rc;

  if(smtp->status_code != SMTP_STATUS_OK){
    return smtp->status_code;
  }

  switch(auth_method){
    case SMTP_AUTH_PLAIN:
      auth_rc = smtp_auth_plain(smtp, user, pass);
      break;
    case SMTP_AUTH_LOGIN:
      auth_rc = smtp_auth_login(smtp, user, pass);
      break;

#ifdef SMTP_OPENSSL
    case SMTP_AUTH_CRAM_MD5:
      auth_rc = smtp_auth_cram_md5(smtp, user, pass);
      break;
#endif /* SMTP_OPENSSL */

    case SMTP_AUTH_NONE:
      auth_rc = 0;
      break;
    default:
      return smtp_status_code_set(smtp, SMTP_STATUS_PARAM);
  }

  if(auth_rc < 0){
    return smtp_status_code_set(smtp, SMTP_STATUS_AUTH);
  }

  return smtp->status_code;
}

/**
 * Sends an email using the addresses, attachments, and headers defined
 * in the current SMTP context.
 *
 * The caller must use the smtp_open function prior to this function. The
 * 'Date' header also gets generated here if it hasn't already been provided.
 *
 * @param[in] smtp SMTP client context.
 * @param[in] body Null-terminated string to send in the email body.
 * @return @ref smtp_status_code.
 */
enum smtp_status_code
smtp_mail(struct smtp *const smtp,
          const char *const body){
  size_t i;
  int has_mail_from;
  struct smtp_address *address;
  char date[SMTP_DATE_MAX_SZ];

  if(smtp->status_code != SMTP_STATUS_OK){
    return smtp->status_code;
  }

  /* MAIL timeout 5 minutes. */
  smtp_set_read_timeout(smtp, 60 * 5);
  has_mail_from = 0;
  for(i = 0; i < smtp->num_address; i++){
    address = &smtp->address_list[i];
    if(address->type == SMTP_ADDRESS_FROM){
      if(smtp_mail_envelope_header(smtp,
                                   "MAIL FROM",
                                   address) != SMTP_STATUS_OK){
        return smtp->status_code;
      }
      has_mail_from = 1;
      break;
    }
  }

  if(!has_mail_from){
    return smtp_status_code_set(smtp, SMTP_STATUS_PARAM);
  }

  /* RCPT timeout 5 minutes. */
  smtp_set_read_timeout(smtp, 60 * 5);

  for(i = 0; i < smtp->num_address; i++){
    address = &smtp->address_list[i];
    if(address->type != SMTP_ADDRESS_FROM){
      if(smtp_mail_envelope_header(smtp,
                                   "RCPT TO",
                                   address) != SMTP_STATUS_OK){
        return smtp->status_code;
      }
    }
  }

  /* DATA timeout 2 minutes. */
  smtp_set_read_timeout(smtp, 60 * 2);

  if(smtp_puts(smtp, "DATA\r\n") != SMTP_STATUS_OK){
    return smtp->status_code;
  }

  /* 354 response to DATA must get returned before we can send the message. */
  if(smtp_read_and_parse_code(smtp) != SMTP_BEGIN_MAIL){
    return smtp_status_code_set(smtp, SMTP_STATUS_SERVER_RESPONSE);
  }

  if(!smtp_header_exists(smtp, "Date")){
    if(smtp_date_rfc_2822(date) < 0){
      return smtp_status_code_set(smtp, SMTP_STATUS_DATE);
    }
    if(smtp_header_add(smtp, "Date", date) != SMTP_STATUS_OK){
      return smtp->status_code;
    }
  }

  /* DATA block timeout 3 minutes. */
  smtp_set_read_timeout(smtp, 60 * 3);

  if(smtp_append_address_to_header(smtp,
                                   SMTP_ADDRESS_FROM,
                                   "From") != SMTP_STATUS_OK ||
     smtp_append_address_to_header(smtp,
                                   SMTP_ADDRESS_TO,
                                   "To") != SMTP_STATUS_OK ||
     smtp_append_address_to_header(smtp,
                                   SMTP_ADDRESS_CC,
                                   "Cc") != SMTP_STATUS_OK){
    return smtp->status_code;
  }

  for(i = 0; i < smtp->num_headers; i++){
    if(smtp_print_header(smtp, &smtp->header_list[i]) != SMTP_STATUS_OK){
      return smtp->status_code;
    }
  }

  if(smtp_print_mime_email(smtp, body) != SMTP_STATUS_OK){
    return smtp->status_code;
  }

  /* End of DATA segment. */
  if(smtp_puts(smtp, ".\r\n") != SMTP_STATUS_OK){
    return smtp->status_code;
  }

  /* DATA termination timeout 250 return code - 10 minutes. */
  smtp_set_read_timeout(smtp, 60 * 10);
  if(smtp_read_and_parse_code(smtp) != SMTP_DONE){
    return smtp_status_code_set(smtp, SMTP_STATUS_SERVER_RESPONSE);
  }

  return smtp->status_code;
}

/**
 * Close the SMTP connection and frees all resources held by the
 * SMTP context.
 *
 * @param[in] smtp SMTP client context.
 * @return @ref smtp_status_code.
 */
enum smtp_status_code
smtp_close(struct smtp *smtp){
  enum smtp_status_code status_code;

  status_code = smtp->status_code;

  if(smtp->flags == SMTP_FLAG_INVALID_MEMORY){
    return status_code;
  }

  if(smtp->sock){
    /*
     * Do not error out if this fails because we still need to free the
     * SMTP client resources.
     */
    smtp->status_code = SMTP_STATUS_OK;
    smtp_puts(smtp, "QUIT\r\n");

#ifdef SMTP_OPENSSL
    if(smtp->tls_on){
      SSL_free(smtp->tls);
      SSL_CTX_free(smtp->tls_ctx);
    }
#endif /* SMTP_OPENSSL */

#ifdef SMTP_IS_WINDOWS
    closesocket(smtp->sock);
    WSACleanup();
#else /* POSIX */
    if(close(smtp->sock) < 0){
      if(smtp->status_code == SMTP_STATUS_OK){
        smtp_status_code_set(smtp, SMTP_STATUS_CLOSE);
      }
    }
#endif /* SMTP_IS_WINDOWS */
  }

  smtp_str_getdelimfd_free(&smtp->gdfd);
  smtp_header_clear_all(smtp);
  smtp_address_clear_all(smtp);
  smtp_attachment_clear_all(smtp);
  if(status_code == SMTP_STATUS_OK){
    status_code = smtp->status_code;
  }
  free(smtp);

  return status_code;
}

/**
 * Get the current status/error code described in @ref smtp_status_code.
 *
 * @param[in] smtp SMTP client context.
 * @return @ref smtp_status_code.
 */
enum smtp_status_code
smtp_status_code_get(const struct smtp *const smtp){
  return smtp->status_code;
}

/**
 * Set the error status of the SMTP client context and return the same code.
 *
 * This function allows the caller to clear an error status to SMTP_STATUS_OK
 * so that previous errors will stop propagating. However, this will only
 * work correctly for clearing the SMTP_STATUS_PARAM and SMTP_STATUS_FILE
 * errors. Clearing the status from any other error code will invoke
 * undefined behavior and will almost never work correctly.
 *
 * @param[in] smtp        SMTP client context.
 * @param[in] status_code See @ref smtp_status_code.
 * @return @ref smtp_status_code.
 */
enum smtp_status_code
smtp_status_code_set(struct smtp *const smtp,
                     enum smtp_status_code status_code){
  if((unsigned)status_code >= SMTP_STATUS__LAST){
    return smtp_status_code_set(smtp, SMTP_STATUS_PARAM);
  }
  smtp->status_code = status_code;
  return status_code;
}

/**
 * Convert a standard smtp-client return code to a description.
 *
 * @param[in] status_code Status code returned from one of the other
 *                        smtp-client library functions.
 * @return String containing a description of the @p status_code. The caller
 *         must not free or modify this string.
 */
const char *
smtp_status_code_errstr(enum smtp_status_code status_code){
  const char *const status_code_err_str[] = {
    /* SMTP_STATUS_OK */
    "Success",
    /* SMTP_STATUS_NOMEM */
    "Memory allocation failed",
    /* SMTP_STATUS_CONNECT */
    "Failed to connect to the mail server",
    /* SMTP_STATUS_HANDSHAKE */
    "Failed to handshake or negotiate a TLS connection with the server",
    /* SMTP_STATUS_AUTH */
    "Failed to authenticate with the given credentials",
    /* SMTP_STATUS_SEND */
    "Failed to send bytes to the server",
    /* SMTP_STATUS_RECV */
    "Failed to receive bytes from the server",
    /* SMTP_STATUS_CLOSE */
    "Failed to properly close a connection",
    /* SMTP_STATUS_SERVER_RESPONSE */
    "SMTP server sent back an unexpected status code",
    /* SMTP_STATUS_PARAM */
    "Invalid parameter",
    /* SMTP_STATUS_FILE */
    "Failed to read or open a local file",
    /* SMTP_STATUS_DATE */
    "Failed to get the local date and time",
    /* SMTP_STATUS__LAST */
    "Unknown error"
  };

  if((unsigned)status_code > SMTP_STATUS__LAST){
    status_code = SMTP_STATUS__LAST;
  }
  return status_code_err_str[status_code];
}

/**
 * Add a key/value header to the header list in the SMTP context.
 *
 * This will insert instead of replacing an existing header with the same key.
 *
 * @param[in] smtp  SMTP client context.
 * @param[in] key   Key name for new header. It must consist only of
 *                  printable US-ASCII characters except colon.
 * @param[in] value Value for new header. It must consist only of printable
 *                  US-ASCII, space, or horizontal tab. If set to NULL,
 *                  this will prevent the header from printing out.
 * @return @ref smtp_status_code.
 */
enum smtp_status_code
smtp_header_add(struct smtp *const smtp,
                const char *const key,
                const char *const value){
  struct smtp_header *new_header_list;
  struct smtp_header *new_header;
  size_t new_realloc_sz;

  if(smtp->status_code != SMTP_STATUS_OK){
    return smtp->status_code;
  }

  if(smtp_header_key_validate(key) < 0){
    return smtp_status_code_set(smtp, SMTP_STATUS_PARAM);
  }

  if(value && smtp_header_value_validate(value) < 0){
    return smtp_status_code_set(smtp, SMTP_STATUS_PARAM);
  }

  new_realloc_sz = (smtp->num_headers + 1) * sizeof(*smtp->header_list);
  if((new_header_list = realloc(smtp->header_list, new_realloc_sz)) == NULL){
    return smtp_status_code_set(smtp, SMTP_STATUS_NOMEM);
  }
  smtp->header_list = new_header_list;
  new_header = &smtp->header_list[smtp->num_headers];

  new_header->key = smtp_strdup(key);
  new_header->value = value ? smtp_strdup(value) : NULL;
  if(new_header->key == NULL ||
     (new_header->value == NULL && value)){
    free(new_header->key);
    free(new_header->value);
    return smtp_status_code_set(smtp, SMTP_STATUS_NOMEM);
  }

  smtp->num_headers += 1;

  qsort(smtp->header_list,
        smtp->num_headers,
        sizeof(*smtp->header_list),
        smtp_header_cmp);

  return smtp->status_code;
}

/**
 * Free all memory related to email headers.
 *
 * @param[in] smtp SMTP client context.
 */
void smtp_header_clear_all(struct smtp *const smtp){
  size_t i;
  struct smtp_header *header;

  for(i = 0; i < smtp->num_headers; i++){
    header = &smtp->header_list[i];
    free(header->key);
    free(header->value);
  }
  free(smtp->header_list);
  smtp->header_list = NULL;
  smtp->num_headers = 0;
}

/**
 * Add a FROM, TO, CC, or BCC address destination to this SMTP context.
 *
 * @note Some SMTP servers may reject over 100 recipients.
 *
 * @param[in] smtp  SMTP client context.
 * @param[in] type  See @ref smtp_address_type.
 * @param[in] email The email address of the party. Must consist only of
 *                  printable characters excluding the angle brackets
 *                  (<) and (>).
 * @param[in] name  Name or description of the party. Must consist only of
 *                  printable characters, excluding the quote characters. If
 *                  set to NULL or empty string, no name will get associated
 *                  with this email.
 * @return @ref smtp_status_code.
 */
enum smtp_status_code
smtp_address_add(struct smtp *const smtp,
                 enum smtp_address_type type,
                 const char *const email,
                 const char *const name){
  size_t new_size;
  struct smtp_address *new_address_list;
  struct smtp_address *new_address;

  if(smtp->status_code != SMTP_STATUS_OK){
    return smtp->status_code;
  }

  if(smtp_address_validate_email(email) < 0){
    return smtp_status_code_set(smtp, SMTP_STATUS_PARAM);
  }

  if(name && smtp_address_validate_name(name) < 0){
    return smtp_status_code_set(smtp, SMTP_STATUS_PARAM);
  }

  new_size = (smtp->num_address + 1) * sizeof(*new_address_list);
  new_address_list = realloc(smtp->address_list, new_size);
  if(new_address_list == NULL){
    return smtp_status_code_set(smtp, SMTP_STATUS_NOMEM);
  }
  new_address = &new_address_list[smtp->num_address];

  smtp->address_list = new_address_list;

  new_address->type = type;
  new_address->email = smtp_strdup(email);
  new_address->name = name ? smtp_strdup(name) : NULL;
  if(new_address->email == NULL ||
     (new_address->name == NULL && name)){
    free(new_address->email);
    free(new_address->name);
    return smtp_status_code_set(smtp, SMTP_STATUS_NOMEM);
  }
  smtp->num_address += 1;

  return smtp->status_code;
}

/**
 * Free all memory related to the address list.
 *
 * @param[in] smtp SMTP client context.
 */
void smtp_address_clear_all(struct smtp *const smtp){
  size_t i;
  struct smtp_address *address;

  for(i = 0; i < smtp->num_address; i++){
    address = &smtp->address_list[i];
    free(address->email);
    free(address->name);
  }
  free(smtp->address_list);
  smtp->address_list = NULL;
  smtp->num_address = 0;
}

/**
 * Add a file attachment from a path.
 *
 * See @ref smtp_attachment_add_mem for more details.
 *
 * @param[in] smtp SMTP client context.
 * @param[in] name Filename of the attachment shown to recipients.
 * @param[in] path Path of file location to read from.
 * @return @ref smtp_status_code.
 */
enum smtp_status_code
smtp_attachment_add_path(struct smtp *const smtp,
                         const char *const name,
                         const char *const path){
  char *data;
  size_t bytes_read;

  if(smtp->status_code != SMTP_STATUS_OK){
    return smtp->status_code;
  }

  errno = 0;
  if((data = smtp_file_get_contents(path, &bytes_read)) == NULL){
    if(errno == ENOMEM){
      return smtp_status_code_set(smtp, SMTP_STATUS_NOMEM);
    }
    return smtp_status_code_set(smtp, SMTP_STATUS_FILE);
  }
  smtp_attachment_add_mem(smtp, name, data, bytes_read);
  free(data);
  return smtp->status_code;
}

/**
 * Add an attachment using a file pointer.
 *
 * See @ref smtp_attachment_add_mem for more details.
 *
 * @param[in] smtp SMTP client context.
 * @param[in] name Filename of the attachment shown to recipients.
 * @param[in] fp   File pointer already opened by the caller.
 * @return @ref smtp_status_code.
 */
enum smtp_status_code
smtp_attachment_add_fp(struct smtp *const smtp,
                       const char *const name,
                       FILE *fp){
  char *data;
  size_t bytes_read;

  if(smtp->status_code != SMTP_STATUS_OK){
    return smtp->status_code;
  }

  errno = 0;
  if((data = smtp_ffile_get_contents(fp, &bytes_read)) == NULL){
    if(errno == ENOMEM){
      return smtp_status_code_set(smtp, SMTP_STATUS_NOMEM);
    }
    return smtp_status_code_set(smtp, SMTP_STATUS_FILE);
  }
  smtp_attachment_add_mem(smtp, name, data, bytes_read);
  free(data);
  return smtp->status_code;
}

/**
 * Add a MIME attachment to this SMTP context with the data retrieved
 * from memory.
 *
 * The attachment data will get base64 encoded before sending to the server.
 *
 * @param[in] smtp   SMTP client context.
 * @param[in] name   Filename of the attachment shown to recipients. Must
 *                   consist only of printable characters excluding the
 *                   quote characters (') and ("), or the space character
 *                   ( ).
 * @param[in] data   Raw attachment data stored in memory.
 * @param[in] datasz Number of bytes in @p data, or -1 if data
 *                   null-terminated.
 * @return @ref smtp_status_code.
 */
enum smtp_status_code
smtp_attachment_add_mem(struct smtp *const smtp,
                        const char *const name,
                        const void *const data,
                        long datasz){
  size_t new_size;
  struct smtp_attachment *new_attachment_list;
  struct smtp_attachment *new_attachment;
  char *b64_encode;

  if(smtp->status_code != SMTP_STATUS_OK){
    return smtp->status_code;
  }

  if(smtp_attachment_validate_name(name) < 0){
    return smtp_status_code_set(smtp, SMTP_STATUS_PARAM);
  }

  if(datasz < 0){
    datasz = strlen(data);
  }

  new_size = (smtp->num_attachment + 1) * sizeof(*new_attachment_list);
  if((new_attachment_list = realloc(smtp->attachment_list,
                                    new_size)) == NULL){
    return smtp_status_code_set(smtp, SMTP_STATUS_NOMEM);
  }
  smtp->attachment_list = new_attachment_list;
  new_attachment = &new_attachment_list[smtp->num_attachment];

  new_attachment->name = smtp_strdup(name);
  b64_encode = smtp_base64_encode(data, datasz);
  if(new_attachment->name == NULL || b64_encode == NULL){
    free(new_attachment->name);
    free(b64_encode);
    return smtp_status_code_set(smtp, SMTP_STATUS_NOMEM);
  }

  new_attachment->b64_data = smtp_chunk_split(b64_encode,
                                              SMTP_LINE_MAX,
                                              "\r\n");
  free(b64_encode);
  if(new_attachment->b64_data == NULL){
    free(new_attachment->name);
    return smtp_status_code_set(smtp, SMTP_STATUS_NOMEM);
  }

  smtp->num_attachment += 1;
  return smtp->status_code;
}

/**
 * Remove all attachments from the SMTP client context.
 *
 * @param[in] smtp SMTP client context.
 */
void smtp_attachment_clear_all(struct smtp *const smtp){
  size_t i;
  struct smtp_attachment *attachment;

  for(i = 0; i < smtp->num_attachment; i++){
    attachment = &smtp->attachment_list[i];
    free(attachment->name);
    free(attachment->b64_data);
  }
  free(smtp->attachment_list);
  smtp->attachment_list = NULL;
  smtp->num_attachment = 0;
}

