/**
 * @file
 * @brief Test the smtp-client library.
 * @author James Humphrey (mail@somnisoft.com)
 * @version 1.00
 *
 * This smtp-client testing framework has 100% branch coverage on POSIX
 * systems. It requires a Postfix SMTP server that supports all of the
 * connection security and authentication methods. These functional tests
 * also require the user to manually check and ensure that the destination
 * addresses received all of the test emails.
 *
 * This software has been placed into the public domain using CC0.
 */

/**
 * This POSIX declaration required for the setenv() function.
 */
#define _POSIX_C_SOURCE 200112L

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/**
 * Get access to the @ref smtp_result_code and @ref smtp_command definitions.
 */
#define SMTP_INTERNAL_DEFINE

#include "test.h"

/**
 * Temporary file path to use for testing the @ref smtp_file_get_contents
 * function.
 */
#define TMP_FILE_PATH "/tmp/test_smtp_file_get_contents.txt"

/**
 * Maximum email subject buffer length.
 */
#define SMTP_TEST_SUBJECT_LEN        100

/**
 * Maximum email body buffer length.
 */
#define SMTP_TEST_BODY_LEN           1000

/**
 * Maximum server name buffer length.
 */
#define SMTP_MAX_SERVER_LEN          255

/**
 * Maximum certificate path length.
 */
#define SMTP_MAX_CAFILE_PATH         255

/**
 * Maximum server port buffer length.
 */
#define SMTP_MAX_PORT_LEN            10

/**
 * Maximum email buffer length.
 */
#define SMTP_MAX_EMAIL_LEN           255

/**
 * Maximum account password buffer length.
 */
#define SMTP_MAX_PASS_LEN            255

/**
 * Maximum file attachment name buffer length.
 */
#define SMTP_MAX_ATTACHMENT_NAME_LEN 100

/**
 * This default connection security method will get used for most test
 * connections with the SMTP server.
 */
#define SMTP_TEST_DEFAULT_CONNECTION_SECURITY SMTP_SECURITY_NONE

/**
 * This default authentication method will get used for most test connections
 * with the SMTP server.
 */
#define SMTP_TEST_DEFAULT_AUTH_METHOD         SMTP_AUTH_PLAIN

/**
 * These default flags will get used for most test connections with the
 * SMTP server.
 */
#define SMTP_TEST_DEFAULT_FLAGS               (SMTP_DEBUG | SMTP_NO_CERT_VERIFY)

/**
 * Use the default certificate path for OpenSSL.
 */
#define SMTP_TEST_DEFAULT_CAFILE              NULL

/**
 * Some unit tests use this for testing encoding or splitting long strings.
 */
#define STR_ALPHABET_LOWERCASE "abcdefghijklmnopqrstuvwxyz"

/**
 * Copy a string and guarantee that the destination string has been
 * null-terminated based on the given size.
 *
 * This function has a safer interface than strncpy because it always null
 * terminates the destination string and it returns the total number of bytes
 * in @p src which makes it easier to determine if the src tried to overflow
 * the buffer.
 *
 * @param[out] dest   Destination string buffer.
 * @param[in]  src    Source string buffer.
 * @param[in]  destsz Number of bytes available in @p dest.
 * @return String length of @p src.
 */
static size_t
smtp_strlcpy(char *dest,
             const char *src,
             size_t destsz){
  size_t src_idx;
  int found_end;

  found_end = 0;

  src_idx = 0;
  while(*src){
    if(!found_end){
      if(src_idx >= destsz - 1 || destsz == 0){
        dest[src_idx] = '\0';
        found_end = 1;
      }
      else{
        dest[src_idx] = *src;
      }
    }
    src_idx += 1;
    src += 1;
  }
  if(!found_end){
    dest[src_idx] = '\0';
  }

  return src_idx;
}

/**
 * Duplicate a string only up to a maximum number of bytes.
 *
 * @param[in] s String to duplicate.
 * @param[in] n Maximum number of bytes to copy.
 * @retval char* Duplicate of string @p s with at most @p n bytes.
 * @retval NULL  Memory allocation failure.
 */
static char *
smtp_strndup(const char *s,
             size_t n){
  char *ns;
  size_t newsz;

  newsz = sizeof(*ns) * (n + 1);
  ns = malloc(newsz);
  if(ns){
    smtp_strlcpy(ns, s, newsz);
  }

  return ns;
}

/**
 * Holds a list of strings.
 *
 * Used by a number of utility functions below to store and operate on lists
 * of strings.
 */
struct smtp_str_list{
  /**
   * Number of strings in @p slist.
   */
  size_t n;

  /**
   * List of strings.
   */
  char **slist;
};

/**
 * Append a string to the string list.
 *
 * @param[in] slist String list to append to.
 * @param[in] s     The new string to append to the list.
 * @param[in] n     Maximum number of bytes to copy in the string.
 * @retval  0 Successfully appended the string to the list.
 * @retval -1 Memory allocation failure.
 */
static int
smtp_str_list_append(struct smtp_str_list *const slist,
                     const char *const s,
                     size_t n){
  char **slist_alloc;
  char *snew;

  if((slist_alloc = realloc(slist->slist,
                            sizeof(*slist->slist) * (slist->n + 1))) == NULL){
    return -1;
  }
  slist->slist = slist_alloc;

  if((snew = smtp_strndup(s, n)) == NULL){
    return -1;
  }
  slist->slist[slist->n] = snew;
  slist->n += 1;
  return 0;
}

/**
 * Free all memory associated to the string list.
 *
 * @param[in] list The string list to free.
 */
static void
smtp_str_list_free(struct smtp_str_list *const list){
  size_t i;

  for(i = 0; i < list->n; i++){
    free(list->slist[i]);
  }
  free(list->slist);
  list->slist = NULL;
  list->n = 0;
}

/**
 * Split a string with delimiters into a list.
 *
 * @param[in]  s         The string to split.
 * @param[in]  slen      Length of string @p s to split, or -1 to split the
 *                       entire string.
 * @param[in]  delimiter Split the string at every delimiter location.
 * @param[in]  limit     A positive limit will limit the maximum number of
 *                       split strings to @p limit with the last string
 *                       containing the rest of the string. A value of 0 has
 *                       the same meaning as 1. A negative value will cut off
 *                       the last @p limit strings from the result.
 * @param[out] slist
 * @retval  0 Successfully split the string and stored the results into
 *            @p slist.
 * @retval -1 Memory allocation failure.
 */
static int
smtp_str_split(const char *const s,
               long slen,
               const char *const delimiter,
               int limit,
               struct smtp_str_list *slist){
  int i;
  size_t i1;
  size_t i2;
  size_t delimiter_len;
  int split_idx;

  memset(slist, 0, sizeof(*slist));
  delimiter_len = strlen(delimiter);

  if(slen < 0){
    slen = strlen(s);
  }

  split_idx = 0;

  for(i1 = 0, i2 = 0; i2 < (size_t)slen; i2++){
    if(limit > 0 && limit - 1 <= split_idx){
      if(smtp_str_list_append(slist, &s[i1], -1) < 0){
        smtp_str_list_free(slist);
        return -1;
      }
      return 0;
    }
    else if(strncmp(&s[i2], delimiter, delimiter_len) == 0){
      if(i2 - i1 == 0 && s[i2] == '\0'){
        break;
      }
      if(smtp_str_list_append(slist, &s[i1], i2 - i1) < 0){
        smtp_str_list_free(slist);
        return -1;
      }
      i1 = i2 + delimiter_len;
      i2 = i1;
      if(strncmp(&s[i2], delimiter, delimiter_len) == 0){
        i2 -= 1;
      }
      split_idx += 1;
    }
  }

  if(smtp_str_list_append(slist, &s[i1], i2 - i1) < 0){
    smtp_str_list_free(slist);
    return -1;
  }

  if(limit < 0){
    for(i = 0; i < abs(limit); i++){
      free(slist->slist[slist->n - i - 1]);
    }
    slist->n -= i;
  }

  return 0;
}

/**
 * Write bytes to an open file stream.
 *
 * @param[in] stream The file stream to write bytes to.
 * @param[in] data   The buffer containing the contents to write to the
 *                   file stream.
 * @param[in] datasz Number of bytes in @p data.
 * @return Number of bytes written to the file.
 */
static size_t
smtp_ffile_put_contents(FILE *stream,
                        const void *const data,
                        long datasz){
  long bytes_written;

  bytes_written = 0;

  if(datasz < 0){
    bytes_written = strlen(data);
    if(fputs(data, stream) == EOF){
      bytes_written = 0;
    }
  }
  else{
    bytes_written = fwrite(data, 1, datasz, stream);
  }

  return bytes_written;
}

/**
 * Write a byte string to a file.
 *
 * This interface handles safely opening, writing, and closing the file.
 *
 * A return of 0 can either indicate an error or it could indicate that the
 * string did not have any bytes to write. Check errno for if further details
 * required.
 *
 * @param[in] filename Path to file for writing the contents.
 * @param[in] data     The buffer contents to write to file.
 * @param[in] datasz   Number of bytes in @p data, or -1 if @p data consists
 *                     of a null-terminated string.
 * @param[in] flags    Set to 0 for write mode or O_APPEND for append mode.
 * @retval  0 Failed to write any bytes to the file.
 * @retval >0 Number of bytes written to file.
 */
static size_t
smtp_file_put_contents(const char *const filename,
                       const void *const data,
                       long datasz,
                       int flags){
  FILE *fp;
  size_t bytes_written;
  const char *mode;

  if(flags == 0){
    mode = "w";
  }
  else if(flags == O_APPEND){
    mode = "a";
  }
  else{
    errno = EINVAL;
    return 0;
  }

  if((fp = fopen(filename, mode)) == NULL){
    return 0;
  }

  bytes_written = smtp_ffile_put_contents(fp, data, datasz);

  if(fclose(fp) == EOF){
    return 0;
  }

  return bytes_written;
}

/**
 * Sleep for number of seconds.
 *
 * Useful for testing failure scenarios because a timeout will occur after
 * too many failed login attempts.
 *
 * @param[in] seconds The number of seconds to pause execution.
 */
static void
smtp_test_sleep(unsigned int seconds){
  fprintf(stderr, "TEST FRAMEWORK: sleeping for %u seconds\n", seconds);
  assert(sleep(seconds) == 0);
}

/**
 * Test harness for @ref smtp_base64_decode.
 *
 * @param[in] buf            Null-terminated base64 string.
 * @param[in] expect_str     Decoded binary data.
 * @param[in] expect_str_len Length of @p expect_str.
 */
static void
smtp_unit_test_base64_decode(const char *const buf,
                             const char *const expect_str,
                             long expect_str_len){
  unsigned char *decode;
  long str_len;

  str_len = smtp_base64_decode(buf, &decode);
  if(expect_str){
    assert(memcmp(decode, expect_str, str_len) == 0);
    free(decode);
  }
  else{ /* NULL */
    assert(decode == NULL);
  }
  assert(str_len == expect_str_len);
}

/**
 * Run all test cases for base64 decoding.
 */
static void
smtp_unit_test_all_base64_decode(void){
  smtp_unit_test_base64_decode(""        , "", 0);
  smtp_unit_test_base64_decode("YQ=="    , "a", 1);

  smtp_unit_test_base64_decode("YWE="    , "aa"   , 2);
  smtp_unit_test_base64_decode("YWFh"    , "aaa"  , 3);
  smtp_unit_test_base64_decode("YWFhYQ==", "aaaa" , 4);
  smtp_unit_test_base64_decode("YWFhYWE=", "aaaaa", 5);
  smtp_unit_test_base64_decode("MTIzNDU=", "12345", 5);
  smtp_unit_test_base64_decode("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=",
                               STR_ALPHABET_LOWERCASE,
                               26);

  /* invalid inputs */
  smtp_unit_test_base64_decode("AB"     , NULL, -1);
  smtp_unit_test_base64_decode("^^^^"   , NULL, -1);
  smtp_unit_test_base64_decode("^^^\xFF", NULL, -1);

  g_smtp_test_err_calloc_ctr = 0;
  smtp_unit_test_base64_decode("", NULL, -1);
  g_smtp_test_err_calloc_ctr = -1;
}

/**
 * Test harness for @ref smtp_base64_encode.
 *
 * @param[in] buf    Binary data to encode in base64.
 * @param[in] buflen Number of bytes in the @p buf parameter.
 * @param[in] expect The expected base64 string that would get returned.
 */
static void
smtp_unit_test_base64_encode(const char *const buf,
                             long buflen,
                             const char *const expect){
  char *result;

  result = smtp_base64_encode(buf, buflen);
  if(expect){
    assert(strcmp(result, expect) == 0);
    free(result);
  }
  else{ /* NULL */
    assert(result == expect);
  }
}

/**
 * Run all test cases for base64 encoding.
 */
static void
smtp_unit_test_all_base64_encode(void){
  smtp_unit_test_base64_encode(""     , -1, "");
  smtp_unit_test_base64_encode("a"    , -1, "YQ==");
  smtp_unit_test_base64_encode("aa"   , -1, "YWE=");
  smtp_unit_test_base64_encode("aaa"  , -1, "YWFh");
  smtp_unit_test_base64_encode("aaaa" , -1, "YWFhYQ==");
  smtp_unit_test_base64_encode("aaaaa", -1, "YWFhYWE=");
  smtp_unit_test_base64_encode("12345", -1, "MTIzNDU=");
  smtp_unit_test_base64_encode(STR_ALPHABET_LOWERCASE,
                               -1,
                               "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=");

  /* binary data */
  smtp_unit_test_base64_encode("a\0b\1c", 5, "YQBiAWM=");
  smtp_unit_test_base64_encode("a\n\r\4bc", 6, "YQoNBGJj");

  /* calloc */
  g_smtp_test_err_calloc_ctr = 0;
  smtp_unit_test_base64_encode("", -1, NULL);
  g_smtp_test_err_calloc_ctr = -1;
}

/**
 * Test harness for @ref smtp_bin2hex.
 *
 * @param[in] s      Buffer containing binary data to convert.
 * @param[in] slen   Number of bytes in @p s.
 * @param[in] expect Expected hex string output returned by @ref smtp_bin2hex.
 */
static void
smtp_unit_test_bin2hex(const char *const s,
                       size_t slen,
                       const char *const expect){
  char *result;

  result = smtp_bin2hex((const unsigned char *const)s, slen);
  if(expect){
    assert(strcmp(result, expect) == 0);
  }
  else{
    assert(result == expect);
  }
  free(result);
}

/**
 * Run all test cases for @ref smtp_bin2hex.
 */
static void
smtp_unit_test_all_bin2hex(void){
  smtp_unit_test_bin2hex(""      , 0, ""            );
  smtp_unit_test_bin2hex("0"     , 0, ""            );
  smtp_unit_test_bin2hex("0"     , 1, "30"          );
  smtp_unit_test_bin2hex("1"     , 1, "31"          );
  smtp_unit_test_bin2hex("012345", 6, "303132333435");
  smtp_unit_test_bin2hex("012345", 3, "303132"      );
  smtp_unit_test_bin2hex("000000", 6, "303030303030");
  smtp_unit_test_bin2hex(
    STR_ALPHABET_LOWERCASE,
    26,
    "6162636465666768696a6b6c6d6e6f707172737475767778797a");
  smtp_unit_test_bin2hex("\xFF", 1, "ff");
  smtp_unit_test_bin2hex("\x00", 1, "00");

  g_smtp_test_err_malloc_ctr = 0;
  smtp_unit_test_bin2hex("", 0, NULL);
  g_smtp_test_err_malloc_ctr = -1;

  g_smtp_test_err_sprintf_ctr = 0;
  g_smtp_test_err_sprintf_rc = -1;
  smtp_unit_test_bin2hex("0", 1, NULL);
  g_smtp_test_err_sprintf_ctr = -1;

  g_smtp_test_err_sprintf_ctr = 0;
  g_smtp_test_err_sprintf_rc = 10;
  smtp_unit_test_bin2hex("0", 1, NULL);
  g_smtp_test_err_sprintf_ctr = -1;
}

/**
 * Test harness for @ref smtp_stpcpy.
 *
 * @param[in] init   Set the destination buffer to this initial string.
 * @param[in] s2     Concatenate this string into the destination buffer.
 * @param[in] expect Expected string result.
 */
static void
smtp_unit_test_stpcpy(const char *const init,
                      const char *const s2,
                      const char *const expect){
  char *buf;
  size_t bufsz;
  char *endptr;
  char *expect_ptr;

  bufsz = strlen(init) + strlen(s2) + 1;
  buf = malloc(bufsz);
  assert(buf);

  strcpy(buf, init);
  endptr = buf + strlen(init);

  endptr = smtp_stpcpy(endptr, s2);
  expect_ptr = buf + bufsz - 1;
  assert(endptr == expect_ptr);
  assert(*endptr == '\0');
  assert(strcmp(buf, expect) == 0);
  free(buf);
}

/**
 * Run all test cases for @ref smtp_stpcpy.
 */
static void
smtp_unit_test_all_stpcpy(void){
  smtp_unit_test_stpcpy("", "", "");
  smtp_unit_test_stpcpy("", "a", "a");
  smtp_unit_test_stpcpy("", "ab", "ab");
  smtp_unit_test_stpcpy("", "abc", "abc");

  smtp_unit_test_stpcpy("a", "", "a");
  smtp_unit_test_stpcpy("ab", "", "ab");
  smtp_unit_test_stpcpy("abc", "", "abc");

  smtp_unit_test_stpcpy("a", "a", "aa");
}

/**
 * Test harness for @ref smtp_strdup.
 *
 * @param[in] s      String to duplicate.
 * @param[in] expect Expected string result.
 */
static void
smtp_unit_test_strdup(const char *const s,
                      const char *const expect){
  char *result;

  result = smtp_strdup(s);
  if(expect){
    assert(strcmp(result, expect) == 0);
    free(result);
  }
  else{ /* NULL */
    assert(result == expect);
  }
}

/**
 * Run all test cases for @ref smtp_strdup.
 */
static void
smtp_unit_test_all_strdup(void){
  smtp_unit_test_strdup("", "");
  smtp_unit_test_strdup("a", "a");
  smtp_unit_test_strdup("ab", "ab");

  /* malloc */
  g_smtp_test_err_malloc_ctr = 0;
  smtp_unit_test_strdup("", NULL);
  g_smtp_test_err_malloc_ctr = -1;
}

/**
 * Test harness for @ref smtp_str_replace.
 *
 * @param[in] search  Substring to search for in @p s.
 * @param[in] replace Replace each instance of the search string with this.
 * @param[in] s       Null-terminated string to search and replace.
 * @param[in] expect  Expected result.
 */
static void
smtp_unit_test_str_replace(const char *const search,
                           const char *const replace,
                           const char *const s,
                           const char *const expect){
  char *result;

  result = smtp_str_replace(search, replace, s);
  if(expect){
    assert(strcmp(result, expect) == 0);
    free(result);
  }
  else{ /* NULL */
    assert(result == expect);
  }
}

/**
 * Run all tests for @ref smtp_str_replace.
 */
static void
smtp_unit_test_all_str_replace(void){
  smtp_unit_test_str_replace("", "", "", "");
  smtp_unit_test_str_replace("a", "b", "", "");
  smtp_unit_test_str_replace("", "", "a b c", "a b c");
  smtp_unit_test_str_replace("a", "", "a b c", " b c");
  smtp_unit_test_str_replace("a", "a", "a", "a");
  smtp_unit_test_str_replace("a", "b", "a", "b");
  smtp_unit_test_str_replace("a", "bc", "a", "bc");
  smtp_unit_test_str_replace("a", "b", "abc", "bbc");
  smtp_unit_test_str_replace("A", "b", "a", "a");
  smtp_unit_test_str_replace("b", "a", "abc", "aac");
  smtp_unit_test_str_replace("string", "test", "test string", "test test");
  smtp_unit_test_str_replace("a", "b", "a b a", "b b b");
  smtp_unit_test_str_replace("a", "b", "a b a", "b b b");
  smtp_unit_test_str_replace("a", "b", "a b a b a", "b b b b b");

  g_smtp_test_err_realloc_ctr = 0;
  smtp_unit_test_str_replace("a", "b", "a b c", NULL);
  g_smtp_test_err_realloc_ctr = -1;

  g_smtp_test_err_realloc_ctr = 0;
  smtp_unit_test_str_replace("b", "a", "a b c", NULL);
  g_smtp_test_err_realloc_ctr = -1;
}

/**
 * Run all tests for @ref smtp_utf8_charlen.
 */
static void
smtp_unit_test_all_smtp_utf8_charlen(void){
  const char *utf8_str;

  assert(smtp_utf8_charlen('a') == 1);

  utf8_str = "щ";
  assert(smtp_utf8_charlen(utf8_str[0]) == 2);

  utf8_str = "€";
  assert(smtp_utf8_charlen(utf8_str[0]) == 3);

  utf8_str = "𠜎";
  assert(smtp_utf8_charlen(utf8_str[0]) == 4);
}

/**
 * Run all tests for @ref smtp_str_has_nonascii_utf8.
 */
static void
smtp_unit_test_all_smtp_str_has_nonascii_utf8(void){
  assert(smtp_str_has_nonascii_utf8("") == 0);
  assert(smtp_str_has_nonascii_utf8("abc") == 0);
  assert(smtp_str_has_nonascii_utf8("?") == 0);
  assert(smtp_str_has_nonascii_utf8("щ") == 1);
  assert(smtp_str_has_nonascii_utf8("abщ") == 1);
}

/**
 * Test harness for @ref smtp_strnlen_utf8.
 *
 * @param[in] s      UTF-8 string.
 * @param[in] maxlen Do not check more than @p maxlen bytes of string @p s.
 * @param[in] expect Expected string length.
 */
static void
smtp_unit_test_strnlen_utf8(const char *s,
                            size_t maxlen,
                            size_t expect){
  size_t slen;

  slen = smtp_strnlen_utf8(s, maxlen);
  assert(slen == expect);
}

/**
 * Run all tests for @ref smtp_strnlen_utf8.
 */
static void
smtp_unit_test_all_strnlen_utf8(void){
  smtp_unit_test_strnlen_utf8(""  , 0, 0);
  smtp_unit_test_strnlen_utf8(""  , 1, 0);
  smtp_unit_test_strnlen_utf8("a" , 0, 0);
  smtp_unit_test_strnlen_utf8("a" , 1, 1);
  smtp_unit_test_strnlen_utf8("a" , 2, 1);
  smtp_unit_test_strnlen_utf8("ab", 0, 0);
  smtp_unit_test_strnlen_utf8("ab", 1, 1);
  smtp_unit_test_strnlen_utf8("ab", 2, 2);
  smtp_unit_test_strnlen_utf8("ab", 3, 2);

  smtp_unit_test_strnlen_utf8("щ", 0, 0);
  smtp_unit_test_strnlen_utf8("щ", 1, 2);
  smtp_unit_test_strnlen_utf8("щ", 2, 2);
  smtp_unit_test_strnlen_utf8("щ", 3, 2);

  smtp_unit_test_strnlen_utf8("€", 0, 0);
  smtp_unit_test_strnlen_utf8("€", 1, 3);
  smtp_unit_test_strnlen_utf8("€", 2, 3);
  smtp_unit_test_strnlen_utf8("€", 3, 3);

  smtp_unit_test_strnlen_utf8("€€", 0, 0);
  smtp_unit_test_strnlen_utf8("€€", 1, 3);
  smtp_unit_test_strnlen_utf8("€€", 2, 3);
  smtp_unit_test_strnlen_utf8("€€", 3, 3);
  smtp_unit_test_strnlen_utf8("€€", 4, 6);
  smtp_unit_test_strnlen_utf8("€€", 5, 6);
  smtp_unit_test_strnlen_utf8("€€", 6, 6);
  smtp_unit_test_strnlen_utf8("€€", 7, 6);

  smtp_unit_test_strnlen_utf8("𠜎", 0, 0);
  smtp_unit_test_strnlen_utf8("𠜎", 1, 4);
  smtp_unit_test_strnlen_utf8("𠜎", 2, 4);
  smtp_unit_test_strnlen_utf8("𠜎", 3, 4);

  /* Invalid UTF-8 sequences. */
  smtp_unit_test_strnlen_utf8("\xBF", 3, -1);
  smtp_unit_test_strnlen_utf8("\xC0", 3, -1);
}

/**
 * Test harness for @ref smtp_chunk_split.
 *
 * @param[in] s        The string to chunk.
 * @param[in] chunklen Number of bytes for each chunk in the string.
 * @param[in] end      Terminating string placed at the end of each chunk.
 * @param[in] expect   Expected chunk string.
 */
static void
smtp_unit_test_chunk_split(const char *const s,
                           int chunklen,
                           const char *const end,
                           const char *const expect){
  char *result;

  result = smtp_chunk_split(s, chunklen, end);
  if(expect == NULL){
    assert(result == expect);
  }
  else{
    assert(strcmp(result, expect) == 0);
    free(result);
  }
}

/**
 * Run all tests for @ref smtp_chunk_split.
 */
static void
smtp_unit_test_all_chunk_split(void){
  smtp_unit_test_chunk_split("", 0, "", NULL);
  smtp_unit_test_chunk_split("a", 0, "a", NULL);
  smtp_unit_test_chunk_split("", 1, "", "");
  smtp_unit_test_chunk_split("", 1, "a", "a");
  smtp_unit_test_chunk_split("", 2, "a", "a");
  smtp_unit_test_chunk_split("a", 1, "", "a");
  smtp_unit_test_chunk_split("abc", 1, "-", "a-b-c-");
  smtp_unit_test_chunk_split("abc", 2, "-", "ab-c-");
  smtp_unit_test_chunk_split("abc", 3, "-", "abc-");
  smtp_unit_test_chunk_split("abcdefghijklmnop",
                             3,
                             "-",
                             "abc-def-ghi-jkl-mno-p-");
  smtp_unit_test_chunk_split("abc", 1, "-!@", "a-!@b-!@c-!@");
  smtp_unit_test_chunk_split("abcdefghijklmnop",
                             3,
                             "-!",
                             "abc-!def-!ghi-!jkl-!mno-!p-!");
  smtp_unit_test_chunk_split("abc", 1, "\r\n", "a\r\nb\r\nc\r\n");
  smtp_unit_test_chunk_split(STR_ALPHABET_LOWERCASE,
                             10,
                             "\r\n",
                             "abcdefghij\r\nklmnopqrst\r\nuvwxyz\r\n");

  /*
   * UTF-8 characters
   * щ - 2 bytes
   * € - 3 bytes
   * 𠜎 - 4 bytes
   */
  smtp_unit_test_chunk_split("€€€", 1, "\r\n", "€\r\n€\r\n€\r\n");
  smtp_unit_test_chunk_split("€€€€€", 1, "\r\n", "€\r\n€\r\n€\r\n€\r\n€\r\n");
  smtp_unit_test_chunk_split("a€c", 1, "-", "a-€-c-");
  smtp_unit_test_chunk_split("a€c", 2, "-", "a€-c-");
  smtp_unit_test_chunk_split("€€€", 3, "-", "€-€-€-");
  smtp_unit_test_chunk_split("щbc", 3, "-", "щb-c-");
  smtp_unit_test_chunk_split("щbc", 4, "-", "щbc-");
  smtp_unit_test_chunk_split("aщ€𠜎e", 2, "-", "aщ-€-𠜎-e-");
  smtp_unit_test_chunk_split("aщ€𠜎e", 4, "-", "aщ€-𠜎-e-");

  /* Memory allocation failure. */
  g_smtp_test_err_calloc_ctr = 0;
  smtp_unit_test_chunk_split("abc", 1, "-", NULL);
  g_smtp_test_err_calloc_ctr = -1;

  /* Invalid UTF-8 characters. */
  smtp_unit_test_chunk_split("\xBF", 1, "-", NULL);
  smtp_unit_test_chunk_split("\xC0", 1, "-", NULL);
}

/**
 * Test harness for @ref smtp_file_get_contents.
 *
 * @param[in] s      The string to write to the temp file before reading.
 * @param[in] nbytes Number of bytes in @p s.
 * @param[in] expect Expected string after reading the file.
 */
static void
smtp_unit_test_file_get_contents(const char *const s,
                                 size_t nbytes,
                                 const char *const expect){
  char *read_buf;
  size_t nbytes_rw;

  nbytes_rw = smtp_file_put_contents(TMP_FILE_PATH, s, nbytes, 0);
  assert(nbytes_rw == strlen(expect));

  read_buf = smtp_file_get_contents(TMP_FILE_PATH, &nbytes_rw);
  assert(read_buf);

  assert(memcmp(expect, read_buf, strlen(expect)) == 0);
  free(read_buf);
}

/**
 * Run all tests for @ref smtp_file_get_contents.
 */
static void
smtp_unit_test_all_file_get_contents(void){
  const char *test_str;

  smtp_unit_test_file_get_contents("", 0, "");

  test_str = "test";
  smtp_unit_test_file_get_contents(test_str, 0, "");
  smtp_unit_test_file_get_contents(test_str, strlen(test_str), test_str);

  test_str = "test\nnewline";
  smtp_unit_test_file_get_contents(test_str, strlen(test_str), test_str);

  test_str = "test";
  smtp_unit_test_file_get_contents(test_str, -1, test_str);

  test_str = STR_ALPHABET_LOWERCASE;
  smtp_unit_test_file_get_contents(test_str, strlen(test_str), test_str);

  /* smtp_file_get_contents - fopen */
  assert(smtp_file_get_contents("", NULL) == NULL);

  /* smtp_file_get_contents - fclose */
  g_smtp_test_err_fclose_ctr = 0;
  assert(smtp_file_get_contents(TMP_FILE_PATH, NULL) == NULL);
  g_smtp_test_err_fclose_ctr = -1;

  /* smtp_file_get_contents - realloc */
  g_smtp_test_err_realloc_ctr = 0;
  assert(smtp_file_get_contents(TMP_FILE_PATH, NULL) == NULL);
  g_smtp_test_err_realloc_ctr = -1;

  /* smtp_file_get_contents - ferror */
  g_smtp_test_err_ferror_ctr = 0;
  assert(smtp_file_get_contents(TMP_FILE_PATH, NULL) == NULL);
  g_smtp_test_err_ferror_ctr = -1;
}

/**
 * Test harness for @ref smtp_parse_cmd_line.
 *
 * @param[in] line        The server response line to parse.
 * @param[in] expect_code Expected server response code.
 * @param[in] expect_more Set to 1 if more lines will get returned or 0 if
 *                        no more lines.
 * @param[in] expect_text Expected text shown after the response code.
 */
static void
smtp_unit_test_parse_cmd_line(const char *const line,
                              enum smtp_result_code expect_code,
                              int expect_more,
                              const char *const expect_text){
  char *line_dup;
  struct smtp_command cmd;
  int rc;

  line_dup = smtp_strdup(line);
  assert(line_dup);

  rc = smtp_parse_cmd_line(line_dup, &cmd);
  assert(rc == expect_code);
  assert(cmd.code == expect_code);
  assert(cmd.more == expect_more);
  assert(strcmp(cmd.text, expect_text) == 0);

  free(line_dup);
}

/**
 * Run all tests for @ref smtp_parse_cmd_line.
 */
static void
smtp_unit_test_all_parse_cmd_line(void){
  smtp_unit_test_parse_cmd_line("",
                                SMTP_INTERNAL_ERROR,
                                0,
                                "");
  smtp_unit_test_parse_cmd_line("<5",
                                SMTP_INTERNAL_ERROR,
                                0,
                                "<5");
  smtp_unit_test_parse_cmd_line("bad text",
                                SMTP_INTERNAL_ERROR,
                                0,
                                "text");
  smtp_unit_test_parse_cmd_line("bad-text",
                                SMTP_INTERNAL_ERROR,
                                1,
                                "text");
  smtp_unit_test_parse_cmd_line("0x1 text",
                                SMTP_INTERNAL_ERROR,
                                0,
                                "text");
  smtp_unit_test_parse_cmd_line("-22 text",
                                -22,
                                0,
                                "text");
  smtp_unit_test_parse_cmd_line("-22 text",
                                -22,
                                0,
                                "text");
  smtp_unit_test_parse_cmd_line("220 ready",
                                SMTP_READY,
                                0,
                                "ready");
}

/**
 * Test harness for @ref smtp_date_rfc_2822.
 *
 * @param[in] t         Force the time() function to return this time_t value.
 * @param[in] expect    Expected date string.
 * @param[in] expect_rc Expected return code.
 */
static void
smtp_unit_test_date_rfc_2822(time_t t,
                             const char *const expect,
                             int expect_rc){
  char result[SMTP_DATE_MAX_SZ];
  int rc;

  g_smtp_test_time_custom_ret = 1;
  g_smtp_test_time_ret_value = t;

  setenv("TZ", "UTC", 1);
  rc = smtp_date_rfc_2822(result);
  assert(rc == expect_rc);
  if(expect_rc == 0){
    assert(strcmp(result, expect) == 0);
  }

  g_smtp_test_time_custom_ret = 0;
  g_smtp_test_time_ret_value = 0;
}

/**
 * Run all tests for @ref smtp_date_rfc_2822.
 */
static void
smtp_unit_test_all_date_rfc_2822(void){
  smtp_unit_test_date_rfc_2822(0, "Thu, 01 Jan 1970 00:00:00 +0000", 0);
  smtp_unit_test_date_rfc_2822(60 * 60 * 24 * 2 + 5,
                               "Sat, 03 Jan 1970 00:00:05 +0000",
                               0);

  smtp_unit_test_date_rfc_2822(-1, NULL, -1);

  g_smtp_test_err_localtime_r_ctr = 0;
  smtp_unit_test_date_rfc_2822(0, NULL, -1);
  g_smtp_test_err_localtime_r_ctr = -1;

  g_smtp_test_err_gmtime_r_ctr = 0;
  smtp_unit_test_date_rfc_2822(0, NULL, -1);
  g_smtp_test_err_gmtime_r_ctr = -1;

  g_smtp_test_err_mktime_ctr = 0;
  smtp_unit_test_date_rfc_2822(0, NULL, -1);
  g_smtp_test_err_mktime_ctr = -1;

  g_smtp_test_err_mktime_ctr = 1;
  smtp_unit_test_date_rfc_2822(0, NULL, -1);
  g_smtp_test_err_mktime_ctr = -1;

  g_smtp_test_err_sprintf_ctr = 0;
  g_smtp_test_err_sprintf_rc = -1;
  smtp_unit_test_date_rfc_2822(0, NULL, -1);
  g_smtp_test_err_sprintf_ctr = -1;
}

/**
 * Run all tests for @ref smtp_address_validate_email.
 */
static void
smtp_unit_test_all_smtp_address_validate_email(void){
  assert(smtp_address_validate_email(STR_ALPHABET_LOWERCASE) == 0);
  assert(smtp_address_validate_email("mail@example.com") == 0);
  assert(smtp_address_validate_email("īḑȋᵭ") == 0);
  assert(smtp_address_validate_email("<abc") == -1);
  assert(smtp_address_validate_email("abc>") == -1);
  assert(smtp_address_validate_email("\x7f") == -1);
  assert(smtp_address_validate_email("a b c") == -1);
}

/**
 * Run all tests for @ref smtp_address_validate_name.
 */
static void
smtp_unit_test_all_smtp_address_validate_name(void){
  assert(smtp_address_validate_name(STR_ALPHABET_LOWERCASE) == 0);
  assert(smtp_address_validate_name("John Doe") == 0);
  assert(smtp_address_validate_name("John O'Doe") == 0);
  assert(smtp_address_validate_name("īḑȋᵭ") == 0);
  assert(smtp_address_validate_name("a\nb\nc") == -1);
  assert(smtp_address_validate_name("\"abc") == -1);
  assert(smtp_address_validate_name("\x7f") == -1);
}

/**
 * Run all tests for @ref smtp_attachment_validate_name.
 */
static void
smtp_unit_test_all_smtp_attachment_validate_name(void){
  assert(smtp_attachment_validate_name(STR_ALPHABET_LOWERCASE) == 0);
  assert(smtp_attachment_validate_name("a b c") == 0);
  assert(smtp_attachment_validate_name("test.txt") == 0);
  assert(smtp_attachment_validate_name("īḑȋᵭ") == 0);
  assert(smtp_attachment_validate_name("a\nbc") == -1);
  assert(smtp_attachment_validate_name("\x7f") == -1);
  assert(smtp_attachment_validate_name("a\'bc") == -1);
  assert(smtp_attachment_validate_name("a\"bc") == -1);
}

/**
 * Run all tests for @ref smtp_header_key_validate.
 */
static void
smtp_unit_test_all_smtp_header_key_validate(void){
  assert(smtp_header_key_validate(STR_ALPHABET_LOWERCASE) == 0);
  assert(smtp_header_key_validate("") == -1);
  assert(smtp_header_key_validate("īḑȋᵭ") == -1);
  assert(smtp_header_key_validate("a b c") == -1);
  assert(smtp_header_key_validate("a\xff") == -1);
  assert(smtp_header_key_validate("a:b:c") == -1);
  assert(smtp_header_key_validate("a\nb\nc") == -1);
}

/**
 * Run all tests for @ref smtp_header_value_validate.
 */
static void
smtp_unit_test_all_smtp_header_value_validate(void){
  assert(smtp_header_value_validate(STR_ALPHABET_LOWERCASE) == 0);
  assert(smtp_header_value_validate("a\tb c") == 0);
  assert(smtp_header_value_validate("īḑȋᵭ") == 0);
  assert(smtp_header_value_validate("a\xff") == 0);
  assert(smtp_header_value_validate("a\nb\nc") == -1);
}

/**
 * Test harness for @ref smtp_status_code_errstr.
 *
 * @param[in] status_code See @ref smtp_status_code.
 * @param[in] expect      Expected error string.
 */
static void
smtp_unit_test_smtp_status_code_errstr(enum smtp_status_code status_code,
                                       const char *const expect){
  const char *result;

  result = smtp_status_code_errstr(status_code);
  assert(strcmp(result, expect) == 0);
}

/**
 * Run all tests for @ref smtp_status_code_errstr.
 */
static void
smtp_unit_test_all_smtp_status_code_errstr(void){
  smtp_unit_test_smtp_status_code_errstr(SMTP_STATUS_OK,
                                         "Success");
  smtp_unit_test_smtp_status_code_errstr(SMTP_STATUS_NOMEM,
                                         "Memory allocation failed");
  smtp_unit_test_smtp_status_code_errstr(-1,
                                         "Unknown error");
  smtp_unit_test_smtp_status_code_errstr(99,
                                         "Unknown error");
}

/**
 * User data pointer for testing the @ref str_getdelimfd interface.
 */
struct smtp_test_getdelimfd_fp{
  /**
   * Read from this file which should contain the contents used to test
   * the parser.
   */
  FILE *fp;
};

/**
 * Set to a non-zero value to force an error return value
 * in @ref smtp_unit_test_getdelimfd_fp.
 */
static int g_smtp_test_getdelimfd_fp_fail = 0;

/**
 * Read function used by the @ref smtp_str_getdelimfd interface.
 *
 * @param[in]  gdfd  See @ref str_getdelimfd.
 * @param[out] buf   Pointer to buffer for storing bytes read.
 * @param[in]  count Maximum number of bytes to try reading.
 * @retval >=0 Number of bytes read.
 * @retval -1  Failed to read from the socket.
 */
static long
smtp_unit_test_getdelimfd_fp(struct str_getdelimfd *const gdfd,
                             void *buf,
                             size_t count){
  struct smtp_test_getdelimfd_fp *getdelimfd_fp;
  size_t bytes_read;

  getdelimfd_fp = gdfd->user_data;
  bytes_read = fread(buf, sizeof(char), count, getdelimfd_fp->fp);
  if(g_smtp_test_getdelimfd_fp_fail){
    return -1;
  }
  return bytes_read;
}

/**
 * Test harness for @ref smtp_str_getdelimfd.
 *
 * @param[in] input_string  Test string used in delimeter parsing.
 * @param[in] nbytes        Number of bytes in @p input_string.
 * @param[in] delim         Delimiter used to split the string.
 * @param[in] expect_rc     Expected return code.
 * @param[in] null_fp       If set, use a NULL read function pointer. Useful
                            for testing that error condition.
 * @param[in] expect_pieces Expected list of strings parsed from the file.
 */
static void
smtp_unit_test_str_getdelimfd(const char *const input_string,
                              size_t nbytes,
                              int delim,
                              enum str_getdelim_retcode expect_rc,
                              int null_fp,
                              const char *expect_pieces, ...){
  const char *piece;
  enum str_getdelim_retcode rc;
  size_t bytes_written;
  struct str_getdelimfd gdfd;
  struct smtp_test_getdelimfd_fp getdelimfd_fp;
  struct smtp_str_list slist;
  FILE *fp;
  size_t piece_idx;
  va_list ap;

  memset(&slist, 0, sizeof(slist));

  bytes_written = smtp_file_put_contents(TMP_FILE_PATH,
                                         input_string,
                                         nbytes,
                                         0);
  assert(bytes_written == nbytes);

  memset(&getdelimfd_fp, 0, sizeof(getdelimfd_fp));
  fp = fopen(TMP_FILE_PATH, "r");
  assert(fp);
  getdelimfd_fp.fp = fp;

  memset(&gdfd, 0, sizeof(gdfd));
  gdfd.delim           = delim;
  if(!null_fp){
    gdfd.getdelimfd_read = smtp_unit_test_getdelimfd_fp;
  }
  gdfd.user_data       = &getdelimfd_fp;

  do{
    rc = smtp_str_getdelimfd(&gdfd);
    if(expect_rc == STRING_GETDELIMFD_ERROR){
      assert(rc == expect_rc);
      smtp_str_list_free(&slist);
      return;
    }
    assert(rc != STRING_GETDELIMFD_ERROR);
    assert(smtp_str_list_append(&slist, gdfd.line, gdfd.line_len) == 0);
  } while (rc != STRING_GETDELIMFD_DONE);
  smtp_str_getdelimfd_free(&gdfd);
  assert(fclose(fp) == 0);

  piece_idx = 0;
  piece = expect_pieces;
  va_start(ap, expect_pieces);
  while (piece){
    assert(strcmp(piece, slist.slist[piece_idx]) == 0);
    piece_idx += 1;
    piece = va_arg(ap, const char *);
  }
  va_end(ap);
  assert(piece_idx == slist.n);

  smtp_str_list_free(&slist);
}

/**
 * Run all tests for @ref smtp_str_getdelimfd.
 */
static void
smtp_unit_test_all_str_getdelimfd(void){
  const char *s;

  s = "";
  smtp_unit_test_str_getdelimfd(s,
                                strlen(s),
                                '\n',
                                STRING_GETDELIMFD_DONE,
                                0,
                                "",
                                NULL);

  s = "a";
  smtp_unit_test_str_getdelimfd(s,
                                strlen(s),
                                '\n',
                                STRING_GETDELIMFD_DONE,
                                0,
                                "a",
                                NULL);

  s = "\n";
  smtp_unit_test_str_getdelimfd(s,
                                strlen(s),
                                '\n',
                                STRING_GETDELIMFD_DONE,
                                0,
                                "",
                                "",
                                NULL);

  s = "a\n";
  smtp_unit_test_str_getdelimfd(s,
                                strlen(s),
                                '\n',
                                STRING_GETDELIMFD_DONE,
                                0,
                                "a",
                                "",
                                NULL);

  s = "\na";
  smtp_unit_test_str_getdelimfd(s,
                                strlen(s),
                                '\n',
                                STRING_GETDELIMFD_DONE,
                                0,
                                "",
                                "a",
                                NULL);

  s = "test line 1";
  smtp_unit_test_str_getdelimfd(s,
                                strlen(s),
                                '\n',
                                STRING_GETDELIMFD_DONE,
                                0,
                                "test line 1",
                                NULL);

  s = "test line 1\n";
  smtp_unit_test_str_getdelimfd(s,
                                strlen(s),
                                '\n',
                                STRING_GETDELIMFD_DONE,
                                0,
                                "test line 1",
                                "",
                                NULL);

  s = "test line 1\ntest line 2";
  smtp_unit_test_str_getdelimfd(s,
                                strlen(s),
                                '\n',
                                STRING_GETDELIMFD_DONE,
                                0,
                                "test line 1",
                                "test line 2",
                                NULL);

  s = "test line 1\ntest line 2\ntest line 3";
  smtp_unit_test_str_getdelimfd(s,
                                strlen(s),
                                '\n',
                                STRING_GETDELIMFD_DONE,
                                0,
                                "test line 1",
                                "test line 2",
                                "test line 3",
                                NULL);

  /* smtp_str_getdelimfd_set_line_and_buf - 2 */
  g_smtp_test_err_calloc_ctr = 0;
  s = "a";
  smtp_unit_test_str_getdelimfd(s,
                                strlen(s),
                                '\n',
                                STRING_GETDELIMFD_ERROR,
                                0,
                                NULL);
  g_smtp_test_err_calloc_ctr = -1;

  /* smtp_str_getdelimfd_set_line_and_buf - 2 */
  g_smtp_test_err_calloc_ctr = 0;
  s = "a\na";
  smtp_unit_test_str_getdelimfd(s,
                                strlen(s),
                                '\n',
                                STRING_GETDELIMFD_ERROR,
                                0,
                                NULL);
  g_smtp_test_err_calloc_ctr = -1;

  /* realloc */
  g_smtp_test_err_realloc_ctr = 0;
  s = "a";
  smtp_unit_test_str_getdelimfd(s,
                                strlen(s),
                                '\n',
                                STRING_GETDELIMFD_ERROR,
                                0,
                                NULL);
  g_smtp_test_err_realloc_ctr = -1;

  /* fread */
  g_smtp_test_getdelimfd_fp_fail = 1;
  s = "a";
  smtp_unit_test_str_getdelimfd(s,
                                strlen(s),
                                '\n',
                                STRING_GETDELIMFD_ERROR,
                                0,
                                NULL);
  g_smtp_test_getdelimfd_fp_fail = 0;

  /* getdelimfd_read unset */
  smtp_unit_test_str_getdelimfd("", 0, '\0', STRING_GETDELIMFD_ERROR, 1, NULL);
}

/**
 * Unit test functions which do not require an SMTP client context.
 */
static void
smtp_unit_test_all(void){
  smtp_unit_test_all_base64_decode();
  smtp_unit_test_all_base64_encode();
  smtp_unit_test_all_bin2hex();
  smtp_unit_test_all_stpcpy();
  smtp_unit_test_all_strdup();
  smtp_unit_test_all_str_replace();
  smtp_unit_test_all_smtp_utf8_charlen();
  smtp_unit_test_all_smtp_str_has_nonascii_utf8();
  smtp_unit_test_all_strnlen_utf8();
  smtp_unit_test_all_chunk_split();
  smtp_unit_test_all_file_get_contents();
  smtp_unit_test_all_parse_cmd_line();
  smtp_unit_test_all_date_rfc_2822();
  smtp_unit_test_all_smtp_address_validate_email();
  smtp_unit_test_all_smtp_address_validate_name();
  smtp_unit_test_all_smtp_attachment_validate_name();
  smtp_unit_test_all_smtp_header_key_validate();
  smtp_unit_test_all_smtp_header_value_validate();
  smtp_unit_test_all_smtp_status_code_errstr();
  smtp_unit_test_all_str_getdelimfd();
}

/**
 * Stores details from the server configuration file.
 *
 * Most of this information gets loaded from separate files because the
 * files contain sensitive account information which should not get stored
 * in a public repository.
 */
struct smtp_test_config{
  /**
   * SMTP client context.
   */
  struct smtp *smtp;

  /**
   * Email subject line.
   */
  char subject[SMTP_TEST_SUBJECT_LEN];

  /**
   * Email body text.
   */
  char body[SMTP_TEST_BODY_LEN];

  /*
   * The following contains fields that get loaded in from the
   * configuration file.
   */

  /**
   * Server name or IP address.
   */
  char server[SMTP_MAX_SERVER_LEN];

  /**
   * Path to server certificate file.
   */
  char cafile[SMTP_MAX_CAFILE_PATH];

  /**
   * Server port number.
   */
  char port[SMTP_MAX_PORT_LEN];

  /**
   * Server port number for direct TLS connection.
   */
  char port_tls[SMTP_MAX_PORT_LEN];

  /**
   * Account user name.
   */
  char user[SMTP_MAX_EMAIL_LEN];

  /**
   * Account password.
   */
  char pass[SMTP_MAX_PASS_LEN];

  /**
   * The email displayed in the email from section.
   */
  char email_from[SMTP_MAX_EMAIL_LEN];

  /**
   * Email destination address.
   */
  char email_to[SMTP_MAX_EMAIL_LEN];

  /**
   * Email destination address (2nd).
   */
  char email_to_2[SMTP_MAX_EMAIL_LEN];

  /**
   * Email destination address (3rd).
   */
  char email_to_3[SMTP_MAX_EMAIL_LEN];
};

/**
 * Load server configuration file containing server connection information.
 *
 * The server connection information contains sensitive information, so we
 * need to load it in from a separate configuration file that does not get
 * saved in the repository. This stores the parsed results into a
 * @ref smtp_test_config data structure.
 *
 * @param[in]  config_path Path to the server configuration file.
 * @param[out] config      The parsed contents from the configuration file
 *                         gets stored in this data structure.
 * @retval  0 Successfully parsed and saved the server configuration into the
 *            data structure.
 * @retval -1 Failed to read file or memory allocation failure.
 */
static int
smtp_test_config_load_from_file(const char *const config_path,
                                struct smtp_test_config *const config){
  char *config_data;
  char *config_data_new;
  size_t config_data_len;
  struct smtp_str_list line_list;
  char *line;
  int rc;
  size_t i;
  const char *key;
  const char *value;

  memset(config, 0, sizeof(*config));

  if((config_data = smtp_file_get_contents(config_path,
                                           &config_data_len)) == NULL){
    return -1;
  }

  /* add a null character at end of file data */
  if((config_data_new = realloc(config_data, config_data_len + 1)) == NULL){
    free(config_data);
    return -1;
  }
  config_data = config_data_new;
  config_data[config_data_len] = '\0';

  rc = smtp_str_split(config_data, config_data_len, "\n", 0, &line_list);
  assert(rc == 0);
  free(config_data);

  for(i = 0; i < line_list.n; i++){
    line = line_list.slist[i];
    if(line[0] == '#'){
      continue;
    }
    key = strtok(line, "=");
    if(key == NULL){
      continue;
    }

    value = strtok(NULL, "=");
    if(value == NULL){
      value = "";
    }

    if(strcmp(key, "server") == 0){
      smtp_strlcpy(config->server, value, sizeof(config->server));
    }
    else if(strcmp(key, "cafile") == 0){
      smtp_strlcpy(config->cafile, value, sizeof(config->cafile));
    }
    else if(strcmp(key, "port") == 0){
      smtp_strlcpy(config->port, value, sizeof(config->port));
    }
    else if(strcmp(key, "port_tls") == 0){
      smtp_strlcpy(config->port_tls, value, sizeof(config->port_tls));
    }
    else if(strcmp(key, "user") == 0){
      smtp_strlcpy(config->user, value, sizeof(config->user));
    }
    else if(strcmp(key, "pass") == 0){
      smtp_strlcpy(config->pass, value, sizeof(config->pass));
    }
    else if(strcmp(key, "email_from") == 0){
      smtp_strlcpy(config->email_from, value, sizeof(config->email_from));
    }
    else if(strcmp(key, "email_to") == 0){
      smtp_strlcpy(config->email_to, value, sizeof(config->email_to));
    }
    else if(strcmp(key, "email_to_2") == 0){
      smtp_strlcpy(config->email_to_2, value, sizeof(config->email_to_2));
    }
    else if(strcmp(key, "email_to_3") == 0){
      smtp_strlcpy(config->email_to_3, value, sizeof(config->email_to_3));
    }
  }
  smtp_str_list_free(&line_list);

  return 0;
}

/**
 * Opens an smtp connection using @ref smtp_open and adds default addresses.
 *
 * Uses default connection and flag parameters and ensures the return status
 * gets set to SMTP_STATUS_OK. Adds the FROM, TO, and CC email addresses
 * given in the config file. This function should always succeed.
 *
 * @param[in] config SMTP server context.
 */
static void
test_smtp_open_default(struct smtp_test_config *const config){
  int rc;

  rc = smtp_open(config->server,
                 config->port,
                 SMTP_TEST_DEFAULT_CONNECTION_SECURITY,
                 SMTP_TEST_DEFAULT_FLAGS,
                 SMTP_TEST_DEFAULT_CAFILE,
                 &config->smtp);
  assert(rc == SMTP_STATUS_OK);

  rc = smtp_address_add(config->smtp,
                        SMTP_ADDRESS_FROM,
                        config->email_from,
                        "");
  assert(rc == SMTP_STATUS_OK);

  rc = smtp_address_add(config->smtp,
                        SMTP_ADDRESS_TO,
                        config->email_to,
                        "Test Email");
  assert(rc == SMTP_STATUS_OK);

  rc = smtp_address_add(config->smtp,
                        SMTP_ADDRESS_CC,
                        config->email_to_2,
                        "Test Email");
  assert(rc == SMTP_STATUS_OK);

  rc = smtp_attachment_add_mem(config->smtp,
                               "test.txt",
                               "test attachment",
                               -1);
  assert(rc == SMTP_STATUS_OK);
}

/**
 * Test the @ref smtp_status_code_get function.
 *
 * @param[in] config SMTP server context.
 */
static void
smtp_func_test_all_status_code_get(struct smtp_test_config *const config){
  int rc;

  rc = smtp_open(config->server,
                 config->port,
                 SMTP_TEST_DEFAULT_CONNECTION_SECURITY,
                 SMTP_TEST_DEFAULT_FLAGS,
                 SMTP_TEST_DEFAULT_CAFILE,
                 &config->smtp);
  assert(rc == SMTP_STATUS_OK);

  rc = smtp_status_code_get(config->smtp);
  assert(rc == SMTP_STATUS_OK);

  smtp_status_code_set(config->smtp, SMTP_STATUS_NOMEM);
  rc = smtp_status_code_get(config->smtp);
  assert(rc == SMTP_STATUS_NOMEM);
  smtp_status_code_set(config->smtp, SMTP_STATUS_OK);

  rc = smtp_close(config->smtp);
  assert(rc == SMTP_STATUS_OK);
}

/**
 * Send a test email with the given parameters.
 *
 * See @ref smtp_open and @ref smtp_auth for more information about this
 * functions parameters.
 *
 * @param[in] config              SMTP server context.
 * @param[in] port                Server connection port.
 * @param[in] connection_security Connection security settings.
 * @param[in] flags               Miscellaneous configuration flags.
 * @param[in] auth_method         Authentication method.
 * @param[in] cafile              Path to certificate file.
 * @param[in] subject             Email subject line.
 * @param[in] body                Email body.
 */
static void
smtp_func_test_send_email(struct smtp_test_config *const config,
                          const char *const port,
                          enum smtp_connection_security connection_security,
                          enum smtp_flag flags,
                          enum smtp_authentication_method auth_method,
                          const char *const cafile,
                          const char *const subject,
                          const char *const body){
  int rc;

  rc = smtp_open(config->server,
                 port,
                 connection_security,
                 flags,
                 cafile,
                 &config->smtp);
  assert(rc == SMTP_STATUS_OK);

  rc = smtp_auth(config->smtp, auth_method, config->user, config->pass);
  assert(rc == SMTP_STATUS_OK);

  rc = smtp_address_add(config->smtp,
                        SMTP_ADDRESS_FROM,
                        config->email_from,
                        NULL);
  assert(rc == SMTP_STATUS_OK);

  rc = smtp_address_add(config->smtp,
                        SMTP_ADDRESS_TO,
                        config->email_to,
                        "Test Email");
  assert(rc == SMTP_STATUS_OK);

  rc = smtp_header_add(config->smtp, "Subject", subject);
  assert(rc == SMTP_STATUS_OK);

  rc = smtp_mail(config->smtp, body);
  assert(rc == SMTP_STATUS_OK);

  rc = smtp_close(config->smtp);
  assert(rc == SMTP_STATUS_OK);
}

/**
 * Send a test email with a specific connection security method.
 *
 * @param[in] config               Server connection details.
 * @param[in] server_port          Server port number to connect to.
 * @param[in] con_security         See @ref smtp_connection_security.
 * @param[in] security_description Description of @p connection_security.
 */
static void
smtp_func_test_connection_security(struct smtp_test_config *const config,
                                   const char *const server_port,
                                   enum smtp_connection_security con_security,
                                   const char *const security_description){
  sprintf(config->subject,
          "SMTP Test: Connection Security %s",
          security_description);
  sprintf(config->body,
          "Email sent with connection security: %s",
          security_description);

  smtp_func_test_send_email(config,
                            server_port,
                            con_security,
                            SMTP_TEST_DEFAULT_FLAGS,
                            SMTP_TEST_DEFAULT_AUTH_METHOD,
                            SMTP_TEST_DEFAULT_CAFILE,
                            config->subject,
                            config->body);
}

/**
 * Run through all types of SMTP connections provided in the
 * @ref smtp_connection_security.
 *
 * @param[in] config Server connection details.
 */
static void
smtp_func_test_all_connection_security(struct smtp_test_config *const config){
  smtp_func_test_connection_security(config,
                                     config->port,
                                     SMTP_SECURITY_NONE,
                                     "None");
  smtp_func_test_connection_security(config,
                                     config->port,
                                     SMTP_SECURITY_STARTTLS,
                                     "STARTTLS");
  smtp_func_test_connection_security(config,
                                     config->port_tls,
                                     SMTP_SECURITY_TLS,
                                     "TLS");
}

/**
 * Send a test email with a self-signed certificate file specified in the
 * cafile parameter.
 *
 * @param[in] config Server connection details.
 */
static void
smtp_func_test_all_cafile(struct smtp_test_config *const config){
  smtp_func_test_send_email(config,
                            config->port,
                            SMTP_SECURITY_STARTTLS,
                            SMTP_DEBUG,
                            SMTP_TEST_DEFAULT_AUTH_METHOD,
                            config->cafile,
                            "SMTP Test: cafile",
                            config->cafile);
}

/**
 * Send a test email with a specific authentication method.
 *
 * @param[in] config           Server connection details.
 * @param[in] auth_method      See @ref smtp_authentication_method.
 * @param[in] auth_description Description of @p auth_method.
 */
static void
smtp_func_test_auth(struct smtp_test_config *const config,
                    enum smtp_authentication_method auth_method,
                    const char *const auth_description){
  sprintf(config->subject,
          "SMTP Test: AUTH %s",
          auth_description);
  sprintf(config->body,
          "Email authenticated using %s",
          auth_description);

  smtp_func_test_send_email(config,
                            config->port,
                            SMTP_TEST_DEFAULT_CONNECTION_SECURITY,
                            SMTP_TEST_DEFAULT_FLAGS,
                            auth_method,
                            SMTP_TEST_DEFAULT_CAFILE,
                            config->subject,
                            config->body);
}

/**
 * Run through all types of SMTP authentication methods provided in the
 * @ref smtp_authentication_method.
 *
 * @param[in] config Server connection details.
 */
static void
smtp_func_test_all_auth_methods(struct smtp_test_config *const config){
  smtp_func_test_auth(config, SMTP_AUTH_NONE, "NONE");
  smtp_func_test_auth(config, SMTP_AUTH_PLAIN, "PLAIN");
  smtp_func_test_auth(config, SMTP_AUTH_LOGIN, "LOGIN");
  smtp_func_test_auth(config, SMTP_AUTH_CRAM_MD5, "CRAM-MD5");
}

/**
 * Test harness for @ref smtp_attachment_add_path.
 *
 * @param[in] config      Server connection details.
 * @param[in] name        Name of the file to display to the recipient.
 * @param[in] path        Local file path to use as the attachment.
 * @param[in] expect_rc   Expected return code for the attachment function
 *                        and every function after that.
 */
static void
smtp_func_test_attachment_path(struct smtp_test_config *const config,
                               const char *const name,
                               const char *const path,
                               int expect_rc){
  int rc;

  strcpy(config->subject, "SMTP Test: Attachment (file path)");
  strcpy(config->body, "This email should contain a pdf attachment");

  rc = smtp_open(config->server,
                 config->port,
                 SMTP_TEST_DEFAULT_CONNECTION_SECURITY,
                 SMTP_TEST_DEFAULT_FLAGS,
                 SMTP_TEST_DEFAULT_CAFILE,
                 &config->smtp);
  assert(rc == SMTP_STATUS_OK);

  rc = smtp_auth(config->smtp,
                 SMTP_TEST_DEFAULT_AUTH_METHOD,
                 config->user,
                 config->pass);
  assert(rc == SMTP_STATUS_OK);

  rc = smtp_address_add(config->smtp,
                        SMTP_ADDRESS_FROM,
                        config->email_from,
                        NULL);
  assert(rc == SMTP_STATUS_OK);

  rc = smtp_address_add(config->smtp,
                        SMTP_ADDRESS_TO,
                        config->email_to,
                        "Test Email");
  assert(rc == SMTP_STATUS_OK);

  rc = smtp_attachment_add_path(config->smtp, name, path);
  assert(rc == expect_rc);

  rc = smtp_header_add(config->smtp, "Subject", config->subject);
  assert(rc == expect_rc);

  rc = smtp_mail(config->smtp, config->body);
  assert(rc == expect_rc);

  rc = smtp_close(config->smtp);
  assert(rc == expect_rc);
}

/**
 * Test harness for @ref smtp_attachment_add_fp.
 *
 * @param[in] config      Server connection details.
 * @param[in] name        Name of the file to display to the recipient.
 * @param[in] path        Local file path to use as the attachment.
 * @param[in] expect_rc   Expected return code for the attachment function
 *                        and every function after that.
 */
static void
smtp_func_test_attachment_fp(struct smtp_test_config *const config,
                             const char *const name,
                             const char *const path,
                             int expect_rc){
  int rc;
  FILE *fp;

  strcpy(config->subject, "SMTP Test: Attachment (fp)");
  strcpy(config->body, "This email should contain a pdf attachment");

  fp = fopen(path, "r");
  assert(fp != NULL);

  rc = smtp_open(config->server,
                 config->port,
                 SMTP_TEST_DEFAULT_CONNECTION_SECURITY,
                 SMTP_TEST_DEFAULT_FLAGS,
                 SMTP_TEST_DEFAULT_CAFILE,
                 &config->smtp);
  assert(rc == SMTP_STATUS_OK);

  rc = smtp_address_add(config->smtp,
                        SMTP_ADDRESS_FROM,
                        config->email_from,
                        NULL);
  assert(rc == SMTP_STATUS_OK);

  rc = smtp_address_add(config->smtp,
                        SMTP_ADDRESS_TO,
                        config->email_to,
                        "Test Email");
  assert(rc == SMTP_STATUS_OK);

  rc = smtp_attachment_add_fp(config->smtp, name, fp);
  assert(rc == expect_rc);

  rc = smtp_header_add(config->smtp, "Subject", config->subject);
  assert(rc == expect_rc);

  rc = smtp_mail(config->smtp, config->body);
  assert(rc == expect_rc);

  rc = smtp_close(config->smtp);
  assert(rc == expect_rc);

  rc = fclose(fp);
  assert(rc == 0);
}

/**
 * Test harness for @ref smtp_attachment_add_mem.
 *
 * @param[in] config         Server connection details.
 * @param[in] num_attachment Number of attachments to send.
 */
static void
smtp_func_test_attachment_mem(struct smtp_test_config *const config,
                              size_t num_attachment){
  size_t i;
  char attachment_name[SMTP_MAX_ATTACHMENT_NAME_LEN];
  char attachment_data[100];
  int rc;

  sprintf(config->subject,
          "SMTP Test: Attachments (%u)",
          (unsigned)num_attachment);
  sprintf(config->body,
          "You should have %u attachments in this email. "
          "Each attachment should contain the text "
          "\"Attachment# <number>\"",
          (unsigned)num_attachment);

  rc = smtp_open(config->server,
                 config->port,
                 SMTP_TEST_DEFAULT_CONNECTION_SECURITY,
                 SMTP_TEST_DEFAULT_FLAGS,
                 SMTP_TEST_DEFAULT_CAFILE,
                 &config->smtp);
  assert(rc == SMTP_STATUS_OK);

  rc = smtp_auth(config->smtp,
                 SMTP_TEST_DEFAULT_AUTH_METHOD,
                 config->user,
                 config->pass);
  assert(rc == SMTP_STATUS_OK);

  rc = smtp_address_add(config->smtp,
                        SMTP_ADDRESS_FROM,
                        config->email_from,
                        NULL);
  assert(rc == SMTP_STATUS_OK);

  rc = smtp_address_add(config->smtp,
                        SMTP_ADDRESS_TO,
                        config->email_to,
                        "Test Email");
  assert(rc == SMTP_STATUS_OK);

  for(i = 0; i < num_attachment; i++){
    sprintf(attachment_name, "%u.txt", (unsigned)(i + 1));
    sprintf(attachment_data, "Attachment# %u", (unsigned)(i + 1));
    rc = smtp_attachment_add_mem(config->smtp,
                                 attachment_name,
                                 attachment_data,
                                 -1);
    assert(rc == SMTP_STATUS_OK);
  }

  rc = smtp_header_add(config->smtp, "Subject", config->subject);
  assert(rc == SMTP_STATUS_OK);

  rc = smtp_mail(config->smtp, config->body);
  assert(rc == SMTP_STATUS_OK);

  rc = smtp_close(config->smtp);
  assert(rc == SMTP_STATUS_OK);
}

/**
 * Run all tests for @ref smtp_attachment_add_mem.
 *
 * @param[in] config Server connection details.
 */
static void
smtp_func_test_all_attachments_mem(struct smtp_test_config *const config){
  /* Send one attachment using the mem interface. */
  smtp_func_test_attachment_mem(config, 1);

  /* Send 10 attachments in one email. */
  smtp_func_test_attachment_mem(config, 10);
}

/**
 * Run all tests for @ref smtp_attachment_add_path.
 *
 * @param[in] config Server connection details.
 */
static void
smtp_func_test_all_attachments_path(struct smtp_test_config *const config){
  /* Send a PDF test file using the path interface. */
  smtp_func_test_attachment_path(config,
                                       "test.pdf",
                                       "test/test.pdf",
                                       SMTP_STATUS_OK);

  /* Try to send a file that does not exist. */
  smtp_func_test_attachment_path(config,
                                       "noexist.txt",
                                       "test/noexist.txt",
                                       SMTP_STATUS_FILE);
}

/**
 * Run all tests for @ref smtp_attachment_add_fp.
 *
 * @param[in] config Server connection details.
 */
static void
smtp_func_test_all_attachments_fp(struct smtp_test_config *const config){
  smtp_func_test_attachment_fp(config,
                               "test.pdf",
                               "test/test.pdf",
                               SMTP_STATUS_OK);
}

/**
 * Test different ways of loading file attachments onto an SMTP context.
 *
 * @param[in] config SMTP server context.
 */
static void
smtp_func_test_all_attachments(struct smtp_test_config *const config){
  smtp_func_test_all_attachments_path(config);
  smtp_func_test_all_attachments_fp(config);
  smtp_func_test_all_attachments_mem(config);
}

/**
 * Test multiple ways of sending to different recipients.
 *
 * @param[in] config SMTP server context.
 */
static void
smtp_func_test_all_address(struct smtp_test_config *const config){
  int rc;

  rc = smtp_open(config->server,
                 config->port,
                 SMTP_TEST_DEFAULT_CONNECTION_SECURITY,
                 SMTP_TEST_DEFAULT_FLAGS,
                 SMTP_TEST_DEFAULT_CAFILE,
                 &config->smtp);
  assert(rc == SMTP_STATUS_OK);

  /* Multiple TO addresses. */
  smtp_header_clear_all(config->smtp);
  smtp_address_clear_all(config->smtp);
  rc = smtp_header_add(config->smtp,
                       "Subject",
                       "SMTP Test: Multiple TO Addresses");
  assert(rc == SMTP_STATUS_OK);
  rc = smtp_address_add(config->smtp,
                        SMTP_ADDRESS_FROM,
                        config->email_from,
                        NULL);
  assert(rc == SMTP_STATUS_OK);
  rc = smtp_address_add(config->smtp,
                        SMTP_ADDRESS_TO,
                        config->email_to,
                        "Test Email");
  assert(rc == SMTP_STATUS_OK);
  rc = smtp_address_add(config->smtp,
                        SMTP_ADDRESS_TO,
                        config->email_to_2,
                        "Test Email");
  assert(rc == SMTP_STATUS_OK);
  rc = smtp_mail(config->smtp,
                 "This email should contain two TO recipients.");
  assert(rc == SMTP_STATUS_OK);

  /* One BCC address. */
  smtp_header_clear_all(config->smtp);
  smtp_address_clear_all(config->smtp);
  rc = smtp_header_add(config->smtp,
                       "Subject",
                       "SMTP Test: BCC Address");
  assert(rc == SMTP_STATUS_OK);
  rc = smtp_address_add(config->smtp,
                        SMTP_ADDRESS_FROM,
                        config->email_from,
                        NULL);
  assert(rc == SMTP_STATUS_OK);
  rc = smtp_address_add(config->smtp,
                        SMTP_ADDRESS_BCC,
                        config->email_to,
                        "Test Email");
  assert(rc == SMTP_STATUS_OK);
  rc = smtp_mail(config->smtp,
                 "This email should contain one BCC recipient.");
  assert(rc == SMTP_STATUS_OK);

  /* One TO and one BCC address. */
  smtp_header_clear_all(config->smtp);
  smtp_address_clear_all(config->smtp);
  rc = smtp_header_add(config->smtp,
                       "Subject",
                       "SMTP Test: TO and BCC Addresses");
  assert(rc == SMTP_STATUS_OK);
  rc = smtp_address_add(config->smtp,
                        SMTP_ADDRESS_FROM,
                        config->email_from,
                        NULL);
  assert(rc == SMTP_STATUS_OK);
  rc = smtp_address_add(config->smtp,
                        SMTP_ADDRESS_TO,
                        config->email_to,
                        "Test Email");
  assert(rc == SMTP_STATUS_OK);
  rc = smtp_address_add(config->smtp,
                        SMTP_ADDRESS_BCC,
                        config->email_to_2,
                        "Test Email");
  assert(rc == SMTP_STATUS_OK);
  rc = smtp_mail(config->smtp,
                 "This email should contain one TO and one BCC recipient.");
  assert(rc == SMTP_STATUS_OK);

  /* One TO, CC, and BCC addresses. */
  smtp_header_clear_all(config->smtp);
  smtp_address_clear_all(config->smtp);
  rc = smtp_header_add(config->smtp,
                       "Subject",
                       "SMTP Test: TO, CC, and BCC Addresses");
  assert(rc == SMTP_STATUS_OK);
  rc = smtp_address_add(config->smtp,
                        SMTP_ADDRESS_FROM,
                        config->email_from,
                        NULL);
  assert(rc == SMTP_STATUS_OK);
  rc = smtp_address_add(config->smtp,
                        SMTP_ADDRESS_TO,
                        config->email_to,
                        "Test Email");
  assert(rc == SMTP_STATUS_OK);
  rc = smtp_address_add(config->smtp,
                        SMTP_ADDRESS_CC,
                        config->email_to_2,
                        "Test Email");
  assert(rc == SMTP_STATUS_OK);
  rc = smtp_address_add(config->smtp,
                        SMTP_ADDRESS_BCC,
                        config->email_to_3,
                        "Test Email");
  assert(rc == SMTP_STATUS_OK);
  rc = smtp_mail(config->smtp,
                 "This email should contain one TO, CC, and BCC recipient.");
  assert(rc == SMTP_STATUS_OK);

  /* No FROM address. */
  smtp_header_clear_all(config->smtp);
  smtp_address_clear_all(config->smtp);
  rc = smtp_header_add(config->smtp,
                       "Subject",
                       "SMTP Test: No FROM address");
  assert(rc == SMTP_STATUS_OK);
  rc = smtp_address_add(config->smtp,
                        SMTP_ADDRESS_TO,
                        config->email_to,
                        "Test Email");
  assert(rc == SMTP_STATUS_OK);
  rc = smtp_mail(config->smtp,
                 "This email should not have a FROM address in the header.");
  assert(rc == SMTP_STATUS_PARAM);
  smtp_status_code_set(config->smtp, SMTP_STATUS_OK);

  /* FROM address contains UTF-8 characters. */
  smtp_header_clear_all(config->smtp);
  smtp_address_clear_all(config->smtp);
  rc = smtp_header_add(config->smtp,
                       "Subject",
                       "SMTP Test: From contains UTF-8 characters");
  assert(rc == SMTP_STATUS_OK);
  rc = smtp_address_add(config->smtp,
                        SMTP_ADDRESS_FROM,
                        "smtp-cli€nt-t€st@somnisoft.com",
                        NULL);
  assert(rc == SMTP_STATUS_OK);
  rc = smtp_address_add(config->smtp,
                        SMTP_ADDRESS_TO,
                        config->email_to,
                        "Test Email");
  assert(rc == SMTP_STATUS_OK);
  /**
   * @todo email successful queued but not sent.
   */
  rc = smtp_mail(config->smtp,
                 "This email should contain a FROM address with UTF-8.");
  assert(rc == SMTP_STATUS_OK);

  rc = smtp_close(config->smtp);
  assert(rc == SMTP_STATUS_OK);
}

/**
 * Test scenario where the caller provides a custom date value in the header.
 *
 * This should override the default date implementation which uses the current
 * local date.
 *
 * @param[in] config SMTP server context.
 */
static void
smtp_func_test_header_custom_date(struct smtp_test_config *const config){
  int rc;

  rc = smtp_open(config->server,
                 config->port,
                 SMTP_TEST_DEFAULT_CONNECTION_SECURITY,
                 SMTP_TEST_DEFAULT_FLAGS,
                 SMTP_TEST_DEFAULT_CAFILE,
                 &config->smtp);
  assert(rc == SMTP_STATUS_OK);

  smtp_header_clear_all(config->smtp);

  rc = smtp_header_add(config->smtp,
                       "Subject",
                       "SMTP Test: Custom Date");
  assert(rc == SMTP_STATUS_OK);

  rc = smtp_header_add(config->smtp,
                       "Date",
                       "Thu, 21 May 1998 05:33:29 -0700");
  assert(rc == SMTP_STATUS_OK);

  rc = smtp_address_add(config->smtp,
                        SMTP_ADDRESS_FROM,
                        config->email_from,
                        NULL);
  assert(rc == SMTP_STATUS_OK);

  rc = smtp_address_add(config->smtp,
                        SMTP_ADDRESS_TO,
                        config->email_to,
                        "Test Email");
  assert(rc == SMTP_STATUS_OK);

  rc = smtp_mail(config->smtp,
                 "This email should contain a custom date header.");
  assert(rc == SMTP_STATUS_OK);

  rc = smtp_close(config->smtp);
  assert(rc == SMTP_STATUS_OK);
}

/**
 * Test scenario where the caller provides a NULL value for a header.
 *
 * This should prevent that header from generating in the email.
 *
 * @param[in] config SMTP server context.
 */
static void
smtp_func_test_header_null_no_date(struct smtp_test_config *const config){
  int rc;

  rc = smtp_open(config->server,
                 config->port,
                 SMTP_TEST_DEFAULT_CONNECTION_SECURITY,
                 SMTP_TEST_DEFAULT_FLAGS,
                 SMTP_TEST_DEFAULT_CAFILE,
                 &config->smtp);
  assert(rc == SMTP_STATUS_OK);

  smtp_header_clear_all(config->smtp);

  rc = smtp_header_add(config->smtp,
                       "Subject",
                       "SMTP Test: Null Header (No Date)");
  assert(rc == SMTP_STATUS_OK);

  rc = smtp_header_add(config->smtp,
                       "Date",
                       NULL);
  assert(rc == SMTP_STATUS_OK);

  rc = smtp_address_add(config->smtp,
                        SMTP_ADDRESS_FROM,
                        config->email_from,
                        NULL);
  assert(rc == SMTP_STATUS_OK);

  rc = smtp_address_add(config->smtp,
                        SMTP_ADDRESS_TO,
                        config->email_to,
                        "Test Email");
  assert(rc == SMTP_STATUS_OK);

  rc = smtp_mail(config->smtp,
                 "This email should not contain a Date header.");
  assert(rc == SMTP_STATUS_OK);

  rc = smtp_close(config->smtp);
  assert(rc == SMTP_STATUS_OK);
}

/**
 * Test multiple ways of sending to different headers.
 *
 * @param[in] config SMTP server context.
 */
static void
smtp_func_test_all_headers(struct smtp_test_config *const config){
  smtp_func_test_header_custom_date(config);
  smtp_func_test_header_null_no_date(config);
}

/**
 * Send a test email with debug mode disabled.
 *
 * @param[in] config SMTP server context.
 */
static void
smtp_func_test_all_nodebug(struct smtp_test_config *const config){
  int rc;

  rc = smtp_open(config->server,
                 config->port,
                 SMTP_TEST_DEFAULT_CONNECTION_SECURITY,
                 SMTP_NO_CERT_VERIFY,
                 SMTP_TEST_DEFAULT_CAFILE,
                 &config->smtp);
  assert(rc == SMTP_STATUS_OK);

  smtp_header_clear_all(config->smtp);

  rc = smtp_header_add(config->smtp,
                       "Subject",
                       "SMTP Test: No Debug Mode");
  assert(rc == SMTP_STATUS_OK);

  rc = smtp_address_add(config->smtp,
                        SMTP_ADDRESS_FROM,
                        config->email_from,
                        NULL);
  assert(rc == SMTP_STATUS_OK);

  rc = smtp_address_add(config->smtp,
                        SMTP_ADDRESS_TO,
                        config->email_to,
                        "Test Email");
  assert(rc == SMTP_STATUS_OK);

  rc = smtp_mail(config->smtp,
                 "This email sent with debug mode disabled.");
  assert(rc == SMTP_STATUS_OK);

  rc = smtp_close(config->smtp);
  assert(rc == SMTP_STATUS_OK);
}

/**
 * Test failure or error conditions not covered by any of the other failure
 * tests.
 *
 * @param[in] config SMTP server context.
 */
static void
test_failure_misc(struct smtp_test_config *const config){
  int rc;

  /* Memory allocation failure in smtp_puts_debug - the error gets ignored. */
  g_smtp_test_err_malloc_ctr = 0;
  rc = smtp_open(config->server,
                 config->port,
                 SMTP_TEST_DEFAULT_CONNECTION_SECURITY,
                 SMTP_TEST_DEFAULT_FLAGS,
                 SMTP_TEST_DEFAULT_CAFILE,
                 &config->smtp);
  g_smtp_test_err_malloc_ctr = -1;
  assert(rc == SMTP_STATUS_OK);
  rc = smtp_close(config->smtp);
  assert(rc == SMTP_STATUS_OK);
}

/**
 * Test failure points in the @ref smtp_open function.
 *
 * @param[in] config SMTP server context.
 */
static void
test_failure_open(struct smtp_test_config *const config){
  int rc;

  /* Initial memory allocation failure for the SMTP client context. */
  g_smtp_test_err_calloc_ctr = 0;
  rc = smtp_open(config->server,
                 config->port,
                 SMTP_TEST_DEFAULT_CONNECTION_SECURITY,
                 SMTP_TEST_DEFAULT_FLAGS,
                 SMTP_TEST_DEFAULT_CAFILE,
                 &config->smtp);
  g_smtp_test_err_calloc_ctr = -1;
  assert(rc == SMTP_STATUS_NOMEM);
  rc = smtp_close(config->smtp);
  assert(rc == SMTP_STATUS_NOMEM);

  /* Invalid hostname should cause getaddrinfo() to fail. */
  rc = smtp_open(NULL,
                 NULL,
                 SMTP_TEST_DEFAULT_CONNECTION_SECURITY,
                 SMTP_TEST_DEFAULT_FLAGS,
                 SMTP_TEST_DEFAULT_CAFILE,
                 &config->smtp);
  assert(rc == SMTP_STATUS_CONNECT);
  rc = smtp_close(config->smtp);
  assert(rc == SMTP_STATUS_CONNECT);

  /* socket() function failure. */
  g_smtp_test_err_socket_ctr = 0;
  rc = smtp_open(config->server,
                 config->port,
                 SMTP_TEST_DEFAULT_CONNECTION_SECURITY,
                 SMTP_TEST_DEFAULT_FLAGS,
                 SMTP_TEST_DEFAULT_CAFILE,
                 &config->smtp);
  g_smtp_test_err_socket_ctr = -1;
  assert(rc == SMTP_STATUS_CONNECT);
  rc = smtp_close(config->smtp);
  assert(rc == SMTP_STATUS_CONNECT);

  /* connect() function failure. */
  g_smtp_test_err_connect_ctr = 0;
  rc = smtp_open(config->server,
                 config->port,
                 SMTP_TEST_DEFAULT_CONNECTION_SECURITY,
                 SMTP_TEST_DEFAULT_FLAGS,
                 SMTP_TEST_DEFAULT_CAFILE,
                 &config->smtp);
  g_smtp_test_err_connect_ctr = -1;
  assert(rc == SMTP_STATUS_CONNECT);
  rc = smtp_close(config->smtp);
  assert(rc == SMTP_STATUS_CONNECT);

  /* SSL_CTX_new() failure. */
  g_smtp_test_err_ssl_ctx_new_ctr = 0;
  rc = smtp_open(config->server,
                 config->port,
                 SMTP_SECURITY_STARTTLS,
                 SMTP_TEST_DEFAULT_FLAGS,
                 SMTP_TEST_DEFAULT_CAFILE,
                 &config->smtp);
  g_smtp_test_err_ssl_ctx_new_ctr = -1;
  assert(rc == SMTP_STATUS_HANDSHAKE);
  rc = smtp_close(config->smtp);
  assert(rc == SMTP_STATUS_HANDSHAKE);

  /* ERR_peek_error() failure. */
  g_smtp_test_err_err_peek_error_ctr = 0;
  rc = smtp_open(config->server,
                 config->port,
                 SMTP_SECURITY_STARTTLS,
                 SMTP_TEST_DEFAULT_FLAGS,
                 SMTP_TEST_DEFAULT_CAFILE,
                 &config->smtp);
  g_smtp_test_err_err_peek_error_ctr = -1;
  assert(rc == SMTP_STATUS_HANDSHAKE);
  rc = smtp_close(config->smtp);
  assert(rc == SMTP_STATUS_HANDSHAKE);

  /* SSL_new() failure. */
  g_smtp_test_err_ssl_new_ctr = 0;
  rc = smtp_open(config->server,
                 config->port,
                 SMTP_SECURITY_STARTTLS,
                 SMTP_TEST_DEFAULT_FLAGS,
                 SMTP_TEST_DEFAULT_CAFILE,
                 &config->smtp);
  g_smtp_test_err_ssl_new_ctr = -1;
  assert(rc == SMTP_STATUS_HANDSHAKE);
  rc = smtp_close(config->smtp);
  assert(rc == SMTP_STATUS_HANDSHAKE);

  /* BIO_new_socket() failure. */
  g_smtp_test_err_bio_new_socket_ctr = 0;
  rc = smtp_open(config->server,
                 config->port,
                 SMTP_SECURITY_STARTTLS,
                 SMTP_TEST_DEFAULT_FLAGS,
                 SMTP_TEST_DEFAULT_CAFILE,
                 &config->smtp);
  g_smtp_test_err_bio_new_socket_ctr = -1;
  assert(rc == SMTP_STATUS_HANDSHAKE);
  rc = smtp_close(config->smtp);
  assert(rc == SMTP_STATUS_HANDSHAKE);

  /* SSL_connect() failure. */
  g_smtp_test_err_ssl_connect_ctr = 0;
  rc = smtp_open(config->server,
                 config->port,
                 SMTP_SECURITY_STARTTLS,
                 SMTP_TEST_DEFAULT_FLAGS,
                 SMTP_TEST_DEFAULT_CAFILE,
                 &config->smtp);
  g_smtp_test_err_ssl_connect_ctr = -1;
  assert(rc == SMTP_STATUS_HANDSHAKE);
  rc = smtp_close(config->smtp);
  assert(rc == SMTP_STATUS_HANDSHAKE);

  /* SSL_do_handshake() failure. */
  g_smtp_test_err_ssl_do_handshake_ctr = 0;
  rc = smtp_open(config->server,
                 config->port,
                 SMTP_SECURITY_STARTTLS,
                 SMTP_TEST_DEFAULT_FLAGS,
                 SMTP_TEST_DEFAULT_CAFILE,
                 &config->smtp);
  g_smtp_test_err_ssl_do_handshake_ctr = -1;
  assert(rc == SMTP_STATUS_HANDSHAKE);
  rc = smtp_close(config->smtp);
  assert(rc == SMTP_STATUS_HANDSHAKE);

  /*
   * Ensure self-signed certificate throws an error. This error will occur by
   * default since the test server uses a self-signed certificate.
   */
  rc = smtp_open(config->server,
                 config->port,
                 SMTP_SECURITY_STARTTLS,
                 SMTP_DEBUG,
                 SMTP_TEST_DEFAULT_CAFILE,
                 &config->smtp);
  assert(rc == SMTP_STATUS_HANDSHAKE);
  rc = smtp_close(config->smtp);
  assert(rc == SMTP_STATUS_HANDSHAKE);

  /* SSL_CTX_load_verify_locations() failure. */
  rc = smtp_open(config->server,
                 config->port,
                 SMTP_SECURITY_STARTTLS,
                 SMTP_DEBUG,
                 "test/config/file_does_not_exist",
                 &config->smtp);
  assert(rc == SMTP_STATUS_HANDSHAKE);
  rc = smtp_close(config->smtp);
  assert(rc == SMTP_STATUS_HANDSHAKE);

  /* SSL_get_peer_certificate() failure. */
  g_smtp_test_err_ssl_get_peer_certificate_ctr = 0;
  rc = smtp_open(config->server,
                 config->port,
                 SMTP_SECURITY_STARTTLS,
                 SMTP_DEBUG,
                 config->cafile,
                 &config->smtp);
  g_smtp_test_err_ssl_get_peer_certificate_ctr = -1;
  assert(rc == SMTP_STATUS_HANDSHAKE);
  rc = smtp_close(config->smtp);
  assert(rc == SMTP_STATUS_HANDSHAKE);

  /* X509_check_host() failure.  */
  g_smtp_test_err_x509_check_host_ctr = 0;
  rc = smtp_open(config->server,
                 config->port,
                 SMTP_SECURITY_STARTTLS,
                 SMTP_DEBUG,
                 config->cafile,
                 &config->smtp);
  g_smtp_test_err_x509_check_host_ctr = -1;
  assert(rc == SMTP_STATUS_HANDSHAKE);
  rc = smtp_close(config->smtp);
  assert(rc == SMTP_STATUS_HANDSHAKE);

  /*
   * TLS failure in @ref smtp_initiate_handshake (1) when using direct
   * TLS connection.
   */
  g_smtp_test_err_ssl_ctx_new_ctr = 0;
  rc = smtp_open(config->server,
                 config->port,
                 SMTP_SECURITY_TLS,
                 SMTP_TEST_DEFAULT_FLAGS,
                 SMTP_TEST_DEFAULT_CAFILE,
                 &config->smtp);
  g_smtp_test_err_ssl_ctx_new_ctr = -1;
  assert(rc == SMTP_STATUS_HANDSHAKE);
  rc = smtp_close(config->smtp);
  assert(rc == SMTP_STATUS_HANDSHAKE);

  /* @ref smtp_initiate_handshake failure in (2). */
  g_smtp_test_err_recv_ctr = 0;
  rc = smtp_open(config->server,
                 config->port,
                 SMTP_TEST_DEFAULT_CONNECTION_SECURITY,
                 SMTP_TEST_DEFAULT_FLAGS,
                 SMTP_TEST_DEFAULT_CAFILE,
                 &config->smtp);
  g_smtp_test_err_recv_ctr = -1;
  assert(rc == SMTP_STATUS_HANDSHAKE);
  rc = smtp_close(config->smtp);
  assert(rc == SMTP_STATUS_HANDSHAKE);

  /* @ref smtp_initiate_handshake failure in (3). */
  g_smtp_test_err_send_ctr = 0;
  rc = smtp_open(config->server,
                 config->port,
                 SMTP_TEST_DEFAULT_CONNECTION_SECURITY,
                 SMTP_TEST_DEFAULT_FLAGS,
                 SMTP_TEST_DEFAULT_CAFILE,
                 &config->smtp);
  g_smtp_test_err_send_ctr = -1;
  assert(rc == SMTP_STATUS_HANDSHAKE);
  rc = smtp_close(config->smtp);
  assert(rc == SMTP_STATUS_HANDSHAKE);

  /* @ref smtp_initiate_handshake STARTTLS send failure in (4). */
  g_smtp_test_err_send_ctr = 1;
  rc = smtp_open(config->server,
                 config->port,
                 SMTP_SECURITY_STARTTLS,
                 SMTP_TEST_DEFAULT_FLAGS,
                 SMTP_TEST_DEFAULT_CAFILE,
                 &config->smtp);
  g_smtp_test_err_send_ctr = -1;
  assert(rc == SMTP_STATUS_HANDSHAKE);
  rc = smtp_close(config->smtp);
  assert(rc == SMTP_STATUS_HANDSHAKE);

  /* @ref smtp_initiate_handshake failed response to STARTTLS in (4). */
  g_smtp_test_err_recv_ctr = 2;
  rc = smtp_open(config->server,
                 config->port,
                 SMTP_SECURITY_STARTTLS,
                 SMTP_TEST_DEFAULT_FLAGS,
                 SMTP_TEST_DEFAULT_CAFILE,
                 &config->smtp);
  g_smtp_test_err_recv_ctr = -1;
  assert(rc == SMTP_STATUS_HANDSHAKE);
  rc = smtp_close(config->smtp);
  assert(rc == SMTP_STATUS_HANDSHAKE);

  /* @ref smtp_initiate_handshake second EHLO in (4). */
  g_smtp_test_err_ssl_write_ctr = 0;
  rc = smtp_open(config->server,
                 config->port,
                 SMTP_SECURITY_STARTTLS,
                 SMTP_TEST_DEFAULT_FLAGS,
                 SMTP_TEST_DEFAULT_CAFILE,
                 &config->smtp);
  g_smtp_test_err_ssl_write_ctr = -1;
  assert(rc == SMTP_STATUS_HANDSHAKE);
  rc = smtp_close(config->smtp);
  assert(rc == SMTP_STATUS_HANDSHAKE);

  /* Failure in @ref BIO_should_retry. */
  g_smtp_test_err_ssl_read_ctr = 0;
  g_smtp_test_err_bio_should_retry_ctr = 0;
  g_smtp_test_err_bio_should_retry_rc = -1;
  rc = smtp_open(config->server,
                 config->port,
                 SMTP_SECURITY_STARTTLS,
                 SMTP_TEST_DEFAULT_FLAGS,
                 SMTP_TEST_DEFAULT_CAFILE,
                 &config->smtp);
  g_smtp_test_err_ssl_read_ctr = -1;
  g_smtp_test_err_bio_should_retry_ctr = -1;
  g_smtp_test_err_bio_should_retry_rc = -1;
  assert(rc == SMTP_STATUS_HANDSHAKE);
  rc = smtp_close(config->smtp);
  assert(rc == SMTP_STATUS_HANDSHAKE);

  /* Failure in @ref SSL_Read but re-reading caused by @ref BIO_should_retry. */
  g_smtp_test_err_ssl_read_ctr = 0;
  g_smtp_test_err_bio_should_retry_ctr = -1;
  g_smtp_test_err_bio_should_retry_rc = 1;
  rc = smtp_open(config->server,
                 config->port,
                 SMTP_SECURITY_STARTTLS,
                 SMTP_TEST_DEFAULT_FLAGS,
                 SMTP_TEST_DEFAULT_CAFILE,
                 &config->smtp);
  g_smtp_test_err_ssl_read_ctr = -1;
  g_smtp_test_err_bio_should_retry_ctr = -1;
  g_smtp_test_err_bio_should_retry_rc = -1;
  assert(rc == SMTP_STATUS_OK);
  rc = smtp_close(config->smtp);
  assert(rc == SMTP_STATUS_OK);

  /* Test server prematurely ending the connection with no bytes to read. */
  g_smtp_test_err_recv_ctr = 2;
  g_smtp_test_err_recv_rc = 0;
  rc = smtp_open(config->server,
                 config->port,
                 SMTP_SECURITY_STARTTLS,
                 SMTP_TEST_DEFAULT_FLAGS,
                 SMTP_TEST_DEFAULT_CAFILE,
                 &config->smtp);
  g_smtp_test_err_recv_ctr = -1;
  g_smtp_test_err_recv_rc = -1;
  assert(rc == SMTP_STATUS_HANDSHAKE);
  rc = smtp_close(config->smtp);
  assert(rc == SMTP_STATUS_HANDSHAKE);
}

/**
 * Test different error results in the address functions, including memory
 * allocation failures.
 *
 * @param[in] config SMTP server context.
 */
static void
test_failure_address_add(struct smtp_test_config *const config){
  int rc;

  rc = smtp_open(config->server,
                 config->port,
                 SMTP_TEST_DEFAULT_CONNECTION_SECURITY,
                 SMTP_TEST_DEFAULT_FLAGS,
                 SMTP_TEST_DEFAULT_CAFILE,
                 &config->smtp);
  assert(rc == SMTP_STATUS_OK);

  /* Invalid SMTP status code. */
  smtp_status_code_set(config->smtp, SMTP_STATUS_NOMEM);
  rc = smtp_address_add(config->smtp,
                        SMTP_ADDRESS_FROM,
                        config->email_from,
                        NULL);
  assert(rc == SMTP_STATUS_NOMEM);

  /* Invalid email address. */
  smtp_status_code_set(config->smtp, SMTP_STATUS_OK);
  rc = smtp_address_add(config->smtp,
                        SMTP_ADDRESS_FROM,
                        "<invalid>",
                        NULL);
  assert(rc == SMTP_STATUS_PARAM);

  /* Invalid email name. */
  smtp_status_code_set(config->smtp, SMTP_STATUS_OK);
  rc = smtp_address_add(config->smtp,
                        SMTP_ADDRESS_FROM,
                        config->email_from,
                        "\"invalid\"");
  assert(rc == SMTP_STATUS_PARAM);

  /* Memory allocation failed while trying to increase size of address list. */
  smtp_status_code_set(config->smtp, SMTP_STATUS_OK);
  g_smtp_test_err_realloc_ctr = 0;
  rc = smtp_address_add(config->smtp,
                        SMTP_ADDRESS_FROM,
                        config->email_from,
                        NULL);
  g_smtp_test_err_realloc_ctr = -1;
  assert(rc == SMTP_STATUS_NOMEM);

  /* Failed to duplicate email string. */
  smtp_status_code_set(config->smtp, SMTP_STATUS_OK);
  g_smtp_test_err_malloc_ctr = 0;
  rc = smtp_address_add(config->smtp,
                        SMTP_ADDRESS_FROM,
                        config->email_from,
                        "test name");
  g_smtp_test_err_malloc_ctr = -1;
  assert(rc == SMTP_STATUS_NOMEM);

  /* Failed to duplicate name string. */
  smtp_status_code_set(config->smtp, SMTP_STATUS_OK);
  g_smtp_test_err_malloc_ctr = 1;
  rc = smtp_address_add(config->smtp,
                        SMTP_ADDRESS_FROM,
                        config->email_from,
                        "test name");
  g_smtp_test_err_malloc_ctr = -1;
  assert(rc == SMTP_STATUS_NOMEM);

  rc = smtp_close(config->smtp);
  assert(rc == SMTP_STATUS_NOMEM);
}

/**
 * Test different error results in the attachment functions, including memory
 * allocation failures.
 *
 * @param[in] config SMTP server context.
 */
static void
test_failure_attachment_add(struct smtp_test_config *const config){
  int rc;
  FILE *fp;

  rc = smtp_open(config->server,
                 config->port,
                 SMTP_TEST_DEFAULT_CONNECTION_SECURITY,
                 SMTP_TEST_DEFAULT_FLAGS,
                 SMTP_TEST_DEFAULT_CAFILE,
                 &config->smtp);
  assert(rc == SMTP_STATUS_OK);


  /* Invalid SMTP status code. */
  smtp_status_code_set(config->smtp, SMTP_STATUS_PARAM);
  rc = smtp_attachment_add_mem(config->smtp, "valid", "test", -1);
  assert(rc == SMTP_STATUS_PARAM);


  /* Invalid filename parameter. */
  smtp_status_code_set(config->smtp, SMTP_STATUS_OK);
  rc = smtp_attachment_add_mem(config->smtp,
                               "\"invalid\"",
                               "test",
                               -1);
  assert(rc == SMTP_STATUS_PARAM);


  /* Memory allocation failure while increasing the attachment list size. */
  smtp_status_code_set(config->smtp, SMTP_STATUS_OK);
  g_smtp_test_err_realloc_ctr = 0;
  rc = smtp_attachment_add_mem(config->smtp, "valid", "test", -1);
  assert(rc == SMTP_STATUS_NOMEM);
  g_smtp_test_err_realloc_ctr = -1;

  /* Memory allocation failure while using smtp_strdup on file name. */
  smtp_status_code_set(config->smtp, SMTP_STATUS_OK);
  g_smtp_test_err_malloc_ctr = 0;
  rc = smtp_attachment_add_mem(config->smtp, "valid", "test", -1);
  assert(rc == SMTP_STATUS_NOMEM);
  g_smtp_test_err_malloc_ctr = -1;


  /* Memory allocation failure while using smtp_base64_encode. */
  smtp_status_code_set(config->smtp, SMTP_STATUS_OK);
  g_smtp_test_err_calloc_ctr = 0;
  rc = smtp_attachment_add_mem(config->smtp, "valid", "test", -1);
  assert(rc == SMTP_STATUS_NOMEM);
  g_smtp_test_err_calloc_ctr = -1;

  /* Invalid SMTP status code. */
  smtp_status_code_set(config->smtp, SMTP_STATUS_PARAM);
  rc = smtp_attachment_add_fp(config->smtp, "test", stdin);
  assert(rc == SMTP_STATUS_PARAM);

  /* @ref smtp_ffile_get_contents memory allocation failure. */
  smtp_status_code_set(config->smtp, SMTP_STATUS_OK);
  g_smtp_test_err_realloc_ctr = 0;
  rc = smtp_attachment_add_fp(config->smtp, "test", stdin);
  g_smtp_test_err_realloc_ctr = -1;
  assert(rc == SMTP_STATUS_NOMEM);

  /* @ref smtp_ffile_get_contents fread error. */
  smtp_status_code_set(config->smtp, SMTP_STATUS_OK);
  fp = fopen("COPYING", "r");
  assert(fp);
  g_smtp_test_err_ferror_ctr = 0;
  rc = smtp_attachment_add_fp(config->smtp, "test", fp);
  g_smtp_test_err_ferror_ctr = -1;
  assert(rc == SMTP_STATUS_FILE);
  rc = fclose(fp);
  assert(rc == 0);

  /* @ref smtp_file_get_contents memory allocation failure. */
  smtp_status_code_set(config->smtp, SMTP_STATUS_OK);
  g_smtp_test_err_realloc_ctr = 0;
  rc = smtp_attachment_add_path(config->smtp, "test", "COPYING");
  g_smtp_test_err_realloc_ctr = -1;
  assert(rc == SMTP_STATUS_NOMEM);

  /* Invalid SMTP status code. */
  smtp_status_code_set(config->smtp, SMTP_STATUS_PARAM);
  rc = smtp_attachment_add_path(config->smtp, "test", "test.txt");
  assert(rc == SMTP_STATUS_PARAM);

  rc = smtp_close(config->smtp);
  assert(rc == SMTP_STATUS_PARAM);
}

/**
 * Test different error results in the @ref smtp_header_add function,
 * including memory allocation failures.
 *
 * @param[in] config SMTP server context.
 */
static void
test_failure_header_add(struct smtp_test_config *const config){
  int rc;

  rc = smtp_open(config->server,
                 config->port,
                 SMTP_TEST_DEFAULT_CONNECTION_SECURITY,
                 SMTP_TEST_DEFAULT_FLAGS,
                 SMTP_TEST_DEFAULT_CAFILE,
                 &config->smtp);
  assert(rc == SMTP_STATUS_OK);

  /* Invalid SMTP status code. */
  smtp_status_code_set(config->smtp, SMTP_STATUS_NOMEM);
  rc = smtp_header_add(config->smtp,
                       "key",
                       "value");
  assert(rc == SMTP_STATUS_NOMEM);

  /* Invalid header key. */
  smtp_status_code_set(config->smtp, SMTP_STATUS_OK);
  rc = smtp_header_add(config->smtp,
                       "invalid:",
                       "value");
  assert(rc == SMTP_STATUS_PARAM);

  /* Invalid header value. */
  smtp_status_code_set(config->smtp, SMTP_STATUS_OK);
  rc = smtp_header_add(config->smtp,
                       "key",
                       "invalid\n");
  assert(rc == SMTP_STATUS_PARAM);

  /* Memory allocation failure while trying to increase header list size. */
  smtp_status_code_set(config->smtp, SMTP_STATUS_OK);
  g_smtp_test_err_realloc_ctr = 0;
  rc = smtp_header_add(config->smtp,
                       "key",
                       "value");
  g_smtp_test_err_realloc_ctr = -1;
  assert(rc == SMTP_STATUS_NOMEM);

  /* Failed to strdup header key. */
  smtp_status_code_set(config->smtp, SMTP_STATUS_OK);
  g_smtp_test_err_malloc_ctr = 0;
  rc = smtp_header_add(config->smtp,
                       "key",
                       "value");
  g_smtp_test_err_malloc_ctr = -1;
  assert(rc == SMTP_STATUS_NOMEM);

  /* Failed to strdup header value. */
  smtp_status_code_set(config->smtp, SMTP_STATUS_OK);
  g_smtp_test_err_malloc_ctr = 1;
  rc = smtp_header_add(config->smtp,
                       "key",
                       "value");
  g_smtp_test_err_malloc_ctr = -1;
  assert(rc == SMTP_STATUS_NOMEM);

  rc = smtp_close(config->smtp);
  assert(rc == SMTP_STATUS_NOMEM);
}

/**
 * Test different error results @ref smtp_status_code_set function.
 *
 * @param[in] config SMTP server context.
 */
static void
test_failure_status_code_set(struct smtp_test_config *const config){
  int rc;

  rc = smtp_open(config->server,
                 config->port,
                 SMTP_TEST_DEFAULT_CONNECTION_SECURITY,
                 SMTP_TEST_DEFAULT_FLAGS,
                 SMTP_TEST_DEFAULT_CAFILE,
                 &config->smtp);
  assert(rc == SMTP_STATUS_OK);

  rc = smtp_status_code_set(config->smtp, -1);
  assert(rc == SMTP_STATUS_PARAM);

  rc = smtp_status_code_set(config->smtp, SMTP_STATUS__LAST);
  assert(rc == SMTP_STATUS_PARAM);

  rc = smtp_status_code_set(config->smtp, SMTP_STATUS_OK);
  assert(rc == SMTP_STATUS_OK);

  rc = smtp_close(config->smtp);
  assert(rc == SMTP_STATUS_OK);
}

/**
 * Test different error conditions in the @ref smtp_mail function.
 *
 * @param[in] config SMTP server context.
 */
static void
test_failure_mail(struct smtp_test_config *const config){
  int rc;

  /* Invalid SMTP client context. */
  test_smtp_open_default(config);
  smtp_status_code_set(config->smtp, SMTP_STATUS_NOMEM);
  rc = smtp_mail(config->smtp, "body");
  assert(rc == SMTP_STATUS_NOMEM);
  smtp_close(config->smtp);

  /*
   * Memory allocation failure in the first call to
   * @ref smtp_mail_envelope_header.
   */
  test_smtp_open_default(config);
  g_smtp_test_err_malloc_ctr = 0;
  rc = smtp_mail(config->smtp, "body");
  g_smtp_test_err_malloc_ctr = -1;
  assert(rc == SMTP_STATUS_NOMEM);
  smtp_close(config->smtp);

  /* Send failure in @ref smtp_mail_envelope_header. */
  test_smtp_open_default(config);
  g_smtp_test_err_send_ctr = 0;
  g_smtp_test_err_ssl_write_ctr = 0;
  rc = smtp_mail(config->smtp, "body");
  g_smtp_test_err_send_ctr = -1;
  g_smtp_test_err_ssl_write_ctr = -1;
  assert(rc == SMTP_STATUS_SEND);
  smtp_close(config->smtp);

  /* Read failure in @ref smtp_mail_envelope_header. */
  test_smtp_open_default(config);
  g_smtp_test_err_recv_ctr = 0;
  g_smtp_test_err_ssl_read_ctr = 0;
  rc = smtp_mail(config->smtp, "body");
  g_smtp_test_err_recv_ctr = -1;
  g_smtp_test_err_ssl_read_ctr = -1;
  assert(rc == SMTP_STATUS_RECV);
  smtp_close(config->smtp);

  /* Send failure in the second call to @ref smtp_mail_envelope_header. */
  test_smtp_open_default(config);
  g_smtp_test_err_send_ctr = 1;
  g_smtp_test_err_ssl_write_ctr = 1;
  rc = smtp_mail(config->smtp, "body");
  g_smtp_test_err_send_ctr = -1;
  g_smtp_test_err_ssl_write_ctr = -1;
  assert(rc == SMTP_STATUS_SEND);
  smtp_close(config->smtp);

  /* Failed to send DATA command. */
  test_smtp_open_default(config);
  g_smtp_test_err_send_ctr = 3;
  g_smtp_test_err_ssl_write_ctr = 3;
  rc = smtp_mail(config->smtp, "body");
  g_smtp_test_err_send_ctr = -1;
  g_smtp_test_err_ssl_write_ctr = -1;
  assert(rc == SMTP_STATUS_SEND);
  smtp_close(config->smtp);

  /* Failed to read response to DATA command. */
  test_smtp_open_default(config);
  g_smtp_test_err_recv_ctr = 3;
  g_smtp_test_err_ssl_read_ctr = 3;
  rc = smtp_mail(config->smtp, "body");
  g_smtp_test_err_recv_ctr = -1;
  g_smtp_test_err_ssl_read_ctr = -1;
  assert(rc == SMTP_STATUS_SERVER_RESPONSE);
  smtp_close(config->smtp);

  /* Failed to generate date string in @ref smtp_date_rfc_2822. */
  test_smtp_open_default(config);
  g_smtp_test_err_localtime_r_ctr = 0;
  rc = smtp_mail(config->smtp, "body");
  g_smtp_test_err_localtime_r_ctr = -1;
  assert(rc == SMTP_STATUS_DATE);
  smtp_close(config->smtp);

  /* Failed to add Date header to list using @ref smtp_header_add. */
  test_smtp_open_default(config);
  g_smtp_test_err_realloc_ctr = 0;
  rc = smtp_mail(config->smtp, "body");
  g_smtp_test_err_realloc_ctr = -1;
  assert(rc == SMTP_STATUS_NOMEM);
  smtp_close(config->smtp);

  /*
   * Failed to add FROM address to header using
   * @ref smtp_append_address_to_header.
   */
  test_smtp_open_default(config);
  g_smtp_test_err_realloc_ctr = 1;
  rc = smtp_mail(config->smtp, "body");
  g_smtp_test_err_realloc_ctr = -1;
  assert(rc == SMTP_STATUS_NOMEM);
  smtp_close(config->smtp);

  /*
   * Failed to add TO address to header using
   * @ref smtp_append_address_to_header.
   */
  test_smtp_open_default(config);
  g_smtp_test_err_realloc_ctr = 3;
  rc = smtp_mail(config->smtp, "body");
  g_smtp_test_err_realloc_ctr = -1;
  assert(rc == SMTP_STATUS_NOMEM);
  smtp_close(config->smtp);

  /*
   * Failed to add CC address to header using
   * @ref smtp_append_address_to_header.
   */
  test_smtp_open_default(config);
  g_smtp_test_err_realloc_ctr = 5;
  rc = smtp_mail(config->smtp, "body");
  g_smtp_test_err_realloc_ctr = -1;
  assert(rc == SMTP_STATUS_NOMEM);
  smtp_close(config->smtp);

  /* Failed memory allocation in @ref smtp_print_header. */
  test_smtp_open_default(config);
  g_smtp_test_err_malloc_ctr = 19;
  rc = smtp_mail(config->smtp, "body");
  g_smtp_test_err_malloc_ctr = -1;
  assert(rc == SMTP_STATUS_NOMEM);
  smtp_close(config->smtp);

  /* Failed @ref smtp_chunk_split in @ref smtp_print_header. */
  test_smtp_open_default(config);
  g_smtp_test_err_calloc_ctr = 4;
  rc = smtp_mail(config->smtp, "body");
  g_smtp_test_err_calloc_ctr = -1;
  assert(rc == SMTP_STATUS_NOMEM);
  smtp_close(config->smtp);

  /* Failed @ref smtp_puts in @ref smtp_print_header. */
  test_smtp_open_default(config);
  g_smtp_test_err_send_ctr = 4;
  g_smtp_test_err_ssl_write_ctr = 4;
  rc = smtp_mail(config->smtp, "body");
  g_smtp_test_err_send_ctr = -1;
  g_smtp_test_err_ssl_write_ctr = -1;
  assert(rc == SMTP_STATUS_SEND);
  smtp_close(config->smtp);

  /*
   * Failure in @ref smtp_print_mime_email ->
   * @ref smtp_print_mime_header_and_body   ->
   * @ref smtp_str_replace.
   */
  test_smtp_open_default(config);
  g_smtp_test_err_realloc_ctr = 7;
  rc = smtp_mail(config->smtp, "body");
  g_smtp_test_err_realloc_ctr = -1;
  assert(rc == SMTP_STATUS_NOMEM);
  smtp_close(config->smtp);

  /*
   * Memory allocation failure in @ref smtp_print_mime_email ->
   * @ref smtp_print_mime_header_and_body   ->
   * malloc after @ref smtp_str_replace.
   */
  test_smtp_open_default(config);
  g_smtp_test_err_malloc_ctr = 27;
  rc = smtp_mail(config->smtp, "body");
  g_smtp_test_err_malloc_ctr = -1;
  assert(rc == SMTP_STATUS_NOMEM);
  smtp_close(config->smtp);

  /*
   * Send failure in @ref smtp_print_mime_email ->
   * @ref smtp_print_mime_header_and_body   ->
   * @ref smtp_puts.
   */
  test_smtp_open_default(config);
  g_smtp_test_err_send_ctr = 8;
  g_smtp_test_err_ssl_write_ctr = 8;
  rc = smtp_mail(config->smtp, "body");
  g_smtp_test_err_send_ctr = -1;
  g_smtp_test_err_ssl_write_ctr = -1;
  assert(rc == SMTP_STATUS_SEND);
  smtp_close(config->smtp);

  /* Memory allocation failure in @ref smtp_print_mime_attachment. */
  test_smtp_open_default(config);
  g_smtp_test_err_malloc_ctr = 29;
  rc = smtp_mail(config->smtp, "body");
  g_smtp_test_err_malloc_ctr = -1;
  assert(rc == SMTP_STATUS_NOMEM);
  smtp_close(config->smtp);

  /* Send failure in @ref smtp_print_mime_attachment. */
  test_smtp_open_default(config);
  g_smtp_test_err_send_ctr = 9;
  g_smtp_test_err_ssl_write_ctr = 9;
  rc = smtp_mail(config->smtp, "body");
  g_smtp_test_err_send_ctr = -1;
  g_smtp_test_err_ssl_write_ctr = -1;
  assert(rc == SMTP_STATUS_SEND);
  smtp_close(config->smtp);

  /* Send failure in @ref smtp_print_mime_end. */
  test_smtp_open_default(config);
  g_smtp_test_err_send_ctr = 10;
  g_smtp_test_err_ssl_write_ctr = 10;
  rc = smtp_mail(config->smtp, "body");
  g_smtp_test_err_send_ctr = -1;
  g_smtp_test_err_ssl_write_ctr = -1;
  assert(rc == SMTP_STATUS_SEND);
  smtp_close(config->smtp);

  /* Failed to send end of DATA segment. */
  test_smtp_open_default(config);
  g_smtp_test_err_send_ctr = 11;
  g_smtp_test_err_ssl_write_ctr = 11;
  rc = smtp_mail(config->smtp, "body");
  g_smtp_test_err_send_ctr = -1;
  g_smtp_test_err_ssl_write_ctr = -1;
  assert(rc == SMTP_STATUS_SEND);
  smtp_close(config->smtp);

  /* Invalid server response on DATA termination. */
  test_smtp_open_default(config);
  g_smtp_test_err_recv_ctr = 4;
  g_smtp_test_err_ssl_read_ctr = 4;
  rc = smtp_mail(config->smtp, "body");
  g_smtp_test_err_recv_ctr = -1;
  g_smtp_test_err_ssl_read_ctr = -1;
  assert(rc == SMTP_STATUS_SERVER_RESPONSE);
  smtp_close(config->smtp);
}

/**
 * Test different error conditions in the @ref smtp_close function.
 *
 * @param[in] config SMTP server context.
 */
static void
test_failure_close(struct smtp_test_config *const config){
  int rc;

  /* Failed to send the QUIT command. */
  rc = smtp_open(config->server,
                 config->port,
                 SMTP_TEST_DEFAULT_CONNECTION_SECURITY,
                 SMTP_TEST_DEFAULT_FLAGS,
                 SMTP_TEST_DEFAULT_CAFILE,
                 &config->smtp);
  assert(rc == SMTP_STATUS_OK);
  g_smtp_test_err_send_ctr = 0;
  g_smtp_test_err_ssl_write_ctr = 0;
  rc = smtp_close(config->smtp);
  g_smtp_test_err_send_ctr = -1;
  g_smtp_test_err_ssl_write_ctr = -1;
  assert(rc == SMTP_STATUS_SEND);

  /* Failed to close the socket file descriptor. */
  rc = smtp_open(config->server,
                 config->port,
                 SMTP_TEST_DEFAULT_CONNECTION_SECURITY,
                 SMTP_TEST_DEFAULT_FLAGS,
                 SMTP_TEST_DEFAULT_CAFILE,
                 &config->smtp);
  assert(rc == SMTP_STATUS_OK);
  g_smtp_test_err_close_ctr = 0;
  rc = smtp_close(config->smtp);
  g_smtp_test_err_close_ctr = -1;
  assert(rc == SMTP_STATUS_CLOSE);
}

/**
 * Test different error results in the auth functions, including memory
 * allocation failures and invalid credentials.
 *
 * @param[in] config SMTP server context.
 */
static void
test_failure_auth(struct smtp_test_config *const config){
  int rc;

  smtp_test_sleep(15);

  /* Invalid SMTP status code. */
  test_smtp_open_default(config);
  smtp_status_code_set(config->smtp, SMTP_STATUS_NOMEM);
  rc = smtp_auth(config->smtp,
                 SMTP_AUTH_NONE,
                 config->user,
                 config->pass);
  assert(rc == SMTP_STATUS_NOMEM);
  smtp_close(config->smtp);

  smtp_test_sleep(15);

  /* Invalid authentication method. */
  test_smtp_open_default(config);
  rc = smtp_auth(config->smtp,
                 -1,
                 config->user,
                 config->pass);
  assert(rc == SMTP_STATUS_PARAM);
  smtp_close(config->smtp);

  smtp_test_sleep(15);

  /* PLAIN - Invalid credentials. */
  test_smtp_open_default(config);
  rc = smtp_auth(config->smtp,
                 SMTP_AUTH_PLAIN,
                 "invalid",
                 "invalid");
  assert(rc == SMTP_STATUS_AUTH);
  smtp_close(config->smtp);

  smtp_test_sleep(15);

  /* PLAIN - Memory allocation failure in (1). */
  test_smtp_open_default(config);
  g_smtp_test_err_malloc_ctr = 0;
  rc = smtp_auth(config->smtp,
                 SMTP_AUTH_PLAIN,
                 config->user,
                 config->pass);
  g_smtp_test_err_malloc_ctr = -1;
  assert(rc == SMTP_STATUS_AUTH);
  smtp_close(config->smtp);

  smtp_test_sleep(15);

  /* PLAIN - @ref smtp_base64_encode failure in (2). */
  test_smtp_open_default(config);
  g_smtp_test_err_calloc_ctr = 0;
  rc = smtp_auth(config->smtp,
                 SMTP_AUTH_PLAIN,
                 config->user,
                 config->pass);
  g_smtp_test_err_calloc_ctr = -1;
  assert(rc == SMTP_STATUS_AUTH);
  smtp_close(config->smtp);

  smtp_test_sleep(15);

  /* PLAIN - Memory allocation failure in (3). */
  test_smtp_open_default(config);
  g_smtp_test_err_malloc_ctr = 1;
  rc = smtp_auth(config->smtp,
                 SMTP_AUTH_PLAIN,
                 config->user,
                 config->pass);
  g_smtp_test_err_malloc_ctr = -1;
  assert(rc == SMTP_STATUS_AUTH);
  smtp_close(config->smtp);

  smtp_test_sleep(15);

  /* PLAIN - @ref smtp_puts failure in (3). */
  test_smtp_open_default(config);
  g_smtp_test_err_send_ctr      = 0;
  g_smtp_test_err_ssl_write_ctr = 0;
  rc = smtp_auth(config->smtp,
                 SMTP_AUTH_PLAIN,
                 config->user,
                 config->pass);
  g_smtp_test_err_send_ctr      = -1;
  g_smtp_test_err_ssl_write_ctr = -1;
  assert(rc == SMTP_STATUS_AUTH);
  smtp_close(config->smtp);

  smtp_test_sleep(15);

  /* LOGIN - @ref smtp_base64_encode failure in (1). */
  test_smtp_open_default(config);
  g_smtp_test_err_calloc_ctr = 0;
  rc = smtp_auth(config->smtp,
                 SMTP_AUTH_LOGIN,
                 config->user,
                 config->pass);
  g_smtp_test_err_calloc_ctr = -1;
  assert(rc == SMTP_STATUS_AUTH);
  smtp_close(config->smtp);

  smtp_test_sleep(15);

  /* LOGIN - Memory allocation failure in (2). */
  test_smtp_open_default(config);
  g_smtp_test_err_malloc_ctr = 0;
  rc = smtp_auth(config->smtp,
                 SMTP_AUTH_LOGIN,
                 config->user,
                 config->pass);
  g_smtp_test_err_malloc_ctr = -1;
  assert(rc == SMTP_STATUS_AUTH);
  smtp_close(config->smtp);

  smtp_test_sleep(15);

  /* LOGIN - @ref smtp_puts send failure in (2). */
  test_smtp_open_default(config);
  g_smtp_test_err_send_ctr      = 0;
  g_smtp_test_err_ssl_write_ctr = 0;
  rc = smtp_auth(config->smtp,
                 SMTP_AUTH_LOGIN,
                 config->user,
                 config->pass);
  g_smtp_test_err_send_ctr      = -1;
  g_smtp_test_err_ssl_write_ctr = -1;
  assert(rc == SMTP_STATUS_AUTH);
  smtp_close(config->smtp);

  smtp_test_sleep(15);

  /* LOGIN - Response read error in (2). */
  test_smtp_open_default(config);
  g_smtp_test_err_recv_ctr     = 0;
  g_smtp_test_err_ssl_read_ctr = 0;
  rc = smtp_auth(config->smtp,
                 SMTP_AUTH_LOGIN,
                 config->user,
                 config->pass);
  g_smtp_test_err_recv_ctr     = -1;
  g_smtp_test_err_ssl_read_ctr = -1;
  assert(rc == SMTP_STATUS_AUTH);
  smtp_close(config->smtp);

  smtp_test_sleep(15);

  /* LOGIN - @ref smtp_base64_encode failure in (3). */
  test_smtp_open_default(config);
  g_smtp_test_err_calloc_ctr = 2;
  rc = smtp_auth(config->smtp,
                 SMTP_AUTH_LOGIN,
                 config->user,
                 config->pass);
  g_smtp_test_err_calloc_ctr = -1;
  assert(rc == SMTP_STATUS_AUTH);
  smtp_close(config->smtp);

  smtp_test_sleep(15);

  /* LOGIN - @ref smtp_puts_terminate failure in (3). */
  test_smtp_open_default(config);
  g_smtp_test_err_send_ctr      = 1;
  g_smtp_test_err_ssl_write_ctr = 1;
  rc = smtp_auth(config->smtp,
                 SMTP_AUTH_LOGIN,
                 config->user,
                 config->pass);
  g_smtp_test_err_send_ctr      = -1;
  g_smtp_test_err_ssl_write_ctr = -1;
  assert(rc == SMTP_STATUS_AUTH);
  smtp_close(config->smtp);

  smtp_test_sleep(15);

  /* LOGIN - @ref smtp_puts_terminate memory allocation failure in (3). */
  test_smtp_open_default(config);
  g_smtp_test_err_malloc_ctr = 3;
  rc = smtp_auth(config->smtp,
                 SMTP_AUTH_LOGIN,
                 config->user,
                 config->pass);
  g_smtp_test_err_malloc_ctr = -1;
  assert(rc == SMTP_STATUS_AUTH);
  smtp_close(config->smtp);

  smtp_test_sleep(15);

  /* LOGIN - Invalid credentials in (3). */
  test_smtp_open_default(config);
  rc = smtp_auth(config->smtp,
                 SMTP_AUTH_LOGIN,
                 "invalid",
                 "invalid");
  assert(rc == SMTP_STATUS_AUTH);
  smtp_close(config->smtp);

  smtp_test_sleep(15);

  /* CRAM-MD5 (1) @ref smtp_puts failure. */
  test_smtp_open_default(config);
  g_smtp_test_err_send_ctr      = 0;
  g_smtp_test_err_ssl_write_ctr = 0;
  rc = smtp_auth(config->smtp,
                 SMTP_AUTH_CRAM_MD5,
                 config->user,
                 config->pass);
  g_smtp_test_err_send_ctr      = -1;
  g_smtp_test_err_ssl_write_ctr = -1;
  assert(rc == SMTP_STATUS_AUTH);
  smtp_close(config->smtp);

  smtp_test_sleep(15);

  /* CRAM-MD5 (1) Response read error. */
  test_smtp_open_default(config);
  g_smtp_test_err_recv_ctr     = 0;
  g_smtp_test_err_ssl_read_ctr = 0;
  rc = smtp_auth(config->smtp,
                 SMTP_AUTH_CRAM_MD5,
                 config->user,
                 config->pass);
  g_smtp_test_err_recv_ctr     = -1;
  g_smtp_test_err_ssl_read_ctr = -1;
  assert(rc == SMTP_STATUS_AUTH);
  smtp_close(config->smtp);

  smtp_test_sleep(15);

  /* CRAM-MD5 (1) Response memory allocation error. */
  test_smtp_open_default(config);
  g_smtp_test_err_calloc_ctr = 0;
  rc = smtp_auth(config->smtp,
                 SMTP_AUTH_CRAM_MD5,
                 config->user,
                 config->pass);
  g_smtp_test_err_calloc_ctr = -1;
  assert(rc == SMTP_STATUS_AUTH);
  smtp_close(config->smtp);

  smtp_test_sleep(15);

  /* CRAM-MD5 (1) Server response bad. */
  test_smtp_open_default(config);
  g_smtp_test_err_recv_ctr     = 0;
  g_smtp_test_err_ssl_read_ctr = 0;
  strcpy(g_smtp_test_err_recv_bytes, "535 authentication failed");
  rc = smtp_auth(config->smtp,
                 SMTP_AUTH_CRAM_MD5,
                 config->user,
                 config->pass);
  g_smtp_test_err_recv_bytes[0] = '\0';
  g_smtp_test_err_recv_ctr     = -1;
  g_smtp_test_err_ssl_read_ctr = -1;
  assert(rc == SMTP_STATUS_AUTH);
  smtp_close(config->smtp);

  smtp_test_sleep(15);

  /* CRAM-MD5 (2) @ref smtp_base64_decode failure. */
  test_smtp_open_default(config);
  g_smtp_test_err_calloc_ctr = 1;
  rc = smtp_auth(config->smtp,
                 SMTP_AUTH_CRAM_MD5,
                 config->user,
                 config->pass);
  g_smtp_test_err_calloc_ctr = -1;
  assert(rc == SMTP_STATUS_AUTH);
  smtp_close(config->smtp);

  smtp_test_sleep(15);

  /* CRAM-MD5 (3) @ref HMAC failure. */
  test_smtp_open_default(config);
  g_smtp_test_err_hmac_ctr = 0;
  rc = smtp_auth(config->smtp,
                 SMTP_AUTH_CRAM_MD5,
                 config->user,
                 config->pass);
  g_smtp_test_err_hmac_ctr = -1;
  assert(rc == SMTP_STATUS_AUTH);
  smtp_close(config->smtp);

  smtp_test_sleep(15);

  /* CRAM-MD5 (4) @ref smtp_bin2hex failure. */
  test_smtp_open_default(config);
  g_smtp_test_err_malloc_ctr = 2;
  rc = smtp_auth(config->smtp,
                 SMTP_AUTH_CRAM_MD5,
                 config->user,
                 config->pass);
  g_smtp_test_err_malloc_ctr = -1;
  assert(rc == SMTP_STATUS_AUTH);
  smtp_close(config->smtp);

  smtp_test_sleep(15);

  /* CRAM-MD5 (5) Memory allocation failure. */
  test_smtp_open_default(config);
  g_smtp_test_err_malloc_ctr = 3;
  rc = smtp_auth(config->smtp,
                 SMTP_AUTH_CRAM_MD5,
                 config->user,
                 config->pass);
  g_smtp_test_err_malloc_ctr = -1;
  assert(rc == SMTP_STATUS_AUTH);
  smtp_close(config->smtp);

  smtp_test_sleep(15);

  /* CRAM-MD5 (6) @ref smtp_base64_encode failure. */
  test_smtp_open_default(config);
  g_smtp_test_err_calloc_ctr = 2;
  rc = smtp_auth(config->smtp,
                 SMTP_AUTH_CRAM_MD5,
                 config->user,
                 config->pass);
  g_smtp_test_err_calloc_ctr = -1;
  assert(rc == SMTP_STATUS_AUTH);
  smtp_close(config->smtp);

  smtp_test_sleep(15);

  /* CRAM-MD5 (7) @ref smtp_puts_terminate failure. */
  test_smtp_open_default(config);
  g_smtp_test_err_send_ctr      = 1;
  g_smtp_test_err_ssl_write_ctr = 1;
  rc = smtp_auth(config->smtp,
                 SMTP_AUTH_CRAM_MD5,
                 config->user,
                 config->pass);
  g_smtp_test_err_send_ctr      = -1;
  g_smtp_test_err_ssl_write_ctr = -1;
  assert(rc == SMTP_STATUS_AUTH);
  smtp_close(config->smtp);

  smtp_test_sleep(15);

  /* CRAM-MD5 (7) Invalid credentials. */
  test_smtp_open_default(config);
  rc = smtp_auth(config->smtp,
                 SMTP_AUTH_CRAM_MD5,
                 "invalid",
                 "invalid");
  assert(rc == SMTP_STATUS_AUTH);
  smtp_close(config->smtp);

  smtp_test_sleep(15);
}

/**
 * Simulate a timeout when reading server response.
 *
 * @param[in] config SMTP server context.
 */
static void
test_failure_timeout(struct smtp_test_config *const config){
  int rc;

  rc = smtp_open(config->server,
                 config->port,
                 SMTP_TEST_DEFAULT_CONNECTION_SECURITY,
                 SMTP_TEST_DEFAULT_FLAGS,
                 SMTP_TEST_DEFAULT_CAFILE,
                 &config->smtp);
  assert(rc == SMTP_STATUS_OK);

  rc = smtp_address_add(config->smtp,
                        SMTP_ADDRESS_FROM,
                        config->email_from,
                        NULL);
  assert(rc == SMTP_STATUS_OK);

  g_smtp_test_err_select_ctr = 0;
  rc = smtp_mail(config->smtp, "body");
  g_smtp_test_err_select_ctr = -1;
  assert(rc == SMTP_STATUS_RECV);

  rc = smtp_close(config->smtp);
  assert(rc == SMTP_STATUS_RECV);
}

/**
 * Test multiple failure modes when using the high-level interfaces.
 *
 * @param[in] config SMTP server context.
 */
static void
test_all_failure_modes(struct smtp_test_config *const config){
  test_failure_misc(config);
  test_failure_open(config);
  test_failure_auth(config);
  test_failure_address_add(config);
  test_failure_attachment_add(config);
  test_failure_header_add(config);
  test_failure_status_code_set(config);
  test_failure_mail(config);
  test_failure_close(config);
  test_failure_timeout(config);
}

/**
 * Run the functional tests on local postfix server.
 *
 * This configuration handles most of the functional testing and includes:
 *   - Failure modes.
 *   - Different combinations of connection and authentication methods.
 *   - Multiple attachments.
 *   - Multiple recipients
 */
static void
smtp_func_test_postfix(void){
  struct smtp_test_config config;
  int rc;

  rc = smtp_test_config_load_from_file("test/config/postfix.txt", &config);
  assert(rc == 0);

  test_all_failure_modes(&config);

  smtp_test_sleep(60);

  smtp_func_test_all_status_code_get(&config);
  smtp_func_test_all_connection_security(&config);
  smtp_func_test_all_cafile(&config);
  smtp_func_test_all_auth_methods(&config);
  smtp_func_test_all_attachments(&config);
  smtp_func_test_all_address(&config);
  smtp_func_test_all_headers(&config);
  smtp_func_test_all_nodebug(&config);
}

/**
 * Run the functional tests on the test SMTP gmail account.
 *
 * This only sends one email using a test gmail account. Most of the tests
 * have been designed to work with a local postfix server instance.
 */
static void
smtp_func_test_gmail(void){
  struct smtp_test_config config;
  int rc;

  rc = smtp_test_config_load_from_file("test/config/gmail.txt", &config);
  assert(rc == 0);

  fprintf(stderr, "SMTP TEST: sending test email using gmail account");
  smtp_func_test_send_email(&config,
                            config.port,
                            SMTP_SECURITY_STARTTLS,
                            SMTP_DEBUG,
                            SMTP_AUTH_PLAIN,
                            SMTP_TEST_DEFAULT_CAFILE,
                            "SMTP Test: gmail",
                            "test email sent through gmail server");
}

/**
 * Run through all functional/integration tests for each test SMTP server.
 */
static void
smtp_func_test_all(void){
  smtp_func_test_gmail();
  smtp_func_test_postfix();
}

/**
 * Configuration flags for the smtp testing framework.
 */
enum smtp_test_flags{
  /**
   * Only run the unit tests, skipping all functional testing.
   */
  SMTP_TEST_UNIT_TESTING_ONLY = 1 << 0
};

/**
 * Program configuration parameters.
 */
struct smtp_test{
  /**
   * See @ref smtp_test_flags.
   */
  enum smtp_test_flags flags;
};

/**
 * Main testing program entry point for testing the smtp-client library.
 *
 * This program supports the following options:
 *   - u - Only run unit tests, skipping the functional testing.
 *
 * @param[in] argc Number of arguments in @p argv.
 * @param[in] argv String array containing the program name and any optional
 *                 parameters described above.
 * @retval 0 All tests passed.
 * @retval 1 Error.
 */
int main(int argc, char *argv[]){
  struct smtp_test smtp_test;
  int c;

  memset(&smtp_test, 0, sizeof(smtp_test));

  while((c = getopt(argc, argv, "u")) != -1){
    switch(c){
      case 'u':
        smtp_test.flags |= SMTP_TEST_UNIT_TESTING_ONLY;
        break;
      default:
        return 1;
    }
  }
  argc -= optind;
  argv += optind;

  smtp_unit_test_all();

  if(!(smtp_test.flags & SMTP_TEST_UNIT_TESTING_ONLY)){
    smtp_func_test_all();
  }

  return 0;
}

