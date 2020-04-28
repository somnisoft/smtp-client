##
## @file
## @brief SMTP Developer Makefile.
## @author James Humphrey (mail@somnisoft.com)
## @version 1.00
##
## This Makefile used internally to build and test the SMTP client library.
## Do not use this Makefile for building the library into your application.
## Instead, include the src/smtp.h and src/smtp.c directly into your project
## and add those files as part of your own build system.
##
## This software has been placed into the public domain using CC0.
##
.PHONY: all clean doc gcov install release test test_unit
.SUFFIXES:

BDIR = build
INSTALL_PREFIX = /usr/local

GCC_VERSION_MAJOR = $(shell gcc -dumpversion | sed 's/\..*//g' | tr -d '\n')

CWARN += -Waggregate-return
CWARN += -Wall
CWARN += -Wbad-function-cast
CWARN += -Wcast-align
CWARN += -Wcast-qual
CWARN += -Wdeclaration-after-statement
CWARN += -Wdisabled-optimization
CWARN += -Wdouble-promotion
CWARN += -Werror
CWARN += -Wextra
CWARN += -Wfatal-errors
CWARN += -Wfloat-equal
CWARN += -Wformat=2
CWARN += -Wframe-larger-than=5000
CWARN += -Winit-self
CWARN += -Winline
CWARN += -Winvalid-pch
CWARN += -Wlarger-than=10000
CWARN += -Wlong-long
CWARN += -Wmissing-declarations
CWARN += -Wmissing-include-dirs
CWARN += -Wmissing-prototypes
CWARN += -Wnested-externs
CWARN += -Wnull-dereference
CWARN += -Wold-style-definition
CWARN += -Wpacked
CWARN += -Wpedantic
CWARN += -pedantic-errors
CWARN += -Wredundant-decls
CWARN += -Wshadow
CWARN += -Wstack-protector
CWARN += -Wstrict-aliasing
CWARN += -Wstrict-overflow=5
CWARN += -Wstrict-prototypes
CWARN += -Wswitch-default
CWARN += -Wswitch-enum
CWARN += -Wundef
CWARN += -Wuninitialized
CWARN += -Wunknown-pragmas
CWARN += -Wunused-parameter
CWARN += -Wvla
CWARN += -Wwrite-strings

ifeq ($(shell test $(GCC_VERSION_MAJOR) -ge 7 ; echo $$?), 0)
  CWARN.gcc += -Wduplicated-branches
  CWARN.gcc += -Wrestrict
  CWARN.gcc += -Wstringop-overflow=4
endif

CWARN.gcc += -Wno-aggressive-loop-optimizations
CWARN.gcc += -Wduplicated-cond
CWARN.gcc += -Wjump-misses-init
CWARN.gcc += -Wlogical-op
CWARN.gcc += -Wnormalized=nfkc
CWARN.gcc += -Wstack-usage=5000
CWARN.gcc += -Wshift-overflow=2
CWARN.gcc += -Wsync-nand
CWARN.gcc += -Wtrampolines
##CWARN.gcc += -Wunsafe-loop-optimizations
CWARN.gcc += -Wunsuffixed-float-constants
CWARN.gcc += -Wvector-operation-performance

CWARN.clang += -Weverything
CWARN.clang += -Wno-format-nonliteral
CWARN.clang += -Wno-documentation-deprecated-sync
CWARN.clang += -fcomment-block-commands=retval

CFLAGS += $(CWARN)
CFLAGS += -fstack-protector-all
CFLAGS += -fstrict-overflow
CFLAGS += -std=c89
CFLAGS += -MD
CFLAGS += -DSMTP_OPENSSL

CFLAGS.debug   += $(CFLAGS)
CFLAGS.debug   += -g3
CFLAGS.debug   += -DSMTP_TEST
CFLAGS.debug   += -Wno-missing-prototypes
CFLAGS.debug   += -fprofile-arcs -ftest-coverage
CFLAGS.debug += -ftrapv

CFLAGS.clang   += -fsanitize=undefined

CFLAGS.release += $(CFLAGS)
CFLAGS.release += -O3

CPPFLAGS += -DSMTP_OPENSSL
CPPFLAGS += -MD
CPPFLAGS += -fpermissive

CPPFLAGS.release = $(CPPFLAGS)

CFLAGS.gcc.debug     += $(CFLAGS.debug) $(CWARN.gcc)
CFLAGS.gcc.release   += $(CFLAGS.release) $(CWARN.gcc)
CFLAGS.clang.debug   += $(CFLAGS.debug) $(CFLAGS.clang) $(CWARN.clang)

CDEF_POSIX = -D_POSIX_C_SOURCE=200112

SCAN_BUILD = $(SILENT) scan-build -maxloop 100          \
                                  -o $(BDIR)/scan-build \
                                  --status-bugs         \
             clang -c -o $(BDIR)/debug/scan-build-smtp.o src/smtp.c

VFLAGS += -q
VFLAGS += --error-exitcode=1
VFLAGS += --gen-suppressions=yes
VFLAGS += --num-callers=40

VFLAGS_MEMCHECK += --tool=memcheck
VFLAGS_MEMCHECK += --expensive-definedness-checks=yes
VFLAGS_MEMCHECK += --track-origins=yes
VFLAGS_MEMCHECK += --leak-check=full
VFLAGS_MEMCHECK += --leak-resolution=high
VFLAGS_MEMCHECK += --suppressions=test/valgrind-suppressions.txt
VALGRIND_MEMCHECK = $(SILENT) valgrind $(VFLAGS) $(VFLAGS_MEMCHECK)

GCOV = gcov -b $(BDIR)/debug/smtp.o

CC  = gcc
CPP = g++

CC.clang = clang

AR.c.debug          = $(SILENT) $(AR) -c -r $@ $^
AR.c.release        = $(SILENT) $(AR) -c -r $@ $^
COMPILE.c.debug     = $(SILENT) $(CC) $(CFLAGS.gcc.debug) -c -o $@ $<
COMPILE.c.release   = $(SILENT) $(CC) $(CFLAGS.gcc.release) -c -o $@ $<
COMPILE.c.clang     = $(SILENT) $(CC.clang) $(CFLAGS.clang.debug) -c -o $@ $<
COMPILE.cpp.release = $(SILENT) $(CPP) $(CPPFLAGS.release) -c -o $@ $<
LINK.c.debug        = $(SILENT) $(CC) $(CFLAGS.gcc.debug) -o $@ $^
LINK.c.release      = $(SILENT) $(CC) $(CFLAGS.gcc.release) -o $@ $^
LINK.c.clang        = $(SILENT) $(CC.clang) $(CFLAGS.clang.debug) -o $@ $^
LINK.cpp.release    = $(SILENT) $(CPP) $(CPPFLAGS.release) -o $@ $^
MKDIR               = $(SILENT) mkdir -p $@
CP                  = $(SILENT) cp $< $@

all: $(BDIR)/debug/libsmtp.a          \
     $(BDIR)/release/libsmtp_nossl.a  \
     $(BDIR)/release/libsmtp.a        \
     $(BDIR)/debug/mailx              \
     $(BDIR)/release/mailx_nossl      \
     $(BDIR)/release/mailx            \
     $(BDIR)/release/test_cpp_wrapper \
     $(BDIR)/doc/html/index.html      \
     $(BDIR)/debug/test               \
     $(BDIR)/debug/clang_test         \
     $(BDIR)/release/example_simple   \
     $(BDIR)/release/example_html     \
     $(BDIR)/release/test_nossl

clean:
	$(SILENT) rm -rf $(BDIR)

doc $(BDIR)/doc/html/index.html: src/mailx.c               \
                                 src/SMTPMail.h            \
                                 src/SMTPMail.cpp          \
                                 src/smtp.h                \
                                 src/smtp.c                \
                                 test/seams.h              \
                                 test/seams.c              \
                                 test/test.h               \
                                 test/test.c               \
                                 test/test_cpp_wrapper.cpp \
                                 test/test_nossl.c         \
                                 doc.cfg | $(BDIR)/doc
	$(SILENT) doxygen doc.cfg

gcov:
	$(GCOV)

install: all
	cp src/smtp.h $(INSTALL_PREFIX)/include/smtp.h
	cp $(BDIR)/release/libsmtp.a $(INSTALL_PREFIX)/lib/libsmtp.a

test: all       \
      test_unit
	$(SCAN_BUILD)
	$(VALGRIND_MEMCHECK) $(BDIR)/debug/test
	##$(VALGRIND_MEMCHECK) $(BDIR)/debug/clang_test
	$(VALGRIND_MEMCHECK) $(BDIR)/release/test_nossl
	$(BDIR)/release/test_cpp_wrapper
	$(GCOV)

test_unit: all
	$(VALGRIND_MEMCHECK) $(BDIR)/debug/test -u
	$(VALGRIND_MEMCHECK) $(BDIR)/debug/clang_test -u

-include $(shell find $(BDIR)/ -name "*.d" 2> /dev/null)

$(BDIR)/doc:
	$(MKDIR)

$(BDIR)/release:
	$(MKDIR)

$(BDIR)/debug:
	$(MKDIR)

$(BDIR):
	$(MKDIR)

$(BDIR)/debug/libsmtp.a: $(BDIR)/debug/smtp.o
	$(AR.c.debug)

$(BDIR)/release/libsmtp_nossl.a: $(BDIR)/release/smtp_nossl.o
	$(AR.c.release)

$(BDIR)/release/libsmtp.a : $(BDIR)/release/smtp.o
	$(AR.c.release)

$(BDIR)/debug/mailx: $(BDIR)/debug/seams.o   \
                     $(BDIR)/debug/mailx.o   \
                     $(BDIR)/debug/libsmtp.a
	$(LINK.c.debug) -lssl -lcrypto

$(BDIR)/release/mailx_nossl: $(BDIR)/release/mailx_nossl.o \
                             $(BDIR)/release/libsmtp_nossl.a
	$(LINK.c.release)

$(BDIR)/release/mailx: $(BDIR)/release/mailx.o   \
                       $(BDIR)/release/libsmtp.a
	$(LINK.c.release) -lssl -lcrypto

$(BDIR)/debug/mailx.o: src/mailx.c | $(BDIR)/debug
	$(COMPILE.c.debug) -Isrc

$(BDIR)/release/mailx_nossl.o: src/mailx.c | $(BDIR)/release
	$(COMPILE.c.release) -Isrc -USMTP_OPENSSL

$(BDIR)/release/mailx.o: src/mailx.c | $(BDIR)/release
	$(COMPILE.c.release) -Isrc

$(BDIR)/release/test_cpp_wrapper: $(BDIR)/release/SMTPMail.o         \
                                  $(BDIR)/release/test_cpp_wrapper.o \
                                  $(BDIR)/release/libsmtp.a
	$(LINK.cpp.release) -lssl -lcrypto

$(BDIR)/release/SMTPMail.o: src/SMTPMail.cpp | $(BDIR)/release
	$(COMPILE.cpp.release) -Isrc

$(BDIR)/release/test_cpp_wrapper.o: test/test_cpp_wrapper.cpp | $(BDIR)/release
	$(COMPILE.cpp.release) -Isrc

$(BDIR)/debug/smtp.o: src/smtp.c | $(BDIR)/debug
	$(COMPILE.c.debug) $(CDEF_POSIX)

$(BDIR)/release/smtp_nossl.o: src/smtp.c | $(BDIR)/release
	$(COMPILE.c.release) $(CDEF_POSIX) -USMTP_OPENSSL

$(BDIR)/release/smtp.o: src/smtp.c | $(BDIR)/release
	$(COMPILE.c.release) $(CDEF_POSIX)

$(BDIR)/debug/test: $(BDIR)/debug/seams.o \
                    $(BDIR)/debug/smtp.o  \
                    $(BDIR)/debug/test.o
	$(LINK.c.debug) -lssl -lcrypto -lgcov

$(BDIR)/debug/test.o: test/test.c | $(BDIR)/debug
	$(COMPILE.c.debug) $(CDEF_POSIX) -Isrc/

$(BDIR)/debug/seams.o: test/seams.c | $(BDIR)/debug
	$(COMPILE.c.debug) $(CDEF_POSIX)

$(BDIR)/debug/clang_test: $(BDIR)/debug/clang_seams.o \
                          $(BDIR)/debug/clang_smtp.o  \
                          $(BDIR)/debug/clang_test.o
	$(LINK.c.clang) -lssl -lcrypto -lgcov -lubsan

$(BDIR)/debug/clang_seams.o: test/seams.c | $(BDIR)/debug
	$(COMPILE.c.clang) $(CDEF_POSIX)

$(BDIR)/debug/clang_smtp.o: src/smtp.c | $(BDIR)/debug
	$(COMPILE.c.clang) $(CDEF_POSIX)

$(BDIR)/debug/clang_test.o: test/test.c | $(BDIR)/debug
	$(COMPILE.c.clang) $(CDEF_POSIX) -Isrc/

$(BDIR)/release/example_simple: $(BDIR)/release/example_simple.o \
                                $(BDIR)/release/smtp.o
	$(LINK.c.release) -lssl -lcrypto
$(BDIR)/release/example_simple.o: test/example_simple.c | $(BDIR)/release
	$(COMPILE.c.release) -Isrc

$(BDIR)/release/example_html: $(BDIR)/release/example_html.o \
                              $(BDIR)/release/smtp.o
	$(LINK.c.release) -lssl -lcrypto
$(BDIR)/release/example_html.o: test/example_html.c | $(BDIR)/release
	$(COMPILE.c.release) -Isrc

$(BDIR)/release/test_nossl: $(BDIR)/release/smtp_nossl.o \
                            $(BDIR)/release/test_nossl.o
	$(LINK.c.release)

$(BDIR)/release/test_nossl.o: test/test_nossl.c | $(BDIR)/release
	$(COMPILE.c.release) -Isrc/ -USMTP_OPENSSL

release: $(BDIR)/smtp-client.tar.gz \
         $(BDIR)/smtp-client.zip
$(BDIR)/smtp-client.tar.gz: $(BDIR)/smtp-client/smtp.c \
                            $(BDIR)/smtp-client/smtp.h
	$(SILENT) tar -C $(BDIR) -c -z -v -f $@ smtp-client
$(BDIR)/smtp-client.zip: $(BDIR)/smtp-client/smtp.c \
                         $(BDIR)/smtp-client/smtp.h
	$(SILENT) cd $(BDIR) && zip -r -T -v smtp-client.zip smtp-client

$(BDIR)/smtp-client/smtp.c: src/smtp.c | $(BDIR)/smtp-client
	$(CP)

$(BDIR)/smtp-client/smtp.h: src/smtp.h | $(BDIR)/smtp-client
	$(CP)

$(BDIR)/smtp-client:
	$(MKDIR)

