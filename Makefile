##
## @file
## @brief SMTP Developer Makefile.
## @author James Humphrey (mail@somnisoft.com)
## @version 0.99
##
## This Makefile used internally to build and test the SMTP client library.
## Do not use this Makefile for building the library into your application.
## Instead, include the src/smtp.h and src/smtp.c directly into your project
## and add those files as part of your own build system.
##
## This software has been placed into the public domain using CC0.
##
.PHONY: all clean doc install release test test_unit
.SUFFIXES:

BDIR = build
INSTALL_PREFIX = /usr/local

SILENT = @

CWARN += -Waggregate-return
CWARN += -Wno-aggressive-loop-optimizations
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
CWARN += -Wjump-misses-init
CWARN += -Wlarger-than=10000
CWARN += -Wlogical-op
CWARN += -Wlong-long
CWARN += -Wmissing-declarations
CWARN += -Wmissing-include-dirs
CWARN += -Wmissing-prototypes
CWARN += -Wnested-externs
CWARN += -Wnormalized=nfkc
CWARN += -Wold-style-definition
CWARN += -Wpacked
CWARN += -Wpedantic
CWARN += -pedantic-errors
CWARN += -Wredundant-decls
CWARN += -Wshadow
CWARN += -Wstack-protector
CWARN += -Wstack-usage=5000
CWARN += -Wstrict-aliasing
CWARN += -Wstrict-prototypes
CWARN += -Wswitch-default
CWARN += -Wswitch-enum
CWARN += -Wsync-nand
CWARN += -Wtrampolines
CWARN += -Wundef
CWARN += -Wuninitialized
CWARN += -Wunknown-pragmas
CWARN += -Wunsafe-loop-optimizations
CWARN += -Wunsuffixed-float-constants
CWARN += -Wunused-parameter
CWARN += -Wvector-operation-performance
CWARN += -Wvla
CWARN += -Wwrite-strings

CFLAGS += $(CWARN)
CFLAGS += -fstack-protector-all
CFLAGS += -fstrict-overflow
CFLAGS += -std=c89
CFLAGS += -MD
CFLAGS += -DSMTP_OPENSSL

CFLAGS.debug   += -g3
CFLAGS.debug   += -DSMTP_TEST
CFLAGS.debug   += -Wno-missing-prototypes
CFLAGS.debug   += -fprofile-arcs -ftest-coverage

CFLAGS.release += -O3

CPPFLAGS += -DSMTP_OPENSSL
CPPFLAGS += -MD
CPPFLAGS += -fpermissive

CPPFLAGS.release = $(CPPFLAGS)

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

CC  = gcc
CPP = g++

AR.c.debug          = $(SILENT) $(AR) -c -r $@ $^
AR.c.release        = $(SILENT) $(AR) -c -r $@ $^
COMPILE.c.debug     = $(SILENT) $(CC) $(CFLAGS) $(CFLAGS.debug) -c -o $@ $<
COMPILE.c.release   = $(SILENT) $(CC) $(CFLAGS) $(CFLAGS.release) -c -o $@ $<
COMPILE.cpp.release = $(SILENT) $(CPP) $(CPPFLAGS.release) -c -o $@ $<
LINK.c.debug        = $(SILENT) $(CC) $(CFLAGS) $(CFLAGS.debug) -o $@ $^
LINK.c.release      = $(SILENT) $(CC) $(CFLAGS) $(CFLAGS.release) -o $@ $^
LINK.cpp.release    = $(SILENT) $(CPP) $(CPPFLAGS.release) -o $@ $^
INKSCAPE            = $(SILENT) inkscape
MOGRIFY             = $(SILENT) mogrify
MKDIR               = $(SILENT) mkdir -p $@
CP                  = $(SILENT) cp $< $@

all: $(BDIR)/debug/libsmtp.a          \
     $(BDIR)/release/libsmtp_nossl.a  \
     $(BDIR)/release/libsmtp.a        \
     $(BDIR)/debug/mailx              \
     $(BDIR)/release/mailx            \
     $(BDIR)/release/test_cpp_wrapper \
     $(BDIR)/doc/html/index.html      \
     $(BDIR)/debug/test               \
     $(BDIR)/release/test_nossl       \
     $(BDIR)/www/images/logo.png

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

install: all
	cp src/smtp.h $(INSTALL_PREFIX)/include/smtp.h
	cp $(BDIR)/release/libsmtp.a $(INSTALL_PREFIX)/lib/libsmtp.a

test: all
	$(VALGRIND_MEMCHECK) $(BDIR)/debug/test
	$(VALGRIND_MEMCHECK) $(BDIR)/release/test_nossl

test_unit: all
	$(VALGRIND_MEMCHECK) $(BDIR)/debug/test -u

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

$(BDIR)/release/mailx: $(BDIR)/release/mailx.o   \
                       $(BDIR)/release/libsmtp.a
	$(LINK.c.release) -lssl -lcrypto

$(BDIR)/debug/mailx.o: src/mailx.c | $(BDIR)/debug
	$(COMPILE.c.debug) -Isrc

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
	$(COMPILE.c.debug)

$(BDIR)/release/smtp_nossl.o: src/smtp.c | $(BDIR)/release
	$(COMPILE.c.release) -USMTP_OPENSSL

$(BDIR)/release/smtp.o: src/smtp.c | $(BDIR)/release
	$(COMPILE.c.release)

$(BDIR)/debug/test: $(BDIR)/debug/seams.o \
                    $(BDIR)/debug/smtp.o  \
                    $(BDIR)/debug/test.o
	$(LINK.c.debug) -lssl -lcrypto -lgcov

$(BDIR)/debug/test.o: test/test.c | $(BDIR)/debug
	$(COMPILE.c.debug) -Isrc/

$(BDIR)/debug/seams.o: test/seams.c | $(BDIR)/debug
	$(COMPILE.c.debug)

$(BDIR)/release/test_nossl: $(BDIR)/release/smtp_nossl.o \
                            $(BDIR)/release/test_nossl.o
	$(LINK.c.release)

$(BDIR)/release/test_nossl.o: test/test_nossl.c | $(BDIR)/release
	$(COMPILE.c.release) -Isrc/ -USMTP_OPENSSL

$(BDIR)/www/images/logo.png: www/images/logo.svg | $(BDIR)/www/images
	$(INKSCAPE) -e $@ -w 71 -h 62 $< > /dev/null
	$(MOGRIFY) -strip $@

$(BDIR)/www/images:
	$(MKDIR)

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

