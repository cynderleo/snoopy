### Include common Makefile configuration
#
include   $(top_srcdir)/build/Makefile.am.common
AUTOMAKE_OPTIONS = foreign subdir-objects
ACLOCAL_AMFLAGS = -I build/m4


### Subdir processing order
#
SUBDIRS  =
SUBDIRS += datasource
if FILTERING_ENABLED
SUBDIRS += filter
endif
SUBDIRS += output
SUBDIRS += .


### Create main library, but without execve() wrappers
#
noinst_LTLIBRARIES = \
	libsnoopy_no_execve.la

libsnoopy_no_execve_la_SOURCES = \
	configuration.c \
	configuration.h \
	error.c \
	error.h \
	genericregistry.c \
	genericregistry.h \
	inputdatastorage.c \
	inputdatastorage.h \
	datasourceregistry.c \
	datasourceregistry.h \
	log.c \
	log.h \
	message.c \
	message.h \
	misc.c \
	misc.h \
	outputregistry.c \
	outputregistry.h \
	parser.c \
	parser.h \
	snoopy.h \
	memset_s.c \
	secureutil.h \
	securectype.h \
	securec.h \
	strcpy_s.c  \
	strncpy_s.c \
	strcat_s.c \
	sprintf_s.c \
	vsprintf_s.c \
	securecutil.c \
	secureprintoutput.h \
	input.inl \
	secureprintoutput_a.c \
	secureprintoutput_w.c \
	output.inl \
	snprintf_s.c \
	vsnprintf_s.c

libsnoopy_no_execve_la_CFLAGS =
if REDHAT_VERSION
libsnoopy_no_execve_la_CFLAGS += $(AM_CFLAGS) -fno-strict-aliasing
endif

if SUSE_VERSION
libsnoopy_no_execve_la_CFLAGS += $(AM_CFLAGS)
endif

libsnoopy_no_execve_la_LDFLAGS = $(AM_LDFLAGS)

libsnoopy_no_execve_la_LIBADD = \
	datasource/libsnoopy_datasources_all.la \
	output/libsnoopy_outputs_all.la

# If config file is enabled, build and link these too
if CONFIGFILE_ENABLED
libsnoopy_no_execve_la_SOURCES += \
	configfile.c \
	configfile.h
libsnoopy_no_execve_la_LIBADD += \
	../lib/iniparser/src/libiniparser.la
endif

# If config file is enabled, build and link these too
if THREAD_SAFETY_ENABLED
libsnoopy_no_execve_la_CFLAGS  += -I$(top_srcdir)/lib/liblcthw/src
libsnoopy_no_execve_la_LDFLAGS += -lpthread
libsnoopy_no_execve_la_SOURCES += \
	../lib/liblcthw/src/dbg.h \
	../lib/liblcthw/src/list.c \
	../lib/liblcthw/src/list.h \
	tsrm.c \
	tsrm.h
endif

# If filtering is enabled, add these too
if FILTERING_ENABLED
libsnoopy_no_execve_la_SOURCES += \
	filtering.c \
	filtering.h \
	filterregistry.c \
	filterregistry.h
libsnoopy_no_execve_la_LIBADD += \
	filter/libsnoopy_filters_all.la
endif



### Create main library, whole
#
# Exclude -pedantic from CFLAGS because casing object pointer received from
# dlsym to function pointer is not allowed by ISO C.
#
lib_LTLIBRARIES      = libsnoopy.la
libsnoopy_la_SOURCES = libsnoopy.c libsnoopy.h
libsnoopy_la_CFLAGS  = `echo $(AM_CFLAGS) | sed -e 's/-pedantic//'`
libsnoopy_la_LIBADD  = libsnoopy_no_execve.la



### Create debugging helper library
#
noinst_LTLIBRARIES                += libsnoopy-debug-addons.la
libsnoopy_debug_addons_la_SOURCES  = libsnoopy-debug-addons.c \
                                     libsnoopy-debug-addons.h
libsnoopy_debug_addons_la_LIBADD   = libsnoopy_no_execve.la


install-exec-local:
	gcc -o logreceive logreceive.c memset_s.c strcpy_s.c strncpy_s.c;
	if [ `pgrep "S99logreceive"`x != ""x ]; then \
		kill `pgrep "S99logreceive"`; \
	fi
	cp logreceive /etc/init.d/logreceive;
	chmod +x /etc/init.d/logreceive;	
