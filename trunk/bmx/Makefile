# Copyright (C) 2010 BMX contributors:
# This program is free software; you can redistribute it and/or
# modify it under the terms of version 2 of the GNU General Public
# License as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA

REVISION_VERSION =	0$(shell if [ -d .svn ]; then which svn > /dev/null && which sed > /dev/null && which awk > /dev/null && { svn info | grep "Rev:" | sed -e '1p' -n | awk '{print $$4}';} fi )


##CFLAGS ?= -I./lua-5.1.4/src -I./cyassl-1.4.0/include -O0 -ggdb3
##LDFLAGS ?= -L./lua-5.1.4/src -L./cyassl-1.4.0/src/.libs

#CFLAGS ?= -I$(shell pwd)/cyassl-1.4.0/ctaocrypt/include -DHAVE_CONFIG_H
#LDFLAGS ?= -L./cyassl-1.4.0/src/.libs


CFLAGS +=	 -pedantic -Wall -W -Wno-unused-parameter -Os -g3 -std=gnu99 -I./  \
                        -DHAVE_CONFIG_H -DREVISION_VERSION=$(REVISION_VERSION) -DDEBUG_MALLOC -DMEMORY_USAGE

LDFLAGS +=	-Wl,-export-dynamic -ldl -g3 -lm

#-lcyassl
#LDFLAGS +=	-shared -lssl -lcrypto
# -static
# -pg


#CFLAGS += -DTESTDEBUG
#CFLAGS += -DAVL_DEBUG -DAVL_TEST
#CFLAGS += -DPROFILING -DEXTREME_PARANOIA -D

#EXTRA_CFLAGS +=
#EXTRA_LDFLAGS +=

# Recommended defines and approximate binary sizes with gcc-x86
# -static
# -pedantic -Wall -W -Wno-unused-parameter -O1 -g3 -std=gnu99
# -pg  # "-pg" with openWrt toolchain results in "gcrt1.o: No such file" ?!
#

# compared to -O1 stripped:
# -Os								- ~29k

# -DDEBUG_MALLOC  						+ ~0k
# -DMEMORY_USAGE 						+ ~1k

# optional defines (you may disable these features if you dont need it):
# -DNOTRAILER							- ~3K
# -DNODEBUGALL							- ~13k
# -DLESS_OPTIONS                                                - ~8K
#
# -DNOTUNNEL  		(only affects this node)		- ~23k
# -DNOSRV  		(only affects this node)		- ~3k
# -DNOVIS  		(only affects this node)		- ~2k

# -DNODEPRECATED	(for backward compatibility)		- ~2k

# experimental or advanced defines (please dont touch):
# -DNOHNA		(affects all nodes in network)		- ~6k
# -DNO_PARANOIA		(makes bug-hunting impossible)		- ~2k
# -DEXTREME_PARANOIA
# -DEXTDEBUG		(this eats your cpu)			+ ~0k
# -DTESTDEBUG		(testing syntax of __VA_ARGS__ dbg...() macros)
# -DWITHUNUSED		(includes yet unused stuff)
# -DPROFILING           (no static functions)


SBINDIR =       $(INSTALL_PREFIX)/usr/sbin

LOG_BRANCH= trunk/bmx2

SRC_FILES= "\(\.c\)\|\(\.h\)\|\(Makefile\)\|\(INSTALL\)\|\(LIESMICH\)\|\(README\)\|\(THANKS\)\|\(./posix\)\|\(./linux\)\|\(./man\)\|\(./doc\)"

SRC_C=  bmx.c msg.c plugin.c list.c allocate.c avl.c iid.c hna.c control.c schedule.c route.c cyassl/sha.c
SRC_H=  bmx.h msg.h plugin.h list.h allocate.h avl.h iid.h hna.h control.h schedule.h route.h cyassl/sha.h
OBJS=  $(SRC_C:.c=.o)

#
#


PACKAGE_NAME=	bmxd
BINARY_NAME=	bmxd



SOURCE_VERSION_HEADER= bmx.h


BAT_VERSION=    $(shell grep "^\#define SOURCE_VERSION " $(SOURCE_VERSION_HEADER) | sed -e '1p' -n | awk -F '"' '{print $$2}' | awk '{print $$1}')
FILE_NAME=      $(PACKAGE_NAME)_$(BAT_VERSION)-rv$(REVISION_VERSION)_$@

NOW=		$(shell date +%Y%m%d%H%M)-$(REVISION_VERSION)

IPKG_DEPENDS=	"kmod-tun"

SNAPSHOT_DIR=	../bmx-snapshots


all:	
	$(MAKE) $(BINARY_NAME)
	# further make targets: help, libs, build_all, strip[_libs|_all], install[_libs|_all], clean[_libs|_all]

libs:	all
	$(MAKE)  -C lib all CORE_CFLAGS='$(CFLAGS)'



$(BINARY_NAME):	$(OBJS) Makefile
	$(CC)  $(OBJS) -o $@  $(LDFLAGS) $(EXTRA_LDFLAGS)

%.o:	%.c %.h Makefile $(SRC_H)
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -c $< -o $@

%.o:	%.c Makefile $(SRC_H)
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -c $< -o $@


strip:	all
	strip $(BINARY_NAME) 

strip_libs: all libs
	$(MAKE) -C lib strip




install:	all
	mkdir -p $(SBINDIR)
	install -m 0755 $(BINARY_NAME) $(SBINDIR)

install_libs:   all
	$(MAKE) -C lib install CORE_CFLAGS='$(CFLAGS)'


	
clean:
	rm -f $(BINARY_NAME) *.o posix/*.o linux/*.o cyassl/*.o

clean_libs:
	$(MAKE) -C lib clean


clean_all: clean clean_libs
build_all: all libs
strip_all: strip strip_libs
install_all: install install_libs


help:
	# further make targets:
	# help					show this help
	# all					compile  bmxd core only
	# libs			 		compile  bmx plugins
	# build_all				compile  bmxd and plugins
	# strip / strip_libs / strip_all	strip    bmxd / plugins / all
	# install / install_libs / install_all	install  bmxd / plugins / all
	# clean / clean_libs / clean_all	clean    bmxd / libs / all

