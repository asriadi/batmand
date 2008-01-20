#
# Copyright (C) 2006-2008 BATMAN contributors
#
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
#


CC =		gcc
CFLAGS =	-Wall -O1 -g3 -DDEBUG_MALLOC -DMEMORY_USAGE -DPROFILE_DATA -DREVISION_VERSION=$(REVISION_VERSION)
STRIP=		strip
LDFLAGS =	-lpthread
SBINDIR =	$(INSTALL_PREFIX)/usr/sbin

UNAME=		$(shell uname)
POSIX_C=	posix/init.c posix/posix.c posix/tunnel.c posix/unix_socket.c
BSD_C=		bsd/route.c bsd/tun.c bsd/kernel.c bsd/compat.c

ifeq ($(UNAME),Linux)
OS_C=		linux/route.c linux/tun.c linux/kernel.c $(POSIX_C)
endif

ifeq ($(UNAME),Darwin)
OS_C=		$(BSD_C) $(POSIX_C)
endif

ifeq ($(UNAME),FreeBSD)
OS_C=		$(BSD_C) $(POSIX_C)
endif

ifeq ($(UNAME),OpenBSD)
OS_C=		$(BSD_C) $(POSIX_C)
endif

LOG_BRANCH=	trunk/batman

SRC_FILES=	"\(\.c\)\|\(\.h\)\|\(Makefile\)\|\(INSTALL\)\|\(LIESMICH\)\|\(README\)\|\(THANKS\)\|\(TRASH\)\|\(Doxyfile\)\|\(./posix\)\|\(./linux\)\|\(./bsd\)\|\(./man\)\|\(./doc\)"

SRC_C=		batman.c originator.c schedule.c list-batman.c allocate.c bitarray.c hash.c profile.c ring_buffer.c $(OS_C)
SRC_H=		batman.h originator.h schedule.h list-batman.h os.h allocate.h bitarray.h hash.h profile.h vis-types.h ring_buffer.h
SRC_O=		$(SRC_C:.c=.o)

PACKAGE_NAME=	batmand
BINARY_NAME=	batmand
SOURCE_VERSION_HEADER= batman.h

REVISION:=	$(shell if [ -d .svn ]; then svn info | grep "Rev:" | sed -e '1p' -n | awk '{print $$4}'; else if [ -d ~/.svk ]; then echo $$(svk info | grep "Mirrored From" | awk '{print $$5}'); fi; fi)
REVISION_VERSION=	\"\ rv$(REVISION)\"

BAT_VERSION=	$(shell grep "^\#define SOURCE_VERSION " $(SOURCE_VERSION_HEADER) | sed -e '1p' -n | awk -F '"' '{print $$2}' | awk '{print $$1}')
FILE_NAME=	$(PACKAGE_NAME)_$(BAT_VERSION)-rv$(REVISION)_$@


all:		$(BINARY_NAME)

$(BINARY_NAME):	$(SRC_O) $(SRC_H) Makefile
	$(CC) -o $@ $(SRC_O) $(LDFLAGS)

sources:
	mkdir -p $(FILE_NAME)

	for i in $$( find . | grep $(SRC_FILES) | grep -v "\.svn" ); do [ -d $$i ] && mkdir -p $(FILE_NAME)/$$i ; [ -f $$i ] && cp -Lvp $$i $(FILE_NAME)/$$i ;done

	wget --no-check-certificate -O changelog.html  https://dev.open-mesh.net/batman/log/$(LOG_BRANCH)/
	html2text -o changelog.txt -nobs -ascii changelog.html
	awk '/View revision/,/10\/01\/06 20:23:03/' changelog.txt > $(FILE_NAME)/CHANGELOG

	for i in $$( find man |	grep -v "\.svn" ); do [ -f $$i ] && groff -man -Thtml $$i > $(FILE_NAME)/$$i.html ;done

	tar czvf $(FILE_NAME).tgz $(FILE_NAME)

clean:
	rm -f $(BINARY_NAME) *.o posix/*.o linux/*.o bsd/*.o


clean-long:
	rm -rf $(PACKAGE_NAME)_*

install:
	mkdir -p $(SBINDIR)
	install -m 0755 batmand $(SBINDIR)
