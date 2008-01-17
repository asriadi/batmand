#
# Copyright (C) 2006 BATMAN contributors
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


CC =			gcc
CFLAGS =		-Wall -W -O1 -g  -DDEBUG_MALLOC -DREVISION_VERSION=$(REVISION_VERSION)
STRIP=			strip
LDFLAGS =		-lpthread -g

UNAME=		$(shell uname)

LOG_BRANCH= trunk/batman-adv-userspace

SRC_FILES= "\(\.c\)\|\(\.h\)\|\(Makefile\)\|\(INSTALL\)\|\(LIESMICH\)\|\(README\)\|\(THANKS\)\|\(TRASH\)\|\(Doxyfile\)\|\(./posix\)\|\(./linux\)\|\(./bsd\)\|\(./man\)\|\(./doc\)"

SRC_C= batman-adv.c originator.c schedule.c list-batman.c posix-specific.c posix.c linux.c allocate.c bitarray.c hash.c trans_table.c ring_buffer.c $(OS_C)
SRC_H= batman-adv.h originator.h schedule.h list-batman.h os.h allocate.h bitarray.h hash.h packet.h trans_table.h dlist.h vis-types.h ring_buffer.h
SRC_O= $(SRC_C:.c=.o)

PACKAGE_NAME=	batmand-adv-userspace

BINARY_NAME=	batmand-adv
SOURCE_VERSION_HEADER= batman-adv.h

REVISION=		$(shell if [ -d .svn ]; then svn info | grep "Rev:" | sed -e '1p' -n | awk '{print $$4}'; else if [ -d ~/.svk ]; then echo $$(svk info | grep "Mirrored From" | awk '{print $$5}'); fi; fi)
REVISION_VERSION=	\"\ rv$(REVISION)\"

BAT_VERSION=		$(shell grep "^\#define SOURCE_VERSION " $(SOURCE_VERSION_HEADER) | sed -e '1p' -n | awk -F '"' '{print $$2}' | awk '{print $$1}')
FILE_NAME=		$(PACKAGE_NAME)_$(BAT_VERSION)-rv$(REVISION)_$@

.SUFFIXES: .c.o

all:		$(BINARY_NAME)

$(BINARY_NAME):	$(SRC_O) $(SRC_H) Makefile
	$(CC) -o $@ $(SRC_O) $(LDFLAGS)


sources:
	mkdir -p $(FILE_NAME)

	for i in $$( find . | grep $(SRC_FILES) | grep -v "\.svn" ); do [ -d $$i ] && mkdir -p $(FILE_NAME)/$$i ; [ -f $$i ] && cp -Lvp $$i $(FILE_NAME)/$$i ;done

	$(BUILD_PATH)/wget --no-check-certificate -O changelog.html  https://dev.open-mesh.net/batman/log/$(LOG_BRANCH)/
	html2text -o changelog.txt -nobs -ascii changelog.html
	awk '/View revision/,/10\/01\/06 20:23:03/' changelog.txt > $(FILE_NAME)/CHANGELOG

	for i in $$( find man |	grep -v "\.svn" ); do [ -f $$i ] && groff -man -Thtml $$i > $(FILE_NAME)/$$i.html ;done

	tar czvf $(FILE_NAME).tgz $(FILE_NAME)

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(BINARY_NAME) *.o


clean-long:
	rm -rf $(PACKAGE_NAME)_*

