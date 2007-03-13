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

CC_MIPS_PATH =	/usr/src/openWrt/build/buildroot-ng/openwrt/staging_dir_mipsel/bin
CC_MIPS =		$(CC_MIPS_PATH)/mipsel-linux-uclibc-gcc
STRIP_MIPS =	$(CC_MIPS_PATH)/sstrip
CFLAGS_MIPS =	-Wall -O0 -g3
LDFLAGS_MIPS =	-lpthread

CC =			gcc
#CC =			mipsel-linux-uclibc-gcc
CFLAGS =		-Wall -O0 -g3
LDFLAGS =		-lpthread
#LDFLAGS =		-static -lpthread

UNAME=$(shell uname)

ifeq ($(UNAME),Linux)
OS_OBJ=	originator.o schedule.o posix-specific.o posix.o linux.o allocate.o bitarray.o hash.o
endif

LINUX_SRC_C= batman-adv.c originator.c schedule.c posix-specific.c posix.c linux.c allocate.c bitarray.c hash.c
LINUX_SRC_H= batman-adv.h originator.h schedule.h list.h os.h allocate.h hash.h

all:	batmand-adv

mips:	batmand-mips-static batmand-mips-dynamic

batmand-adv:	batman-adv.o $(OS_OBJ) Makefile batman-adv.h
	$(CC) -o $@ batman-adv.o $(OS_OBJ) $(LDFLAGS)

batmand-mips-static:	$(LINUX_SRC_C) $(LINUX_SRC_H) Makefile
	$(CC_MIPS) $(CFLAGS_MIPS) -o $@ $(LINUX_SRC_C) $(LDFLAGS_MIPS) -static
	$(STRIP_MIPS) $@

batmand-mips-dynamic:	$(LINUX_SRC_C) $(LINUX_SRC_H) Makefile
	$(CC_MIPS) $(CFLAGS_MIPS) -o $@ $(LINUX_SRC_C) $(LDFLAGS_MIPS)
	$(STRIP_MIPS) $@


clean:
		rm -f batmand-adv batmand-mips* *.o *~
