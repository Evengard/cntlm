#
# You can tweak these three variables to make things install where you
# like, but do not touch more unless you know what you are doing. ;)
#
DESTDIR=
SYSCONFDIR=$(DESTDIR)/etc
BINDIR=$(DESTDIR)/usr/sbin
MANDIR=$(DESTDIR)/usr/share/man

#
# Careful now...
# __BSD_VISIBLE is for FreeBSD AF_* constants
# _ALL_SOURCE is for AIX 5.3 LOG_PERROR constant
#
NAME=cntlm
CC=gcc
VER=`cat VERSION`
OBJS=utils.o ntlm.o xcrypt.o config.o socket.o acl.o auth.o http.o proxy.o forward.o direct.o scanner.o pages.o
CFLAGS=$(FLAGS) -std=c99 -Wall -pedantic -O3 -D__BSD_VISIBLE -D_ALL_SOURCE -D_XOPEN_SOURCE=600 -D_POSIX_C_SOURCE=200112 -D_ISOC99_SOURCE -D_REENTRANT -DVERSION=\"`cat VERSION`\"
OS=$(shell uname -s)
OSLDFLAGS=$(shell [ $(OS) = "SunOS" ] && echo "-lrt -lsocket -lnsl")
LDFLAGS:=-lpthread $(OSLDFLAGS)

$(NAME): configure-stamp $(OBJS)
	@echo "Linking $@"
	@$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

proxy.o: proxy.c
	@echo "Compiling $<"
	@if [ -z "$(SYSCONFDIR)" ]; then \
		$(CC) $(CFLAGS) -c proxy.c -o $@; \
	else \
		$(CC) $(CFLAGS) -DSYSCONFDIR=\"$(SYSCONFDIR)\" -c proxy.c -o $@; \
	fi

.c.o:
	@echo "Compiling $<"
	@$(CC) $(CFLAGS) -c -o $@ $<

install: $(NAME)
	# AIX?
	if [ -f /usr/bin/oslevel ]; then \
		install -M 755 -S -f $(BINDIR) $(NAME); \
		install -M 644 -f $(MANDIR)/man1 doc/$(NAME).1; \
		install -M 600 -c $(SYSCONFDIR) doc/$(NAME).conf; \
	else \
		install -D -m 755 -s $(NAME) $(BINDIR)/$(NAME); \
		install -D -m 644 doc/$(NAME).1 $(MANDIR)/man1/$(NAME).1; \
		[ -f $(SYSCONFDIR)/$(NAME).conf -o -z "$(SYSCONFDIR)" ] \
			|| install -D -m 600 doc/$(NAME).conf $(SYSCONFDIR)/$(NAME).conf; \
	fi
	@echo; echo "Cntlm will look for configuration in $(SYSCONFDIR)/$(NAME).conf"

deb:
	sed -i "s/^\(cntlm *\)([^)]*)/\1($(VER))/g" debian/changelog
	if [ `id -u` = 0 ]; then \
		debian/rules binary; \
		debian/rules clean; \
	else \
		fakeroot debian/rules binary; \
		fakeroot debian/rules clean; \
	fi
	mv ../cntlm_$(VER)*.deb .

rpm:
	sed -i "s/^\(Version:[\t ]*\)\(.*\)/\1$(VER)/g" redhat/cntlm.spec
	if [ `id -u` = 0 ]; then \
		redhat/rules binary; \
		redhat/rules clean; \
	else \
		fakeroot redhat/rules binary; \
		fakeroot redhat/rules clean; \
	fi

tgz:
	mkdir -p tmp
	rm -rf tmp/$(NAME)-$(VER)
	svn export . tmp/$(NAME)-$(VER)
	tar zcvf $(NAME)-$(VER).tar.gz -C tmp/ $(NAME)-$(VER)
	rm -rf tmp/$(NAME)-$(VER)
	rmdir tmp 2>/dev/null || true

tbz2:
	mkdir -p tmp
	rm -rf tmp/$(NAME)-$(VER)
	svn export . tmp/$(NAME)-$(VER)
	tar jcvf $(NAME)-$(VER).tar.bz2 -C tmp/ $(NAME)-$(VER)
	rm -rf tmp/$(NAME)-$(VER)
	rmdir tmp 2>/dev/null || true

win:
	groff -t -e -mandoc -Tps doc/cntlm.1 | ps2pdf - win32/cntlm_manual.pdf
	cat doc/cntlm.conf | unix2dos > win32/cntlm.ini
	cat COPYRIGHT LICENSE | unix2dos > win32/license.txt
	sed "s/\$$VERSION/$(VER)/g" win32/setup.iss.in > win32/setup.iss
	cp /bin/cygwin1.dll /bin/cygrunsrv.exe win32/
	cp cntlm.exe win32/
	strip win32/cntlm.exe
	@echo
	@echo Now go to win32/ and run InnoSetup setup.iss
	@echo It will generate a complete installer setup.exe

uninstall:
	rm -f $(BINDIR)/$(NAME) $(MANDIR)/man1/$(NAME).1 2>/dev/null || true

clean:
	rm -f *.o cntlm cntlm.exe configure-stamp build-stamp config/config.h 2>/dev/null
	rm -f win32/*.exe win32/*.dll win32/*.iss win32/*.pdf win32/cntlm.ini win32/license.txt 2>/dev/null
	rm -f config/endian config/gethostname config/strdup config/socklen_t config/*.exe
	if [ -h Makefile ]; then rm -f Makefile; mv Makefile.gcc Makefile; fi

distclean: clean
	if [ `id -u` = 0 ]; then \
		debian/rules clean; \
		redhat/rules clean; \
	else \
		fakeroot debian/rules clean; \
		fakeroot redhat/rules clean; \
	fi
	rm -f *.deb *.rpm *.tgz *.tar.gz *.tar.bz2 tags ctags pid 2>/dev/null
