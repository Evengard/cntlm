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
OBJS=utils.o ntlm.o xcrypt.o config.o socket.o acl.o auth.o http.o forward.o direct.o scanner.o pages.o main.o
CFLAGS=$(FLAGS) -std=c99 -Wall -pedantic -O3 -D__BSD_VISIBLE -D_ALL_SOURCE -D_XOPEN_SOURCE=600 -D_POSIX_C_SOURCE=200112 -D_ISOC99_SOURCE -D_REENTRANT -DVERSION=\"`cat VERSION`\" -g
OS=$(shell uname -s)
OSLDFLAGS=$(shell [ $(OS) = "SunOS" ] && echo "-lrt -lsocket -lnsl")
LDFLAGS:=-lpthread $(OSLDFLAGS)

$(NAME): configure-stamp $(OBJS)
	@echo "Linking $@"
	@$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

main.o: main.c
	@echo "Compiling $<"
	@if [ -z "$(SYSCONFDIR)" ]; then \
		$(CC) $(CFLAGS) -c main.c -o $@; \
	else \
		$(CC) $(CFLAGS) -DSYSCONFDIR=\"$(SYSCONFDIR)\" -c main.c -o $@; \
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

deb: builddeb
builddeb:
	sed -i "s/^\(cntlm *\)([^)]*)/\1($(VER))/g" debian/changelog
	if [ `id -u` = 0 ]; then \
		debian/rules binary; \
		debian/rules clean; \
	else \
		fakeroot debian/rules binary; \
		fakeroot debian/rules clean; \
	fi
	mv ../cntlm_$(VER)*.deb .

rpm: buildrpm
buildrpm:
	sed -i "s/^\(Version:[\t ]*\)\(.*\)/\1$(VER)/g" rpm/cntlm.spec
	if [ `id -u` = 0 ]; then \
		rpm/rules binary; \
		rpm/rules clean; \
	else \
		fakeroot rpm/rules binary; \
		fakeroot rpm/rules clean; \
	fi

win: buildwin
buildwin:
	@echo
	@echo "* This build target must be run from a Cywgin shell on Windows *"
	@echo "* and you also need InnoSetup installed                        *"
	@echo
	groff -t -e -mandoc -Tps doc/cntlm.1 | ps2pdf - win/cntlm_manual.pdf
	cat doc/cntlm.conf | unix2dos > win/cntlm.ini
	cat COPYRIGHT LICENSE | unix2dos > win/license.txt
	sed "s/\$$VERSION/$(VER)/g" win/setup.iss.in > win/setup.iss
	cp /bin/cygwin1.dll /bin/cygrunsrv.exe win/
	cp cntlm.exe win/
	strip win/cntlm.exe
	@echo
	@echo Now open folder "win", right-click "setup.iss", then "Compile".
	@echo InnoSetup will generate a new installer cntlm-X.XX-setup.exe
	@echo

uninstall:
	rm -f $(BINDIR)/$(NAME) $(MANDIR)/man1/$(NAME).1 2>/dev/null || true

clean:
	@rm -f *.o cntlm cntlm.exe configure-stamp build-stamp config/config.h 2>/dev/null
	@rm -f win/*.exe win/*.dll win/*.iss win/*.pdf win/cntlm.ini win/license.txt 2>/dev/null
	@rm -f config/endian config/gethostname config/strdup config/socklen_t config/*.exe
	@if [ -h Makefile ]; then rm -f Makefile; mv Makefile.gcc Makefile; fi

distclean: clean
	if [ `id -u` = 0 ]; then \
		debian/rules clean; \
		rpm/rules clean; \
	else \
		fakeroot debian/rules clean; \
		fakeroot rpm/rules clean; \
	fi
	@rm -f *.deb *.rpm *.tgz *.tar.gz *.tar.bz2 tags ctags pid 2>/dev/null
