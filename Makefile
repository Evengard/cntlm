#
# You can tweak these three variables to make things install where you
# like, but do not touch more unless you know what you are doing. ;)
#
SYSCONFDIR=/usr/local/etc
BINDIR=/usr/local/bin
MANDIR=/usr/local/man

#
# Careful now...
#
CC=gcc
OBJS=utils.o ntlm.o xcrypt.o config.o socket.o acl.o auth.o http.o proxy.o 
CFLAGS=$(FLAGS) -std=c99 -Wall -pedantic -O3 -D__BSD_VISIBLE -D_XOPEN_SOURCE=600 -D_POSIX_C_SOURCE=200112 -D_ISOC99_SOURCE -D_REENTRANT -DVERSION=\"`cat VERSION`\"
LDFLAGS=-lpthread
NAME=cntlm
VER=`cat VERSION`
DIR=`pwd`

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
		install -O root -G system -M 755 -S -f $(BINDIR) $(NAME); \
		install -O root -G system -M 644 -f $(MANDIR)/man1 doc/$(NAME).1; \
		install -O root -G system -M 600 -c $(SYSCONFDIR) doc/$(NAME).conf; \
	else \
		install -D -o root -g root -m 755 -s $(NAME) $(BINDIR)/$(NAME); \
		install -D -o root -g root -m 644 doc/$(NAME).1 $(MANDIR)/man1/$(NAME).1; \
		[ -f $(SYSCONFDIR)/$(NAME).conf -o -z "$(SYSCONFDIR)" ] \
			|| install -D -o root -g root -m 600 doc/$(NAME).conf $(SYSCONFDIR)/$(NAME).conf; \
	fi
	@echo; echo "Cntlm will look for configuration in $(SYSCONFDIR)/$(NAME).conf"

rpm:
	if [ `id -u` = 0 ]; then \
		redhat/rules binary; \
		redhat/rules clean; \
	else \
		fakeroot redhat/rules binary; \
		fakeroot redhat/rules clean; \
	fi

tgz:
	mkdir -p tmp
	rm -f tmp/$(NAME)-$(VER)
	ln -s $(DIR) tmp/$(NAME)-$(VER)
	sed "s/^\./$(NAME)-$(VER)/" doc/files.txt | tar zchf $(NAME)-$(VER).tar.gz --no-recursion -C tmp -T -
	rm tmp/$(NAME)-$(VER)
	rmdir tmp 2>/dev/null || true

win:
	groff -t -e -mandoc -Tps doc/cntlm.1 | ps2pdf - win32/cntlm_manual.pdf
	cat doc/cntlm.conf | unix2dos > win32/cntlm.ini
	cp /bin/cygwin1.dll /bin/cygrunsrv.exe win32/
	strip cntlm.exe
	cp cntlm.exe win32/
	rm -f cntlm-install
	ln -s win32 cntlm-install
	zip -r cntlm-$(VER)-win32.zip cntlm-install -x *.svn/*
	rm -f cntlm-install cntlm-$(VER)-win32.zip.sig

uninstall:
	rm -f $(BINDIR)/$(NAME) $(MANDIR)/man1/$(NAME).1 2>/dev/null || true

clean:
	@rm -f *.o cntlm cntlm.exe configure-stamp build-stamp config/config.h 2>/dev/null
	@rm -f cntlm-install win32/cyg* win32/cntlm* 2>/dev/null
	@rm -f config/endian config/gethostname config/strdup config/*.exe

cleanp: clean
	@rm -f *.deb *.tgz *.tar.gz *.rpm *.o tags cntlm pid massif* callgrind* 2>/dev/null

distclean: clean
	if [ `id -u` = 0 ]; then \
		redhat/rules clean; \
	else \
		fakeroot redhat/rules clean; \
	fi

