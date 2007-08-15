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
OBJS=utils.o ntlm.o xcrypt.o config.o socket.o acl.o proxy.o
CFLAGS=$(FLAGS) -Wall -pedantic -O3 -D_POSIX_C_SOURCE=199506L -D_ISOC99_SOURCE -D_REENTRANT -DVERSION=\"`cat VERSION`\"
LDFLAGS=-lpthread
NAME=cntlm
VER=`cat VERSION`
DIR=`pwd`

$(NAME): endian $(OBJS)
	@echo "Linking $@"
	@$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

endian: endian.c
	@printf "Checking arch: "
	@$(CC) $(CFLAGS) -o $@ endian.c
	@if [ x`./endian NTLM_BIG_ENDIAN` != x ]; then echo "big endian"; else echo "little endian"; fi

proxy.o: proxy.c
	@echo "Compiling $<"
	@if [ -z "$(SYSCONFDIR)" ]; then \
		$(CC) $(CFLAGS) `./endian NTLM_BIG_ENDIAN` -c proxy.c -o $@; \
	else \
		$(CC) $(CFLAGS) `./endian NTLM_BIG_ENDIAN` -DSYSCONFDIR=\"$(SYSCONFDIR)\" -c proxy.c -o $@; \
	fi

.c.o:
	@echo "Compiling $<"
	@$(CC) $(CFLAGS) `./endian NTLM_BIG_ENDIAN` -c -o $@ $<

install: $(NAME)
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

rpm:
	if [ `id -u` = 0 ]; then \
		redhat/rules binary; \
		redhat/rules clean; \
	else \
		fakeroot redhat/rules binary; \
		fakeroot redhat/rules clean; \
	fi

deb:
	@echo
	@echo "This option is no longer available. Get the source"
	@echo "from ftp://awk.cz/cntlm/debian/ and follow the README." 
	@echo

tgz:
	mkdir -p tmp
	rm -f tmp/$(NAME)-$(VER)
	ln -s $(DIR) tmp/$(NAME)-$(VER)
	sed "s/^\./$(NAME)-$(VER)/" doc/files.txt | tar zchf $(NAME)-$(VER).tar.gz --no-recursion -C tmp -T -
	rm tmp/$(NAME)-$(VER)
	rmdir tmp 2>/dev/null || true

uninstall:
	rm -f $(BINDIR)/$(NAME) $(MANDIR)/man1/$(NAME).1 2>/dev/null || true

clean:
	@rm -f *.o tags cntlm endian pid massif* callgrind* 2>/dev/null

cleanp:
	@rm -f *.deb *.tgz *.tar.gz *.rpm *.o tags cntlm pid massif* callgrind* 2>/dev/null

distclean: clean
	if [ `id -u` = 0 ]; then \
		debian/rules clean; \
		redhat/rules clean; \
	else \
		fakeroot debian/rules clean; \
		fakeroot redhat/rules clean; \
	fi

