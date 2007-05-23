SYSCONFDIR=/etc
PREFIX=/usr/local
NAME=cntlm

CC=gcc
OBJS=utils.o ntlm.o xcrypt.o config.o socket.o proxy.o
CFLAGS+=-Wall -pedantic -g -O3 -D_REENTRANT -DVERSION=\"0.23\" -DSYSCONFDIR=\"$(SYSCONFDIR)\"
LDFLAGS=-lpthread -g

$(NAME): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

install: $(NAME)
	install -D -o root -g root -m 755 -s $(NAME) $(PREFIX)/bin
	install -D -o root -g root -m 644 doc/$(NAME).1 $(PREFIX)/share/man/man1
	install -D -o root -g root -m 600 doc/$(NAME).conf $(SYSCONFDIR)

uninstall: $(NAME)
	rm -f $(PREFIX)/bin/$(NAME) $(PREFIX)/share/man/man1/$(NAME).1 2>/dev/null || true

clean:
	rm -f *.o tags cntlm pid massif* callgrind* 2>/dev/null

%.o: %.c
	$(CC) $(CFLAGS) -c $^ -o $@
