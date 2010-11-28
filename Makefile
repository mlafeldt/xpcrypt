CC = gcc
CFLAGS = -Wall -Werror -O2 -s
LIBS =
prefix = $(HOME)

PROG = xpcrypt
OBJS += xp_crypto.o
OBJS += xpcrypt.o

all: $(PROG)

install: $(PROG)
	install $(PROG) $(prefix)/bin

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $? $(LIBS)

$(OBJS): xp_crypto.h

clean:
	$(RM) $(PROG) $(OBJS)
