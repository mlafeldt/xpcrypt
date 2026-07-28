CC = gcc
CFLAGS = -Wall -Werror -O2
LIBS =
prefix = $(HOME)

PROG = xpcrypt
OBJS += xp_crypto.o
OBJS += xpcrypt.o

all: $(PROG)

install: $(PROG)
	install -s $(PROG) $(prefix)/bin

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

$(OBJS): xp_crypto.h

clean:
	$(RM) $(PROG) $(OBJS)
