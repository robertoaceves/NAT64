# Make libxt_nat64.so
IDIR =../include
CFLAGS = -O2 -Wall -I$(IDIR)

default:libxt_nat64.so

lib%.so: lib%.o
	gcc -shared -o $@ $^;
lib%.o: lib%.c
	gcc ${CFLAGS} -fPIC -D_INIT=lib$*_init -c -o $@ $<;

install:
	sudo cp libxt_nat64.so /lib/xtables/.

clean:
	rm -f libxt_nat64.so
