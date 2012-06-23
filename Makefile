CFLAGS+=-I../forge_socket/ -I/usr/local/include -L/usr/local/lib/
LDFLAGS+=-levent -levent_core -levent_extra


all: syn_spew

server: server.c tcp_spoof.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

syn_spew: syn_spew.c tcp_spoof.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)
