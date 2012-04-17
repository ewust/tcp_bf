CFLAGS+=-I../forge_socket/ -I/usr/local/include -L/usr/local/lib/
LDFLAGS+=-levent -levent_core -levent_extra

server: server.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)
