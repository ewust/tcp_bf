CFLAGS+=-I/usr/local/include -I../ -L/usr/local/lib/
LDFLAGS+=-levent -levent_core -levent_extra


all: conn_spoof dos parse-pcap 

conn_spoof: conn_spoof.c ../tcp_spoof.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

dos: dos.c ../tcp_spoof.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

parse-pcap: parse-pcap.c
	$(CC) $(CFLAGS) $^ -o $@ -lpcap

