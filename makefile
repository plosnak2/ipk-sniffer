CC=g++
CFLAGS=-cpp -Wall -D_GNU_SOURCE
LDFLAGS=-lpcap

.PHONY: all ipk-sniffer.cpp ipk-sniffer

all: ipk-sniffer.cpp ipk-sniffer

ipk-sniffer: ipk-sniffer.o 
	$(CC) $^ -o $@ $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) -I. $< -o $@

 