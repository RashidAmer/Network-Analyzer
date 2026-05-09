CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -std=gnu11 -D_DEFAULT_SOURCE
LDFLAGS = -lpcap

TARGET  = sniffer
SRC     = sniffer.c

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(SRC) sniffer.h
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LDFLAGS)

test: sniffer.h
	$(CC) $(CFLAGS) -o test_sniffer ../../../tests/unit/test_sniffer.c $(SRC) $(LDFLAGS)
	./test_sniffer

clean:
	rm -f $(TARGET) test_sniffer *.o
