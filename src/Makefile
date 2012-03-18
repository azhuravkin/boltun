CC = gcc -Wall -O0 -g -ggdb
TARGET = boltun
OBJECTS = main.o tunnel.o options.o
LIBS = -lcrypt

all: $(TARGET)

$(TARGET): Makefile $(OBJECTS)
	$(CC) -o $(TARGET) $(OBJECTS) $(LIBS)

main.o: Makefile main.c boltun.h
	$(CC) -D'PROG_NAME="$(TARGET)"' -o main.o -c main.c

tunnel.o: Makefile tunnel.c boltun.h
	$(CC) -D'PROG_NAME="$(TARGET)"' -o tunnel.o -c tunnel.c

options.o: Makefile options.c boltun.h
	$(CC) -D'PROG_NAME="$(TARGET)"' -o options.o -c options.c

install: $(TARGET)
	install -s $(TARGET) /usr/sbin/$(TARGET)

clean:
	rm -f $(OBJECTS) $(TARGET)
