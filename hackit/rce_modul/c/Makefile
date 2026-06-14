CC = gcc
CFLAGS = -Wall -O2 -std=c11
TARGET = bin/rce_engine

all: $(TARGET)

$(TARGET): main.c
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $(TARGET) main.c

clean:
	rm -f $(TARGET)

rebuild: clean all
