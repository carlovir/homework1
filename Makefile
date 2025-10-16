CC = gcc
CFLAGS = -Wall -Wextra -pedantic -std=c11
TARGET = procman

.PHONY: all clean

all: $(TARGET)

$(TARGET): procman.c procman.h
	$(CC) $(CFLAGS) -o $(TARGET) procman.c

clean:
	rm -f $(TARGET)
