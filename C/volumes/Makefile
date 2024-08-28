CC = gcc
CFLAGS = -Wall -Wextra
TARGET = syn_flood

# Default target
all: $(TARGET)

# Compile the program
%: %.c
	$(CC) $(CFLAGS) -o $@ $<

# Clean up build files
clean:
	rm -f $(TARGET)

# Phony targets to avoid conflict with files of the same name
.PHONY: all clean
