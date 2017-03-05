TARGET = chat_room
SRCS   = chat_room.c

CC = gcc
FLAGS  = -Wall -Werror
LIBS   =

.PHONY: default
default: $(TARGET)

.PHONY: all
all: default

.PHONY: debug
debug: DEBUG = -g
debug: all

.PHONY: clean
clean:
	$(RM) $(TARGET)

$(TARGET) : $(SRCS)
	$(CC) $(FLAGS) $(DEBUG) $(SRCS) $(LIBS) -o $(TARGET)
