TARGET = chat_room
SRCS   = chat_room.c

FLAGS  = -Wall -Werror
LIBS   = -lpthread

all: $(TARGET)

$(TARGET) : $(SRCS)
	$(CC) $(FLAGS) $(SRCS) $(LIBS) -o $(TARGET)

clean:
	$(RM) $(TARGET)
