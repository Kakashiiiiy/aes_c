CC 	= clang

TARGET 	= aes

SRC 	= aes.c \
	  aes_use.c \

FLAGS 	= -Wall -Wextra -pedantic -O2 -march=native 

all:
	$(CC) -o $(TARGET) $(SRC) $(FLAGS)

clean:
	rm $(TARGET)
