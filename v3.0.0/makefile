
CC = gcc
CC_FLAGS = -Wall -pedantic -c -O2

OUTPUT_NAME = cha20crypt

all: ./obj/main.o\
		./obj/chacha20.o\
		./obj/sha256.o\
		./obj/prog_bar.o
	$(CC) -o $(OUTPUT_NAME) $^

# Creating objects
./obj/main.o: ./src/main.c
	$(CC) $(CC_FLAGS) -o $@ $^

./obj/chacha20.o: ./src/chacha20.c
	$(CC) $(CC_FLAGS) -o $@ $^

./obj/sha256.o: ./src/sha256.c
	$(CC) $(CC_FLAGS) -o $@ $^

./obj/prog_bar.o: ./src/prog_bar.c
	$(CC) $(CC_FLAGS) -o $@ $^

.PHONY: clean
clean:
	rm $(OUTPUT_NAME) ./obj/*.o
