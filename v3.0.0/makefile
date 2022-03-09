
CC = gcc
CC_FLAGS = -Wall -pedantic -c -O2

PROG_NAME = cha

.PHONY: clean

all: ./obj/main.o\
		./obj/chacha20.o\
		./obj/sha256.o\
		./obj/prog_bar.o\
		./obj/progargs.o
	$(CC) -o $(PROG_NAME) $^

# Creating objects
./obj/main.o: ./src/main.c
	$(CC) $(CC_FLAGS) -o $@ $^

./obj/chacha20.o: ./src/chacha20.c
	$(CC) $(CC_FLAGS) -o $@ $^

./obj/sha256.o: ./src/sha256.c
	$(CC) $(CC_FLAGS) -o $@ $^

./obj/prog_bar.o: ./src/prog_bar.c
	$(CC) $(CC_FLAGS) -o $@ $^

./obj/progargs.o: ./src/progargs.c
	$(CC) $(CC_FLAGS) -o $@ $^

clean:
	rm $(PROG_NAME) ./obj/*.o
