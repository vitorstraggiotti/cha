
CC = gcc
CC_RELEASE_FLAGS = -Wall -pedantic -c -O2
CC_DEBUG_FLAGS = -Wall -pedantic -c -g

PROG_NAME = cha

.PHONY: clean cleanall all

all:
	@echo "Build options:"
	@echo "  make $(PROG_NAME)       --> Build release version"
	@echo "  make $(PROG_NAME)_debug --> Build debug version"
	@echo "  make clean     --> Delete generated object files"
	@echo "  make cleanall  --> Same as 'clean' + compiled program"

# Linking release version
$(PROG_NAME): ./obj/main.o\
				./obj/chacha20.o\
				./obj/sha256.o\
				./obj/prog_bar.o\
				./obj/progargs.o
	$(CC) -o $(PROG_NAME) $^

# Linking debug version
$(PROG_NAME)_debug: ./obj/main_d.o\
				./obj/chacha20_d.o\
				./obj/sha256_d.o\
				./obj/prog_bar_d.o\
				./obj/progargs_d.o
	$(CC) -o $@ $^

# Creating objects for release version
./obj/main.o: ./src/main.c
	$(CC) $(CC_RELEASE_FLAGS) -o $@ $^

./obj/chacha20.o: ./src/chacha20.c
	$(CC) $(CC_RELEASE_FLAGS) -o $@ $^

./obj/sha256.o: ./src/sha256.c
	$(CC) $(CC_RELEASE_FLAGS) -o $@ $^

./obj/prog_bar.o: ./src/prog_bar.c
	$(CC) $(CC_RELEASE_FLAGS) -o $@ $^

./obj/progargs.o: ./src/progargs.c
	$(CC) $(CC_RELEASE_FLAGS) -o $@ $^

# Creating objects for debug version
./obj/main_d.o: ./src/main.c
	$(CC) $(CC_DEBUG_FLAGS) -o $@ $^

./obj/chacha20_d.o: ./src/chacha20.c
	$(CC) $(CC_DEBUG_FLAGS) -o $@ $^

./obj/sha256_d.o: ./src/sha256.c
	$(CC) $(CC_DEBUG_FLAGS) -o $@ $^

./obj/prog_bar_d.o: ./src/prog_bar.c
	$(CC) $(CC_DEBUG_FLAGS) -o $@ $^

./obj/progargs_d.o: ./src/progargs.c
	$(CC) $(CC_DEBUG_FLAGS) -o $@ $^

cleanall: clean
	rm $(PROG_NAME) $(PROG_NAME)_debug

clean:
	rm ./obj/*.o
