
CC = gcc
CC_FLAGS = -Wall -pedantic -c -O2
GUI_FLAGS = -Wall -pedantic -O2 -Wno-deprecated-declarations -Wno-format-security `pkg-config --cflags --libs gtk+-3.0` -export-dynamic

OUTPUT_NAME = crypt
OUTPUT_NAME_GUI = cryptGUI

all: 
	@echo "Build options for make:"
	@echo "  make $(OUTPUT_NAME)	--> Build CLI version"
	@echo "  make $(OUTPUT_NAME_GUI)	--> Build GUI version"
	@echo "  make clean	--> remove executable and compilation files"

$(OUTPUT_NAME): ./obj/main.o\
				./obj/chacha20.o\
				./obj/sha256.o\
				./obj/prog_bar.o
	$(CC) -o $@ $^

$(OUTPUT_NAME_GUI): ./src/mainGUI.c\
					./src/chacha20.c\
					./src/sha256.c\
					./src/prog_bar.c
	$(CC) $^ -o $@ $(GUI_FLAGS)


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
	rm $(OUTPUT_NAME) $(OUTPUT_NAME_GUI) ./obj/*.o
