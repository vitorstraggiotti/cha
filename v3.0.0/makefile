
PROG_NAME = cha
PROG_VERSION=3.0.0
ARCH=amd64

# Variables for compile process 
CC = gcc
CC_RELEASE_FLAGS = -Wall -pedantic -c -O2
CC_DEBUG_FLAGS = -Wall -pedantic -c -g

# Variables for building .deb package
CONTROLFILEPATH=./$(PROG_NAME)_$(PROG_VERSION)_$(ARCH)/DEBIAN
CONTROLFILE=$(CONTROLFILEPATH)/control
BINPATH=./$(PROG_NAME)_$(PROG_VERSION)_$(ARCH)/usr/bin

.PHONY: clean cleanall all

# Menu
all:
	@echo "Build options:"
	@echo "  make $(PROG_NAME)       --> Build release version"
	@echo "  make $(PROG_NAME)_debug --> Build debug version"
	@echo "  make $(PROG_NAME)_pack  --> Build .deb package"
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

# Building .deb package
$(PROG_NAME)_pack: $(PROG_NAME)
	@mkdir -p "$(CONTROLFILEPATH)" && touch "$(CONTROLFILE)"
	@mkdir -p "$(BINPATH)"
	@cp $(PROG_NAME) $(BINPATH)

	@echo "Package: $(PROG_NAME)" >> $(CONTROLFILE)
	@echo "Version: $(PROG_VERSION)" >> $(CONTROLFILE)
	@echo "Architecture: all" >> $(CONTROLFILE)
	@echo "Essential: no" >> $(CONTROLFILE)
	@echo "Priority: optional" >> $(CONTROLFILE)
	@echo "Depends: " >> $(CONTROLFILE)
	@echo "Maintainer: Vitor Henrique A. H. S. Silva" >> $(CONTROLFILE)
	@echo "Description: Encrypt and decrypt files using chacha algorithm" >> $(CONTROLFILE)

	@dpkg-deb --build $(PROG_NAME)_$(PROG_VERSION)_$(ARCH)

	@rm -r $(PROG_NAME)_$(PROG_VERSION)_$(ARCH)

	@## preinst and postinst ca be added
	@#echo "" >> ./cha_3.0.0_amd64/DEBIAN/postinst
	@#chmod 755 ./cha_3.0.0_amd64/DEBIAN/postinst

# Cleaning process
cleanall: clean
	rm $(PROG_NAME) $(PROG_NAME)_debug *.deb

clean:
	rm ./obj/*.o
