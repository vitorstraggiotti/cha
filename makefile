
all:
	gcc main.c chacha20.c sha256.c -o cha20crypt

release:
	gcc -O1 main.c chacha20.c sha256.c -o cha20crypt
	
debug:
	gcc -g main.c chacha20.c sha256.c -o cha20crypt

clean:
	rm cha20crypt
