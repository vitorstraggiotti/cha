# chacha20
Very simple encryption and decryption tool with no dependencies and using chacha20 cipher

## How to build and use (Linux)
You will need: gcc compiler, make and Git(optional)

Can be installed with:
`$ sudo apt install build-essential`
`$ sudo apt install git`

1) Clone repository: `git clone https://github.com/vitorstraggiotti/chacha20.git && cd ./chacha20/v1.0`

2) Build: `$ make`

3) Use: `$ ./cha20crypt <path_to_file>`

### Versions
V1.0 --> WORKING
 - Known issues:
   * Encryption of big files get corrupted (when aproaching 1GB)

 - Not ideal:
   * No password specific hash algorithm (using SHA256 own implementation)
   * Hash algorithm with big potencial memory footprint
   * Encryption algorithm: memory footprint and filesize are the same

 - Limitation:
   * Max filesize for encryption: 274'877'906'944 bytes (~274.8GB or 256GiB)

V1.1 --> IN PROGRESS
