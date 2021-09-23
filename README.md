# chacha20
Very simple encryption and decryption tool with no dependencies and using chacha20 cipher

## How to build and use (Linux)
You will need: gcc compiler, make and Git(optional)

Can be installed with:
`$ sudo apt install build-essential git`

1) Clone repository: `git clone https://github.com/vitorstraggiotti/chacha20.git && cd ./chacha20/v1.1`

2) Build: `$ make`

3) Use: `$ ./cha20crypt <path_to_file>`

### Versions
V1.0 --> WORKING
 - Known issues:
   * Encryption of big files get corrupted (when aproaching 4GB)

 - Not ideal:
   * No password specific hash algorithm (using SHA256 own implementation)
   * Hash algorithm with big potencial memory footprint

 - Limitation:
   * Max filesize for encryption: 274'877'906'944 bytes (~274.8GB or 256GiB)

V1.1 --> WORKING
 - Changelog:
   * Fixed encryption of big files geting corrupted (when aproaching 4GB)
   * Changed from dinamic to static allocation of encription variables for better performance
   * Improvement on output filename creation
   * Better code redability (getting rid of magic numbers)
   * Fixed memory leak on pointer to key for encrypt/decrypt
   * Fixed memory leak on cipher generation
   * Fixed progress bar animation restart when file is too big

 - Not ideal:
   * No password specific hash algorithm (using SHA256 own implementation)
   * Hash algorithm with big potencial memory footprint

 - Limitation:
   * Max filesize for encryption: 274'877'906'944 bytes (~274.8GB or 256GiB)
