# cha
Very simple encryption and decryption tool with no dependencies and using chacha20 cipher

## How to build and use (Linux)

You will need: gcc compiler, make and Git(optional). Can be installed with:
`$ sudo apt install build-essential git`

1) Clone repository: `$ git clone https://github.com/vitorstraggiotti/chacha20.git && cd ./chacha20/v3.0.0`

2) Build: `$ make cha`

3) Use: `$ ./cha -h`

## Versions

### V4.0.0
 IN PROGESS

 - To do:
   * Fix chacha algorithm (possible endianness problem)
   * Create validation program to verify chacha algorithm implementation
   * Add option for diferent key and nonce sizes

### V3.0.0
 - Changelog:
   * Added custom header to encrypted files
   * Added help menu
   * Added support for program options
     * Added option to configure number of chacha rounds to be performed
     * Added suport to use filekey (use any file as key to encrypt/decrypt)
   * Refactored some parts

### V2.0.0
 - Changelog:
   * Using newer version of SHA256 library (optimized for small memory footprint)
   * Using newer version of progbar library (automatic adjustment of the progress bar update intervals. Reduction in slowdown effect due to printing overhead)
   * Main source code refactored
   * No more file size limit
   * Due to changes on nonce generation v2.0.0 is not compatible with previous versions (v1.1.0 and v1.0.0)

 - Encryption/Decryption library changes:
   * Refactored library
   * Changed to bigger limit on key stream generation by using bigger block counter
   * Added control over the number of chacha rounds that can be performed


### V1.1.0
 - Changelog:
   * Fixed encryption of big files geting corrupted (when aproaching 4GB)
   * Changed from dinamic to static allocation of encription variables for better performance
   * Improvement on output filename creation
   * Better code redability (getting rid of magic numbers)
   * Fixed memory leak on pointer to key for encrypt/decrypt
   * Fixed memory leak on cipher generation
   * Fixed progress bar animation restart when file is too big

 - Not ideal:
   * No password specific hash algorithm (using SHA256)
   * Hash algorithm with big potencial memory footprint

 - Limitation:
   * Max filesize for encryption: 274'877'906'944 bytes (~274.8GB or 256GiB)

### V1.0.0
 - Known issues:
   * Encryption of big files get corrupted (when aproaching 4GB)

 - Not ideal:
   * No password specific hash algorithm (using SHA256 own implementation)
   * Hash algorithm with big potencial memory footprint

 - Limitation:
   * Max filesize for encryption: 274'877'906'944 bytes (~274.8GB or 256GiB)

