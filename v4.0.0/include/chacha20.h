/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
	Library for implementing chacha20 cipher
	
	Author: Vitor Henrique Andrade Helfensteller Straggiotti Silva
	Start date: 30/06/2021 (DD/MM/YYYY)
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#ifndef CHACHA20_H
#define CHACHA20_H

#include <stdint.h>
#include <stdlib.h>



//(in) Key --> pointer to 32 bytes array used as key to generate the output cipher stream
//(in) Counter --> 64 bits value meant to start at 0 and be incremented by 1 on each call
//(in) Nonce --> 64 bits value used as "Number Used Once"
//(in) Rounds --> Number of chacha rounds to be performed. Is an even number. If odd number
//            is used it will be rounded to nearest smallest even number
//(out) OutCipher --> pointer to 64 bytes array of cipher to be XOR'ed with data
void generate_chacha_cipher_key(uint8_t *Key, uint64_t Counter, uint64_t Nonce, uint32_t Rounds, uint8_t *OutCipher);

#endif
