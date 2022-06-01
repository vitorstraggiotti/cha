/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * **
	Program to validate chacha cypher using test vectors
	
	Author: Vitor Henrique Andrade Helfensteller Straggiotti Silva
	Start date: 29/05/2022 (DD/MM/YYYY)
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/* Chacha test vectors:
https://datatracker.ietf.org/doc/html/draft-strombergson-chacha-test-vectors-00
   Chacha algorithm:
https://datatracker.ietf.org/doc/html/rfc7539 */

#include <stdio.h>
#include <stdint.h>

#include "validate_cha.h"
#include "../include/chacha20.h"

uint64_t array_uint8_to_uint64(uint8_t *ByteArray);
uint8_t keystream_is_equal(uint8_t *Array1, uint8_t *Array2);

int main(void)
{
	uint8_t  Keystream[BYTES_PER_BLOCK];
	uint8_t  *Key256;
	uint8_t  *Key128;
	uint64_t BlockNum;
	uint64_t Nonce;
	uint32_t Rounds;

	/*================================= Testing TC1 =========================*/
	printf("     ===============================================\n");
	printf("     ========== TEST VECTOR GROUP 1 (TC1) ==========\n");
	printf("     ===============================================\n\n");
	
	Nonce = array_uint8_to_uint64(Nonce_64[TC1]);
	
	/* 128 bits key */
	printf("++++++++++ 128 BIT KEYS ++++++++++\n\n");
	Key128 = Key_128[TC1];

		/* NEED TO WRITE VALIDATION FOR 128 BIT KEY */

	/* 256 bits key*/
	printf("++++++++++ 256 BIT KEYS ++++++++++\n\n");
	Key256 = Key_256[TC1];

	Rounds = 8;

	BlockNum = 0;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC1_Key_256_Nonce_64_Rounds_8 on Block 0 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC1_Key_256_Nonce_64_Rounds_8][BlockNum]))
		printf("OK\n");
	else
		printf("FAIL\n");

	BlockNum = 1;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC1_Key_256_Nonce_64_Rounds_8 on Block 1 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC1_Key_256_Nonce_64_Rounds_8][BlockNum]))
		printf("OK\n\n");
	else
		printf("FAIL\n\n");

	Rounds = 12;

	BlockNum = 0;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC1_Key_256_Nonce_64_Rounds_12 on Block 0 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC1_Key_256_Nonce_64_Rounds_12][BlockNum]))
		printf("OK\n");
	else
		printf("FAIL\n");

	BlockNum = 1;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC1_Key_256_Nonce_64_Rounds_12 on Block 1 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC1_Key_256_Nonce_64_Rounds_12][BlockNum]))
		printf("OK\n\n");
	else
		printf("FAIL\n\n");

	Rounds = 20;

	BlockNum = 0;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC1_Key_256_Nonce_64_Rounds_20 on Block 0 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC1_Key_256_Nonce_64_Rounds_20][BlockNum]))
		printf("OK\n");
	else
		printf("FAIL\n");

	BlockNum = 1;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC1_Key_256_Nonce_64_Rounds_20 on Block 1 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC1_Key_256_Nonce_64_Rounds_20][BlockNum]))
		printf("OK\n\n");
	else
		printf("FAIL\n\n");

	/*================================= Testing TC2 =========================*/
	printf("     ===============================================\n");
	printf("     ========== TEST VECTOR GROUP 2 (TC2) ==========\n");
	printf("     ===============================================\n\n");

	Nonce = array_uint8_to_uint64(Nonce_64[TC2]);
	
	/* 128 bits key */
	printf("++++++++++ 128 BIT KEYS ++++++++++\n\n");
	Key128 = Key_128[TC2];

		/* NEED TO WRITE VALIDATION FOR 128 BIT KEY */

	/* 256 bits key*/
	printf("++++++++++ 256 BIT KEYS ++++++++++\n\n");
	Key256 = Key_256[TC2];

	Rounds = 8;

	BlockNum = 0;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC2_Key_256_Nonce_64_Rounds_8 on Block 0 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC2_Key_256_Nonce_64_Rounds_8][BlockNum]))
		printf("OK\n");
	else
		printf("FAIL\n");

	BlockNum = 1;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC2_Key_256_Nonce_64_Rounds_8 on Block 1 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC2_Key_256_Nonce_64_Rounds_8][BlockNum]))
		printf("OK\n\n");
	else
		printf("FAIL\n\n");

	Rounds = 12;

	BlockNum = 0;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC2_Key_256_Nonce_64_Rounds_12 on Block 0 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC2_Key_256_Nonce_64_Rounds_12][BlockNum]))
		printf("OK\n");
	else
		printf("FAIL\n");

	BlockNum = 1;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC2_Key_256_Nonce_64_Rounds_12 on Block 1 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC2_Key_256_Nonce_64_Rounds_12][BlockNum]))
		printf("OK\n\n");
	else
		printf("FAIL\n\n");

	Rounds = 20;

	BlockNum = 0;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC2_Key_256_Nonce_64_Rounds_20 on Block 0 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC2_Key_256_Nonce_64_Rounds_20][BlockNum]))
		printf("OK\n");
	else
		printf("FAIL\n");

	BlockNum = 1;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC2_Key_256_Nonce_64_Rounds_20 on Block 1 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC2_Key_256_Nonce_64_Rounds_20][BlockNum]))
		printf("OK\n\n");
	else
		printf("FAIL\n\n");

	/*================================= Testing TC3 =========================*/
	printf("     ===============================================\n");
	printf("     ========== TEST VECTOR GROUP 3 (TC3) ==========\n");
	printf("     ===============================================\n\n");

	Nonce = array_uint8_to_uint64(Nonce_64[TC3]);
	
	/* 128 bits key */
	printf("++++++++++ 128 BIT KEYS ++++++++++\n\n");
	Key128 = Key_128[TC3];

		/* NEED TO WRITE VALIDATION FOR 128 BIT KEY */

	/* 256 bits key*/
	printf("++++++++++ 256 BIT KEYS ++++++++++\n\n");
	Key256 = Key_256[TC3];

	Rounds = 8;

	BlockNum = 0;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC3_Key_256_Nonce_64_Rounds_8 on Block 0 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC3_Key_256_Nonce_64_Rounds_8][BlockNum]))
		printf("OK\n");
	else
		printf("FAIL\n");

	BlockNum = 1;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC3_Key_256_Nonce_64_Rounds_8 on Block 1 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC3_Key_256_Nonce_64_Rounds_8][BlockNum]))
		printf("OK\n\n");
	else
		printf("FAIL\n\n");

	Rounds = 12;

	BlockNum = 0;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC3_Key_256_Nonce_64_Rounds_12 on Block 0 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC3_Key_256_Nonce_64_Rounds_12][BlockNum]))
		printf("OK\n");
	else
		printf("FAIL\n");

	BlockNum = 1;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC3_Key_256_Nonce_64_Rounds_12 on Block 1 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC3_Key_256_Nonce_64_Rounds_12][BlockNum]))
		printf("OK\n\n");
	else
		printf("FAIL\n\n");

	Rounds = 20;

	BlockNum = 0;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC3_Key_256_Nonce_64_Rounds_20 on Block 0 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC3_Key_256_Nonce_64_Rounds_20][BlockNum]))
		printf("OK\n");
	else
		printf("FAIL\n");

	BlockNum = 1;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC3_Key_256_Nonce_64_Rounds_20 on Block 1 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC3_Key_256_Nonce_64_Rounds_20][BlockNum]))
		printf("OK\n\n");
	else
		printf("FAIL\n\n");

	/*================================= Testing TC4 =========================*/
	printf("     ===============================================\n");
	printf("     ========== TEST VECTOR GROUP 4 (TC4) ==========\n");
	printf("     ===============================================\n\n");

	Nonce = array_uint8_to_uint64(Nonce_64[TC4]);
	
	/* 128 bits key */
	printf("++++++++++ 128 BIT KEYS ++++++++++\n\n");
	Key128 = Key_128[TC4];

		/* NEED TO WRITE VALIDATION FOR 128 BIT KEY */

	/* 256 bits key*/
	printf("++++++++++ 256 BIT KEYS ++++++++++\n\n");
	Key256 = Key_256[TC4];

	Rounds = 8;

	BlockNum = 0;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC4_Key_256_Nonce_64_Rounds_8 on Block 0 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC4_Key_256_Nonce_64_Rounds_8][BlockNum]))
		printf("OK\n");
	else
		printf("FAIL\n");

	BlockNum = 1;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC4_Key_256_Nonce_64_Rounds_8 on Block 1 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC4_Key_256_Nonce_64_Rounds_8][BlockNum]))
		printf("OK\n\n");
	else
		printf("FAIL\n\n");

	Rounds = 12;

	BlockNum = 0;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC4_Key_256_Nonce_64_Rounds_12 on Block 0 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC4_Key_256_Nonce_64_Rounds_12][BlockNum]))
		printf("OK\n");
	else
		printf("FAIL\n");

	BlockNum = 1;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC4_Key_256_Nonce_64_Rounds_12 on Block 1 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC4_Key_256_Nonce_64_Rounds_12][BlockNum]))
		printf("OK\n\n");
	else
		printf("FAIL\n\n");

	Rounds = 20;

	BlockNum = 0;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC4_Key_256_Nonce_64_Rounds_20 on Block 0 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC4_Key_256_Nonce_64_Rounds_20][BlockNum]))
		printf("OK\n");
	else
		printf("FAIL\n");

	BlockNum = 1;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC4_Key_256_Nonce_64_Rounds_20 on Block 1 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC4_Key_256_Nonce_64_Rounds_20][BlockNum]))
		printf("OK\n\n");
	else
		printf("FAIL\n\n");

	/*================================= Testing TC5 =========================*/
	printf("     ===============================================\n");
	printf("     ========== TEST VECTOR GROUP 5 (TC5) ==========\n");
	printf("     ===============================================\n\n");

	Nonce = array_uint8_to_uint64(Nonce_64[TC2]);
	
	/* 128 bits key */
	printf("++++++++++ 128 BIT KEYS ++++++++++\n\n");
	Key128 = Key_128[TC5];

		/* NEED TO WRITE VALIDATION FOR 128 BIT KEY */

	/* 256 bits key*/
	printf("++++++++++ 256 BIT KEYS ++++++++++\n\n");
	Key256 = Key_256[TC5];

	Rounds = 8;

	BlockNum = 0;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC5_Key_256_Nonce_64_Rounds_8 on Block 0 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC5_Key_256_Nonce_64_Rounds_8][BlockNum]))
		printf("OK\n");
	else
		printf("FAIL\n");

	BlockNum = 1;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC5_Key_256_Nonce_64_Rounds_8 on Block 1 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC5_Key_256_Nonce_64_Rounds_8][BlockNum]))
		printf("OK\n\n");
	else
		printf("FAIL\n\n");

	Rounds = 12;

	BlockNum = 0;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC5_Key_256_Nonce_64_Rounds_12 on Block 0 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC5_Key_256_Nonce_64_Rounds_12][BlockNum]))
		printf("OK\n");
	else
		printf("FAIL\n");

	BlockNum = 1;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC5_Key_256_Nonce_64_Rounds_12 on Block 1 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC5_Key_256_Nonce_64_Rounds_12][BlockNum]))
		printf("OK\n\n");
	else
		printf("FAIL\n\n");

	Rounds = 20;

	BlockNum = 0;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC5_Key_256_Nonce_64_Rounds_20 on Block 0 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC5_Key_256_Nonce_64_Rounds_20][BlockNum]))
		printf("OK\n");
	else
		printf("FAIL\n");

	BlockNum = 1;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC5_Key_256_Nonce_64_Rounds_20 on Block 1 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC5_Key_256_Nonce_64_Rounds_20][BlockNum]))
		printf("OK\n\n");
	else
		printf("FAIL\n\n");

	/*================================= Testing TC7 =========================*/
	printf("     ===============================================\n");
	printf("     ========== TEST VECTOR GROUP 7 (TC7) ==========\n");
	printf("     ===============================================\n\n");

	Nonce = array_uint8_to_uint64(Nonce_64[TC7]);
	
	/* 128 bits key */
	printf("++++++++++ 128 BIT KEYS ++++++++++\n\n");
	Key128 = Key_128[TC7];

		/* NEED TO WRITE VALIDATION FOR 128 BIT KEY */

	/* 256 bits key*/
	printf("++++++++++ 256 BIT KEYS ++++++++++\n\n");
	Key256 = Key_256[TC7];

	Rounds = 8;

	BlockNum = 0;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC7_Key_256_Nonce_64_Rounds_8 on Block 0 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC7_Key_256_Nonce_64_Rounds_8][BlockNum]))
		printf("OK\n");
	else
		printf("FAIL\n");

	BlockNum = 1;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC7_Key_256_Nonce_64_Rounds_8 on Block 1 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC7_Key_256_Nonce_64_Rounds_8][BlockNum]))
		printf("OK\n\n");
	else
		printf("FAIL\n\n");

	Rounds = 12;

	BlockNum = 0;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC7_Key_256_Nonce_64_Rounds_12 on Block 0 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC7_Key_256_Nonce_64_Rounds_12][BlockNum]))
		printf("OK\n");
	else
		printf("FAIL\n");

	BlockNum = 1;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC7_Key_256_Nonce_64_Rounds_12 on Block 1 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC7_Key_256_Nonce_64_Rounds_12][BlockNum]))
		printf("OK\n\n");
	else
		printf("FAIL\n\n");

	Rounds = 20;

	BlockNum = 0;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC7_Key_256_Nonce_64_Rounds_20 on Block 0 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC7_Key_256_Nonce_64_Rounds_20][BlockNum]))
		printf("OK\n");
	else
		printf("FAIL\n");

	BlockNum = 1;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC7_Key_256_Nonce_64_Rounds_20 on Block 1 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC7_Key_256_Nonce_64_Rounds_20][BlockNum]))
		printf("OK\n\n");
	else
		printf("FAIL\n\n");

	/*================================= Testing TC8 =========================*/
	printf("     ===============================================\n");
	printf("     ========== TEST VECTOR GROUP 8 (TC8) ==========\n");
	printf("     ===============================================\n\n");

	Nonce = array_uint8_to_uint64(Nonce_64[TC8]);
	
	/* 128 bits key */
	printf("++++++++++ 128 BIT KEYS ++++++++++\n\n");
	Key128 = Key_128[TC8];

		/* NEED TO WRITE VALIDATION FOR 128 BIT KEY */

	/* 256 bits key*/
	printf("++++++++++ 256 BIT KEYS ++++++++++\n\n");
	Key256 = Key_256[TC8];

	Rounds = 8;

	BlockNum = 0;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC8_Key_256_Nonce_64_Rounds_8 on Block 0 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC8_Key_256_Nonce_64_Rounds_8][BlockNum]))
		printf("OK\n");
	else
		printf("FAIL\n");

	BlockNum = 1;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC8_Key_256_Nonce_64_Rounds_8 on Block 1 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC8_Key_256_Nonce_64_Rounds_8][BlockNum]))
		printf("OK\n\n");
	else
		printf("FAIL\n\n");

	Rounds = 12;

	BlockNum = 0;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC8_Key_256_Nonce_64_Rounds_12 on Block 0 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC8_Key_256_Nonce_64_Rounds_12][BlockNum]))
		printf("OK\n");
	else
		printf("FAIL\n");

	BlockNum = 1;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC8_Key_256_Nonce_64_Rounds_12 on Block 1 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC8_Key_256_Nonce_64_Rounds_12][BlockNum]))
		printf("OK\n\n");
	else
		printf("FAIL\n\n");

	Rounds = 20;

	BlockNum = 0;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC8_Key_256_Nonce_64_Rounds_20 on Block 0 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC8_Key_256_Nonce_64_Rounds_20][BlockNum]))
		printf("OK\n");
	else
		printf("FAIL\n");

	BlockNum = 1;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC8_Key_256_Nonce_64_Rounds_20 on Block 1 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC8_Key_256_Nonce_64_Rounds_20][BlockNum]))
		printf("OK\n\n");
	else
		printf("FAIL\n\n");



    return 0;
}

/*===========================================================================*/
uint64_t array_uint8_to_uint64(uint8_t *ByteArray)
{
	uint64_t Result;

	for(uint8_t i = 0; i < 8; i++)
	{
		Result = (Result << 8) || ByteArray[i];
	}

	return Result;
}

/*---------------------------------------------------------------------------*/
uint8_t keystream_is_equal(uint8_t *Array1, uint8_t *Array2)
{
	for(uint8_t i = 0; i < BYTES_PER_BLOCK; i++)
	{
		if(Array1[i] != Array2[i])
			return 0;
	}

	return 1;
}