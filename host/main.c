/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#define _CRT_SECURE_NO_WARNINGS 
#pragma warning(disable :4996)

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

int main(int argc, char* argv[])
{	
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	char plaintext[64] = {0,};
	char ciphertext[64] = {0,};
	char encrypted_key[4];
	char decrypted_key[4];
	int len=64;
	FILE *fp;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	memset(&op, 0, sizeof(op));

	/*
	 * Prepare the argument. Pass a value in the first parameter,
	 * the remaining three parameters are unused.
	 */
	
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INOUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.size = len;
	op.params[1].value.a = 0; 
	
	if(strcmp(argv[1], "-e") == 0){ //encrypt...
		//open file and get file content
		fp = fopen(argv[2], "r");
		if(fp == NULL){
			printf("fail to open file... %s\n", strerror( errno));
			return 1;	
		}
		memset(plaintext, 0, sizeof(plaintext));
		fgets(plaintext, sizeof(plaintext), fp);
		printf("file content: %s", plaintext);
			
		//param setting -> call TA to encrypt
		printf("encrypt......\n");
		memcpy(op.params[0].tmpref.buffer, plaintext, len);

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op,&err_origin); 
		if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
	
		//save encrypted text and key in .txt file
		memcpy(ciphertext, op.params[0].tmpref.buffer, len);
		fp = fopen("ciphertext.txt", "w");
		fprintf(fp, ciphertext);
		fclose(fp);

		sprintf(encrypted_key, "%d", op.params[1].value.a); // int to char
		fp = fopen("encrypted_key.txt", "w");
		fprintf(fp, encrypted_key);
		fprintf(fp, "\n");
		fclose(fp);

		printf("done\n");
		return 0;
		
	}
	else if(strcmp(argv[1], "-d") == 0){ //decrypt...
		//open file and get content -> ciphertext, key
		fp = fopen(argv[2], "r");
		if(fp == NULL){
			printf("fail to open file... %s\n", strerror( errno));
			return 1;	
		}
		memset(ciphertext, 0, sizeof(ciphertext));
		fgets(ciphertext, sizeof(ciphertext), fp);

		fp = fopen(argv[3], "r");
		if(fp == NULL){
			printf("fail to open file... %s\n", strerror( errno));
			return 1;	
		}
		memset(encrypted_key, 0, sizeof(encrypted_key));
		fgets(encrypted_key, sizeof(encrypted_key), fp);
		printf("file content: %s", ciphertext);
		printf("key content: %s", encrypted_key);
		
		//param setting -> call TA to decrypt
		printf("decrypt......\n");
		memcpy(op.params[0].tmpref.buffer, ciphertext, len);
		if(strlen(encrypted_key) == 2){ // char to int	
			op.params[1].value.a = encrypted_key[0] - '0';
		}else{
			int ten = encrypted_key[0] - '0';
			int one = encrypted_key[1] - '0';
			op.params[1].value.a = ten * 10 + one;
		} 

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,&err_origin); 
		if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);

		//save decrypted text and key in .txt file
		memcpy(plaintext, op.params[0].tmpref.buffer, len);
		fp = fopen("decrypted.txt", "w");
		fprintf(fp, plaintext);
		fclose(fp);

		sprintf(decrypted_key, "%d", op.params[1].value.a); // int to char
		fp = fopen("decrypted_key.txt", "w");
		fprintf(fp, decrypted_key);
		fprintf(fp, "\n");
		fclose(fp);

		printf("done\n");
		return 0;
	}
	else{
		printf("error: you didn't enter a appropriate command.\n");
	}

	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return 0;
}
