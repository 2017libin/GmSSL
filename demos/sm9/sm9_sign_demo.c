/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/sm9.h>
#include <gmssl/error.h>

void sm9_point_from_hex_x_y(SM9_POINT *R, const char hexx[], const char hexy[])
{
	sm9_bn_from_hex(R->X, hexx);
	sm9_bn_from_hex(R->Y, hexy);
	sm9_bn_set_one(R->Z);
}

void sm9_twist_point_from_hex_x_y(SM9_TWIST_POINT *R, const char hexx[], const char hexy[])
{
	sm9_fp2_from_hex(R->X, hexx);
	sm9_fp2_from_hex(R->Y, hexy);
	sm9_fp2_set_one(R->Z);
}

int main(void)
{
	SM9_SIGN_MASTER_KEY sign_master;
	SM9_SIGN_MASTER_KEY sign_master_public;
	SM9_SIGN_KEY sign_key;
	SM9_SIGN_CTX sign_ctx;
	const char *id = "Alice";
	uint8_t sig[SM9_SIGNATURE_SIZE];
	size_t siglen;
	uint8_t buf[512];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len;
	int ret;

	char hexx1[] = "85aef3d078640c98597b6027b441a01ff1dd2c190f5e93c454806c11d880614185aef3d078640c98597b6027b441a01ff1dd2c190f5e93c454806c11d8806141";
	char hexy1[] = "a7cf28d519be3da65f3170153d278ff247efba98a71a08116215bba5c999a7c785aef3d078640c98597b6027b441a01ff1dd2c190f5e93c454806c11d8806141";
	char hexx2[] = "17509b092e845c1266ba0d262cbee6ed0736a96fa347c8bd856dc76b84ebeb96";
	char hexy2[] = "3722755292130b08d2aab97fd34ec120ee265948d19c17abf9b7213baf82d65b";

	// sm9_sign_master_key_generate(&sign_master);

	// sm9_sign_master_key_extract_key(&sign_master, id, strlen(id), &sign_key);
	sm9_point_from_hex_x_y(&(sign_key.ds), hexx2, hexy2);
	sm9_twist_point_from_hex_x_y(&(sign_key.Ppubs), hexx1, hexy1);

	sm9_point_print(NULL,0,0,"ds", &(sign_key.ds));
	sm9_twist_point_print(NULL,0,0,"Ppubs", &(sign_key.Ppubs));

	sm9_sign_init(&sign_ctx);
	sm9_sign_update(&sign_ctx, (uint8_t *)"hello world", strlen("hello world"));
	sm9_sign_finish(&sign_ctx, &sign_key, sig, &siglen);

	format_bytes(stdout, 0, 0, "signature", sig, siglen);

	sm9_sign_master_public_key_to_der(&sign_master, &p, &len);
	sm9_sign_master_public_key_from_der(&sign_master_public, &cp, &len);

	sm9_verify_init(&sign_ctx);
	sm9_verify_update(&sign_ctx, (uint8_t *)"hello world", strlen("hello world"));
	ret = sm9_verify_finish(&sign_ctx, sig, siglen, &sign_master_public, id, strlen(id));
	printf("verify %s\n", ret == 1 ? "success" : "failure");


	return 0;
}
