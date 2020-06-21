/*
 * Copyright (c) 2020 Pedro Martelletto. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <cbor.h>
#include <err.h>
#include <fido.h>
#include <string.h>

#include "base64.h"
#include "cbor.h"

static void
free_pair(struct cbor_pair **pp)
{
	struct cbor_pair *p;

	if (pp == NULL || (p = *pp) == NULL)
		return;
	if (p->key)
		cbor_decref(&p->key);
	if (p->value)
		cbor_decref(&p->value);

	free(p);
	*pp = NULL;
}

static struct cbor_pair *
cbor_pack_item(const char *key, cbor_item_t **item)
{
	struct cbor_pair *p;

	if ((p = calloc(1, sizeof(*p))) == NULL ||
	    (p->key = cbor_build_string(key)) == NULL ||
	    *item == NULL) {
		warnx("%s: %s", __func__, key);
		if (*item)
			cbor_decref(item);
		free_pair(&p);
	} else {
		p->value = *item;
	}

	*item = NULL;

	return p;
}

static struct cbor_pair *
cbor_pack_str(const char *key, const char *val)
{
	cbor_item_t *item = cbor_build_string(val);

	return cbor_pack_item(key, &item);
}

static struct cbor_pair *
cbor_pack_cose(const char *key, int type)
{
	cbor_item_t *item = cbor_build_negint8(-type - 1);

	return cbor_pack_item(key, &item);
}

static struct cbor_pair *
cbor_pack_blob(const char *key, const uint8_t *ptr, size_t len)
{
	cbor_item_t *item = cbor_build_bytestring(ptr, len);

	return cbor_pack_item(key, &item);
}

static struct cbor_pair *
cbor_wrap_blob(const char *key, const uint8_t *ptr, size_t len)
{
	cbor_item_t		*array = NULL;
	cbor_item_t		*blob = NULL;
	struct cbor_pair	*p = NULL;

	if ((blob = cbor_build_bytestring(ptr, len)) == NULL ||
	    (array = cbor_new_definite_array(1)) == NULL ||
	    cbor_array_push(array, blob) == false ||
	    (p = cbor_pack_item(key, &array)) == NULL) {
		warnx("%s: %s", __func__, key);
	}

	if (blob)
		cbor_decref(&blob);
	if (array)
		cbor_decref(&array);

	return p;
}

static cbor_item_t *
cbor_encode_attestation_statement(const fido_cred_t *c, const char *fmt)
{
	cbor_item_t		*attstmt = NULL;
	const unsigned char	*sig_ptr;
	const unsigned char	*x5c_ptr;
	int			 ok = -1;
	int			 type;
	size_t			 sig_len;
	size_t			 x5c_len;
	struct cbor_pair	*argv[3];

	memset(argv, 0, sizeof(argv));

	if ((type = fido_cred_type(c)) != COSE_ES256 ||
	    (sig_ptr = fido_cred_sig_ptr(c)) == NULL ||
	    (sig_len = fido_cred_sig_len(c)) == 0 ||
	    (x5c_ptr = fido_cred_x5c_ptr(c)) == NULL ||
	    (x5c_len = fido_cred_x5c_len(c)) == 0) {
		warnx("%s: fido_cred", __func__);
		goto fail;
	}

	if ((attstmt = cbor_new_definite_map(3)) == NULL) {
		warnx("%s: cbor_new_definite_map", __func__);
		goto fail;
	}

	if ((argv[0] = cbor_pack_cose("alg", type)) == NULL ||
	    (argv[1] = cbor_pack_blob("sig", sig_ptr, sig_len)) == NULL ||
	    (argv[2] = cbor_wrap_blob("x5c", x5c_ptr, x5c_len)) == NULL) {
		warnx("%s: cbor_pack", __func__);
		goto fail;
	}

	if (cbor_map_add(attstmt, *argv[1]) == false ||
	    cbor_map_add(attstmt, *argv[2]) == false) {
		warnx("%s: cbor_map_add", __func__);
		goto fail;
	}

	if (strcmp(fmt, "packed") == 0) {
		if (cbor_map_add(attstmt, *argv[0]) == false) {
			warnx("%s: cbor_map_add", __func__);
			goto fail;
		}
	}

	ok = 0;
fail:
	for (size_t i = 0; i < 3; i++)
		free_pair(&argv[i]);

	if (ok < 0 && attstmt != NULL)
		cbor_decref(&attstmt);

	return attstmt;
}

static int
base64_encode_cbor(const cbor_item_t *item, char **out)
{
	unsigned char	*ptr = NULL;
	size_t		 len;
	size_t		 alloc_len;

	if ((len = cbor_serialize_alloc(item, &ptr, &alloc_len)) == 0 ||
	    base64_encode(ptr, len, out) < 0) {
		free(ptr);
		return -1;
	}

	free(ptr);

	return 0;
}

char *
cbor_build_attestation_object(const fido_cred_t *c)
{
	cbor_item_t		*attobj = NULL;
	cbor_item_t		*attstmt = NULL;
	cbor_item_t		*authdata = NULL;
	char			*attobj_b64 = NULL;
	const char		*fmt;
	const unsigned char	*authdata_ptr;
	size_t			 authdata_len;
	struct cbor_load_result	 cbor;
	struct cbor_pair	*argv[3];

	memset(argv, 0, sizeof(argv));

	if ((fmt = fido_cred_fmt(c)) == NULL ||
	    (attstmt = cbor_encode_attestation_statement(c, fmt)) == NULL ||
	    (authdata_ptr = fido_cred_authdata_ptr(c)) == NULL ||
	    (authdata_len = fido_cred_authdata_len(c)) == 0) {
		warnx("%s: fido_cred", __func__);
		goto fail;
	}

	if ((authdata = cbor_load(authdata_ptr, authdata_len, &cbor)) == NULL) {
		warnx("%s: cbor_load", __func__);
		goto fail;
	}

	if ((attobj = cbor_new_definite_map(3)) == NULL) {
		warnx("%s: cbor_new_definite_map", __func__);
		goto fail;
	}

	if ((argv[0] = cbor_pack_str("fmt", fmt)) == NULL ||
	    (argv[1] = cbor_pack_item("attStmt", &attstmt)) == NULL ||
	    (argv[2] = cbor_pack_item("authData", &authdata)) == NULL) {
		warnx("%s: cbor_pack", __func__);
		goto fail;
	}

	if (cbor_map_add(attobj, *argv[0]) == false ||
	    cbor_map_add(attobj, *argv[1]) == false ||
	    cbor_map_add(attobj, *argv[2]) == false) {
		warnx("%s: cbor_map_add", __func__);
		goto fail;
	}

	if (base64_encode_cbor(attobj, &attobj_b64) < 0) {
		warnx("%s: base64_encode_cbor", __func__);
		goto fail;
	}

fail:
	if (attobj != NULL)
		cbor_decref(&attobj);

	if (attstmt != NULL)
		cbor_decref(&attstmt);

	if (authdata != NULL)
		cbor_decref(&authdata);

	for (size_t i = 0; i < 3; i++)
		free_pair(&argv[i]);

	return attobj_b64;
}
