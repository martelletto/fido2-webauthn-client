/*
 * Copyright (c) 2020 Pedro Martelletto. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <err.h>
#include <stdlib.h>
#include <string.h>

#include <cbor.h>
#include <fido.h>
#include <jansson.h>
#include <openssl/sha.h>

#include "base64.h"
#include "clientdata.h"
#include "http.h"
#include "json.h"
#include "param.h"
#include "webauthn-assert.h"

struct webauthn_assert {
	fido_assert_t		*assert;
	char			*clientdata;
	char			*request_id;
	struct http_post	*begin;
	struct http_post	*finish;
};

struct webauthn_assert *
webauthn_assert_new(void)
{
	struct webauthn_assert *wa;

	if ((wa = calloc(1, sizeof(*wa))) == NULL) {
		warnx("%s: calloc", __func__);
		return NULL;
	}

	if ((wa->assert = fido_assert_new()) == NULL) {
		warnx("%s: fido_assert_new", __func__);
		webauthn_assert_free(&wa);
	}

	return wa;
}

void
webauthn_assert_free(struct webauthn_assert **wap)
{
	struct webauthn_assert *wa;

	if (wap == NULL || (wa = *wap) == NULL)
		return;

	fido_assert_free(&wa->assert);
	free(wa->clientdata);
	free(wa->request_id);
	http_free(&wa->begin);
	http_free(&wa->finish);
	free(wa);
	*wap = NULL;
}

static int
webauthn_assert_begin_parse_response(struct webauthn_assert *wa)
{
	json_t	*blob;
	json_t	*data;
	json_t	*pubkey;
	char	*challenge = NULL;
	void	*cred_ptr = NULL;
	size_t	 cred_len;
	int	 ok = -1;

	if ((blob = http_response_json(wa->begin)) == NULL ||
	    json_check_str(blob, "status", "success") < 0 ||
	    (data = json_parse_obj(blob, "data")) == NULL) {
		warnx("%s: json", __func__);
		goto fail;
	}

	if ((pubkey = json_parse_obj(data, "publicKey")) == NULL ||
	    (wa->request_id = json_parse_str(data, "requestId")) == NULL) {
		warnx("%s: json data", __func__);
		goto fail;
	}

	if ((challenge = json_parse_str(pubkey, "challenge")) == NULL ||
	    json_check_str(pubkey, "rpId", RP_ID) < 0 ||
	    json_parse_allowcred(pubkey, &cred_ptr, &cred_len) < 0) {
		warnx("%s: json publicKey", __func__);
		goto fail;
	}

	if ((wa->clientdata = clientdata_json("webauthn.get",
	    challenge)) == NULL) {
		warnx("%s: json challenge", __func__);
		goto fail;
	}

	if (fido_assert_set_rp(wa->assert, RP_ID) != FIDO_OK) {
		warnx("%s: fido_assert_set_rp", __func__);
		goto fail;
	}

	if (fido_assert_allow_cred(wa->assert, cred_ptr, cred_len) != FIDO_OK) {
		warnx("%s: fido_assert_allow_cred", __func__);
		goto fail;
	}

	ok = 0;
fail:
	if (blob)
		json_decref(blob);

	free(challenge);
	free(cred_ptr);

	return ok;
}

int
webauthn_assert_begin(struct webauthn_assert *wa, const char *cookie)
{
	if (http_request(&wa->begin, AUTH_BEGIN_URL, AUTH_BEGIN_BODY,
	    cookie) < 0) {
		warnx("%s: http_request", __func__);
		return -1;
	}

	if (webauthn_assert_begin_parse_response(wa) < 0) {
		warnx("%s: webauthn_assert_begin_parse_response", __func__);
		return -1;
	}

	return 0;
}

int
webauthn_assert_get(struct webauthn_assert *wa, fido_dev_t *token)
{
	uint8_t	dgst[SHA256_DIGEST_LENGTH];
	int	status;

	if (SHA256((const uint8_t *)wa->clientdata, strlen(wa->clientdata),
	    dgst) != dgst) {
		warnx("%s: SHA256", __func__);
		return -1;
	}

	if (fido_assert_set_clientdata_hash(wa->assert, dgst,
	    sizeof(dgst)) != FIDO_OK) {
		warnx("%s: fido_assert_set_clientdata_hash", __func__);
		return -1;
	}

	if ((status = fido_dev_get_assert(token, wa->assert, NULL)) != FIDO_OK) {
		warnx("%s: fido_dev_get_assert: %s", __func__,
		    fido_strerr(status));
		return -1;
	}

	return 0;
}

static int
webauthn_assert_finish_parse_response(struct http_post *r)
{
	json_t	*blob;
	int	 ok = 0;

	if ((blob = http_response_json(r)) == NULL ||
	    json_check_str(blob, "status", "success") < 0) {
		warnx("%s: json", __func__);
		ok = -1;
	}

	if (blob)
		json_decref(blob);

	return ok;
}

static int
webauthn_assert_encode_authdata(const fido_assert_t *assert, char **out)
{
	cbor_item_t		*body = NULL;
	const unsigned char	*ptr;
	size_t			 len;
	int			 ok = -1;
	struct cbor_load_result	 cbor;

	*out = NULL;

	if ((body = cbor_load(fido_assert_authdata_ptr(assert, 0),
	    fido_assert_authdata_len(assert, 0), &cbor)) == NULL) {
		warnx("%s: cbor_load", __func__);
		goto fail;
	}

	if (cbor_isa_bytestring(body) == false ||
	    (ptr = cbor_bytestring_handle(body)) == NULL ||
	    (len = cbor_bytestring_length(body)) == 0) {
		warnx("%s: cbor_bytestring", __func__);
		goto fail;
	}

	if (base64_encode(ptr, len, out) < 0) {
		warnx("%s: base64_encode", __func__);
		goto fail;
	}

	ok = 0;
fail:
	if (body)
		cbor_decref(&body);

	return ok;
}

static int
webauthn_assert_encode_clientdata(const char *clientdata, char **out)
{
	if (base64_encode(clientdata, strlen(clientdata), out) < 0) {
		warnx("%s: base64_encode", __func__);
		return -1;
	}

	return 0;
}

static int
webauthn_assert_encode_cred_id(const fido_assert_t *assert, char **out)
{
	const void	*ptr = fido_assert_id_ptr(assert, 0);
	const size_t	 len = fido_assert_id_len(assert, 0);

	if (base64_encode(ptr, len, out) < 0) {
		warnx("%s: base64_encode", __func__);
		return -1;
	}

	return 0;
}

static int
webauthn_assert_encode_sig(const fido_assert_t *assert, char **out)
{
	const void	*ptr = fido_assert_sig_ptr(assert, 0);
	const size_t	 len = fido_assert_sig_len(assert, 0);

	if (base64_encode(ptr, len, out) < 0) {
		warnx("%s: base64_encode", __func__);
		return -1;
	}

	return 0;
}

static int
webauthn_assert_build_response(const struct webauthn_assert *wa, char **out)
{
	char	*authdata = NULL;
	char	*clientdata = NULL;
	char	*cred_id = NULL;
	char	*response = NULL;
	char	*sig = NULL;
	int	 n;
	int	 ok = -1;

	*out = NULL;

	if (webauthn_assert_encode_authdata(wa->assert, &authdata) < 0 ||
	    webauthn_assert_encode_clientdata(wa->clientdata, &clientdata) < 0 ||
	    webauthn_assert_encode_cred_id(wa->assert, &cred_id) < 0 ||
	    webauthn_assert_encode_sig(wa->assert, &sig) < 0) {
		warnx("%s: webauthn_assert_encode", __func__);
		goto fail;
	}

	if ((response = calloc(1, MAX_RESPONSE_LEN)) == NULL) {
		warnx("%s: calloc", __func__);
		goto fail;
	}

	n = snprintf(response, MAX_RESPONSE_LEN, "{\"requestId\":\"%s\","
	    "\"assertion\":{\"credentialId\":\"%s\",\"authenticatorData\":"
	    "\"%s\",\"clientDataJSON\":\"%s\",\"signature\":\"%s\"}}",
	    wa->request_id, cred_id, authdata, clientdata, sig);

	if (n < 0 || (size_t)n >= MAX_RESPONSE_LEN) {
		warnx("%s: snprintf", __func__);
		goto fail;
	}

	*out = response;
	response = NULL;
	ok = 0;
fail:
	free(authdata);
	free(clientdata);
	free(cred_id);
	free(response);
	free(sig);

	return ok;
}

int
webauthn_assert_finish(struct webauthn_assert *wa)
{
	char	*body = NULL;
	int	 ok = -1;

	if (webauthn_assert_build_response(wa, &body) < 0) {
		warnx("%s: webauthn_assert_build_response", __func__);
		goto fail;
	}

	if (http_request(&wa->finish, AUTH_FINISH_URL, body,
	    http_response_cookie(wa->begin)) < 0) {
		warnx("%s: http_request", __func__);
		goto fail;
	}

	if (webauthn_assert_finish_parse_response(wa->finish) < 0) {
		warnx("%s: webauthn_assert_finish_parse_response", __func__);
		goto fail;
	}

	ok = 0;
fail:
	free(body);

	return ok;
}
