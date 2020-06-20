/*
 * Copyright (c) 2020 Pedro Martelletto. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <stdlib.h>
#include <string.h>
#include <err.h>

#include <fido.h>
#include <jansson.h>
#include <openssl/sha.h>

#include "base64.h"
#include "cbor.h"
#include "clientdata.h"
#include "http.h"
#include "json.h"
#include "param.h"
#include "webauthn-cred.h"

struct webauthn_cred {
	fido_cred_t		*cred;
	char			*clientdata;
	char			*request_id;
	struct http_post	*begin;
	struct http_post	*finish;
};

struct webauthn_cred *
webauthn_cred_new(void)
{
	struct webauthn_cred *wc;

	if ((wc = calloc(1, sizeof(*wc))) == NULL) {
		warnx("%s: calloc", __func__);
		return NULL;
	}

	if ((wc->cred = fido_cred_new()) == NULL) {
		warnx("%s: fido_cred_new", __func__);
		webauthn_cred_free(&wc);
	}

	return wc;
}

void
webauthn_cred_free(struct webauthn_cred **wcp)
{
	struct webauthn_cred *wc;

	if (wcp == NULL || (wc = *wcp) == NULL)
		return;

	fido_cred_free(&wc->cred);
	free(wc->clientdata);
	free(wc->request_id);
	http_free(&wc->begin);
	http_free(&wc->finish);
	free(wc);
	*wcp = NULL;
}

static int
webauthn_cred_begin_parse_response(struct webauthn_cred *wc)
{
	json_t	*blob;
	json_t	*data;
	json_t	*pubkey;
	json_t	*user;
	json_t	*rp;
	char	*challenge = NULL;
	char	*display_name = NULL;
	char	*rp_name = NULL;
	char	*user_name = NULL;
	void	*user_id_ptr = NULL;
	size_t	 user_id_len;
	int	 ok = -1;

	if ((blob = http_response_json(wc->begin)) == NULL ||
	    json_check_str(blob, "status", "success") < 0 ||
	    (data = json_parse_obj(blob, "data")) == NULL) {
		warnx("%s: json", __func__);
		goto fail;
	}

	if ((pubkey = json_parse_obj(data, "publicKey")) == NULL ||
	    (wc->request_id = json_parse_str(data, "requestId")) == NULL) {
		warnx("%s: json data", __func__);
		goto fail;
	}

	if ((challenge = json_parse_str(pubkey, "challenge")) == NULL ||
	    (user = json_parse_obj(pubkey, "user")) == NULL ||
	    (rp = json_parse_obj(pubkey, "rp")) == NULL) {
		warnx("%s: json publicKey", __func__);
		goto fail;
	}

	if (json_parse_blob(user, "id", &user_id_ptr, &user_id_len) < 0 ||
	    (user_name = json_parse_str(user, "name")) == NULL ||
	    (display_name = json_parse_str(user, "displayName")) == NULL) {
		warnx("%s: json user", __func__);
		goto fail;
	}

	if (json_check_str(rp, "id", RP_ID) < 0 ||
	    (rp_name = json_parse_str(rp, "name")) == NULL) {
		warnx("%s: json rp", __func__);
		goto fail;
	}

	if ((wc->clientdata = clientdata_json("webauthn.create",
	    challenge)) == NULL) {
		warnx("%s: json", __func__);
		goto fail;
	}

	if (fido_cred_set_rp(wc->cred, RP_ID, rp_name) != FIDO_OK) {
		warnx("%s: fido_cred_set_rp", __func__);
		goto fail;
	}

	if (fido_cred_set_user(wc->cred, user_id_ptr, user_id_len, user_name,
	    display_name, NULL) != FIDO_OK) {
		warnx("%s: fido_cred_set_user", __func__);
		goto fail;
	}

	ok = 0;
fail:
	if (blob)
		json_decref(blob);

	free(challenge);
	free(display_name);
	free(rp_name);
	free(user_name);
	free(user_id_ptr);

	return ok;
}

int
webauthn_cred_begin(struct webauthn_cred *wc)
{
	if (http_request(&wc->begin, REGISTER_BEGIN_URL, REGISTER_BEGIN_BODY,
	    NULL) < 0) {
		warnx("%s: http_request", __func__);
		return -1;
	}

	if (webauthn_cred_begin_parse_response(wc) < 0) {
		warnx("%s: webauthn_cred_begin_parse_response", __func__);
		return -1;
	}

	return 0;
}

int
webauthn_cred_make_cred(struct webauthn_cred *wc, fido_dev_t *token)
{
	uint8_t	dgst[SHA256_DIGEST_LENGTH];
	int	status;

	if (SHA256((const uint8_t *)wc->clientdata, strlen(wc->clientdata),
	    dgst) != dgst) {
		warnx("%s: SHA256", __func__);
		return -1;
	}

	if (fido_cred_set_clientdata_hash(wc->cred, dgst,
	    sizeof(dgst)) != FIDO_OK) {
		warnx("%s: fido_cred_set_clientdata_hash", __func__);
		return -1;
	}

	if (fido_cred_set_type(wc->cred, COSE_ES256) != FIDO_OK) {
		warnx("%s: fido_cred_set_type", __func__);
		return -1;
	}

	status = fido_dev_make_cred(token, wc->cred, NULL);

	if (status == FIDO_ERR_PIN_REQUIRED) {
		fido_dev_force_u2f(token);
		status = fido_dev_make_cred(token, wc->cred, NULL);
	}

	if (status != FIDO_OK) {
		warnx("%s: fido_dev_make_cred: %s", __func__,
		    fido_strerr(status));
		return -1;
	}

	return 0;
}

static int
webauthn_cred_finish_parse_response(struct http_post *wc)
{
	json_t	*blob;
	int	 ok = 0;

	if ((blob = http_response_json(wc)) == NULL ||
	    json_check_str(blob, "status", "success") < 0) {
		warnx("%s: json", __func__);
		ok = -1;
	}

	if (blob)
		json_decref(blob);

	return ok;
}

static int
webauthn_cred_build_response(const struct webauthn_cred *wc, char **out)
{
	char	*attobj = NULL;
	char	*clientdata = NULL;
	char	*response = NULL;
	int	 n;
	int	 ok = -1;

	*out = NULL;

	if (fido_cred_user_name(wc->cred) == NULL ||
	    fido_cred_display_name(wc->cred) == NULL) {
		warnx("%s: fido_cred", __func__);
		goto fail;
	}

	if ((attobj = cbor_build_attestation_object(wc->cred)) == NULL) {
		warnx("%s: cbor_build_attestation_object", __func__);
		goto fail;
	}

	if (base64_encode(wc->clientdata, strlen(wc->clientdata),
	    &clientdata) < 0) {
		warnx("%s: base64_encode_str" , __func__);
		goto fail;
	}

	if ((response = calloc(1, MAX_RESPONSE_LEN)) == NULL) {
		warnx("%s: calloc", __func__);
		goto fail;
	}

	n = snprintf(response, MAX_RESPONSE_LEN, "{\"requestId\":\"%s\","
	    "\"username\":\"%s\",\"displayName\":\"%s\",\"icon\":null,"
	    "\"attestation\":{\"attestationObject\":\"%s\",\""
	    "clientDataJSON\":\"%s\"}}", wc->request_id,
	    fido_cred_user_name(wc->cred), fido_cred_display_name(wc->cred),
	    attobj, clientdata);

	if (n < 0 || (size_t)n >= MAX_RESPONSE_LEN) {
		warnx("%s: snprintf", __func__);
		goto fail;
	}

	*out = response;
	response = NULL;
	ok = 0;
fail:
	free(attobj);
	free(clientdata);
	free(response);

	return ok;
}

int
webauthn_cred_finish(struct webauthn_cred *wc)
{
	char	*body = NULL;
	int	 ok = -1;

	if (webauthn_cred_build_response(wc, &body) < 0) {
		warnx("%s: webauthn_cred_build_response", __func__);
		goto fail;
	}

	if (http_request(&wc->finish, REGISTER_FINISH_URL, body,
	    http_response_cookie(wc->begin)) < 0) {
		warnx("%s: http_request", __func__);
		goto fail;
	}

	if (webauthn_cred_finish_parse_response(wc->finish) < 0) {
		warnx("%s: webauthn_cred_finish_parse_response", __func__);
		goto fail;
	}

	ok = 0;
fail:
	free(body);

	return ok;
}

const char *
webauthn_cred_session_cookie(const struct webauthn_cred *wc)
{
	return http_response_cookie(wc->finish);
}
