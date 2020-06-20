/*
 * Copyright (c) 2020 Pedro Martelletto. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <err.h>
#include <jansson.h>
#include <stdlib.h>
#include <string.h>

#include "base64.h"
#include "json.h"

json_t *
json_parse_obj(const json_t *obj, const char *key)
{
	json_t *val;

	if ((val = json_object_get(obj, key)) == NULL ||
	    json_is_object(val) == 0) {
		warnx("%s: json %s", __func__, key);
		return NULL;
	}

	return val;
}

char *
json_parse_str(const json_t *obj, const char *key)
{
	json_t *val;

	if ((val = json_object_get(obj, key)) == NULL ||
	    json_is_string(val) == 0) {
		warnx("%s: json %s", __func__, key);
		return NULL;
	}

	return strdup(json_string_value(val));
}

int
json_check_str(const json_t *obj, const char *key, const char *expected_val)
{
	json_t *val;

	if ((val = json_object_get(obj, key)) == NULL ||
	    json_is_string(val) == 0 ||
	    strcmp(json_string_value(val), expected_val) != 0) {
		warnx("%s: json %s != %s", __func__, key, expected_val);
		return -1;
	}

	return 0;
}

int
json_parse_blob(const json_t *obj, const char *key, void **ptr, size_t *len)
{
	json_t *blob;

	if ((blob = json_object_get(obj, key)) == NULL ||
	    json_is_string(blob) == 0 ||
	    base64_decode(json_string_value(blob), ptr, len) < 0) {
		warnx("%s json %s", __func__, key);
		return -1;
	}

	return 0;
}
 
int
json_parse_allowcred(const json_t *obj, void **ptr, size_t *len)
{
	json_t	*allowcred;
	json_t	*cred;

	if ((allowcred = json_object_get(obj, "allowCredentials")) == NULL ||
	    json_is_array(allowcred) == 0 || json_array_size(allowcred) != 1) {
		warnx("%s: json", __func__);
		return -1;
	}

	if ((cred = json_array_get(allowcred, 0)) == NULL ||
	    json_is_object(cred) == 0) {
		warnx("%s: json cred", __func__);
		return -1;
	}

	if (json_check_str(cred, "type", "public-key") < 0 ||
	    json_parse_blob(cred, "id", ptr, len) < 0) {
		warnx("%s: json", __func__);
		return -1;
	}

	return 0;
}
