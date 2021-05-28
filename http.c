/*
 * Copyright (c) 2020 Pedro Martelletto. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>

#include "http.h"
#include "param.h"

#define HTTP_CONTENT_TYPE	"Content-Type: application/json"

struct http_post {
	char			*url;
	char			*request;
	char			*request_cookie;
	char			*response;
	char			*response_cookie;
	CURL			*curl;
	FILE			*fp;
	struct curl_slist	*header;
};

static size_t
sink(void *body, size_t size, size_t nmemb, void *p)
{
	return fwrite(body, size, nmemb, (FILE *)p);
}

int
http_init(void)
{
	if (curl_global_init(CURL_GLOBAL_DEFAULT) != 0) {
		warnx("%s: curl_global_init", __func__);
		return -1;
	}

	return 0;
}

void
http_exit(void)
{
	curl_global_cleanup();
}

struct http_post *
http_new(const char *url, const char *request)
{
	struct http_post	*h;
	int			 ok = -1;

	if ((h = calloc(1, sizeof(*h))) == NULL) {
		warnx("%s: calloc http", __func__);
		return NULL;
	}

	if ((h->url = strdup(url)) == NULL) {
		warnx("%s: strdup url", __func__);
		goto fail;
	}

	if ((h->request = strdup(request)) == NULL) {
		warnx("%s: strdup request", __func__);
		goto fail;
	}

	if ((h->response = calloc(1, MAX_RESPONSE_LEN)) == NULL) {
		warnx("%s: calloc response", __func__);
		goto fail;
	}

	if ((h->curl = curl_easy_init()) == NULL) {
		warnx("%s: curl_easy_init", __func__);
		goto fail;
	}

	if ((h->header = curl_slist_append(NULL, HTTP_CONTENT_TYPE)) == NULL) {
		warnx("%s: curl_slist_append", __func__);
		goto fail;
	}

	if (curl_easy_setopt(h->curl, CURLOPT_HTTPHEADER, h->header) != 0 ||
	    curl_easy_setopt(h->curl, CURLOPT_URL, h->url) != 0 ||
	    curl_easy_setopt(h->curl, CURLOPT_POSTFIELDS, h->request) != 0 ||
	    curl_easy_setopt(h->curl, CURLOPT_COOKIEFILE, "") != 0) {
		warnx("%s: curl_easy_setopt", __func__);
		goto fail;
	}

	ok = 0;
fail:
	if (ok < 0)
		http_free(&h);

	return h;
}

void
http_free(struct http_post **hp)
{
	struct http_post *h;

	if (hp == NULL || (h = *hp) == NULL)
		return;

	free(h->url);
	free(h->request);
	free(h->request_cookie);
	free(h->response);
	free(h->response_cookie);

	if (h->curl)
		curl_easy_cleanup(h->curl);
	if (h->header)
		curl_slist_free_all(h->header);

	free(h);
	*hp = NULL;
}

int
http_set_cookie(struct http_post *h, const char *cookie)
{
	if (h->request_cookie) {
		warnx("%s: cookie set", __func__);
		return -1;
	}

	if ((h->request_cookie = strdup(cookie)) == NULL) {
		warnx("%s: strdup", __func__);
		return -1;
	}

	if (curl_easy_setopt(h->curl, CURLOPT_COOKIELIST,
	    h->request_cookie) != 0) {
		warnx("%s: curl_easy_setopt", __func__);
		free(h->request_cookie);
		h->request_cookie = NULL;
		return -1;
	}

	return 0;
}

int
http_post(struct http_post *h)
{
	CURLcode		 r;
	int			 ok = -1;
	struct curl_slist	*cookie = NULL;

	if ((h->fp = fmemopen(h->response, MAX_RESPONSE_LEN, "w")) == NULL) {
		warnx("%s: fmemopen", __func__);
		return -1;
	}

	if (curl_easy_setopt(h->curl, CURLOPT_WRITEFUNCTION, sink) != 0 ||
	    curl_easy_setopt(h->curl, CURLOPT_WRITEDATA, h->fp) != 0) {
		warnx("%s: curl_easy_setopt", __func__);
		goto fail;
	}

	if ((r = curl_easy_perform(h->curl)) != CURLE_OK) {
		warnx("%s: curl_easy_perform: %s", __func__,
		    curl_easy_strerror(r));
		goto fail;
	}

	if (curl_easy_getinfo(h->curl, CURLINFO_COOKIELIST, &cookie) != 0) {
		warnx("%s: curl_easy_getinfo", __func__);
		goto fail;
	}

	if (cookie == NULL || cookie->data == NULL) {
		warnx("%s: response cookie", __func__);
		goto fail;
	}

	if ((h->response_cookie = strdup(cookie->data)) == NULL) {
		warnx("%s: strdup", __func__);
		goto fail;
	}

	ok = 0;
fail:
	fclose(h->fp);
	h->fp = NULL;

	if (cookie)
		curl_slist_free_all(cookie);

	return ok;
}

int
http_request(struct http_post **h, const char *url, const char *body,
    const char *cookie)
{
	json_t		*blob;
	json_error_t	 error;

	warnx("%s: %s", __func__, url);

	if ((blob = json_loads(body, 0, &error)) == NULL) {
		warnx("%s: json_loads", __func__);
		return -1;
	}

	if (json_dumpf(blob, stderr, JSON_INDENT(2)) < 0)
		warnx("%s: json_dumpf", __func__);
	else
		fputc('\n', stderr);

	json_decref(blob);
	blob = NULL;

	if ((*h = http_new(url, body)) == NULL) {
		warnx("%s: http_new", __func__);
		return -1;
	}

	if (cookie && http_set_cookie(*h, cookie) < 0) {
		warnx("%s: http_set_cookie", __func__);
		return -1;
	}

	if (http_post(*h) < 0) {
		warnx("%s: http_post", __func__);
		return -1;
	}

	return 0;
}

const char *
http_response(const struct http_post *h)
{
	return h->response;
}

const char *
http_response_cookie(const struct http_post *h)
{
	return h->response_cookie;
}

json_t *
http_response_json(struct http_post *h)
{
	json_error_t	 error;
	json_t		*blob;

	warnx("%s: %s", __func__, h->url);

	if ((blob = json_loads(h->response, JSON_DECODE_INT_AS_REAL,
	    &error)) == NULL) {
		warnx("%s: json_loads", __func__);
		return NULL;
	}

	if (json_is_object(blob) == 0) {
		warnx("%s: json_is_object", __func__);
		json_decref(blob);
		return NULL;
	}

	if (json_dumpf(blob, stderr, JSON_INDENT(2)) < 0)
		warnx("%s: json_dumpf", __func__);
	else
		fputc('\n', stderr);

	return blob;
}
