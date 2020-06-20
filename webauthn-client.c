/*
 * Copyright (c) 2020 Pedro Martelletto. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <err.h>
#include <fido.h>
#include <stdlib.h>
#include <string.h>

#include "clientdata.h"
#include "http.h"
#include "webauthn-assert.h"
#include "webauthn-cred.h"

static void
usage(void)
{
	fprintf(stderr, "usage: webauthn_client <dev>\n");
	exit(1);
}

static char *
registration(fido_dev_t *token)
{
	struct webauthn_cred	*wc;
	char			*cookie = NULL;

	if ((wc = webauthn_cred_new()) == NULL) {
		warnx("%s: webauthn_cred_new", __func__);
		goto fail;
	}

	if (webauthn_cred_begin(wc) < 0) {
		warnx("%s: webauthn_cred_begin", __func__);
		goto fail;
	}

	if (webauthn_cred_make_cred(wc, token) < 0) {
		warnx("%s: webauthn_cred_make_cred", __func__);
		goto fail;
	}

	if (webauthn_cred_finish(wc) < 0) {
		warnx("%s: webauthn_cred_finish", __func__);
		goto fail;
	}

	if ((cookie = strdup(webauthn_cred_session_cookie(wc))) == NULL) {
		warnx("%s: strdup", __func__);
		goto fail;
	}

fail:
	webauthn_cred_free(&wc);

	return cookie;

}

static int
authentication(fido_dev_t *token, const char *cookie)
{
	struct webauthn_assert	*wa;
	int			 ok = -1;

	if ((wa = webauthn_assert_new()) == NULL) {
		warnx("%s: webauthn_assert_new", __func__);
		goto fail;
	}

	if (webauthn_assert_begin(wa, cookie) < 0) {
		warnx("%s: webauthn_assert_begin", __func__);
		goto fail;
	}

	if (webauthn_assert_get(wa, token) < 0) {
		warnx("%s: webauthn_assert_get_assert", __func__);
		goto fail;
	}

	if (webauthn_assert_finish(wa) < 0) {
		warnx("%s: webauthn_assert_finish", __func__);
		goto fail;
	}

	ok = 0;
fail:
	webauthn_assert_free(&wa);

	return ok;
}

int
main(int argc, char **argv)
{
	fido_dev_t	*dev;
	char		*cookie;

	if (argc != 2)
		usage();

	fido_init(0);
	http_init();

	if ((dev = fido_dev_new()) == NULL)
		errx(1, "fido_dev_new");

	if (fido_dev_open(dev, argv[1]) != FIDO_OK)
		errx(1, "fido_dev_open");

	if ((cookie = registration(dev)) == NULL)
		errx(1, "%s: registration", __func__);

	if (authentication(dev, cookie) < 0)
		errx(1, "%s: authentication", __func__);

	fido_dev_close(dev);
	fido_dev_free(&dev);
	free(cookie);

	exit(0);
}
