/*
 * Copyright (c) 2020 Pedro Martelletto. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base64.h"
#include "clientdata.h"
#include "param.h"

char *
clientdata_json(const char *type, const char *challenge)
{
	char	 buf[MAX_CLIENTDATA_JSON_LEN];
	int	 n;
	int	 ok = -1;
	void	*ptr = NULL;
	size_t	 len = 0;

	memset(buf, 0, sizeof(buf));

	if (base64_decode(challenge, &ptr, &len) < 0 || len < 32) {
		warnx("%s: challenge", __func__);
		goto fail;
	}

	if ((n = snprintf(buf, sizeof(buf), "{\"type\":\"%s\",\"challenge\":"
	    "\"%s\",\"origin\":\"%s\",\"crossOrigin\":false}", type, challenge,
	    ORIGIN)) < 0 || (size_t)n >= sizeof(buf)) {
		warnx("%s: snprintf", __func__);
		goto fail;
	}

	ok = 0;
fail:
	free(ptr);

	if (ok < 0)
		return NULL;

	return strdup(buf);
}
