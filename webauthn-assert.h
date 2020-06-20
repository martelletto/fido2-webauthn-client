/*
 * Copyright (c) 2020 Pedro Martelletto. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#ifndef _WEBAUTHN_ASSERT_H_
#define _WEBAUTHN_ASSERT_H_

#include <fido.h>

struct webauthn_assert	*webauthn_assert_new(void);
void			 webauthn_assert_free(struct webauthn_assert **);
int			 webauthn_assert_begin(struct webauthn_assert *, const char *);
int			 webauthn_assert_get(struct webauthn_assert *, fido_dev_t *);
int			 webauthn_assert_finish(struct webauthn_assert *);

#endif
