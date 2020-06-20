/*
 * Copyright (c) 2020 Pedro Martelletto. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#ifndef _WEBAUTHN_CRED_H_
#define _WEBAUTHN_CRED_H_

struct webauthn_cred	*webauthn_cred_new(void);
void			 webauthn_cred_free(struct webauthn_cred **);
int			 webauthn_cred_begin(struct webauthn_cred *);
int			 webauthn_cred_make_cred(struct webauthn_cred *, fido_dev_t *);
int			 webauthn_cred_finish(struct webauthn_cred *);
const char		*webauthn_cred_session_cookie(const struct webauthn_cred *);

#endif
