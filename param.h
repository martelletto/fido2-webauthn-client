/*
 * Copyright (c) 2020 Pedro Martelletto. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#define RP_ID			"demo.yubico.com"
#define TRANSPORT		"https://"
#define ORIGIN			TRANSPORT RP_ID

#define REGISTER_BEGIN_BODY	"{\"userVerification\":\"discouraged\"}"
#define REGISTER_BEGIN_URL	ORIGIN "/api/v1/simple/webauthn/register-begin"
#define REGISTER_FINISH_URL	ORIGIN "/api/v1/simple/webauthn/register-finish"

#define AUTH_BEGIN_BODY		"{\"userVerification\":\"discouraged\"}"
#define AUTH_BEGIN_URL		ORIGIN "/api/v1/simple/webauthn/authenticate-begin"
#define AUTH_FINISH_URL		ORIGIN "/api/v1/simple/webauthn/authenticate-finish"

#define MAX_RESPONSE_LEN	8192
#define MAX_CLIENTDATA_JSON_LEN	512
#define MIN_CHALLENGE_LEN	32
