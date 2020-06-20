/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#ifndef _BASE64_H_
#define _BASE64_H_

int base64_decode(const char *, void **, size_t *);
int base64_encode(const void *, size_t, char **);

#endif
