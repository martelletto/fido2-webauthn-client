/*
 * Copyright (c) 2020 Pedro Martelletto. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#ifndef _HTTP_H_
#define _HTTP_H_

#include <jansson.h>

struct http_post;

int			 http_init(void);
int			 http_set_cookie(struct http_post *, const char *);
int			 http_post(struct http_post *);
int			 http_request(struct http_post **, const char *, const char *, const char *);
void			 http_exit(void);
void			 http_free(struct http_post **);
struct http_post	*http_new(const char *, const char *);
const char		*http_response(const struct http_post *);
const char		*http_response_cookie(const struct http_post *);
json_t			*http_response_json(struct http_post *);

#endif
