/*
 * Copyright (c) 2020 Pedro Martelletto. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#ifndef _JSON_H_
#define _JSON_H_

json_t *	json_parse_obj(const json_t *, const char *);
char *		json_parse_str(const json_t *, const char *);
int		json_check_str(const json_t *, const char *, const char *);
int		json_parse_blob(const json_t *, const char *, void **, size_t *);
int		json_parse_allowcred(const json_t *, void **, size_t *);

#endif
