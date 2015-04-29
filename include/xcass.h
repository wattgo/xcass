/*
  Copyright (c) 2015 WattGo

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

#ifndef _XCASS_H_
#define _XCASS_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <regex.h>
#include <inttypes.h>
#include <math.h>

#include <cassandra.h>


#ifndef XCASS_FIELD_DELIM_LEFT
#define XCASS_FIELD_DELIM_LEFT      '<'
#endif

#ifndef XCASS_FIELD_DELIM_RIGHT
#define XCASS_FIELD_DELIM_RIGHT     '>'
#endif

#define XCASS_SETTINGS_REGEX \
            "([a-zA-Z_]+)[[:space:]]{0,}?=[[:space:]]{0,}?([a-zA-Z0-9.]+)"

typedef struct {
  const char *name;
  CassValueType type;
  //CassValueType key;    
  //CassValueType value;
} xcass_type_mapping_t;

typedef struct {
  CassCluster *cluster;
  CassSession *session;
  char *last_error;
  CassConsistency consistency;
  int page_size;
} xcass_t;

typedef struct {
  xcass_t *xs;
  CassConsistency consistency;
  int page_size;
  CassStatement *statement;
  const CassResult *result;
  const CassPrepared *prepared;
  char *cql;
  xcass_type_mapping_t *types;
  unsigned int argc;
} xcass_query_t;

typedef struct {
  const CassRow *row;
  CassIterator *iterator;
} xcass_row_t;

typedef struct {
  cass_size_t size;
  cass_byte_t **output;
} xcass_custom_t;

typedef struct {
  CassBatch *handle;
  CassFuture *future;
} xcass_batch_t;


/**
 * xcass.c
 */
CASS_EXPORT xcass_t *
xcass_create(const char *hosts,
             unsigned int port);

CASS_EXPORT CassError
xcass_connect(xcass_t *xs,
              const char *keyspace);

CASS_EXPORT void
xcass_close(xcass_t *xs);

CASS_EXPORT void
xcass_cleanup(xcass_t *xs);

CASS_EXPORT void
xcass_log_level(const char *level);

CASS_EXPORT void
xcass_settings(xcass_t *xs,
               const char *settings, ...);

CASS_EXPORT void
xcass_auth(xcass_t *xs,
           const char *username,
           const char *password);

/**
 * batch.c
 */

CASS_EXPORT void
xcass_batch_add(CassBatch *batch,
                xcass_query_t *query);

CASS_EXPORT CassError
xcass_batch_execute(xcass_t *xs,
                    CassBatch *batch);


/**
 * query.c
 */
CASS_EXPORT xcass_query_t *
xcass_query_new(xcass_t *xs);

CASS_EXPORT xcass_query_t *
xcass_query(xcass_t *xs,
            const char *fmt, ...);

CASS_EXPORT xcass_query_t *
xcass_prepare(xcass_t *xs,
              const char *cql);

CASS_EXPORT int
xcass_query_parse(xcass_query_t *query,
                  const char *cql);

CASS_EXPORT CassError
xcass_bind(xcass_query_t *query, ...);

CASS_EXPORT CassError
xcass_ibind(xcass_query_t *query,
            unsigned int index, ...);

CASS_EXPORT CassError
xcass_query_ibind(xcass_query_t *query,
                  unsigned int index,
                  va_list ap);

CASS_EXPORT xcass_query_t *
xcass_query_nobind(xcass_t *xs,
                   const char *cql);

CASS_EXPORT void
xcass_query_free(xcass_query_t *query);

CASS_EXPORT void
xcass_query_consistency(xcass_query_t *query,
                        CassConsistency consistency);

CASS_EXPORT void
xcass_query_page_size(xcass_query_t *query,
                      int page_size);

CassStatement *
xcass_new_statement(xcass_query_t *query);

CASS_EXPORT CassError
xcass_execute(xcass_t *xs, xcass_query_t *query);

CASS_EXPORT int
xcass_query_has_more_pages(xcass_query_t *query);


/**
 * row.c
 */
#define xcass_foreach(q, r)                               \
  if(!r) {                                                \
    r = (xcass_row_t *) malloc(sizeof(*r));             \
    r->row = NULL;                                      \
  }                                                       \
  r->iterator = cass_iterator_from_result(q->result);     \
  while(cass_iterator_next(r->iterator))
      
CASS_EXPORT xcass_row_t *
xcass_first_row(xcass_query_t *query);

CASS_EXPORT void
xcass_row_free(xcass_row_t *row);

CASS_EXPORT cass_size_t
xcass_count(xcass_query_t *query);


/**
 * getter.c
 */
CASS_EXPORT CassIterator *
xcass_get_map(xcass_row_t *r,
              const char *name);

CASS_EXPORT CassIterator *
xcass_iget_map(xcass_row_t *r,
               unsigned int index);

CASS_EXPORT CassIterator *
xcass_get_collection(xcass_row_t *r,
                     const char *name);

CASS_EXPORT CassIterator *
xcass_iget_collection(xcass_row_t *r,
                      unsigned int index);

CASS_EXPORT unsigned int
xcass_collection_count(xcass_row_t *r,
                       const char *name);

CASS_EXPORT unsigned int
xcass_icollection_count(xcass_row_t *r,
                        unsigned int index);

CASS_EXPORT const CassValue *
xcass_get_value(xcass_row_t *r,
                const char *name);

CASS_EXPORT const CassValue *
xcass_iget_value(xcass_row_t *,
                 unsigned int index);

CASS_EXPORT CassValueType
xcass_get_type(xcass_row_t *r,
               const char *name);

CASS_EXPORT CassValueType
xcass_iget_type(xcass_row_t *r,
                unsigned int index);

CASS_EXPORT CassError
xcass_get_string(xcass_row_t *r,
                 const char *name,
                 CassString *s);

CASS_EXPORT CassError
xcass_iget_string(xcass_row_t *r,
                  unsigned int index,
                  CassString *s);

CASS_EXPORT CassError
xcass_get_string_dup(xcass_row_t *r,
                     const char *name,
                     char **dest);

CASS_EXPORT CassError
xcass_iget_string_dup(xcass_row_t *r,
                      unsigned int index,
                      char **dest);

CASS_EXPORT CassError
xcass_get_double(xcass_row_t *r,
                 const char *name,
                 cass_double_t *d);

CASS_EXPORT CassError
xcass_iget_double(xcass_row_t *r,
                  unsigned int index,
                  cass_double_t *d);

CASS_EXPORT CassError
xcass_get_int(xcass_row_t *r,
              const char *name,
              cass_int32_t *i);

CASS_EXPORT CassError
xcass_iget_int(xcass_row_t *r,
               unsigned int index,
               cass_int32_t *i);

CASS_EXPORT CassError
xcass_get_bigint(xcass_row_t *r,
                 const char *name,
                 cass_int64_t *i);

CASS_EXPORT CassError
xcass_iget_bigint(xcass_row_t *r,
                  unsigned int index,
                  cass_int64_t *i);

CASS_EXPORT CassError
xcass_get_boolean(xcass_row_t *r,
                  const char *name,
                  cass_bool_t *b);

CASS_EXPORT CassError
xcass_iget_boolean(xcass_row_t *r,
                   unsigned int index,
                   cass_bool_t *b);

CASS_EXPORT CassError
xcass_get_bytes(xcass_row_t *r,
                const char *name,
                CassBytes *bytes);

CASS_EXPORT CassError
xcass_iget_bytes(xcass_row_t *r,
                 unsigned int index,
                 CassBytes *bytes);

CASS_EXPORT CassError
xcass_get_uuid(xcass_row_t *r,
               const char *name,
               CassUuid *uuid);

CASS_EXPORT CassError
xcass_iget_uuid(xcass_row_t *r,
                unsigned int index,
                CassUuid *uuid);

CASS_EXPORT CassError
xcass_get_uuid_string_dup(xcass_row_t *r,
                          const char *name,
                          char **dest);

CASS_EXPORT CassError
xcass_iget_uuid_string_dup(xcass_row_t *r,
                           unsigned int index,
                           char **dest);

/**
 *  extra...
 */
CASS_EXPORT cass_int64_t
xcass_string_uuid_timestamp(const char *s);

#endif