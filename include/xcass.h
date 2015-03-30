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

#define XCASS_SETTINGS_REGEX \
            "([a-zA-Z_]+)[[:space:]]{0,}?=[[:space:]]{0,}?([a-zA-Z0-9.]+)"

typedef struct xcass_type_mapping_t {
    const char *name;
    CassValueType type;
    //CassValueType key;    
    //CassValueType value;
} xcass_type_mapping_t;

typedef struct _xcass_t {
    CassCluster *cluster;
    CassSession *session;
    CassFuture *connect;
    CassFuture *close;
    char *last_error;
    /**
     *  default query consistency &page size
     */
    CassConsistency consistency;
    int page_size;
} xcass_t;

typedef struct _xcass_query_t {
    xcass_t *xs;
    CassConsistency consistency;
    int page_size;
    CassError rc;
    CassFuture *future;
    CassStatement *statement;
    const CassResult *result;
} xcass_query_t;

typedef struct _xcass_row_t {
    xcass_query_t *query;
    const CassRow *row;
    CassIterator *iterator;
} xcass_row_t;

typedef struct _xcass_custom_t {
    cass_size_t size;
    cass_byte_t **output;
} xcass_custom_t;

CASS_EXPORT const char *
xcass_last_error(xcass_t *xs);

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

void
xcass_auth(xcass_t *xs,
           const char *username,
           const char *password);

CASS_EXPORT xcass_query_t *
xcass_query(xcass_t *xs,
            const char *fmt, ...);

CASS_EXPORT xcass_query_t *
xcass_query_nobind(xcass_t *xs,
                   const char *fmt, ...);

CASS_EXPORT void
xcass_query_free(xcass_query_t *query);

CASS_EXPORT void
xcass_query_consistency(xcass_query_t *query,
                        CassConsistency consistency);

CASS_EXPORT void
xcass_query_page_size(xcass_query_t *query,
                      int page_size);

CASS_EXPORT int
xcass_statement(xcass_query_t *query,
                char *cql,
                unsigned int argc);

CASS_EXPORT CassValueType
xcass_get_type_byname(const char *name);

CASS_EXPORT int
xcass_bind(xcass_t *xs,
           xcass_query_t *query,
           xcass_type_mapping_t *types,
           unsigned int count,
           va_list ap);

CASS_EXPORT CassError
xcass_execute(xcass_t *xs, xcass_query_t *query);

CASS_EXPORT int
xcass_query_has_more_pages(xcass_query_t *query);

CASS_EXPORT xcass_row_t *
xcass_first_row(xcass_query_t *query);

CASS_EXPORT void
xcass_row_free(xcass_row_t *row);

#define xcass_foreach(q, r)                                 \
    if(!r) {                                                \
        r = (xcass_row_t *) malloc(sizeof(*r));             \
        r->row = NULL;                                      \
        r->query = q;                                       \
    }                                                       \
    r->iterator = cass_iterator_from_result(q->result);     \
    if(q->future) {                                         \
        cass_future_free(q->future);                        \
        q->future = NULL;                                   \
    }                                                       \
    while(cass_iterator_next(r->iterator))

CASS_EXPORT cass_size_t
xcass_count(xcass_query_t *query);

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
cs_iget_type(xcass_row_t *r,
             unsigned int index);

CASS_EXPORT CassString *
xcass_get_string(xcass_row_t *r,
                 const char *name);

CASS_EXPORT CassString *
xcass_iget_string(xcass_row_t *r,
                  unsigned int index);

CASS_EXPORT char *
xcass_get_string_dup(xcass_row_t *r,
                     const char *name);

CASS_EXPORT char *
xcass_iget_string_dup(xcass_row_t *r,
                      unsigned int index);

CASS_EXPORT cass_double_t
xcass_get_double(xcass_row_t *r,
                 const char *name);

CASS_EXPORT cass_double_t
xcass_iget_double(xcass_row_t *r,
                  unsigned int index);

CASS_EXPORT cass_int32_t
xcass_get_int(xcass_row_t *r,
              const char *name);

CASS_EXPORT cass_int32_t
xcass_iget_int(xcass_row_t *r,
               unsigned int index);

CASS_EXPORT cass_int64_t
xcass_get_bigint(xcass_row_t *r,
                 const char *name);

CASS_EXPORT cass_int64_t
xcass_iget_bigint(xcass_row_t *r,
                  unsigned int index);

CASS_EXPORT cass_bool_t
xcass_get_boolean(xcass_row_t *r,
                  const char *name);

CASS_EXPORT cass_bool_t
xcass_iget_boolean(xcass_row_t *r,
                   unsigned int index);

CASS_EXPORT CassBytes *
xcass_get_bytes(xcass_row_t *r,
                const char *name);

CASS_EXPORT CassBytes *
xcass_iget_bytes(xcass_row_t *r,
                 unsigned int index);

CASS_EXPORT CassUuid *
xcass_get_uuid(xcass_row_t *r,
               const char *name);

CASS_EXPORT CassUuid *
xcass_iget_uuid(xcass_row_t *r,
                unsigned int index);

CASS_EXPORT char *
xcass_get_string_uuid(xcass_row_t *r,
                      const char *name);

CASS_EXPORT char *
xcass_iget_string_uuid(xcass_row_t *r,
                       unsigned int index);

/**
 *  extra...
 */
CASS_EXPORT cass_int64_t
xcass_string_uuid_timestamp(const char *s);

#endif