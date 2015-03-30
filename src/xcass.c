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

#include "xcass.h"

static const xcass_type_mapping_t
xcass_types_mapping[] = {
    { "custom", CASS_VALUE_TYPE_CUSTOM },
    { "ascii", CASS_VALUE_TYPE_ASCII },
    { "bigint", CASS_VALUE_TYPE_BIGINT },
    { "blob", CASS_VALUE_TYPE_BLOB },
    { "boolean", CASS_VALUE_TYPE_BOOLEAN },
    { "counter", CASS_VALUE_TYPE_COUNTER },
    { "decimal", CASS_VALUE_TYPE_DECIMAL },
    { "double", CASS_VALUE_TYPE_DOUBLE },
    { "float", CASS_VALUE_TYPE_FLOAT },
    { "inet", CASS_VALUE_TYPE_INET },
    { "int", CASS_VALUE_TYPE_INT },
    { "text", CASS_VALUE_TYPE_TEXT },
    { "timestamp", CASS_VALUE_TYPE_TIMESTAMP },
    { "timeuuid", CASS_VALUE_TYPE_TIMEUUID },
    { "uuid", CASS_VALUE_TYPE_UUID },
    { "varchar", CASS_VALUE_TYPE_VARCHAR },
    { "varint", CASS_VALUE_TYPE_VARINT },
    { "map", CASS_VALUE_TYPE_MAP },
    { "set", CASS_VALUE_TYPE_SET },
    { "list", CASS_VALUE_TYPE_LIST }
};

static const char *
xcass_collection_types[] = { "map", "list", "set", 0 };

static void
xcass_set_error(xcass_t *xs, CassFuture *future) {
    CassString message = cass_future_error_message(future);
    if(xs->last_error)
        free(xs->last_error);
    xs->last_error = strndup(message.data, message.length);
}

const char *
xcass_last_error(xcass_t *xs) {
    return xs->last_error;
}

/**
 *  xcass init related functions
 */
xcass_t *
xcass_create(const char *hosts,
             unsigned int port) {

    xcass_t *xs = (xcass_t *) malloc(sizeof(*xs));
    xs->cluster = cass_cluster_new();
    xs->session = NULL;
    xs->connect = NULL;
    xs->close = NULL;
    xs->last_error = NULL;
    xs->consistency = CASS_CONSISTENCY_ONE;
    xs->page_size = -1;
    cass_cluster_set_contact_points(xs->cluster, hosts);
    cass_cluster_set_port(xs->cluster, port);
    return xs;
}

CassError
xcass_connect(xcass_t *xs,
              const char *keyspace) {

    xs->session = cass_session_new();
    if(keyspace) 
        xs->connect = cass_session_connect_keyspace(xs->session, xs->cluster, keyspace);
    else
        xs->connect = cass_session_connect(xs->session, xs->cluster);
    cass_future_wait(xs->connect);
    CassError rc = cass_future_error_code(xs->connect);
    cass_future_free(xs->connect);
    xs->connect = NULL;
    return rc;
}

void
xcass_close(xcass_t *xs) {
    if(xs->session) {
        CassFuture *close = cass_session_close(xs->session);
        cass_future_wait(close);
        cass_future_free(close);
    }
}

void
xcass_cleanup(xcass_t *xs) {
    xcass_close(xs);
    if(xs->cluster)
        cass_cluster_free(xs->cluster);
    if(xs->session)
        cass_session_free(xs->session);
    free(xs);
}

void
xcass_log_level(const char *level) {
    if(!strcasecmp(level, ""))
        cass_log_set_level(CASS_LOG_DISABLED);
    else if(!strcasecmp(level, "critical"))
        cass_log_set_level(CASS_LOG_CRITICAL);
    else if(!strcasecmp(level, "error"))
        cass_log_set_level(CASS_LOG_ERROR);
    else if(!strcasecmp(level, "warn"))
        cass_log_set_level(CASS_LOG_WARN);
    else if(!strcasecmp(level, "info"))
        cass_log_set_level(CASS_LOG_INFO);
    else if(!strcasecmp(level, "debug"))
        cass_log_set_level(CASS_LOG_DEBUG);
    else if(!strcasecmp(level, "trace"))
        cass_log_set_level(CASS_LOG_TRACE);
}

void
xcass_settings(xcass_t *xs,
               const char *settings, ...) {

    va_list args;
    regex_t regex;
    char *buffer = (char *) malloc(1024);
    char *buf = buffer;

    va_start(args, settings);
    memset(buffer, 0, 1024);
    vsnprintf(buffer, 1024, settings, args);
    va_end(args);

    int err = regcomp(&regex,
                      XCASS_SETTINGS_REGEX,
                      REG_EXTENDED | REG_ICASE);
    if(!err) {
        int match = 0;
        size_t nmatch = 0;
        regmatch_t *pmatch = NULL;
        int matched = 0;
        do {
            nmatch = regex.re_nsub + 1;
            pmatch = (regmatch_t *) malloc(sizeof(regmatch_t) * nmatch);
            if(pmatch) {
                match = regexec(&regex, buffer, nmatch, pmatch,
                                REG_EXTENDED | REG_ICASE);
                if(!match) {
                    int i;
                    int max = 0;
                    for(i = 1; i < (int)nmatch; i += 2) {
                        char *setting = NULL;
                        char *value = NULL;

                        int st = pmatch[i].rm_so;
                        size_t sz = pmatch[i].rm_eo - st;
                        setting = strndup(&buffer[st], sz + 1);
                        setting[sz] = '\0';

                        st = pmatch[i+1].rm_so;
                        sz = pmatch[i+1].rm_eo - st;
                        value = strndup(&buffer[st], sz + 1);
                        value[sz] = '\0';

                        char *p = value;
                        int type = -2; // -1 double 0 int 1 char *
                        while(*p) {
                            if(*p >= '0' && *p <= '9')
                                type = (strchr(value, '.') ? -1 : 0);
                            else if((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || *p == '_') {
                                type = 1;
                                break;
                            }
                            p++;
                        }

                        int int_value = 0;
                        if(!type)
                            int_value = atoi(value);

                        /**
                         *  Dealing with double value :
                         *      double double_value = 0;
                         *      if(type < 0)
                         *          double_value = strtod(value, NULL);
                         */

                        if(!strcmp(setting, "num_threads_io"))
                            cass_cluster_set_num_threads_io(xs->cluster, int_value);
                        else if(!strcmp(setting, "queue_size_io"))
                            cass_cluster_set_queue_size_io(xs->cluster, int_value);
                        else if(!strcmp(setting, "core_connections_per_host"))
                            cass_cluster_set_core_connections_per_host(xs->cluster, int_value);
                        else if(!strcmp(setting, "max_connections_per_host"))
                            cass_cluster_set_max_connections_per_host(xs->cluster, int_value);
                        else if(!strcmp(setting, "connect_timeout"))
                            cass_cluster_set_connect_timeout(xs->cluster, int_value);
                        else if(!strcmp(setting, "request_timeout"))
                            cass_cluster_set_request_timeout(xs->cluster, int_value);
                        else if(!strcmp(setting, "log_level"))
                            cass_log_set_level((CassLogLevel) int_value);
                        else if(!strcmp(setting, "consistency"))
                            xs->consistency = (CassConsistency) int_value;
                        else if(!strcmp(setting, "paging_size"))
                            xs->page_size = int_value;
                        else if(!strcmp(setting, "log"))
                            xcass_log_level(value);
                        else
                            fprintf(stderr, "(xcass_settings) skip unsupported option '%s'\n", setting);

                        free(setting);
                        free(value);
                        matched = 1;
                        max = pmatch[i].rm_eo;
                    }
                    buffer += max;
                }
                else if(match == REG_NOMATCH && !matched) {
                    fprintf(stderr, "'%s' didnt match any supported setting\n", buffer);
                }
                free(pmatch);
            }
            else {
                perror("malloc");
            }
        } while(!match && buffer);
        regfree(&regex);
    }
    free(buf);
}

void
xcass_auth(xcass_t *xs,
           const char *username,
           const char *password) {

    cass_cluster_set_credentials(xs->cluster, username, password);
}

/**
 *  xcass query related function
 */

CassValueType
xcass_get_type_byname(const char *name) {
    unsigned int i;
    for(i = 0; i < sizeof(xcass_types_mapping) / sizeof(*xcass_types_mapping); i++)
        if(!strcmp(name, xcass_types_mapping[i].name))
            return xcass_types_mapping[i].type;
    return CASS_VALUE_TYPE_UNKNOWN;
}

void
xcass_query_consistency(xcass_query_t *query,
                        CassConsistency consistency) {
    query->consistency = consistency;
}

void
xcass_query_page_size(xcass_query_t *query,
                      int page_size) {
    query->page_size = page_size;
}

int
xcass_statement(xcass_query_t *query,
                char *cql,
                unsigned int argc) {

    query->statement = cass_statement_new(cass_string_init(cql), argc);
    return 0;
}

int
xcass_bind(xcass_t *xs,
           xcass_query_t *query,
           xcass_type_mapping_t *types,
           unsigned int count,
           va_list ap) {

    unsigned int i;
    xcass_custom_t custom;
    va_list aq;
    
    va_copy(aq, ap);

    for(i = 0; i < count; i++) {
        switch(types[i].type) {
            case CASS_VALUE_TYPE_COUNTER:
            case CASS_VALUE_TYPE_TIMESTAMP:
            case CASS_VALUE_TYPE_BIGINT:
                cass_statement_bind_int64(query->statement, i, va_arg(aq, cass_int64_t));
            break;
            case CASS_VALUE_TYPE_BOOLEAN:
                cass_statement_bind_bool(query->statement, i, (cass_bool_t) va_arg(aq, int));
            break;
            case CASS_VALUE_TYPE_DECIMAL:
                cass_statement_bind_decimal(query->statement, i, va_arg(aq, CassDecimal));
            break;
            case CASS_VALUE_TYPE_DOUBLE:
                cass_statement_bind_double(query->statement, i, va_arg(aq, cass_double_t));
            break;
            case CASS_VALUE_TYPE_FLOAT:
                cass_statement_bind_float(query->statement, i, va_arg(aq, cass_double_t));
            break;
            case CASS_VALUE_TYPE_INET:
                cass_statement_bind_inet(query->statement, i, va_arg(aq, CassInet));
            break;
            case CASS_VALUE_TYPE_INT:
                cass_statement_bind_int32(query->statement, i, va_arg(aq, cass_int32_t));
            break;
            case CASS_VALUE_TYPE_TIMEUUID:
            case CASS_VALUE_TYPE_UUID:
                cass_statement_bind_uuid(query->statement, i, va_arg(aq, CassUuid));
            break;
            case CASS_VALUE_TYPE_BLOB:
            case CASS_VALUE_TYPE_VARINT:
                cass_statement_bind_bytes(query->statement, i, va_arg(aq, CassBytes));
            break;
            case CASS_VALUE_TYPE_LIST:
            case CASS_VALUE_TYPE_SET:
            case CASS_VALUE_TYPE_MAP:
                cass_statement_bind_collection(query->statement, i, va_arg(aq, CassCollection *));
            break;
            case CASS_VALUE_TYPE_ASCII:
            case CASS_VALUE_TYPE_VARCHAR:
            case CASS_VALUE_TYPE_TEXT:
                cass_statement_bind_string(query->statement, i, cass_string_init(va_arg(aq, char *)));
            break;
            case CASS_VALUE_TYPE_CUSTOM:
                custom = va_arg(aq, xcass_custom_t);
                cass_statement_bind_custom(query->statement, i, custom.size, custom.output);
            break;
            case CASS_VALUE_TYPE_UNKNOWN:
            default:
                va_end(aq);
                return 1;
        }
    }
    va_end(aq);
    return 0;
}

xcass_query_t *
xcass_query(xcass_t *xs,
            const char *fmt, ...) {

    va_list argv;
    unsigned int argc = 0;
    xcass_type_mapping_t *types = NULL;

    char *cql = (char *) malloc(strlen(fmt) + 1);
    memset(cql, 0, strlen(fmt) + 1);

    va_start(argv, fmt);

    /**
     *  quick & dirty CQL types parsing
     */
    char *p = (char *) fmt;
    int qt = 0;
    int ndx = 0;

    while(*p) {

        if(*p == '\'' && *(p-1) != '\\')
            qt = !qt;

        char *pp = strchr(p, '>');
        if(!qt && *p == '<' && *(p+1) != '=' && pp) {

            // collection ?
            char **clt = (char **) xcass_collection_types;
            while(*clt) {
                char *s = *clt;
                s += strlen(s)-1;
                while(*s) {
                    char c = *((p-1)-(strlen(s)-1));
                    if(!c || c != *s--)
                        break;
                }
                if(!strlen(s))
                    break;
                clt++;
            }

#define TRIM(st, le)                                                    \
    while(*st && (*st==' ' || *st==',')) st++;                          \
    while(st[le] && st[le]!=' ' && st[le]!=',' && st[le]!='>') le++;

            int sz = 0;
            char *f = p+1;
            TRIM(f, sz);
            char *key = strndup(f, sz);

            CassValueType ktype = xcass_get_type_byname(key);
            if(ktype == CASS_VALUE_TYPE_UNKNOWN) {
                fprintf(stderr, "(xcass_query) unknown type '%s'\n", f);
                free(key);
                va_end(argv);
                free(types);
                free(cql);
                return NULL;
            }

            types = (xcass_type_mapping_t *)
                        realloc(types, (argc+1) * sizeof(xcass_type_mapping_t));

            if(*clt) {
                types[argc].type = xcass_get_type_byname(*clt);

                /**
                 * Get key/value types :
                 *
                 *  types[argc].key = ktype;
                 *  if(!strcmp(*clt, "map")) {
                 *      sz = 0;
                 *      f += strlen(key);
                 *      TRIM(f, sz);
                 *      char *value = strndup(f, sz);
                 *      types[argc].value = xcass_get_type_byname(value);
                 *      free(value);
                 *      if(types[argc].value == CASS_VALUE_TYPE_UNKNOWN) {
                 *          fprintf(stderr, "(xcass_query) unknown type '%s'\n", f);
                 *          free(key);
                 *          va_end(argv);
                 *          free(types);
                 *          free(cql);
                 *          return NULL;
                 *      }
                 *  }
                 */

                ndx -= strlen(*clt);
            }
            else {
                types[argc].type = ktype;
                free(key);
            }
            argc++;
            p += pp-p;
            cql[ndx++] = '?';
        }
        else {
            cql[ndx++] = *p;
        }
        p++;
    }

    xcass_query_t *query = (xcass_query_t *) malloc(sizeof(*query));
    query->xs = xs;
    query->statement = NULL;
    query->result = NULL;
    query->page_size = xs->page_size;
    query->consistency = xs->consistency;

    int err = xcass_statement(query, cql, argc);
    if(err) {
        xcass_query_free(query);
        query = NULL;
    }
    else {
        err = xcass_bind(xs, query, types, argc, argv);
        if(err) {
            xcass_query_free(query);
            query = NULL;
        }
    }

    va_end(argv);
    free(types);
    free(cql);

    return query;
}

xcass_query_t *
xcass_query_nobind(xcass_t *xs,
                   const char *fmt, ...) {

    va_list argv;
    va_start(argv, fmt);

    char *cql = (char *) malloc(2048);
    memset(cql, 0, 2048);
    vsnprintf(cql, 2048, fmt, argv);
    va_end(argv);

    xcass_query_t *query = (xcass_query_t *) malloc(sizeof(*query));
    query->xs = xs;
    query->statement = NULL;
    query->result = NULL;
    query->page_size = xs->page_size;
    query->consistency = xs->consistency;

    int err = xcass_statement(query, cql, 0);
    if(err) {
        xcass_query_free(query);
        query = NULL;
    }

    free(cql);
    return query;
}

void
xcass_query_free(xcass_query_t *query) {
    if(query->result)
        cass_result_free(query->result);
    if(query->future)
        cass_future_free(query->future);
    if(query->statement)
        cass_statement_free(query->statement);
    query->result = NULL;
    query->statement = NULL;
    query->future = NULL;
    free(query);
}

CassError
xcass_execute(xcass_t *xs,
              xcass_query_t *query) {

    CassError rc = CASS_OK;
    
    cass_statement_set_consistency(query->statement, query->consistency);
    cass_statement_set_paging_size(query->statement, query->page_size);

    query->future = cass_session_execute(xs->session, query->statement);
    cass_future_wait(query->future);
    rc = cass_future_error_code(query->future);
    if(rc != CASS_OK) {
        xcass_set_error(xs, query->future);
        cass_future_free(query->future);
        query->future = NULL;
        return rc;
    }
    query->result = cass_future_get_result(query->future);
    return rc;
}

int
xcass_query_has_more_pages(xcass_query_t *query) {
    if(cass_result_has_more_pages(query->result)) {
        cass_statement_set_paging_state(query->statement, query->result);
        cass_result_free(query->result);
        query->result = NULL;
        return 1;
    }
    return 0;
}

cass_size_t
xcass_count(xcass_query_t *query) {
    return cass_result_row_count(query->result);
}

xcass_row_t *
xcass_first_row(xcass_query_t *query) {
    xcass_row_t *r = (xcass_row_t *) malloc(sizeof(*r));
    r->iterator = NULL;
    r->row = cass_result_first_row(query->result);
    if(query->future) {
        cass_future_free(query->future);
        query->future = NULL;
    }
    return r;
}

void
xcass_row_free(xcass_row_t *row) {
    if(row->iterator)
        cass_iterator_free(row->iterator);
    free(row);
}

/**
 *  CassValue helpers
 */

const CassValue *
xcass_get_value(xcass_row_t *r,
                const char *name) {

    if(r->iterator)
        r->row = cass_iterator_get_row(r->iterator);

    const CassValue *value = cass_row_get_column_by_name(r->row, name);
    if(!value)
        return NULL;

    return value;
}

const CassValue *
xcass_iget_value(xcass_row_t *r,
                 unsigned int index) {

    if(r->iterator)
        r->row = cass_iterator_get_row(r->iterator);

    const CassValue *value = cass_row_get_column(r->row, index);
    if(!value)
        return NULL;

    return value;
}

CassValueType
xcass_get_type(xcass_row_t *r,
               const char *name) {

    const CassValue *value = xcass_get_value(r, name);
    if(!value)
        return CASS_VALUE_TYPE_UNKNOWN;

    return cass_value_type(value);
}

CassValueType
xcass_iget_type(xcass_row_t *r,
             unsigned int index) {

    const CassValue *value = xcass_iget_value(r, index);
    if(!value)
        return CASS_VALUE_TYPE_UNKNOWN;

    return cass_value_type(value);
}

CassIterator *
xcass_get_map(xcass_row_t *r,
              const char *name) {
    
    const CassValue *value = xcass_get_value(r, name);
    if(!value)
        return NULL;

    return cass_iterator_from_map(value);
}

CassIterator *
xcass_iget_map(xcass_row_t *r,
                 unsigned int index) {

    const CassValue *value = xcass_iget_value(r, index);
    if(!value)
        return NULL;

    return cass_iterator_from_map(value);
}

CassIterator *
xcass_get_collection(xcass_row_t *r,
                     const char *name) {
    
    const CassValue *value = xcass_get_value(r, name);
    if(!value)
        return NULL;

    return cass_iterator_from_collection(value);
}

CassIterator *
xcass_iget_collection(xcass_row_t *r,
                      unsigned int index) {

    const CassValue *value = xcass_iget_value(r, index);
    if(!value)
        return NULL;

    return cass_iterator_from_collection(value);
}

CassString *
xcass_get_string(xcass_row_t *r,
                 const char *name) {

    CassString *str = (CassString *) malloc(sizeof(CassString));
    const CassValue *value = xcass_get_value(r, name);
    if(!value) {
        free(str);
        return NULL;
    }

    cass_value_get_string(value, str);
    return str;
}

CassString *
xcass_iget_string(xcass_row_t *r,
                  unsigned int index) {

    CassString *str = (CassString *) malloc(sizeof(CassString));
    const CassValue *value = xcass_iget_value(r, index);
    if(!value) {
        free(str);
        return NULL;
    }

    cass_value_get_string(value, str);
    return str;
}

char *
xcass_get_string_dup(xcass_row_t *r,
                     const char *name) {

    const CassValue *value = xcass_get_value(r, name);
    if(!value)
        return NULL;

    CassString str;
    cass_value_get_string(value, &str);
    return strndup(str.data, str.length);
}

char *
xcass_iget_string_dup(xcass_row_t *r,
                      unsigned int index) {

    const CassValue *value = xcass_iget_value(r, index);
    if(!value)
            return NULL;

    CassString str;
    cass_value_get_string(value, &str);
    return strndup(str.data, str.length);
}

cass_double_t
xcass_get_double(xcass_row_t *r,
                 const char *name) {

    const CassValue *value = xcass_get_value(r, name);
    if(!value)
        return NAN;

    cass_double_t d;
    cass_value_get_double(value, &d);
    return d;
}

cass_double_t
xcass_iget_double(xcass_row_t *r,
                  unsigned int index) {

    const CassValue *value = xcass_iget_value(r, index);
    if(!value)
        return NAN;

    cass_double_t d;
    cass_value_get_double(value, &d);
    return d;
}

cass_int32_t
xcass_get_int(xcass_row_t *r,
              const char *name) {

    const CassValue *value = xcass_get_value(r, name);
    cass_int32_t i;
    cass_value_get_int32(value, &i);
    return i;
}

cass_int32_t
xcass_iget_int(xcass_row_t *r,
               unsigned int index) {

    const CassValue *value = xcass_iget_value(r, index);
    cass_int32_t i;
    cass_value_get_int32(value, &i);
    return i;
}

cass_int64_t
xcass_get_bigint(xcass_row_t *r,
                 const char *name) {

    const CassValue *value = xcass_get_value(r, name);
    cass_int64_t i;
    cass_value_get_int64(value, &i);
    return i;
}

cass_int64_t
xcass_iget_bigint(xcass_row_t *r,
                  unsigned int index) {

    const CassValue *value = xcass_iget_value(r, index);
    cass_int64_t i;
    cass_value_get_int64(value, &i);
    return i;
}

unsigned int
xcass_collection_count(xcass_row_t *r,
                       const char *name) {

    const CassValue *values = xcass_get_value(r, name);
    if(!values)
            return 0;

    return cass_value_item_count(values);
}

unsigned int
xcass_icollection_count(xcass_row_t *r,
                        unsigned int index) {

    const CassValue *values = xcass_iget_value(r, index);
    if(!values)
            return 0;

    return cass_value_item_count(values);
}

cass_bool_t
xcass_get_boolean(xcass_row_t *r,
                  const char *name) {

    const CassValue *value = xcass_get_value(r, name);
    if(!value)
        return cass_false;

    cass_bool_t b;
    cass_value_get_bool(value, &b);
    return b;
}

cass_bool_t
xcass_iget_boolean(xcass_row_t *r,
                   unsigned int index) {

    const CassValue *value = xcass_iget_value(r, index);
    if(!value)
        return cass_false;

    cass_bool_t b;
    cass_value_get_bool(value, &b);
    return b;
}

CassBytes *
xcass_get_bytes(xcass_row_t *r,
                const char *name) {
    
    CassBytes *bytes = (CassBytes *) malloc(sizeof(CassBytes));
    const CassValue *value = xcass_get_value(r, name);
    if(!value) {
        free(bytes);
        return NULL;
    }

    cass_value_get_bytes(value, bytes);
    return bytes;
}

CassBytes *
xcass_iget_bytes(xcass_row_t *r,
                 unsigned int index) {

    CassBytes *bytes = (CassBytes *) malloc(sizeof(CassBytes));
    const CassValue *value = xcass_iget_value(r, index);
    if(!value) {
        free(bytes);
        return NULL;
    }

    cass_value_get_bytes(value, bytes);
    return bytes;
}

CassUuid *
xcass_get_uuid(xcass_row_t *r,
               const char *name) {

    CassUuid *uuid = (CassUuid *) malloc(sizeof(CassUuid));
    const CassValue *value = xcass_get_value(r, name);
    if(!value) {
        free(uuid);
        return NULL;
    }

    cass_value_get_uuid(value, uuid);
    return uuid;
}

CassUuid *
xcass_iget_uuid(xcass_row_t *r,
                unsigned int index) {

    CassUuid *uuid = (CassUuid *) malloc(sizeof(CassUuid));
    const CassValue *value = xcass_iget_value(r, index);
    if(!value) {
        free(uuid);
        return NULL;
    }

    cass_value_get_uuid(value, uuid);
    return uuid;
}

char *
xcass_get_string_uuid(xcass_row_t *r,
                      const char *name) {

    const CassValue *value = xcass_get_value(r, name);
    if(!value)
        return NULL;

    char *s = (char *) malloc(CASS_UUID_STRING_LENGTH);
    memset(s, 0, CASS_UUID_STRING_LENGTH);
    CassUuid uuid;
    cass_value_get_uuid(value, &uuid);
    cass_uuid_string(uuid, s);
    return s;
}

char *
xcass_iget_string_uuid(xcass_row_t *r,
                       unsigned int index) {

    const CassValue *value = xcass_iget_value(r, index);
    if(!value)
        return NULL;

    char *s = (char *) malloc(CASS_UUID_STRING_LENGTH);
    memset(s, 0, CASS_UUID_STRING_LENGTH);
    CassUuid uuid;
    cass_value_get_uuid(value, &uuid);
    cass_uuid_string(uuid, s);
    return s;
}


/**
 *  extra...
 */
cass_int64_t
xcass_string_uuid_timestamp(const char *s) {
    CassUuid uuid;
    cass_uuid_from_string(s, &uuid);
    return cass_uuid_timestamp(uuid);
}
