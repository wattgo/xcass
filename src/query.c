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


static CassValueType
xcass_get_type_byname(const char *name) {

  unsigned int i, count;
  count = sizeof(xcass_types_mapping) / sizeof(*xcass_types_mapping);

  for(i = 0; i < count; i++)
    if(!strcmp(name, xcass_types_mapping[i].name))
      return xcass_types_mapping[i].type;

  return CASS_VALUE_TYPE_UNKNOWN;
}

/**
 * Allocate a new query object
 * @return Returns allocated object
 *
 * @param[in] xs xcass_t instance object
 */
xcass_query_t *
xcass_query_new(xcass_t *xs) {

  xcass_query_t *query = (xcass_query_t *) malloc(sizeof(xcass_query_t));
  query->xs = xs;
  query->statement = NULL;
  query->result = NULL;
  query->cql = NULL;
  query->types = NULL;
  query->prepared = NULL;
  query->argc = 0;
  query->page_size = xs->page_size;
  query->consistency = xs->consistency;
  return query;
}

/**
 * Free a query object
 *
 * @param[in] query Query object to free
 */
void
xcass_query_free(xcass_query_t *query) {

  if(query->result)
    cass_result_free(query->result);
  if(query->statement)
    cass_statement_free(query->statement);
  if(query->prepared)
    cass_prepared_free(query->prepared);
  if(query->types)
    free(query->types);
  if(query->cql)
    free(query->cql);

  free(query);
}


/**
 * Set query consistency to given CassConsistency
 *
 * @param[in] query Query object
 * @param[in] consistency Consistency value to set
 */
void
xcass_query_consistency(xcass_query_t *query,
                        CassConsistency consistency) {

  query->consistency = consistency;
}


/**
 * Set query page size
 *
 * @param[in] query Query object
 * @param[in] page_size Page size to set (default: -1 disabled)
 */
void
xcass_query_page_size(xcass_query_t *query,
                      int page_size) {

  query->page_size = page_size;
}



CassError
xcass_query_ibind(xcass_query_t *query,
                  unsigned int index,
                  va_list aq) {

  CassError rc = CASS_OK;
  xcass_custom_t custom;

  switch(query->types[index].type) {
    case CASS_VALUE_TYPE_COUNTER:
    case CASS_VALUE_TYPE_TIMESTAMP:
    case CASS_VALUE_TYPE_BIGINT:
      rc = cass_statement_bind_int64(query->statement, index,
                                     va_arg(aq, cass_int64_t));
    break;
    case CASS_VALUE_TYPE_BOOLEAN:
      rc = cass_statement_bind_bool(query->statement, index,
                                   (cass_bool_t) va_arg(aq, int));
    break;
    case CASS_VALUE_TYPE_DECIMAL:
      rc = cass_statement_bind_decimal(query->statement, index,
                                       va_arg(aq, CassDecimal));
    break;
    case CASS_VALUE_TYPE_DOUBLE:
      rc = cass_statement_bind_double(query->statement, index,
                                      va_arg(aq, cass_double_t));
    break;
    case CASS_VALUE_TYPE_FLOAT:
      rc = cass_statement_bind_float(query->statement, index,
                                     va_arg(aq, cass_double_t));
    break;
    case CASS_VALUE_TYPE_INET:
      rc = cass_statement_bind_inet(query->statement, index,
                                    va_arg(aq, CassInet));
    break;
    case CASS_VALUE_TYPE_INT:
      rc = cass_statement_bind_int32(query->statement, index,
                                     va_arg(aq, cass_int32_t));
    break;
    case CASS_VALUE_TYPE_TIMEUUID:
    case CASS_VALUE_TYPE_UUID:
      rc = cass_statement_bind_uuid(query->statement, index,
                                    va_arg(aq, CassUuid));
    break;
    case CASS_VALUE_TYPE_BLOB:
    case CASS_VALUE_TYPE_VARINT:
      rc = cass_statement_bind_bytes(query->statement, index,
                                     va_arg(aq, CassBytes));
    break;
    case CASS_VALUE_TYPE_LIST:
    case CASS_VALUE_TYPE_SET:
    case CASS_VALUE_TYPE_MAP:
      rc = cass_statement_bind_collection(query->statement, index,
                                          va_arg(aq, CassCollection *));
    break;
    case CASS_VALUE_TYPE_ASCII:
    case CASS_VALUE_TYPE_VARCHAR:
    case CASS_VALUE_TYPE_TEXT:
      rc = cass_statement_bind_string(query->statement, index,
                                      cass_string_init(va_arg(aq, char *)));
    break;
    case CASS_VALUE_TYPE_CUSTOM:
      custom = va_arg(aq, xcass_custom_t);
      rc = cass_statement_bind_custom(query->statement, index,
                                      custom.size, custom.output);
    break;
    case CASS_VALUE_TYPE_UNKNOWN:
    default:
      return CASS_ERROR_LIB_BAD_PARAMS;
  }

  return rc;
}


CassError
xcass_bind(xcass_query_t *query, ...) {

  CassError rc = CASS_OK;
  va_list aq, ap;

  va_start(aq, query);
  va_copy(ap, aq);

  int i;
  for(i = 0; i < query->argc; i++) {
    void *p = va_arg(ap, void *);
    if(!p) {
      va_arg(aq, void *);
      rc = cass_statement_bind_null(query->statement, i);
    }
    else
      rc = xcass_query_ibind(query, i, aq);

    if(rc < 0)
      break;
  }

  va_end(ap);
  va_end(aq);
  return rc;
}


CassError
xcass_ibind(xcass_query_t *query,
            unsigned int index, ...) {

  CassError rc = CASS_OK;
  va_list aq, ap;
  
  va_start(aq, index);
  va_copy(ap, aq);

  if(!va_arg(ap, void *))
    rc = cass_statement_bind_null(query->statement, index);
  else
    rc = xcass_query_ibind(query, index, aq);

  va_end(ap);
  va_end(aq);
  return rc;
}



int
xcass_query_parse(xcass_query_t *query,
                  const char *cql) {

  xcass_type_mapping_t *types = NULL;
  int argc = 0;

  query->cql = (char *) malloc(strlen(cql) + 1);
  memset(query->cql, 0, strlen(cql) + 1);

#define TRIM(st, le)                                 \
  do {                                               \
    while(*st && (*st == ' ' || *st == ','))         \
      st++;                                          \
    while(st[le] && st[le] != ' ' && st[le] != ','   \
        && st[le] != XCASS_FIELD_DELIM_RIGHT)        \
      le++;                                          \
  } while(0);

  char *p = (char *) cql;
  int qt = 0;
  int ndx = 0;

  while(*p) {

    // quotes
    if(*p == '\'' && *(p-1) != '\\')
      qt = !qt;

    char *pp = strchr(p, XCASS_FIELD_DELIM_RIGHT);
    if(!qt && *p == XCASS_FIELD_DELIM_LEFT && *(p+1) != '=' && pp) {

      // collection ?
      char **col = (char **) xcass_collection_types;
      while(*col) {
        char *s = *col;
        s += strlen(s)-1;
        while(*s) {
          char c = *((p-1)-(strlen(s)-1));
          if(!c || c != *s--)
            break;
        }
        if(!strlen(s))
          break;
        col++;
      }

      int sz = 0;
      char *f = p+1;
      TRIM(f, sz);
      char *key = strndup(f, sz);

      CassValueType ktype = xcass_get_type_byname(key);
      free(key);
      if(ktype == CASS_VALUE_TYPE_UNKNOWN) {
        fprintf(stderr, "(xcass_query) unknown type '%s'\n", f);
        free(types);
        free(query->cql);
        return -1;
      }

      types = (xcass_type_mapping_t *) realloc(types, (argc + 1)
                * sizeof(xcass_type_mapping_t));

      if(*col) {
        types[argc].type = xcass_get_type_byname(*col);
        ndx -= strlen(*col);
      }
      else
        types[argc].type = ktype;

      argc++;
      p += pp-p;
      query->cql[ndx++] = '?';
    }
    else {
      query->cql[ndx++] = *p;
    }
    p++;
  }

  query->types = types;
  query->argc = argc;

  return argc;
}



xcass_query_t *
xcass_prepare(xcass_t *xs,
              const char *cql) {

  xcass_query_t *query = xcass_query_new(xs);

  int argc = xcass_query_parse(query, cql);
  if(argc < 0)
    goto fail;

  CassFuture *future = cass_session_prepare(xs->session,
                                            cass_string_init(query->cql));
  cass_future_wait(future);

  CassError rc = cass_future_error_code(future);
  if(rc != CASS_OK) {
    cass_future_free(future);
    goto fail;
  }

  query->prepared = cass_future_get_prepared(future);
  cass_future_free(future);

  return query;

  fail:
    xcass_query_free(query);
    return NULL;
}


xcass_query_t *
xcass_query(xcass_t *xs,
            const char *fmt, ...) {

  va_list aq;
  xcass_query_t *query = xcass_query_new(xs);

  int argc = xcass_query_parse(query, fmt);
  if(argc < 0) 
    goto fail;

  query->statement = cass_statement_new(cass_string_init(query->cql),
                                        query->argc);
  
  if(argc) {
    va_start(aq, fmt);
    int i;
    for(i = 0; i < query->argc; i++) {
      if(xcass_query_ibind(query, i, aq) != CASS_OK) {
        va_end(aq);
        goto fail;
      }
    }
    va_end(aq);
  }

  return query;

  fail:
    xcass_query_free(query);
    return NULL;
}


xcass_query_t *
xcass_query_nobind(xcass_t *xs,
                   const char *cql) {

  xcass_query_t *query = xcass_query_new(xs);
  query->cql = strdup(cql);
  query->argc = 0;
  query->statement = cass_statement_new(cass_string_init(query->cql), 0);
  return query;
}


CassStatement *
xcass_new_statement(xcass_query_t *query) {

  if(query->statement)
    cass_statement_free(query->statement);

  if(query->prepared)
    query->statement = cass_prepared_bind(query->prepared);
  else
    query->statement = cass_statement_new(cass_string_init(query->cql),
                                          query->argc);

  return query->statement;
}


CassError
xcass_execute(xcass_t *xs,
              xcass_query_t *query) {

  CassError rc = CASS_OK;
  cass_statement_set_consistency(query->statement, query->consistency);
  cass_statement_set_paging_size(query->statement, query->page_size);

  CassFuture *future = cass_session_execute(xs->session, query->statement);
  cass_future_wait(future);
  rc = cass_future_error_code(future);
  if(rc != CASS_OK) {
    cass_future_free(future);
    return rc;
  }

  query->result = cass_future_get_result(future);
  cass_future_free(future);
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
