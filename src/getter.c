#include "xcass.h"

const CassValue *
xcass_get_value(xcass_row_t *r,
                const char *name) {

  if(r->iterator)
    r->row = cass_iterator_get_row(r->iterator);
  const CassValue *value = cass_row_get_column_by_name(r->row, name);
  return value;
}

const CassValue *
xcass_iget_value(xcass_row_t *r,
                 unsigned int index) {

  if(r->iterator)
    r->row = cass_iterator_get_row(r->iterator);
  const CassValue *value = cass_row_get_column(r->row, index);
  return value;
}

CassValueType
xcass_get_type(xcass_row_t *r,
               const char *name) {

  const CassValue *value = xcass_get_value(r, name);
  return cass_value_type(value);
}

CassValueType
xcass_iget_type(xcass_row_t *r,
                unsigned int index) {

  const CassValue *value = xcass_iget_value(r, index);
  return cass_value_type(value);
}

CassIterator *
xcass_get_map(xcass_row_t *r,
              const char *name) {
    
  const CassValue *value = xcass_get_value(r, name);
  return cass_iterator_from_map(value);
}

CassIterator *
xcass_iget_map(xcass_row_t *r,
                 unsigned int index) {

  const CassValue *value = xcass_iget_value(r, index);
  return cass_iterator_from_map(value);
}

CassIterator *
xcass_get_collection(xcass_row_t *r,
                     const char *name) {
    
  const CassValue *value = xcass_get_value(r, name);
  return cass_iterator_from_collection(value);
}

CassIterator *
xcass_iget_collection(xcass_row_t *r,
                      unsigned int index) {

  const CassValue *value = xcass_iget_value(r, index);
  return cass_iterator_from_collection(value);
}

CassError
xcass_get_string(xcass_row_t *r,
                 const char *name,
                 CassString *s) {

  const CassValue *value = xcass_get_value(r, name);
  return cass_value_get_string(value, s);
}

CassError
xcass_iget_string(xcass_row_t *r,
                  unsigned int index,
                  CassString *s) {

  const CassValue *value = xcass_iget_value(r, index);
  return cass_value_get_string(value, s);
}

CassError
xcass_get_string_dup(xcass_row_t *r,
                     const char *name,
                     char **dest) {

  const CassValue *value = xcass_get_value(r, name);
  CassString s;
  CassError rc = cass_value_get_string(value, &s);
  if(rc != CASS_OK)
    return rc;
  *dest = strndup(s.data, s.length);
  return CASS_OK;
}

CassError
xcass_iget_string_dup(xcass_row_t *r,
                      unsigned int index,
                      char **dest) {

  const CassValue *value = xcass_iget_value(r, index);
  CassString s;
  CassError rc = cass_value_get_string(value, &s);
  if(rc != CASS_OK)
    return rc;
  *dest = strndup(s.data, s.length);
  return CASS_OK;
}

CassError
xcass_get_double(xcass_row_t *r,
                 const char *name,
                 cass_double_t *d) {

  const CassValue *value = xcass_get_value(r, name);
  return cass_value_get_double(value, d);
}

CassError
xcass_iget_double(xcass_row_t *r,
                  unsigned int index,
                  cass_double_t *d) {

  const CassValue *value = xcass_iget_value(r, index);
  return cass_value_get_double(value, d);
}

CassError
xcass_get_int(xcass_row_t *r,
              const char *name,
              cass_int32_t *i) {

  const CassValue *value = xcass_get_value(r, name);
  return cass_value_get_int32(value, i);
}

CassError
xcass_iget_int(xcass_row_t *r,
               unsigned int index,
               cass_int32_t *i) {

  const CassValue *value = xcass_iget_value(r, index);
  return cass_value_get_int32(value, i);
}

CassError
xcass_get_bigint(xcass_row_t *r,
                 const char *name,
                 cass_int64_t *i) {

  const CassValue *value = xcass_get_value(r, name);
  return cass_value_get_int64(value, i);
}

CassError
xcass_iget_bigint(xcass_row_t *r,
                  unsigned int index,
                  cass_int64_t *i) {

  const CassValue *value = xcass_iget_value(r, index);
  return cass_value_get_int64(value, i);
}

unsigned int
xcass_collection_count(xcass_row_t *r,
                       const char *name) {

  const CassValue *values = xcass_get_value(r, name);
  return cass_value_item_count(values);
}

unsigned int
xcass_icollection_count(xcass_row_t *r,
                        unsigned int index) {

  const CassValue *values = xcass_iget_value(r, index);
  return cass_value_item_count(values);
}

CassError
xcass_get_boolean(xcass_row_t *r,
                  const char *name,
                  cass_bool_t *b) {

  const CassValue *value = xcass_get_value(r, name);
  return cass_value_get_bool(value, b);
}

CassError
xcass_iget_boolean(xcass_row_t *r,
                   unsigned int index,
                   cass_bool_t *b) {

  const CassValue *value = xcass_iget_value(r, index);
  return cass_value_get_bool(value, b);
}

CassError
xcass_get_bytes(xcass_row_t *r,
                const char *name,
                CassBytes *bytes) {

  const CassValue *value = xcass_get_value(r, name);
  return cass_value_get_bytes(value, bytes);
}

CassError
xcass_iget_bytes(xcass_row_t *r,
                 unsigned int index,
                 CassBytes *bytes) {

  const CassValue *value = xcass_iget_value(r, index);
  return cass_value_get_bytes(value, bytes);
}

CassError
xcass_get_uuid(xcass_row_t *r,
               const char *name,
               CassUuid *uuid) {

  const CassValue *value = xcass_get_value(r, name);
  return cass_value_get_uuid(value, uuid);
}

CassError
xcass_iget_uuid(xcass_row_t *r,
                unsigned int index,
                CassUuid *uuid) {

  const CassValue *value = xcass_iget_value(r, index);
  return cass_value_get_uuid(value, uuid);
}

CassError
xcass_get_uuid_string_dup(xcass_row_t *r,
                          const char *name,
                          char **dest) {

  const CassValue *value = xcass_get_value(r, name);
  CassUuid uuid;
  CassError rc = cass_value_get_uuid(value, &uuid);
  if(rc != CASS_OK)
    return rc;

  *dest = (char *) malloc(CASS_UUID_STRING_LENGTH);
  memset(*dest, 0, CASS_UUID_STRING_LENGTH);
  cass_uuid_string(uuid, *dest);

  return CASS_OK;
}

CassError
xcass_iget_uuid_string_dup(xcass_row_t *r,
                           unsigned int index,
                           char **dest) {

  const CassValue *value = xcass_iget_value(r, index);
  CassUuid uuid;
  CassError rc = cass_value_get_uuid(value, &uuid);
  if(rc != CASS_OK)
    return rc;

  *dest = (char *) malloc(CASS_UUID_STRING_LENGTH);
  memset(*dest, 0, CASS_UUID_STRING_LENGTH);
  cass_uuid_string(uuid, *dest);

  return CASS_OK;
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
