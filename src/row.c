#include "xcass.h"

/**
 * 
 */
void
xcass_row_free(xcass_row_t *row) {
    
  if(row->iterator)
    cass_iterator_free(row->iterator);
  free(row);
}

/**
 * 
 */
cass_size_t
xcass_count(xcass_query_t *query) {

  return cass_result_row_count(query->result);
}

/**
 * 
 */
xcass_row_t *
xcass_first_row(xcass_query_t *query) {

  xcass_row_t *r = (xcass_row_t *) malloc(sizeof(*r));
  r->iterator = NULL;
  r->row = cass_result_first_row(query->result);
  return r;
}
