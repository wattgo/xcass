#include "xcass.h"

void
xcass_batch_add(CassBatch *batch,
                xcass_query_t *query) {

  cass_statement_set_consistency(query->statement, query->consistency);
  cass_statement_set_paging_size(query->statement, query->page_size);
  cass_batch_add_statement(batch, query->statement);
}

CassError
xcass_batch_execute(xcass_t *xs,
                    CassBatch *batch) {

  CassFuture *future = cass_session_execute_batch(xs->session, batch);
  cass_future_wait(future);
  CassError rc = cass_future_error_code(future);
  cass_future_free(future);
  return rc;
}
