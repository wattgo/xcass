#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "xcass.h"

int main(int argc, char **argv) {

  const char *hosts = "127.0.0.1";
  const char *keyspace = "datastax_examples";
  unsigned int port = 9042;

  /**
   *  Create CassCluster instance, open a CassSession
   */
  xcass_t *xs = xcass_create(hosts, port);
  CassError rc = xcass_connect(xs, keyspace);
  if(rc != CASS_OK) {
    fprintf(stderr, "%s\n", cass_error_desc(rc));
    exit(EXIT_FAILURE);
  }

  /**
   *  create statement & bind parameters
   */
  xcass_query_t *query = xcass_query(xs, "SELECT * FROM playlists");

  /**
   *  fetch 1 row per page for example purpose
   */
  xcass_query_page_size(query, 1);

  /**
   *  count pages
   */
  unsigned int page = 0;

  /**
   *  execute paged query
   */
  do {
    printf("Page %d\n", ++page);

    CassError rc = xcass_execute(xs, query);
    if(rc != CASS_OK) {
      fprintf(stderr, "%s\n", cass_error_desc(rc));
      exit(EXIT_FAILURE);
    }

    printf("\tPlaylist (%zu results) :\n", xcass_count(query));

    /**
     *  get an iterator from result 
     */
    xcass_row_t *row = NULL;
    xcass_foreach(query, row) {
      int order;
      char *artist, *title;

      /**
       * get fields
       */
      assert(xcass_get_int(row, "song_order", &order) == CASS_OK);
      assert(xcass_get_string_dup(row, "artist", &artist) == CASS_OK);
      assert(xcass_get_string_dup(row, "title", &title) == CASS_OK);

      printf("\t  (%d) %s : %s\n", order, artist, title);
      
      free(artist);
      free(title);
    }
    xcass_row_free(row);

  } while(xcass_query_has_more_pages(query));

  /**
   *  cleanup
   */
  xcass_query_free(query);
  xcass_cleanup(xs);

  return 0;
}