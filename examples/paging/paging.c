#include <stdio.h>
#include <stdlib.h>

#include "xcass.h"

int main(int argc, char **argv) {

	const char *hosts = "node05,node06,node07";
	const char *keyspace = "datastax_examples";
	unsigned int port = 9042;

	const char *playlist_id = "62c36092-82a1-3a00-93d1-46196ee77204";
	CassUuid uuid;
	cass_uuid_from_string(playlist_id, &uuid);

	/**
	 *	Create CassCluster instance, open a CassSession
	 */
	xcass_t *xs = xcass_create(hosts, port);
	xcass_connect(xs, keyspace);

	/**
	 *	create statement & bind parameters
	 */
	xcass_query_t *query = xcass_query(xs, "SELECT * FROM playlists");

	/**
	 *	fetch only 2 rows per page for example purpose ;)
	 */
	xcass_query_page_size(query, 2);

	/**
	 *	count pages
	 */
	unsigned int page = 0;

	/**
	 *	execute paged query
	 */
	do {
		printf("Page %d\n", ++page);

		CassError rc = xcass_execute(xs, query);
		if(rc != CASS_OK) {
			fprintf(stderr, "%s\n", xcass_last_error(xs));
			exit(EXIT_FAILURE);
		}

		printf("\tPlaylist (%zu results) :\n", xcass_count(query));

		/**
		 *	get an iterator from result 
		 */
		xcass_row_t *row = NULL;
		xcass_foreach(query, row) {
			int order = xcass_get_int(row, "song_order");
			char *artist = xcass_get_string_dup(row, "artist");
			char *title = xcass_get_string_dup(row, "title");

			printf("\t  (%d) %s : %s\n", order, artist, title);
			
			free(artist);
			free(title);
		}
		xcass_row_free(row);

	} while(xcass_query_has_more_pages(query));

	/**
	 *	cleanup
	 */
	xcass_query_free(query);
	xcass_cleanup(xs);

	return 0;
}