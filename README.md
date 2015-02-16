##xcass

###desc

A bunch of helpers to make your life easier while using the DataStax C/C++ Driver for Apache Cassandra ;)

###usage

from [examples/simple/simple.c](examples/simple/simple.c)

```C
	/**
	 *	init & connect
	 */
	xcass_t *xs = xcass_create(hosts, port);
	xcass_connect(xs, keyspace);

	/**
	 *	variadic function to create statement & bind parameters
	 */
	xcass_query_t *query =
		xcass_query(xs, "SELECT * FROM playlists WHERE id = <uuid>", uuid);

	/**
	 *	execute query
	 */
	CassError rc = xcass_execute(xs, query);
	if(rc != CASS_OK) {
		fprintf(stderr, "%s\n", xcass_last_error(xs));
		exit(EXIT_FAILURE);
	}

	printf("Playlist (%zu results) :\n", xcass_count(query));

	/**
	 *	get an iterator from result 
	 */
	xcass_row_t *row = NULL;
	xcass_foreach(query, row) {
		int order = xcass_get_int(row, "song_order");
		char *artist = xcass_get_string_dup(row, "artist");
		char *title = xcass_get_string_dup(row, "title");
		printf("  (%d) %s : %s\n", order, artist, title);
		free(artist);
		free(title);
	}
	xcass_row_free(row);

	/**
	 *	cleanup
	 */
	xcass_query_free(query);
	xcass_cleanup(xs);
```

###TODO

*	prepared statement
*	batch queries
*	some missing getter
*	doc
*	...
