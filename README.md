##xcass

###description

A bunch of helpers to make your life easier while using the DataStax C/C++ Driver for Apache Cassandra ;)

###usage

from [examples/simple/simple.c](examples/simple/simple.c)

```C
  const char *hosts = "127.0.0.1";
  const char *keyspace = "datastax_examples";
  unsigned int port = 9042;

  const char *playlist_id = "62c36092-82a1-3a00-93d1-46196ee77204";
  CassUuid uuid;
  cass_uuid_from_string(playlist_id, &uuid);

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
  xcass_query_t *query =
    xcass_query(xs, "SELECT * FROM playlists WHERE id = <uuid>", uuid);

  /**
   *  execute query
   */
  rc = xcass_execute(xs, query);
  if(rc != CASS_OK) {
    fprintf(stderr, "%s\n", cass_error_desc(rc));
    exit(EXIT_FAILURE);
  }

  printf("Playlist (%zu results) :\n", xcass_count(query));

  /**
   *  get an iterator from result 
   */
  xcass_row_t *row = NULL;
  xcass_foreach(query, row) {
    int order;
    char *artist, *title;

    assert(xcass_get_int(row, "song_order", &order) == CASS_OK);
    assert(xcass_get_string_dup(row, "artist", &artist) == CASS_OK);
    assert(xcass_get_string_dup(row, "title", &title) == CASS_OK);

    printf("  (%d) %s : %s\n", order, artist, title);
    
    free(artist);
    free(title);
  }
  xcass_row_free(row);

  /**
   *  cleanup
   */
  xcass_query_free(query);
  xcass_cleanup(xs);

  return 0;
```

Feel free to contribute !


###TODO

* cpp-driver 2.0 support
*	improve documentation
