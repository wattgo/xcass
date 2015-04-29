#include <stdio.h>
#include <stdlib.h>

#include "xcass.h"

typedef struct {
  const char *id;
  int song_order;
  const char *song_id;
  const char *title;
  const char *album;
  const char *artist;
} song_t;

song_t songs[] = {
  {
    .id = "62c36092-82a1-3a00-93d1-46196ee77204",
    .song_order = 1,
    .song_id = "a3e64f8f-bd44-4f28-b8d9-6938726e34d4",
    .title = "La Grange",
    .album = "Tres Hombres",
    .artist = "ZZ Top"
  },
  {
    .id = "62c36092-82a1-3a00-93d1-46196ee77204",
    .song_order = 2,
    .song_id = "8a172618-b121-4136-bb10-f665cfc469eb",
    .title = "Moving in Stereo",
    .album = "We Must Obey",
    .artist = "Fu Manchu"
  },
  {
    .id = "62c36092-82a1-3a00-93d1-46196ee77204",
    .song_order = 3,
    .song_id = "2b09185b-fb5a-4734-9b56-49077de9edbf",
    .title = "Outside Woman Blues",
    .album = "Roll Away",
    .artist = "Back Door Slam"
  }
};

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
   *  create prepared statement
   */
  xcass_query_t *prepared =
    xcass_prepare(xs,
      "UPDATE "
          "playlists "
      "SET "
          "song_id = <uuid>, "
          "title = <text>, "
          "album = <text>, "
          "artist = <text> "
      "WHERE "
          "id = <uuid> AND song_order = <int>");

  int i;
  for(i = 0; i < sizeof(songs) / sizeof(*songs); i++) {
    CassUuid id;
    CassUuid song_id;
    cass_uuid_from_string(songs[i].id, &id);
    cass_uuid_from_string(songs[i].song_id, &song_id);

    printf("id %s song_id %s song_order %d\n",
           songs[i].id, songs[i].song_id, songs[i].song_order);

    /**
     * bind parameters in order
     */
    xcass_new_statement(prepared);
    xcass_bind(prepared, song_id, songs[i].title, songs[i].album,
               songs[i].artist, id, songs[i].song_order);

    CassError rc = xcass_execute(xs, prepared);
    if(rc != CASS_OK) {
      fprintf(stderr, "%s\n", cass_error_desc(rc));
      exit(EXIT_FAILURE);
    }
  }

  /**
   *  cleanup
   */
  xcass_query_free(prepared);
  xcass_cleanup(xs);

  return 0;
}