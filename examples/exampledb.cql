CREATE KEYSPACE datastax_examples
	WITH REPLICATION = { 'class' : 'SimpleStrategy', 'replication_factor' : 3 };

USE datastax_examples;

CREATE TABLE playlists (
	id uuid,
	song_order int,
	song_id uuid,
	title text,
	album text,
	artist text,
	PRIMARY KEY  (id, song_order ) );

INSERT INTO playlists (id, song_order, song_id, title, artist, album)
	VALUES (62c36092-82a1-3a00-93d1-46196ee77204, 1,
	a3e64f8f-bd44-4f28-b8d9-6938726e34d4, 'La Grange', 'ZZ Top', 'Tres Hombres');

INSERT INTO playlists (id, song_order, song_id, title, artist, album)
	VALUES (62c36092-82a1-3a00-93d1-46196ee77204, 2,
	8a172618-b121-4136-bb10-f665cfc469eb, 'Moving in Stereo', 'Fu Manchu', 'We Must Obey');

INSERT INTO playlists (id, song_order, song_id, title, artist, album)
	VALUES (62c36092-82a1-3a00-93d1-46196ee77204, 3,
	2b09185b-fb5a-4734-9b56-49077de9edbf, 'Outside Woman Blues', 'Back Door Slam', 'Roll Away');
