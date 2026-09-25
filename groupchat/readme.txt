
This is simple group chat implementation using the spsync.

Idea:

Create new object for each message, the record header contains the message and no record data is needed.
The server orders the "messages" for us, so everyone will see messages in same order.



Shared files (doc/shared_files.txt): a file shared with a chat is its own object of the
chat storage with a gc_file_v1 entry in its record and the file as the record's data,
stored and moved by spsync's record data machinery (doc/record_data.txt). Nothing is
fetched unasked; the server needs the data role for it (spsync_server --data_role
--data_servers, see scripts/multi_server_env.sh).

Future ideas:

* Introduce editing the messages afterwards by just making change out of it for the same object.
* Versions of a shared file and deleting a share for everyone (doc/shared_files.txt SF 5)