
This is simple group chat implementation using the spsync.

Idea:

Create new object for each message, the record header contains the message and no record data is needed.
The server orders the "messages" for us, so everyone will see messages in same order.



Future ideas:

* Introduce editing the messages afterwards by just making change out of it for the same object.
* Attach pictures or other data to the message as record data