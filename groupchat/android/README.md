# groupchat on Android

The groupchat core for an Android app: `gc_lib` (the core with its JSON API, built for
each ABI by `build-android.sh`) behind a small JNI adapter, `libgc_adapter.so`, and one
Java class, `fi.securepath.groupchat.GroupChat`.

```
scripts/build-android-deps.sh <deps dir> arm64-v8a     # Botan, sqlite3, asio for the ABI
ANDROID_NDK=<ndk> build-android.sh <deps dir> arm64-v8a  # gc_lib and json_manager.hpp
```

Then the app's Gradle `externalNativeBuild` points at `groupchat/android/CMakeLists.txt`
with `-DGC_DEPS=<deps dir>` and the ABI filter, and `java/fi/securepath/groupchat/
GroupChat.java` goes into the app's sources.

## The Java side

```java
GroupChat.init(getFilesDir().getPath(), rootKeyFile, (type, json) -> handle(type, json));
String account = GroupChat.call("get_account", "");
String sent = GroupChat.call("send_message", "{\"id\": \"...\", \"message\": \"hello\"}");
GroupChat.shutdown();
```

`init` starts the core with the app's private directory as the root of its files (its
databases, chat data, the log `gc.log`) and the DER file of the root public key that
anchors the servers' certificates. Calling it again only replaces the listener, which a
reloaded front end needs. `call` runs a command of the JSON API by the name of the
`json_manager` function (`get_account`, `create_account`, `get_config`, `set_config`,
`connect`, `disconnect`, `get_contacts`, `add_contact`, `get_chats`, `create_chat`,
`join_chat`, `get_chat_members`, `change_chat_member`, `get_messages`, `send_message`,
`share_file`, `get_files`, `fetch_file`, `save_file`, `remove_file`, `handle_qr_code`,
`get_version`, `get_requests`, `request_action`) with its JSON argument and answers with
the JSON result; an unknown command or a call before `init` answers
`{"error": {"code": -1, "message": ..., "aux": ...}}`, the shape of every error of the
API. The commands, arguments, results and notifications are documented in
`groupchat/json_protocol/doc`.

The listener's `onEvent(type, json)` gets every notification of the core with the type
`notification`, `state_change` or `request`, from the core's own thread: hand it to the
UI thread before touching views. A listener that was garbage collected is skipped.
