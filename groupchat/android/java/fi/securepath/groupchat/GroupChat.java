package fi.securepath.groupchat;

/**
 * The groupchat core on Android: the JSON API of json_manager over JNI. Commands are
 * called by name with their JSON argument and answer with JSON; notifications come to the
 * listener from the core's own thread. The commands, their arguments and the
 * notifications are documented in groupchat/json_protocol/doc.
 */
public final class GroupChat {
	/** What the core tells the app; type is "notification", "state_change" or "request". */
	public interface Listener {
		void onEvent(String type, String json);
	}

	static {
		System.loadLibrary("gc_adapter");
	}

	/**
	 * Start the core with the app's private directory as the root of its files and the
	 * DER file of the root public key that anchors the servers' certificates (empty for
	 * the built-in default). Calling it again only replaces the listener, which a
	 * reload of the app front end needs.
	 */
	public static native void init(String path, String rootPublicKeyFile, Listener listener);

	/** A command of the JSON API by its name, e.g. "send_message", with its JSON argument. */
	public static native String call(String command, String args);

	/** Stop the core: the connections close and nothing is delivered after this. */
	public static native void shutdown();

	private GroupChat() {}
}
