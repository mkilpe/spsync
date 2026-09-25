// SPDX-License-Identifier: MIT

// The JNI side of fi.securepath.groupchat.GroupChat (GroupChat.java): one json_manager for
// the process, its commands called by name, its notifications delivered to the listener
// from the core's thread. Built by the CMakeLists next to this file into libgc_adapter.so
// against the gc_lib archive of build-android.sh.

#include <jni.h>
#include <android/log.h>

#include "json_manager.hpp"

#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>

namespace {

using namespace securepath::groupchat::json_protocol;

char const* const log_tag = "groupchat";

std::mutex mutex;
std::unique_ptr<json_manager> manager;
JavaVM* java_vm{};
/// the listener, weakly: a front end that went away is not kept alive
jweak listener{};
jmethodID on_event{};

void log_info(std::string const& message) {
	__android_log_write(ANDROID_LOG_INFO, log_tag, message.c_str());
}

void log_warn(std::string const& message) {
	__android_log_write(ANDROID_LOG_WARN, log_tag, message.c_str());
}

std::string to_std_string(JNIEnv* env, jstring s) {
	if(!s) {
		return {};
	}
	char const* native = env->GetStringUTFChars(s, nullptr);
	std::string ret{native};
	env->ReleaseStringUTFChars(s, native);
	return ret;
}

jstring to_java(JNIEnv* env, std::string const& s) {
	return env->NewStringUTF(s.c_str());
}

char const* type_name(event_type type) {
	switch(type) {
	case event_type::notification: return "notification";
	case event_type::state_change: return "state_change";
	case event_type::request: return "request";
	}
	return "notification";
}

/// the JNI environment of this thread, attached for the call when it is not a Java thread
struct attached_env {
	attached_env(JavaVM* vm)
	: vm(vm)
	{
		int const res = vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6);
		if(res == JNI_EDETACHED) {
			JavaVMAttachArgs args{JNI_VERSION_1_6, "groupchat core", nullptr};
			attached = vm->AttachCurrentThread(&env, &args) == JNI_OK;
			if(!attached) {
				log_warn("could not attach the core's thread to the JVM");
				env = nullptr;
			}
		} else if(res != JNI_OK) {
			log_warn("JNI version not supported");
			env = nullptr;
		}
	}

	~attached_env() {
		if(attached) {
			vm->DetachCurrentThread();
		}
	}

	JavaVM* vm{};
	JNIEnv* env{};
	bool attached{};
};

/// a notification of the core to the listener's onEvent, from the core's thread
void deliver(event_type type, std::string const& json) {
	JavaVM* vm{};
	jweak target{};
	jmethodID method{};
	{
		std::unique_lock l{mutex};
		vm = java_vm;
		target = listener;
		method = on_event;
	}
	if(!vm || !target || !method) {
		log_warn("a notification before init, dropped");
		return;
	}
	attached_env attached{vm};
	if(!attached.env) {
		return;
	}
	auto* env = attached.env;
	// the front end may have been collected: then there is nobody to tell
	if(!env->IsSameObject(target, nullptr)) {
		env->CallVoidMethod(target, method, to_java(env, type_name(type)), to_java(env, json));
	}
	if(env->ExceptionCheck()) {
		log_warn("the listener threw on a notification");
		env->ExceptionDescribe();
		env->ExceptionClear();
	}
}

using command = std::function<std::string(json_manager&, std::string const&)>;

/// the commands of the JSON API by the names of the json_manager functions
std::map<std::string, command> const& commands() {
	static std::map<std::string, command> const table{
		{"get_account", [](json_manager& m, std::string const&) { return m.get_account(); }},
		{"create_account", [](json_manager& m, std::string const& a) { return m.create_account(a); }},
		{"get_config", [](json_manager& m, std::string const& a) { return m.get_config(a); }},
		{"set_config", [](json_manager& m, std::string const& a) { return m.set_config(a); }},
		{"connect", [](json_manager& m, std::string const&) { return m.connect(); }},
		{"disconnect", [](json_manager& m, std::string const&) { return m.disconnect(); }},
		{"get_contacts", [](json_manager& m, std::string const& a) { return m.get_contacts(a); }},
		{"add_contact", [](json_manager& m, std::string const& a) { return m.add_contact(a); }},
		{"get_chats", [](json_manager& m, std::string const& a) { return m.get_chats(a); }},
		{"create_chat", [](json_manager& m, std::string const& a) { return m.create_chat(a); }},
		{"join_chat", [](json_manager& m, std::string const& a) { return m.join_chat(a); }},
		{"get_chat_members", [](json_manager& m, std::string const& a) { return m.get_chat_members(a); }},
		{"change_chat_member", [](json_manager& m, std::string const& a) { return m.change_chat_member(a); }},
		{"get_messages", [](json_manager& m, std::string const& a) { return m.get_messages(a); }},
		{"send_message", [](json_manager& m, std::string const& a) { return m.send_message(a); }},
		{"share_file", [](json_manager& m, std::string const& a) { return m.share_file(a); }},
		{"get_files", [](json_manager& m, std::string const& a) { return m.get_files(a); }},
		{"fetch_file", [](json_manager& m, std::string const& a) { return m.fetch_file(a); }},
		{"save_file", [](json_manager& m, std::string const& a) { return m.save_file(a); }},
		{"remove_file", [](json_manager& m, std::string const& a) { return m.remove_file(a); }},
		{"handle_qr_code", [](json_manager& m, std::string const& a) { return m.handle_qr_code(a); }},
		{"get_version", [](json_manager& m, std::string const&) { return m.get_version(); }},
		{"get_requests", [](json_manager& m, std::string const& a) { return m.get_requests(a); }},
		{"request_action", [](json_manager& m, std::string const& a) { return m.request_action(a); }},
	};
	return table;
}

/// an error answer in the shape of the JSON API's errors (json_helpers error_to_json)
std::string error_json(std::string const& message, std::string const& aux) {
	return "{\"error\": {\"code\": -1, \"message\": \"" + message + "\", \"aux\": \"" + aux + "\"}}";
}

}

extern "C" {

JNIEXPORT void JNICALL
Java_fi_securepath_groupchat_GroupChat_init(JNIEnv* env, jclass, jstring path, jstring root_key_file, jobject java_listener) {
	std::unique_lock l{mutex};
	// the listener is set again on every init: a reloaded front end brings a new one
	env->GetJavaVM(&java_vm);
	if(listener) {
		env->DeleteWeakGlobalRef(listener);
	}
	listener = env->NewWeakGlobalRef(java_listener);
	on_event = env->GetMethodID(env->GetObjectClass(java_listener), "onEvent", "(Ljava/lang/String;Ljava/lang/String;)V");
	if(manager) {
		log_info("groupchat core already running, listener replaced");
		return;
	}
	auto const root = to_std_string(env, path);
	log_info("groupchat core starting under " + root);
	initialise_logging(root + "/gc.log");
	manager = std::make_unique<json_manager>([](event_type type, std::string const& json) { deliver(type, json); }
		, root, to_std_string(env, root_key_file));
}

JNIEXPORT jstring JNICALL
Java_fi_securepath_groupchat_GroupChat_call(JNIEnv* env, jclass, jstring command, jstring args) {
	auto const name = to_std_string(env, command);
	auto const it = commands().find(name);
	if(!manager) {
		return to_java(env, error_json("the groupchat core is not running", "init first"));
	}
	if(it == commands().end()) {
		return to_java(env, error_json("no such command", name));
	}
	return to_java(env, it->second(*manager, to_std_string(env, args)));
}

JNIEXPORT void JNICALL
Java_fi_securepath_groupchat_GroupChat_shutdown(JNIEnv* env, jclass) {
	std::unique_ptr<json_manager> stopping;
	{
		std::unique_lock l{mutex};
		stopping.swap(manager);
		if(listener) {
			env->DeleteWeakGlobalRef(listener);
			listener = nullptr;
		}
		on_event = nullptr;
	}
	if(stopping) {
		log_info("groupchat core stopping");
		stopping->close();
		stopping.reset();
	}
}

}
