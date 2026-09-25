// SPDX-License-Identifier: MIT

#pragma once

#include <functional>
#include <memory>
#include <type_traits>
#include <utility>
#include <version>

namespace securepath {

#if defined(__cpp_lib_move_only_function) && __cpp_lib_move_only_function >= 202110L

template<typename Signature>
using move_only_function = std::move_only_function<Signature>;

#else

template<typename Signature>
class move_only_function;

/**
 * move_only_function of C++23 where the standard library lacks it (libc++ up to 21,
 * the Android NDK): a move-only, type erased callable of a plain signature. No small
 * buffer, no const or noexcept qualified signatures - what this code base uses.
 */
template<typename R, typename... Args>
class move_only_function<R(Args...)> {
	struct callable {
		virtual ~callable() = default;
		virtual R call(Args&&... args) = 0;
	};

	template<typename F>
	struct holder : callable {
		template<typename G>
		explicit holder(G&& g) : f(std::forward<G>(g)) {}

		R call(Args&&... args) override {
			return std::invoke(f, std::forward<Args>(args)...);
		}

		F f;
	};

public:
	move_only_function() = default;
	move_only_function(std::nullptr_t) {}

	template<typename F>
	requires (!std::is_same_v<std::remove_cvref_t<F>, move_only_function> && std::is_invocable_r_v<R, std::decay_t<F>&, Args...>)
	move_only_function(F&& f)
	: callable_(std::make_unique<holder<std::decay_t<F>>>(std::forward<F>(f)))
	{}

	move_only_function(move_only_function&&) noexcept = default;
	move_only_function& operator=(move_only_function&&) noexcept = default;

	move_only_function& operator=(std::nullptr_t) {
		callable_.reset();
		return *this;
	}

	R operator()(Args... args) {
		return callable_->call(std::forward<Args>(args)...);
	}

	explicit operator bool() const noexcept {
		return callable_ != nullptr;
	}

private:
	std::unique_ptr<callable> callable_;
};

#endif

}
