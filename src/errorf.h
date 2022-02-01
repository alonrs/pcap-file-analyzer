#pragma once

#include <cstdarg>
#include <sstream>
#include <stdexcept>

// Create an exception with an arbitrary message using printf convention
#define errorf(...) Error::create() <<  "Exception: (" <<  \
	__func__ << "@" << __FILE__ << ":" << __LINE__ << ") " << \
	Error::format(__VA_ARGS__)

/**
 * @brief A general error class for constructing informative exceptions
 *        while updating log. Usage should be via MACRO error()
 */
class Error : public std::exception {

	std::stringstream _buffer;
	std::string _message;
	Error() {}

public:

	/**
	 * @brief Used by the throw mechanism
	 */
	Error(const Error& rhs) {
		this->_message = rhs._message;
	}

	/**
	 * @brief Creates new exception class
	 */
	static Error create() {
		return Error();
	}

	/**
	 * @brief Append to message arbitrary info
	 */
	template <typename T>
	Error& operator<<(const T& rhs) {
		_buffer << rhs;
		_message = _buffer.str();
		return *this;
	}

	/**
	 * @brief A log command. Adds formatted message.
	 */
	static std::string format(const char* fmt, ...) {
		std::va_list args;
		va_start(args, fmt);
		size_t size = vsnprintf( nullptr, 0, fmt, args) + 1;
		char buffer[size];
		va_start(args, fmt);
		vsnprintf(buffer, size, fmt, args);
		return std::string(buffer);
	}

	virtual const char* what() const noexcept {
		return _message.c_str();
	}
};

