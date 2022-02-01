#ifndef STRINGOPS_H
#define STRINGOPS_H

#include <stdexcept>
#include <functional>
#include <string>
#include <sstream>
#include <list>
#include <vector>
#include <string.h>

/**
 * @brief Operations of strings and T
 * @tparam T the typename to work with
 */
template<typename T>
struct StringOperations {

	/**
	 * @brief Group a list of items to one string (using parser) with glue string between each
	 * @tparam L a container object that holds elements of type T
	 * @tparam F a function object that converts from const T& to std::string
	 * @param glue String to glue elements with
	 */
	template<typename L, class F>
	std::string join(const L& lst, const std::string& glue, F t_to_string) {
		std::stringstream ss;
		uint32_t counter=0;
		for (auto it : lst) {
			ss << t_to_string(it);
			if (counter++ != lst.size()-1) {
				ss << glue;
			}
		}
		return ss.str();
	}

	/**
	 * @brief Splits a string base of delimiter char
	 * @tparam F a function object that converts from const std::string& to T
	 * @param str A string to split
	 * @param delim Array of delimiter chars
	 * @return A vector of T
	 */
	template<class F>
	std::vector<T> split(const std::string& str, const std::string& delim, F string_to_t) {
		std::vector<T> output;
		// Split to parts by delimiters
		char* local_cpy = strdup(str.c_str());
		const char* delimiters = delim.c_str();
		char* token = strtok(local_cpy, delimiters);
		while (token != NULL) {
			// Create a copy of the string
			std::string current(token);
			// Parse it, add to output vector
			output.push_back(string_to_t(current));
			// Get the next token
			token = strtok(NULL, delimiters);
		}
		// Delete local memory
		free(local_cpy);
	    return output;
	}

	/**
	 * @brief Converts an hex representation to 32bit integer
	 * @param str A string with hex representation of a number
	 * @note Taken from here: https://stackoverflow.com/a/39052987/4103200
	 */
	static uint32_t hex2int(const std::string& str) {
	    uint32_t val = 0;
	    const char* hex = str.c_str();
	    // Skip the chars 0x if exist
	    if (*hex == '0' && *(hex+1) == 'x') hex+=2;
	    while (*hex) {
	        // get current character then increment
	        uint8_t byte = *hex++;
	        // transform hex character to the 4bit equivalent number, using the ascii table indexes
	        if (byte >= '0' && byte <= '9') byte = byte - '0';
	        else if (byte >= 'a' && byte <='f') byte = byte - 'a' + 10;
	        else if (byte >= 'A' && byte <='F') byte = byte - 'A' + 10;
	        // shift 4 to make space for new digit, and add the 4 bits of the new digit
	        val = (val << 4) | (byte & 0xF);
	    }
	    return val;
	}

	static uint32_t str2uint(const std::string s) {
		return atoi(s.c_str());
	}
};
#endif
