#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

typedef void(*log_callback_t)(const char*);

#define LOG_SET_STDOUT log_config(NULL, log_stdout)
#define LOG_SET_CALLBACK(callback) log_config(NULL, callback)

#define DEBUG(...)                             \
	log_fmt_msg("(%s) ", __func__);               \
	log_fmt_msg(__VA_ARGS__);                     \
	log_fmt_msg(" (%s, %d)", __FILE__, __LINE__); \
	log_flush();

#define MESSAGE(...) log_fmt_msg(__VA_ARGS__); log_flush()

void log_stdout(const char* msg);

void log_config(const char* msg, log_callback_t callback);

void log_fmt_msg(const char* fmt, ...);

void log_flush();

#endif
