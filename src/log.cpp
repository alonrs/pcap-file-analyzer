#include "log.h"
#include "string.h"

#define MAX_LOG_SIZE 1024

static char buffer[MAX_LOG_SIZE];
static int position = 0;

void
log_stdout(const char* msg)
{
	fprintf(stdout, "%s", msg);
	fflush(stdout);
}

void
log_config(const char* msg,
           log_callback_t callback)
{
	static log_callback_t cb;
	if (callback) {
		cb = callback;
	}
	if (cb && msg) {
		cb(msg);
	}
}

void
log_fmt_msg(const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	size_t size = vsnprintf(NULL, 0, fmt, args)+1;
	if (position + size >= MAX_LOG_SIZE) {
		size = MAX_LOG_SIZE - position - 1;
	}
	va_start(args, fmt);
	vsnprintf(buffer+position, size, fmt, args);
	position = (position + size - 1) % MAX_LOG_SIZE;
}

void
log_flush() {
	log_config(buffer, NULL);
	position = 0;
}

