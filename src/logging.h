#ifndef LOGGING_H
#define LOGGING_H

#ifndef WARN
#define WARN(...) fprintf(stderr, "[WARN]: " __VA_ARGS__)
#else
#define WARN(...) /* nothing */
#endif

#if !(defined(_NDEBUG) || defined(NDEBUG))
#define LOG_DEBUG(...) gmp_fprintf(stderr, "[DEBUG]: " __VA_ARGS__)
#define Zd(x) LOG_DEBUG(#x ": %Zd\n", x)
#else
#define LOG_DEBUG(...) /* nothing */
#define Zd(x)          /* nothing */
#endif

#endif LOGGING_H