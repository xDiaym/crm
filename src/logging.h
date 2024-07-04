#ifndef LOGGING_H
#define LOGGING_H

#ifndef WARN
#define WARN(...) fprintf(stderr, "[WARN]: " __VA_ARGS__)
#else
#define WARN(...) /* nothing */
#endif

#if !(defined(_NDEBUG) || defined(NDEBUG))
#define DEBUG_LOG(...) gmp_fprintf(stderr, "[DEBUG]: " __VA_ARGS__)
#else
#define DEBUG_LOG(...) /* nothing */
#endif

#endif LOGGING_H