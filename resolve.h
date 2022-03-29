#pragma once
#include <stdbool.h>
#include <sys/socket.h>

/**
 * Resolve a string with an IP adress or DNS name into a socket address
 */
bool resolve_address(const char *addrstr, struct sockaddr *dst);
