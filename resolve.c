#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include "resolve.h"

bool resolve_address(const char *addrstr, struct sockaddr *dst) {
  struct addrinfo *info;
  struct addrinfo hints;

  memset(&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_family = AF_INET;

  if (getaddrinfo(addrstr, NULL, &hints, &info) < 0) {
    printf("Could not look up hostname %s\n", addrstr);
    return false;
  }

  memcpy(dst, info->ai_addr, info->ai_addrlen);
  return true;
}