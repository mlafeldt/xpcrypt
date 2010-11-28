PROJECT("xpcrypt" C)

CMAKE_MINIMUM_REQUIRED(VERSION 2.6)

SET(CMAKE_C_FLAGS "-Wall -Werror -O2 -s")

ADD_EXECUTABLE(xpcrypt xp_crypto.c xpcrypt.c)

INSTALL(TARGETS xpcrypt DESTINATION bin)
