/*
===========================================================================

Copyright (c) 2010-2014 Darkstar Dev Teams

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see http://www.gnu.org/licenses/

This file is part of DarkStar-server source code.

===========================================================================
*/

#ifndef __XILOADER_NETWORK_H_INCLUDED__
#define __XILOADER_NETWORK_H_INCLUDED__

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

#include <conio.h>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>

#include "console.h"

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"

namespace xiloader
{
    /**
     * @brief Socket object used to hold various important information.
     */
    typedef struct datasocket_t
    {
        datasocket_t()
        : s(INVALID_SOCKET)
        , LocalAddress((ULONG)-1)
        , ServerAddress((ULONG)-1)
        {
        }

        SOCKET s;
        ULONG  LocalAddress;
        ULONG  ServerAddress;
    } datasocket;

    /**
     * @brief Network class containing functions related to networking.
     */
    class network
    {
        /**
         * @brief Data communication between the local client and the game server.
         *
         * @param lpParam       Thread param object.
         *
         * @return Non-important return.
         */
        static DWORD __stdcall FFXiDataComm(LPVOID lpParam);

    public:
        /**
         * @brief Creates a connection on the given port.
         *
         * @param sock          The datasocket object to store information within.
         * @param port          The port to create the connection on.
         *
         * @return True on success, false otherwise.
         */
        static bool CreateConnection(datasocket* sock, const char* port);

        /**
         * @brief Creates a connection to the server on the given port.
         *
         * @param sock          The datasocket object to store information within.
         * @param port          The port to create the connection on.
         *
         * @return True on success, false otherwise.
         */
        static bool CreateAuthConnection(datasocket* sock, const char* port);

        /**
         * @brief Resolves the given hostname to its long ip format.
         *
         * @param host          The host name to resolve.
         * @param lpOutput      Pointer to a ULONG to store the result.
         *
         * @return True on success, false otherwise.
         */
        static bool ResolveHostname(const char* host, PULONG lpOutput);

        /**
         * @brief Sends authentication requests to the server.
         *
         * @param sock          The datasocket object with the connection socket.
         *
         * @return True on success, false otherwise.
         */
        static bool AuthRequest(datasocket* sock);
    };

}; // namespace xiloader

#endif // __XILOADER_NETWORK_H_INCLUDED__
