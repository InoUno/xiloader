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

#ifndef __XILOADER_FUNCTIONS_H_INCLUDED__
#define __XILOADER_FUNCTIONS_H_INCLUDED__

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

#include <optional>
#include <string>
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <psapi.h>

namespace xiloader
{
    struct mac_address
    {
        uint8_t bytes[6];
    };

    /**
     * @brief Functions class containing helper functions for various tasks.
     */
    class functions
    {
        /**
         * @brief Compares a pattern against a given memory pointer.
         *
         * @param lpDataPtr     The live data to compare with.
         * @param lpPattern     The pattern of bytes to compare with.
         * @param pszMask       The mask to compare against.
         *
         * @return True if pattern was found, false otherwise.
         */
        static bool MaskCompare(const unsigned char* lpDataPtr, const unsigned char* lpPattern, const char* pszMask);

    public:
        /**
         * @brief Locates a signature of bytes using the given mask within the given module.
         *
         * @param moduleName    The name of the module to scan within.
         * @param lpPattern     The pattern of bytes to compare with.
         * @param pszMask       The mask to compare against.
         *
         * @return Start address of where the pattern was found, NULL otherwise.
         */
        static DWORD FindPattern(const char* moduleName, const unsigned char* lpPattern, const char* pszMask);

        /**
         * @brief Obtains the PlayOnline registry key.
         *  "SOFTWARE\PlayOnlineXX"
         *
         * @param lang      The language id the loader was started with.
         *
         * @return registry pathname.
         */
        static const char* GetRegistryPlayOnlineKey(int lang);

        /**
         * @brief Obtains the PlayOnline language id from the system registry.
         *
         * @param lang      The language id the loader was started with.
         *
         * @return The language id from the registry, 1 otherwise.
         */
        static int GetRegistryPlayOnlineLanguage(int lang);

        /**
         * @brief Obtains the PlayOnlineViewer folder from the system registry.
         *  "C:\Program Files\PlayOnline\PlayOnlineViewer"
         *
         * @param lang      The language id the loader was started with.
         *
         * @return installation folder path.
         */
        static const char* GetRegistryPlayOnlineInstallFolder(int lang);

        /**
         * @brief Finds the MAC address of the network adapter.
         *
         * @return The MAC address of the network adapter.
         */
        static std::optional<mac_address> GetMACAddress();

        /**
         * Takes a password as input and masks it.
         */
        static void ReadAndMaskPassword(std::string& output);

        /**
         * Prompts for an input of a certain length until it matches.
         */
        static void PromptInput(std::string& output, const size_t minLen, const size_t maxLen, const char* inputText, const char* retryText = "");

        /**
         * Prompts for an input of a certain length until it matches.
         */
        static void PromptMaskedInput(std::string& output, const size_t minLen, const size_t maxLen, const char* inputText, const char* retryText = "");

        static std::string          Base64Encode(const uint8_t* src, const size_t len);
        static std::vector<uint8_t> Base64Decode(const std::string_view& input);
    };

}; // namespace xiloader

#endif // __XILOADER_FUNCTIONS_H_INCLUDED__
