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

#include "functions.h"

#include <conio.h>
#include <iostream>
#include <iphlpapi.h>
#include <sstream>
#include <string>

namespace xiloader
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
    bool functions::MaskCompare(const unsigned char* lpDataPtr, const unsigned char* lpPattern, const char* pszMask)
    {
        for (; *pszMask; ++pszMask, ++lpDataPtr, ++lpPattern)
        {
            if (*pszMask == 'x' && *lpDataPtr != *lpPattern)
                return false;
        }
        return (*pszMask) == NULL;
    }

    /**
     * @brief Locates a signature of bytes using the given mask within the given module.
     *
     * @param moduleName    The name of the module to scan within.
     * @param lpPattern     The pattern of bytes to compare with.
     * @param pszMask       The mask to compare against.
     *
     * @return Start address of where the pattern was found, NULL otherwise.
     */
    DWORD functions::FindPattern(const char* moduleName, const unsigned char* lpPattern, const char* pszMask)
    {
        MODULEINFO mod = { 0 };
        if (!GetModuleInformation(GetCurrentProcess(), GetModuleHandleA(moduleName), &mod, sizeof(MODULEINFO)))
            return 0;

        for (DWORD x = 0; x < mod.SizeOfImage; x++)
        {
            if (functions::MaskCompare(reinterpret_cast<unsigned char*>((DWORD)mod.lpBaseOfDll + x), lpPattern, pszMask))
                return ((DWORD)mod.lpBaseOfDll + x);
        }
        return 0;
    }

    /**
     * @brief Obtains the PlayOnline registry key.
     *  "SOFTWARE\PlayOnlineXX"
     *
     * @param lang      The language id the loader was started with.
     *
     * @return registry pathname.
     */
    const char* functions::GetRegistryPlayOnlineKey(int lang)
    {
        static const char* RegistryKeys[3] = {
            "SOFTWARE\\PlayOnline",   // xiloader::Japanese
            "SOFTWARE\\PlayOnlineUS", // xiloader::English
            "SOFTWARE\\PlayOnlineEU"  // xiloader::European
        };

        if (lang < 0)
            lang = 0;
        if (lang > 2)
            lang = 2;

        return RegistryKeys[lang];
    }

    /**
     * @brief Obtains the PlayOnline language id from the system registry.
     *
     * @param lang          The language id the loader was started with.
     *
     * @return The language id from the registry, 1 otherwise.
     */
    int functions::GetRegistryPlayOnlineLanguage(int lang)
    {
        const char* SquareEnix = (lang == 0 /*xiloader::Japanese*/) ? "Square" : "SquareEnix";

        char szRegistryPath[MAX_PATH];
        sprintf_s(szRegistryPath, MAX_PATH, "%s\\%s\\PlayOnlineViewer\\Settings", functions::GetRegistryPlayOnlineKey(lang), SquareEnix);

        HKEY  hKey       = NULL;
        DWORD dwRegValue = 0;
        DWORD dwRegSize  = sizeof(DWORD);
        DWORD dwRegType  = REG_DWORD;

        if (::RegOpenKeyExA(HKEY_LOCAL_MACHINE, szRegistryPath, 0, KEY_QUERY_VALUE | KEY_WOW64_32KEY, &hKey) == ERROR_SUCCESS)
        {
            if (::RegQueryValueExA(hKey, "Language", NULL, &dwRegType, (LPBYTE)&dwRegValue, &dwRegSize) == ERROR_SUCCESS)
            {
                if (dwRegType == REG_DWORD && dwRegSize == sizeof(DWORD))
                    lang = (int)dwRegValue;
            }
            ::RegCloseKey(hKey);
        }

        return lang;
    }

    /**
     * @brief Obtains the PlayOnlineViewer folder from the system registry.
     *  "C:\Program Files\PlayOnline\PlayOnlineViewer"
     *
     * @param lang      The language id the loader was started with.
     *
     * @return installation folder path.
     */
    const char* functions::GetRegistryPlayOnlineInstallFolder(int lang)
    {
        static char InstallFolder[MAX_PATH] = { 0 };

        char szRegistryPath[MAX_PATH];
        sprintf_s(szRegistryPath, MAX_PATH, "%s\\InstallFolder", functions::GetRegistryPlayOnlineKey(lang));

        HKEY  hKey      = NULL;
        DWORD dwRegSize = sizeof(InstallFolder);
        DWORD dwRegType = REG_SZ;
        bool  found     = false;

        if (::RegOpenKeyExA(HKEY_LOCAL_MACHINE, szRegistryPath, 0, KEY_QUERY_VALUE | KEY_WOW64_32KEY, &hKey) == ERROR_SUCCESS)
        {
            if (::RegQueryValueExA(hKey, "1000", NULL, &dwRegType, (LPBYTE)InstallFolder, &dwRegSize) == ERROR_SUCCESS)
            {
                if (dwRegType == REG_SZ && dwRegSize > 0 && dwRegSize < sizeof(InstallFolder))
                    found = true;
            }
            ::RegCloseKey(hKey);
        }

        if (found == false)
            InstallFolder[0] = '\0';

        return InstallFolder;
    }

    std::optional<mac_address> functions::GetMACAddress()
    {
        // Allocate space for at least one adapter..
        auto  adapter = (IP_ADAPTER_INFO*)new uint8_t[sizeof(IP_ADAPTER_INFO)];
        ULONG size    = 0;

        auto result = ::GetAdaptersInfo(adapter, &size);
        // Obtain the adapter info, if fails, resize the buffer..
        while (result != ERROR_SUCCESS)
        {
            delete[] adapter;
            if (result == ERROR_BUFFER_OVERFLOW)
            {
                adapter = (IP_ADAPTER_INFO*)new uint8_t[size];
                result  = ::GetAdaptersInfo(adapter, &size);
            }
            else
            {
                return std::nullopt;
            }
        }

        // Find an adapter with the right amount of bytes
        mac_address mac = {};
        while (adapter)
        {
            if (adapter->AddressLength != 6)
            {
                adapter = adapter->Next;
                continue;
            }

            // An address with the correct length has been found
            memcpy(&mac.bytes, adapter->Address, 6);
            delete[] adapter;
            return std::make_optional(mac);
        }

        // No valid address found
        delete[] adapter;
        return std::nullopt;
    }

    void functions::ReadAndMaskPassword(std::string& output)
    {
        /* Read in each char and instead of displaying it. display a "*" */
        char ch;
        while ((ch = static_cast<char>(_getch())) != '\r')
        {
            if (ch == '\0')
            {
                continue;
            }
            else if (ch == '\b')
            {
                if (output.size())
                {
                    output.pop_back();
                    std::cout << "\b \b";
                }
            }
            else
            {
                output.push_back(ch);
                std::cout << '*';
            }
        }
        std::cout << std::endl;
    }

    void functions::PromptInput(std::string& output, const size_t minLen, const size_t maxLen, const char* inputText, const char* retryText)
    {
        const char* retryTextUse = strlen(retryText) == 0 ? inputText : retryText;

        std::ostringstream ss;
        ss << minLen << "-" << maxLen;
        const std::string charRange = ss.str();

        std::cout << inputText << " (" << charRange << " characters): ";

        output.clear();
        std::cin >> output;

        while (output.length() < minLen || output.length() > maxLen)
        {
            std::cout << retryTextUse << " has to be " << charRange << " characters, try again: ";
            output.clear();
            std::cin >> output;
        }
    }

    void functions::PromptMaskedInput(std::string& output, const size_t minLen, const size_t maxLen, const char* inputText, const char* retryText)
    {
        const char* retryTextUse = strlen(retryText) == 0 ? inputText : retryText;

        std::ostringstream ss;
        ss << minLen << "-" << maxLen;
        const std::string charRange = ss.str();

        std::cout << inputText << " (" << charRange << " characters): ";

        output.clear();
        xiloader::functions::ReadAndMaskPassword(output);

        while (output.length() < minLen || output.length() > maxLen)
        {
            std::cout << retryTextUse << " has to be " << charRange << " characters, try again: ";
            output.clear();
            xiloader::functions::ReadAndMaskPassword(output);
        }
    }

    constexpr const char BASE64_CHARS[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /*
     * Base64 encoding/decoding (RFC1341)
     * Copyright (c) 2005-2011, Jouni Malinen <j@w1.fi>
     *
     * This software may be distributed under the terms of the BSD license.
     * See README for more details.
     * https://web.mit.edu/freebsd/head/contrib/wpa/src/utils/base64.c
     */
    std::string functions::Base64Encode(const uint8_t* src, const size_t len)
    {
        unsigned char *      out, *pos;
        const unsigned char *end, *in;

        size_t olen;

        olen = 4 * ((len + 2) / 3); /* 3-byte blocks to 4-byte */

        if (olen < len)
            return std::string(); /* integer overflow */

        std::string outStr;
        outStr.resize(olen);
        out = (unsigned char*)&outStr[0];

        end = src + len;
        in  = src;
        pos = out;
        while (end - in >= 3)
        {
            *pos++ = BASE64_CHARS[in[0] >> 2];
            *pos++ = BASE64_CHARS[((in[0] & 0x03) << 4) | (in[1] >> 4)];
            *pos++ = BASE64_CHARS[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
            *pos++ = BASE64_CHARS[in[2] & 0x3f];
            in += 3;
        }

        if (end - in)
        {
            *pos++ = BASE64_CHARS[in[0] >> 2];
            if (end - in == 1)
            {
                *pos++ = BASE64_CHARS[(in[0] & 0x03) << 4];
                *pos++ = '=';
            }
            else
            {
                *pos++ = BASE64_CHARS[((in[0] & 0x03) << 4) |
                                      (in[1] >> 4)];
                *pos++ = BASE64_CHARS[(in[1] & 0x0f) << 2];
            }
            *pos++ = '=';
        }

        return outStr;
    }

    static const int B64index[256] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 62, 63, 62, 62, 63, 52, 53, 54, 55,
        56, 57, 58, 59, 60, 61, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6,
        7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 0,
        0, 0, 0, 63, 0, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51
    };

    // Decode is a from this snippet from polfosol: https://stackoverflow.com/a/37109258/2236416
    std::vector<uint8_t> functions::Base64Decode(const std::string_view& input)
    {
        const char*  p   = input.data();
        const size_t len = input.length();

        int          pad = len > 0 && (len % 4 || p[len - 1] == '=');
        const size_t L   = ((len + 3) / 4 - pad) * 4;

        std::vector<uint8_t> out(L / 4 * 3 + pad, 0);

        for (size_t i = 0, j = 0; i < L; i += 4)
        {
            int n    = B64index[p[i]] << 18 | B64index[p[i + 1]] << 12 | B64index[p[i + 2]] << 6 | B64index[p[i + 3]];
            out[j++] = n >> 16;
            out[j++] = n >> 8 & 0xFF;
            out[j++] = n & 0xFF;
        }
        if (pad)
        {
            int n               = B64index[p[L]] << 18 | B64index[p[L + 1]] << 12;
            out[out.size() - 1] = n >> 16;

            if (len > L + 2 && p[L + 2] != '=')
            {
                n |= B64index[p[L + 2]] << 6;
                out.push_back(n >> 8 & 0xFF);
            }
        }
        return out;
    }

}; // namespace xiloader
