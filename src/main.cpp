/*
===========================================================================

Copyright (c) 2010-2015 Darkstar Dev Teams
Copyright (c) 2021-2022 LandSandBoat Dev Teams

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

#include "defines.h"

#include <ctime>
#include <filesystem>
#include <fstream>
#include <intrin.h>
#include <iostream>
#include <optional>

#include "console.h"
#include "functions.h"
#include "helpers.h"
#include "network.h"

#include "argparse/argparse.hpp"

/* Global Variables */
namespace globals
{
    xiloader::Language g_Language = xiloader::Language::English; // The language of the loader to be used for polcore.

    std::string g_ServerAddress; // The server address to connect to.

    uint16_t g_AuthPort      = 15849; // Login server loader port to connect to
    uint16_t g_PolPort       = 51220; // The POL server port to connect to.
    uint16_t g_LoginViewPort = 54001; // Login view port to connect to

    std::string           g_Username        = ""; // The username being logged in with.
    std::string           g_Password        = ""; // The password being logged in with.
    std::string           g_NewPassword     = ""; // The new password for the account.
    uint8_t               g_SessionHash[16] = {}; // Session hash sent from auth
    std::string           g_Email           = ""; // Email
    xiloader::mac_address g_MacAddress      = {}; // The MAC address for the connection.

    std::string          g_AuthToken = ""; // A provided token that'll be used for authentication.
    std::vector<uint8_t> g_AuthTokenBytes; // The bytes of the auth token to use.

    std::string g_AuthTokenFile = ""; // The file containing the auth token to use or to be saved to.

    bool  g_IsFirstLogin  = true; // Specifies whether this is the first login attempt.
    char* g_CharacterList = NULL; // Pointer to the character list data being sent from the server.

    /* Hairpin Fix Variables */
    DWORD g_NewServerAddress;     // Hairpin server address to be overriden with.
    DWORD g_HairpinReturnAddress; // Hairpin return address to allow the code cave to return properly.
};                                // namespace globals

namespace sslState
{
    // mbed tls state
    mbedtls_net_context               server_fd = {};
    mbedtls_entropy_context           entropy   = {};
    mbedtls_ctr_drbg_context          ctr_drbg  = {};
    mbedtls_ssl_context               ssl       = {};
    mbedtls_ssl_config                conf      = {};
    mbedtls_x509_crt                  cacert    = {};
    std::unique_ptr<mbedtls_x509_crt> ca_chain  = {};
}; // namespace sslState

/**
 * @brief Detour function definitions.
 */
extern "C"
{
    hostent*(WINAPI __stdcall* Real_gethostbyname)(const char* name)       = gethostbyname;
    int(WINAPI* Real_send)(SOCKET s, const char* buf, int len, int flags)  = send;
    int(WINAPI* Real_recv)(SOCKET s, char* buf, int len, int flags)        = recv;
    int(WINAPI* Real_connect)(SOCKET s, const sockaddr* name, int namelen) = connect;
}

/**
 * @brief Hairpin fix codecave.
 */
__declspec(naked) void HairpinFixCave(void)
{
    __asm {
        mov eax, globals::g_NewServerAddress
        mov[edx + 0x012E90], eax
        mov[edx], eax
        jmp globals::g_HairpinReturnAddress
    }
}

/**
 * @brief Applies the hairpin fix modifications.
 *
 * @param lpParam       Thread param object.
 *
 * @return Non-important return.
 */
DWORD ApplyHairpinFixThread(LPVOID lpParam)
{
    UNREFERENCED_PARAMETER(lpParam);

    do
    {
        /* Sleep until we find FFXiMain loaded.. */
        Sleep(100);
    } while (GetModuleHandleA("FFXiMain.dll") == NULL);

    /* Convert server address.. */
    xiloader::network::ResolveHostname(globals::g_ServerAddress.c_str(), &globals::g_NewServerAddress);

    // Locate the main hairpin location..
    //
    // As of 07.08.2013:
    //      8B 82 902E0100        - mov eax, [edx+00012E90]
    //      89 02                 - mov [edx], eax <-- edit this

    auto hairpinAddress = (DWORD)xiloader::functions::FindPattern("FFXiMain.dll", (BYTE*)"\x8B\x82\xFF\xFF\xFF\xFF\x89\x02\x8B\x0D", "xx????xxxx");
    if (hairpinAddress == 0)
    {
        xiloader::console::output(xiloader::color::error, "Failed to locate main hairpin hack address!");
        return 0;
    }

    // Locate zoning IP change address..
    //
    // As of 07.08.2013
    //      74 08                 - je FFXiMain.dll+E5E72
    //      8B 0D 68322B03        - mov ecx, [FFXiMain.dll+463268]
    //      89 01                 - mov [ecx], eax <-- edit this
    //      8B 46 0C              - mov eax, [esi+0C]
    //      85 C0                 - test eax, eax

    auto zoneChangeAddress = (DWORD)xiloader::functions::FindPattern("FFXiMain.dll", (BYTE*)"\x8B\x0D\xFF\xFF\xFF\xFF\x89\x01\x8B\x46", "xx????xxxx");
    if (zoneChangeAddress == 0)
    {
        xiloader::console::output(xiloader::color::error, "Failed to locate zone change hairpin address!");
        return 0;
    }

    /* Apply the hairpin fix.. */
    auto caveDest                   = ((int)HairpinFixCave - ((int)hairpinAddress)) - 5;
    globals::g_HairpinReturnAddress = hairpinAddress + 0x08;

    *(BYTE*)(hairpinAddress + 0x00) = 0xE9; // jmp
    *(UINT*)(hairpinAddress + 0x01) = caveDest;
    *(BYTE*)(hairpinAddress + 0x05) = 0x90; // nop
    *(BYTE*)(hairpinAddress + 0x06) = 0x90; // nop
    *(BYTE*)(hairpinAddress + 0x07) = 0x90; // nop

    /* Apply zone ip change patch.. */
    memset((LPVOID)(zoneChangeAddress + 0x06), 0x90, 2);

    xiloader::console::output(xiloader::color::success, "Hairpin fix applied!");
    return 0;
}

/**
 * @brief gethostbyname detour callback.
 *
 * @param name The hostname to obtain information of.
 *
 * @return Hostname information object.
 */
hostent* __stdcall Mine_gethostbyname(const char* name)
{
    if (!strcmp("ffxi00.pol.com", name))
    {
        return Real_gethostbyname(globals::g_ServerAddress.c_str());
    }

    if (!strcmp("pp000.pol.com", name))
    {
        return Real_gethostbyname(globals::g_ServerAddress.c_str());
    }

    return Real_gethostbyname(name);
}

/**
 * Checks if the socket peer is the lobby view socket by its port
 */
inline bool isViewSocket(const SOCKET& socket)
{
    sockaddr_in addr;
    int         addr_len = sizeof(addr);

    if (getpeername(socket, (sockaddr*)&addr, &addr_len) != 0)
    {
        return false;
    }

    auto port = ntohs(addr.sin_port);

    return port == globals::g_LoginViewPort;
}

/**
 * @brief send detour callback. https://man7.org/linux/man-pages/man2/send.2.html
 */
int WINAPI Mine_send(SOCKET s, const char* buf, int len, int flags)
{
    const auto ret = _ReturnAddress();
    std::ignore    = ret;

    // Add in the session hash if it's the view socket
    if (isViewSocket(s))
    {
        // Always send server provided session hash in packets to the view
        std::memcpy((char*)buf + 12, globals::g_SessionHash, 16);
    }

    return Real_send(s, buf, len, flags);
}

/**
 * @brief recv detour callback. https://man7.org/linux/man-pages/man2/recv.2.html
 */
int WINAPI Mine_recv(SOCKET s, char* buf, int len, int flags)
{
    const auto ret = _ReturnAddress();
    std::ignore    = ret;

    // Check if view socket is receiving characters
    if (len >= 0x1C && isViewSocket(s))
    {
        auto result = Real_recv(s, buf, len, flags);
        if (buf[0x08] == 0x20)
        {
            xiloader::console::output(xiloader::color::lightcyan, "Receiving character list..");

            const uint8_t charSlots = buf[0x1C];
            for (size_t idx = 0; idx < charSlots; idx++)
            {
                globals::g_CharacterList[0x00 + (idx * 0x68)] = 1;
                globals::g_CharacterList[0x02 + (idx * 0x68)] = 1;
                globals::g_CharacterList[0x10 + (idx * 0x68)] = (char)idx;
                globals::g_CharacterList[0x11 + (idx * 0x68)] = 0x80u;
                globals::g_CharacterList[0x18 + (idx * 0x68)] = 0x20;
                globals::g_CharacterList[0x28 + (idx * 0x68)] = 0x20;

                const size_t offset = 32 + idx * 140;

                uint32_t contentId   = ref<uint32_t>(buf, offset);
                uint32_t characterId = ref<uint16_t>(buf, offset + 4) + (buf[offset + 6] << 16) + (buf[offset + 11] << 24);
                memcpy(globals::g_CharacterList + 0x04 + (idx * 0x68), &characterId, 4); // Character Id
                memcpy(globals::g_CharacterList + 0x08 + (idx * 0x68), &contentId, 4);   // Content Id

                if (characterId > 0 || contentId > 0)
                {
                    xiloader::console::output(xiloader::color::lightcyan, "Found character with ID %u (%x)", contentId, contentId);
                }
            }
        }

        return result;
    }

    return Real_recv(s, buf, len, flags);
}

std::optional<int> redirectPolConnect(SOCKET s, const sockaddr* name, int namelen)
{
    // Change POL connect port if it's different from the default one
    constexpr uint16_t DEFAULT_POL_PORT = 51220;
    if (globals::g_PolPort == DEFAULT_POL_PORT)
    {
        return std::nullopt;
    }

    // Check that it's a TCP/IP connection (AF_INET or AF_INET6)
    if (!(name->sa_family == AF_INET || name->sa_family == AF_INET6))
    {
        return std::nullopt;
    }

    char hostname[NI_MAXHOST];
    char portstr[NI_MAXSERV];

    // Use NI_NUMERICSERV to get port as number
    auto result = getnameinfo(name, namelen, hostname, NI_MAXHOST, portstr, NI_MAXSERV, NI_NUMERICSERV);

    if (result != 0)
    {
        std::cerr << "getnameinfo failed: " << gai_strerror(result) << std::endl;
        return std::nullopt;
    }

    // Get the port number
    uint16_t port = 0;
    if (name->sa_family == AF_INET)
    {
        port = ntohs(reinterpret_cast<sockaddr_in const*>(name)->sin_port);
    }
    else if (name->sa_family == AF_INET6)
    {
        port = ntohs(reinterpret_cast<sockaddr_in6 const*>(name)->sin6_port);
    }

    // Get hostname of the server
    auto server_host = gethostbyname(hostname);

    // If server hostname matches connect hostname, and the target port is the default POL port, we want to replace it.
    if (strcmp(hostname, server_host->h_name) == 0 && port == DEFAULT_POL_PORT)
    {
        sockaddr_in newAddr;
        memcpy(&newAddr, name, namelen);

        // Replace port
        if (name->sa_family == AF_INET)
        {
            newAddr.sin_port = htons(globals::g_PolPort);
        }
        else if (name->sa_family == AF_INET6)
        {
            sockaddr_in6* newAddr6 = reinterpret_cast<sockaddr_in6*>(&newAddr);
            newAddr6->sin6_port    = htons(globals::g_PolPort);
        }

        xiloader::console::output(xiloader::color::debug, "Redirected POL to %s:%u", hostname, globals::g_PolPort);
        return { Real_connect(s, reinterpret_cast<sockaddr*>(&newAddr), namelen) };
    }

    return std::nullopt;
}

/**
 * @brief connect detour callback. https://man7.org/linux/man-pages/man2/connect.2.html
 */
int WINAPI Mine_connect(SOCKET s, const sockaddr* name, int namelen)
{
    auto redirect = redirectPolConnect(s, name, namelen);
    if (redirect.has_value())
    {
        return redirect.value();
    }

    // Default to original address
    return Real_connect(s, name, namelen);
}

/**
 * @brief Locates the INET mutex function call inside of polcore.dll
 *
 * @return The pointer to the function call.
 */
inline DWORD FindINETMutex(void)
{
    const char* module = (globals::g_Language == xiloader::Language::European) ? "polcoreeu.dll" : "polcore.dll";
    auto        result = (DWORD)xiloader::functions::FindPattern(module, (BYTE*)"\x8B\x56\x2C\x8B\x46\x28\x8B\x4E\x24\x52\x50\x51", "xxxxxxxxxxxx");
    return (*(DWORD*)(result - 4) + (result));
}

/**
 * @brief Locates the PlayOnline connection object inside of polcore.dll
 *
 * @return Pointer to the pol connection object.
 */
inline DWORD FindPolConn(void)
{
    const char* module = (globals::g_Language == xiloader::Language::European) ? "polcoreeu.dll" : "polcore.dll";
    auto        result = (DWORD)xiloader::functions::FindPattern(module, (BYTE*)"\x81\xC6\x38\x03\x00\x00\x83\xC4\x04\x81\xFE", "xxxxxxxxxxx");
    return (*(DWORD*)(result - 10));
}

/**
 * @brief Locates the current character information block.
 *
 * @return Pointer to the character information table.
 */
inline LPVOID FindCharacters(void** commFuncs)
{
    LPVOID lpCharTable = NULL;
    memcpy(&lpCharTable, (char*)commFuncs[0xD3] + 31, sizeof(lpCharTable));
    return lpCharTable;
}

// Source: https://curl.se/mail/lib-2019-06/0057.html
std::unique_ptr<mbedtls_x509_crt> extract_cert(PCCERT_CONTEXT certificateContext)
{
    // TODO: add delete!
    std::unique_ptr<mbedtls_x509_crt> certificate(new mbedtls_x509_crt);
    mbedtls_x509_crt_init(certificate.get());
    mbedtls_x509_crt_parse(certificate.get(), certificateContext->pbCertEncoded, certificateContext->cbCertEncoded);
    return std::move(certificate);
}

// Source: https://curl.se/mail/lib-2019-06/0057.html
std::unique_ptr<mbedtls_x509_crt> build_windows_ca_chain()
{
    std::unique_ptr<mbedtls_x509_crt> ca_chain         = NULL;
    HCERTSTORE                        certificateStore = NULL;

    if (certificateStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, CERT_SYSTEM_STORE_CURRENT_USER, L"Root"))
    {
        std::unique_ptr<mbedtls_x509_crt> previousCertificate = NULL;
        std::unique_ptr<mbedtls_x509_crt> currentCertificate  = NULL;
        PCCERT_CONTEXT                    certificateContext  = NULL;

        if (certificateContext = CertEnumCertificatesInStore(certificateStore, certificateContext))
        {
            if (certificateContext->dwCertEncodingType & X509_ASN_ENCODING)
            {
                ca_chain            = extract_cert(certificateContext);
                previousCertificate = std::move(ca_chain);
            }

            while (certificateContext = CertEnumCertificatesInStore(certificateStore, certificateContext))
            {
                if (certificateContext->dwCertEncodingType & X509_ASN_ENCODING)
                {
                    currentCertificate        = extract_cert(certificateContext);
                    previousCertificate->next = currentCertificate.get();
                    previousCertificate       = std::move(currentCertificate);
                }
            }

            if (!CertCloseStore(certificateStore, 0))
            {
                return NULL;
            }
        }
    }
    else
    {
        return NULL;
    }

    return ca_chain;
}

/**
 * @brief Main program entrypoint.
 *
 * @param argc      The count of arguments being passed to this application on launch.
 * @param argv      Pointer to array of argument data.
 *
 * @return 1 on error, 0 on success.
 */
int __cdecl main(int argc, char* argv[])
{
    argparse::ArgumentParser args("xiloader", XILOADER_VERSION_STRING);

    bool bUseHairpinFix = false;
    bool bHideConsole   = true;

    // NOTE: .append() is used to allow multiple arguments to be passed to the same option.
    //     : Otherwise it will throw on repeated arguments (normally accidental).

    args.add_argument("--server")
        .store_into(globals::g_ServerAddress)
        .default_value("127.0.0.1")
        .help("The server address to connect to.")
        .append();

    args.add_argument("--user", "--username")
        .store_into(globals::g_Username)
        .default_value("")
        .help("The username being logged in with.")
        .append();

    args.add_argument("--pass", "--password")
        .store_into(globals::g_Password)
        .default_value("")
        .help("The password being logged in with.")
        .append();

    args.add_argument("--email", "--email")
        .store_into(globals::g_Email)
        .default_value("")
        .help("The email being logged in with.")
        .append();

    args.add_argument("--token")
        .store_into(globals::g_AuthToken)
        .default_value("")
        .help("The auth token being logged in with.")
        .append();

    args.add_argument("--tokenfile")
        .store_into(globals::g_AuthTokenFile)
        .default_value("")
        .help("Path to file containing the auth token to use or save to.")
        .append();

    args.add_argument("--authport")
        .store_into(globals::g_AuthPort)
        .default_value(15849)
        .help("The authentication port to connect to.")
        .append();

    args.add_argument("--lang")
        .help("The language of your FFXI install: JP/US/EU (0/1/2).")
        .append();

    args.add_argument("--hairpin")
        .implicit_value(true)
        .store_into(bUseHairpinFix)
        .default_value(false)
        .help("Use this if connecting to a local server which you have exposed publicly. This should not have to be used if you are connecting to a remote server.")
        .append();

    args.add_argument("--hide")
        .implicit_value(true)
        .store_into(bHideConsole)
        .default_value(true)
        .help("Hides the console window after FFXI starts.")
        .append();

    args.add_argument("--show")
        .implicit_value(false)
        // clang-format off
        .action([&bHideConsole](const std::string& value)
        {
            bHideConsole = false;
        })
        // clang-format on
        .help("Keeps the console window open after FFXI starts.")
        .append();

    try
    {
        args.parse_args(argc, argv);
    }
    catch (const std::runtime_error& err)
    {
        std::cerr << err.what() << std::endl;
        std::cerr << args;

        std::cout << "Press enter to close the window.";
        std::cin.get();
        exit(1);
    }

    if (args.is_used("--lang"))
    {
        std::string language = args.get<std::string>("--lang");

        if (!_strnicmp(language.c_str(), "JP", 2) || !_strnicmp(language.c_str(), "0", 1))
        {
            globals::g_Language = xiloader::Language::Japanese;
        }
        if (!_strnicmp(language.c_str(), "US", 2) || !_strnicmp(language.c_str(), "1", 1))
        {
            globals::g_Language = xiloader::Language::English;
        }
        if (!_strnicmp(language.c_str(), "EU", 2) || !_strnicmp(language.c_str(), "2", 1))
        {
            globals::g_Language = xiloader::Language::European;
        }
    }

    auto macAddressOpt = xiloader::functions::GetMACAddress();
    if (!macAddressOpt.has_value())
    {
        xiloader::console::output(xiloader::color::error, "Could not load necessary information.");
        exit(1);
    }
    globals::g_MacAddress = macAddressOpt.value();

    time_t currentTime = time(NULL);
    int    currentYear = localtime(&currentTime)->tm_year + 1900; // Year is returned as the number of years since 1900.

    xiloader::console::output(xiloader::color::lightred, "==========================================================");
    xiloader::console::output(xiloader::color::lightgreen, "DarkStar Boot Loader (c) 2015 DarkStar Team");
    xiloader::console::output(xiloader::color::lightgreen, "LandSandBoat Boot Loader (c) 2021-2024 LandSandBoat Team");
    xiloader::console::output(xiloader::color::lightgreen, "XI Boot Loader (c) 2025-%u InoUno (v%s)", currentYear, XILOADER_VERSION_STRING);
    xiloader::console::output(xiloader::color::lightpurple, "Git Repo   : https://github.com/InoUno/xiloader");
    xiloader::console::output(xiloader::color::lightred, "==========================================================");

    if (!globals::g_AuthTokenFile.empty())
    {
        if (std::filesystem::exists(globals::g_AuthTokenFile))
        {
            std::ifstream tokenFile;
            tokenFile.open(globals::g_AuthTokenFile, std::ios_base::in | std::ios_base::binary);

            if (tokenFile.is_open())
            {
                tokenFile.seekg(0, tokenFile.end);
                size_t length = tokenFile.tellg();
                tokenFile.seekg(0, tokenFile.beg);

                globals::g_AuthTokenBytes.resize(length);
                tokenFile.read((char*)&globals::g_AuthTokenBytes[0], length);
                tokenFile.close();
                xiloader::console::output(xiloader::color::lightgreen, "Loaded auth token from file.", length);
            }
        }
        else if (globals::g_Username.empty() || globals::g_Password.empty())
        {
            xiloader::console::output(xiloader::color::error, "Provided auth token file was not found.");
        }
    }

    /* Initialize Winsock */
    WSADATA wsaData = { 0 };
    auto    ret     = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (ret != 0)
    {
        xiloader::console::output(xiloader::color::error, "Failed to initialize winsock, error code: %d", ret);
        return 1;
    }

    /* Initialize COM */
    auto hResult = CoInitialize(NULL);
    if (hResult != S_OK && hResult != S_FALSE)
    {
        /* Cleanup Winsock */
        WSACleanup();

        xiloader::console::output(xiloader::color::error, "Failed to initialize COM, error code: %d", hResult);
        return 1;
    }

    /* Attach detour for gethostbyname.. */
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)Real_gethostbyname, Mine_gethostbyname);
    DetourAttach(&(PVOID&)Real_send, Mine_send);
    DetourAttach(&(PVOID&)Real_recv, Mine_recv);
    DetourAttach(&(PVOID&)Real_connect, Mine_connect);
    if (DetourTransactionCommit() != NO_ERROR)
    {
        /* Cleanup COM and Winsock */
        CoUninitialize();
        WSACleanup();

        xiloader::console::output(xiloader::color::error, "Failed to detour necessary functions. Cannot continue!");
        return 1;
    }

    // init mbed tls
    mbedtls_net_init(&sslState::server_fd);
    mbedtls_ssl_init(&sslState::ssl);
    mbedtls_ssl_config_init(&sslState::conf);
    mbedtls_x509_crt_init(&sslState::cacert);
    mbedtls_ctr_drbg_init(&sslState::ctr_drbg);
    mbedtls_entropy_init(&sslState::entropy);

    const char* pers = "xiloader";

    if ((ret = mbedtls_ctr_drbg_seed(&sslState::ctr_drbg, mbedtls_entropy_func, &sslState::entropy,
                                     (const unsigned char*)pers,
                                     strlen(pers))) != 0)
    {
        xiloader::console::output(xiloader::color::error, "mbedtls_ctr_drbg_seed failed!");
        return 1;
    }

    sslState::ca_chain = build_windows_ca_chain();

    /* Attempt to resolve the server address.. */
    ULONG ulAddress = 0;
    if (xiloader::network::ResolveHostname(globals::g_ServerAddress.c_str(), &ulAddress))
    {
        globals::g_ServerAddress = inet_ntoa(*((struct in_addr*)&ulAddress));
        xiloader::datasocket sock;

        /* Attempt to create socket to server..*/
        if (xiloader::network::CreateAuthConnection(&sock, std::to_string(globals::g_AuthPort).c_str()))
        {
            /* Attempt to verify the users account info.. */
            while (!xiloader::network::AuthRequest(&sock))
            {
                Sleep(10);
            }

            /* Start hairpin hack thread if required.. */
            if (bUseHairpinFix)
            {
                CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ApplyHairpinFixThread, NULL, 0, NULL);
            }

            /* Attempt to create polcore instance..*/
            IPOLCoreCom* polcore = NULL;
            if (CoCreateInstance(xiloader::CLSID_POLCoreCom[globals::g_Language], NULL, 0x17, xiloader::IID_IPOLCoreCom[globals::g_Language], (LPVOID*)&polcore) != S_OK)
            {
                xiloader::console::output(xiloader::color::error, "Failed to initialize instance of polcore!");
            }
            else
            {
                /* Invoke the setup functions for polcore.. */
                // Create string for the login view port
                std::string polcorecmd = " /game eAZcFcB -net 3 -port " + std::to_string(globals::g_LoginViewPort);
                // Cast to an LPSTR
                LPSTR cmd = const_cast<char*>(polcorecmd.c_str());
                polcore->SetAreaCode(globals::g_Language);
                polcore->SetParamInit(GetModuleHandle(NULL), cmd);

                /* Obtain the common function table.. */
                void* (**lpCommandTable)(...);
                polcore->GetCommonFunctionTable((unsigned long**)&lpCommandTable);

                /* Invoke the inet mutex function.. */
                auto findMutex = (void* (*)(...))FindINETMutex();
                findMutex();

                /* Locate and prepare the pol connection.. */
                auto polConnection = (char*)FindPolConn();
                memset(polConnection, 0x00, 0x68);
                auto enc = (char*)malloc(0x1000);
                memset(enc, 0x00, 0x1000);
                memcpy(polConnection + 0x48, &enc, sizeof(char**));

                /* Locate the character storage buffer.. */
                globals::g_CharacterList = (char*)FindCharacters((void**)lpCommandTable);

                /* Invoke the setup functions for polcore.. */
                lpCommandTable[POLFUNC_REGISTRY_LANG](globals::g_Language);
                lpCommandTable[POLFUNC_FFXI_LANG](xiloader::functions::GetRegistryPlayOnlineLanguage(globals::g_Language));
                lpCommandTable[POLFUNC_REGISTRY_KEY](xiloader::functions::GetRegistryPlayOnlineKey(globals::g_Language));
                lpCommandTable[POLFUNC_INSTALL_FOLDER](xiloader::functions::GetRegistryPlayOnlineInstallFolder(globals::g_Language));
                lpCommandTable[POLFUNC_INET_MUTEX]();

                /* Attempt to create FFXi instance..*/
                IFFXiEntry* ffxi = NULL;
                if (CoCreateInstance(xiloader::CLSID_FFXiEntry, NULL, 0x17, xiloader::IID_IFFXiEntry, (LPVOID*)&ffxi) != S_OK)
                {
                    xiloader::console::output(xiloader::color::error, "Failed to initialize instance of FFXI!");
                }
                else
                {
                    /* Attempt to start Final Fantasy.. */
                    IUnknown* message = NULL;
                    if (bHideConsole)
                    {
                        xiloader::console::hide();
                    }
                    ffxi->GameStart(polcore, &message);
                    xiloader::console::show();
                    ffxi->Release();
                }

                /* Cleanup polcore object.. */
                if (polcore != NULL)
                {
                    polcore->Release();
                }
            }

            /* Cleanup threads.. */
            xiloader::console::output(xiloader::color::lightyellow, "Cleaning up...");

            mbedtls_ssl_close_notify(&sslState::ssl);
            mbedtls_net_close(&sslState::server_fd);
        }
    }
    else
    {
        xiloader::console::output(xiloader::color::error, "Failed to resolve server hostname.");
    }

    mbedtls_net_free(&sslState::server_fd);
    mbedtls_ssl_free(&sslState::ssl);
    mbedtls_ssl_config_free(&sslState::conf);
    mbedtls_ctr_drbg_free(&sslState::ctr_drbg);
    mbedtls_entropy_free(&sslState::entropy);
    mbedtls_x509_crt_free(&sslState::cacert);

    sslState::ca_chain = nullptr;

    /* Detach detour for gethostbyname. */
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)Real_gethostbyname, Mine_gethostbyname);
    DetourDetach(&(PVOID&)Real_send, Mine_send);
    DetourDetach(&(PVOID&)Real_recv, Mine_recv);
    DetourDetach(&(PVOID&)Real_connect, Mine_connect);
    DetourTransactionCommit();

    /* Cleanup COM and Winsock */
    CoUninitialize();
    WSACleanup();

    xiloader::console::output(xiloader::color::lightyellow, "Closing...");
    Sleep(1000);

    return ERROR_SUCCESS;
}
