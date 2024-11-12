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

#include "network.h"
#include "functions.h"
#include "helpers.h"

#include <fstream>
#include <iostream>
#include <iphlpapi.h>
#include <vector>

/* Externals */
namespace globals
{
    extern std::string g_ServerAddress;

    extern std::string g_Username;
    constexpr size_t   g_Username_MinLen = 3;
    constexpr size_t   g_Username_MaxLen = 32;

    extern std::string g_Password;
    extern std::string g_NewPassword;
    constexpr size_t   g_Password_MinLen = 6;
    constexpr size_t   g_Password_MaxLen = 32;

    extern std::string g_Email;
    constexpr size_t   g_Email_MinLen = 6;
    constexpr size_t   g_Email_MaxLen = 64;

    extern xiloader::mac_address g_MacAddress;

    extern uint8_t g_SessionHash[16];

    extern std::string          g_AuthToken;
    extern std::vector<uint8_t> g_AuthTokenBytes;
    extern std::string          g_AuthTokenFile;

    extern uint16_t g_AuthPort;
    extern uint16_t g_PolPort;
    extern uint16_t g_LoginViewPort;

    extern bool  g_IsFirstLogin;
    extern char* g_CharacterList;
} // namespace globals

// mbed tls state
namespace sslState
{

    extern mbedtls_net_context               server_fd;
    extern mbedtls_entropy_context           entropy;
    extern mbedtls_ctr_drbg_context          ctr_drbg;
    extern mbedtls_ssl_context               ssl;
    extern mbedtls_ssl_config                conf;
    extern mbedtls_x509_crt                  cacert;
    extern std::unique_ptr<mbedtls_x509_crt> ca_chain;
}; // namespace sslState

namespace xiloader
{
    /**
     * @brief Creates a connection on the given port.
     *
     * @param sock      The datasocket object to store information within.
     * @param port      The port to create the connection on.
     *
     * @return True on success, false otherwise.
     */
    bool network::CreateConnection(datasocket* sock, const char* port)
    {
        struct addrinfo hints;
        memset(&hints, 0x00, sizeof(hints));

        hints.ai_family   = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        /* Attempt to get the server information. */
        struct addrinfo* addr = NULL;
        if (getaddrinfo(globals::g_ServerAddress.c_str(), port, &hints, &addr))
        {
            xiloader::console::output(xiloader::color::error, "Failed to obtain remote server information.");
            return 0;
        }

        /* Determine which address is valid to connect.. */
        for (auto ptr = addr; ptr != NULL; ptr->ai_next)
        {
            /* Attempt to create the socket.. */
            sock->s = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
            if (sock->s == INVALID_SOCKET)
            {
                xiloader::console::output(xiloader::color::error, "Failed to create socket.");

                freeaddrinfo(addr);
                return 0;
            }

            /* Attempt to connect to the server.. */
            if (connect(sock->s, ptr->ai_addr, ptr->ai_addrlen) == SOCKET_ERROR)
            {
                xiloader::console::output(xiloader::color::error, "Failed to connect to server!");

                closesocket(sock->s);
                sock->s = INVALID_SOCKET;
                return 0;
            }

            xiloader::console::output(xiloader::color::info, "Connected to server!");
            break;
        }

        std::string localAddress = "";

        /* Attempt to locate the client address.. */
        char hostname[1024] = { 0 };
        if (gethostname(hostname, sizeof(hostname)) == 0)
        {
            PHOSTENT hostent = NULL;
            if ((hostent = gethostbyname(hostname)) != NULL)
                localAddress = inet_ntoa(*(struct in_addr*)*hostent->h_addr_list);
        }

        sock->LocalAddress  = inet_addr(localAddress.c_str());
        sock->ServerAddress = inet_addr(globals::g_ServerAddress.c_str());

        return 1;
    }

    /**
     * @brief Creates a connection to the auth server on the given port.
     *
     * @param sock      The datasocket object to store information within.
     * @param port      The port to create the connection on.
     *
     * @return True on success, false otherwise.
     */
    bool network::CreateAuthConnection(datasocket* sock, const char* port)
    {
        struct addrinfo hints;
        memset(&hints, 0x00, sizeof(hints));

        hints.ai_family   = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        /* Attempt to get the server information. */
        struct addrinfo* addr = NULL;
        if (getaddrinfo(globals::g_ServerAddress.c_str(), port, &hints, &addr))
        {
            xiloader::console::output(xiloader::color::error, "Failed to obtain remote server information.");
            return 0;
        }

        if ((mbedtls_net_connect(&sslState::server_fd, globals::g_ServerAddress.c_str(), port, MBEDTLS_NET_PROTO_TCP)) != 0)
        {
            xiloader::console::output(xiloader::color::error, "Could not connect to server: %s:%u", globals::g_ServerAddress.c_str(), port);
            return 0;
        }

        if (mbedtls_ssl_config_defaults(&sslState::conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) != 0)
        {
            xiloader::console::output(xiloader::color::error, "mbedtls_ssl_config_defaults failed.");
            return 0;
        }

        // MBEDTLS_SSL_VERIFY_OPTIONAL provides warnings, but doesn't stop connections.
        mbedtls_ssl_conf_authmode(&sslState::conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
        mbedtls_ssl_conf_ca_chain(&sslState::conf, sslState::ca_chain.get(), NULL);
        mbedtls_ssl_conf_rng(&sslState::conf, mbedtls_ctr_drbg_random, &sslState::ctr_drbg);

        int ret = 0;

        if ((ret = mbedtls_ssl_setup(&sslState::ssl, &sslState::conf)) != 0)
        {
            xiloader::console::output(xiloader::color::error, "mbedtls_ssl_setup returned %d", ret);
            return 0;
        }

        mbedtls_ssl_set_bio(&sslState::ssl, &sslState::server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

        while ((ret = mbedtls_ssl_handshake(&sslState::ssl)) != 0)
        {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
            {
                xiloader::console::output(xiloader::color::error, "mbedtls_ssl_handshake returned -0x%x", (unsigned int)-ret);
                return 0;
            }
        }

        uint32_t flags = 0;

        if ((flags = mbedtls_ssl_get_verify_result(&sslState::ssl)) != 0)
        {
            // We genuinely don't care if the error flags is ONLY that the cert isn't trusted,
            // If this is the only warning, just don't print it.
            if (flags != MBEDTLS_X509_BADCERT_NOT_TRUSTED)
            {
                char        vrfy_buf[1024] = {};
                std::string timestamp      = xiloader::console::getTimestamp();

                flags &= ~MBEDTLS_X509_BADCERT_NOT_TRUSTED; // Don't report the cert isn't trusted -- we don't care.

                mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), timestamp.c_str(), flags);

                xiloader::console::output(xiloader::color::warning, "Remote server certificate warnings:", vrfy_buf);
                xiloader::console::print(xiloader::color::warning, vrfy_buf);
            }
        }
        else
        {
            xiloader::console::output(xiloader::color::info, "Remote server (%s) certificate is valid.", globals::g_ServerAddress.c_str());
        }

        sockaddr clientAddr  = {};
        int      sockaddrLen = sizeof(clientAddr);
        getsockname(static_cast<SOCKET>(sslState::server_fd.fd), &clientAddr, &sockaddrLen);

        struct sockaddr_in* their_inaddr_ptr = (struct sockaddr_in*)&clientAddr;

        sock->LocalAddress  = their_inaddr_ptr->sin_addr.S_un.S_addr;
        sock->ServerAddress = inet_addr(globals::g_ServerAddress.c_str());

        return 1;
    }

    /**
     * @brief Resolves the given hostname to its long ip format.
     *
     * @param host      The host name to resolve.
     * @param lpOutput  Pointer to a ULONG to store the result.
     *
     * @return True on success, false otherwise.
     */
    bool network::ResolveHostname(const char* host, PULONG lpOutput)
    {
        struct addrinfo hints, *info = 0;
        memset(&hints, 0, sizeof(hints));

        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        if (getaddrinfo(host, "1000", &hints, &info))
            return false;

        *lpOutput = ((struct sockaddr_in*)info->ai_addr)->sin_addr.S_un.S_addr;

        freeaddrinfo(info);
        return true;
    }

    enum class AuthAction : uint8_t
    {
        None              = 0,
        Login             = 1,
        CreateAccount     = 2,
        ChangePassword    = 3,
        GenerateAuthToken = 4,
    };

    AuthAction promptAuthAction(datasocket* sock)
    {
        constexpr auto OptLogin          = "1";
        constexpr auto OptCreateAccount  = "2";
        constexpr auto OptChangePassword = "3";
        constexpr auto OptGenAuthToken   = "4";
        constexpr auto OptLoginAuthToken = "5";

        while (true)
        {
            xiloader::console::output("==========================================================");
            xiloader::console::output("What would you like to do?");
            xiloader::console::output("   1.) Login");
            xiloader::console::output("   2.) Create New Account");
            xiloader::console::output("   3.) Change Account Password");
            xiloader::console::output("   4.) Generate auth token");
            xiloader::console::output("   5.) Login with auth token");
            xiloader::console::output("==========================================================");
            printf("\nEnter a selection: ");

            std::string input;
            std::cin >> input;
            std::cout << std::endl;

            /* User wants to log into an existing account, generate auth token, or modify an existing account's password. */
            if (input == OptLogin || input == OptGenAuthToken || input == OptChangePassword)
            {
                if (input == OptChangePassword)
                {
                    xiloader::console::output("Before resetting your password, first verify your account details.");
                }

                xiloader::console::output("Please enter your login information.");
                std::cout << std::endl;

                functions::PromptInput(globals::g_Username, globals::g_Username_MinLen, globals::g_Username_MaxLen, "Username");
                functions::PromptMaskedInput(globals::g_Password, globals::g_Password_MinLen, globals::g_Password_MaxLen, "Password");

                if (input == OptLogin)
                {
                    return AuthAction::Login;
                }
                else if (input == OptGenAuthToken)
                {
                    return AuthAction::GenerateAuthToken;
                }
                else
                {
                    // Changing password
                    std::string repeatedPassword = "";
                    while (true)
                    {
                        xiloader::console::output("Enter the new password.");

                        functions::PromptMaskedInput(globals::g_NewPassword, globals::g_Password_MinLen, globals::g_Password_MaxLen, "Password");
                        functions::PromptMaskedInput(repeatedPassword, globals::g_Password_MinLen, globals::g_Password_MaxLen, "Repeat Password", "Password");

                        if (globals::g_NewPassword == repeatedPassword)
                        {
                            break;
                        }
                        else
                        {
                            xiloader::console::output(xiloader::color::error, "Passwords did not match! Please try again.");
                        }
                    }
                    globals::g_NewPassword = repeatedPassword;

                    return AuthAction::ChangePassword;
                }
            }
            /* User wants to create a new account.. */
            else if (input == OptCreateAccount)
            {
                xiloader::console::output("Please enter your desired login information.");
                std::cout << std::endl;

                functions::PromptInput(globals::g_Username, globals::g_Username_MinLen, globals::g_Username_MaxLen, "Username");
                functions::PromptInput(globals::g_Email, globals::g_Email_MinLen, globals::g_Email_MaxLen, "Email");

                while (true)
                {
                    functions::PromptMaskedInput(globals::g_Password, globals::g_Password_MinLen, globals::g_Password_MaxLen, "Password");
                    functions::PromptMaskedInput(input, globals::g_Password_MinLen, globals::g_Password_MaxLen, "Repeat Password", "Password");

                    if (input == globals::g_Password)
                    {
                        break;
                    }
                    else
                    {
                        xiloader::console::output(xiloader::color::error, "Passwords did not match! Please try again.");
                    }
                }

                // Create account
                return AuthAction::CreateAccount;
            }
            else if (input == OptLoginAuthToken)
            {
                std::cout << "Auth token: ";
                globals::g_AuthToken.clear();
                std::cin >> globals::g_AuthToken;
                std::cout << std::endl;

                return AuthAction::Login;
            }
            else
            {
                xiloader::console::output(xiloader::color::error, "Invalid option.");
            }

            std::cout << std::endl;
        }
    }

    enum class AuthResult : uint8_t
    {
        LoginSuccess                = 0x01,
        LoginError                  = 0x02,
        LoginTokenError             = 0x03,
        CreateAccountSuccess        = 0x04,
        CreateAccountError          = 0x05,
        CreateAccountErrorNameTaken = 0x06,
        ChangePasswordSuccess       = 0x07,
        ChangePasswordError         = 0x08,
        GenAuthTokenSuccess         = 0x09,
        GenAuthTokenError           = 0x10,
        CustomErrorMessage          = 0xFF,
    };

    /**
     * @brief Verifies the players login information; also handles creating new accounts.
     *
     * @param sock The datasocket object with the connection socket.
     *
     * @return True on success, false otherwise.
     */
    bool network::AuthRequest(datasocket* sock)
    {
        constexpr size_t BUFFER_SIZE = 1024;

        uint8_t recvBuffer[BUFFER_SIZE] = { 0 };
        uint8_t sendBuffer[BUFFER_SIZE] = { 0 };

        /* Determine if we should auto-login.. */
        bool bUseAutoLogin = globals::g_IsFirstLogin && (!globals::g_AuthToken.empty() || !globals::g_AuthTokenBytes.empty() || (!globals::g_Username.empty() && !globals::g_Password.empty()));
        auto action        = bUseAutoLogin ? AuthAction::Login : AuthAction::None;

        if (bUseAutoLogin)
        {
            xiloader::console::output(xiloader::color::lightgreen, "Autologin activated!");
            // User has auto-login enabled, disable it for next time incase the authentication fails
            globals::g_IsFirstLogin = false;

            if (!globals::g_AuthTokenFile.empty() && !globals::g_Username.empty() && !globals::g_Password.empty())
            {
                // Generate auth token, if token file is specified along username and password
                action = AuthAction::GenerateAuthToken;
            }
        }
        else if (!globals::g_AuthToken.empty() || !globals::g_AuthTokenBytes.empty())
        {
            // If the auth token is not empty at this point, a token has just been generated, and we want to continue with a login.
            action = AuthAction::Login;
        }
        else
        {
            action = promptAuthAction(sock);
        }

        if (action == AuthAction::None)
        {
            return false;
        }

        bool didLoginWithToken = true;

        /* Prepare the request */

        // Magic bytes identifying this variation of xiloader
        sendBuffer[0x00] = 'R';
        sendBuffer[0x01] = 'E';
        sendBuffer[0x02] = 'X';
        sendBuffer[0x03] = 'I';

        // Next 2 bytes saved for the length of the response
        // 0x04
        // 0x05

        // Byte used to indicate the action to take
        sendBuffer[0x06] = static_cast<uint8_t>(action);

        // xiloader version number
        sendBuffer[0x07] = XILOADER_MAJOR_VERSION;
        sendBuffer[0x08] = XILOADER_MINOR_VERSION;
        sendBuffer[0x09] = XILOADER_PATCH_VERSION;

        // MAC address bytes
        memcpy(sendBuffer + 0x0A, globals::g_MacAddress.bytes, 6);

        // End of header bytes. Start keeping track of current send length
        uint32_t sendLength = 16;

        // Add in authentication bytes
        if (!globals::g_Username.empty() && !globals::g_Password.empty())
        {
            // Byte to indicate it's a user/pass auth request
            sendBuffer[sendLength++] = 0x01;
            didLoginWithToken        = false;
            xiloader::console::output(xiloader::color::lightgreen, "Authenticating with username and password.");

            // All requests require at least the username and password
            if (globals::g_Username.length() > globals::g_Username_MaxLen)
            {
                xiloader::console::output(xiloader::color::error, "Failed to login. Username is too long.");
                return false;
            }
            if (globals::g_Username.length() < globals::g_Username_MinLen)
            {
                xiloader::console::output(xiloader::color::error, "Failed to login. Username is too short.");
                return false;
            }

            static_assert(globals::g_Username_MaxLen == 32);
            memcpy(sendBuffer + sendLength, globals::g_Username.c_str(), globals::g_Username.length());
            sendLength += globals::g_Username_MaxLen;

            if (globals::g_Password.length() > globals::g_Password_MaxLen)
            {
                xiloader::console::output(xiloader::color::error, "Failed to login. Password is too long.");
                return false;
            }
            if (globals::g_Password.length() < globals::g_Password_MinLen)
            {
                xiloader::console::output(xiloader::color::error, "Failed to login. Password is too short.");
                return false;
            }

            static_assert(globals::g_Password_MaxLen == 32);
            memcpy(sendBuffer + sendLength, globals::g_Password.c_str(), globals::g_Password.length());
            sendLength += globals::g_Password_MaxLen;
            globals::g_Password.clear();
        }

        else if (!globals::g_AuthToken.empty() || !globals::g_AuthTokenBytes.empty())
        {
            // Byte to indicate it's a token auth request
            sendBuffer[sendLength++] = 0x02;
            didLoginWithToken        = true;
            xiloader::console::output(xiloader::color::lightgreen, "Authenticating with token.");

            if (!globals::g_AuthToken.empty())
            {
                globals::g_AuthTokenBytes = functions::Base64Decode(globals::g_AuthToken);
                globals::g_AuthToken.clear();
            }

            if (globals::g_AuthTokenBytes.empty())
            {
                // Invalid token
                xiloader::console::output(xiloader::color::error, "Failed to login. Auth token could not be decoded.");
                return false;
            }

            // Set length of auth token bytes
            ref<uint16_t>(sendBuffer, sendLength) = static_cast<uint16_t>(globals::g_AuthTokenBytes.size());
            sendLength += 2;

            // Add in the auth token bytes, if it fits
            auto startOffset = sendLength;
            sendLength += globals::g_AuthTokenBytes.size();

            if (sendLength > BUFFER_SIZE)
            {
                // Token too long
                xiloader::console::output(xiloader::color::error, "Failed to login. Auth token too long.");
                return false;
            }

            memcpy(sendBuffer + startOffset, globals::g_AuthTokenBytes.data(), globals::g_AuthTokenBytes.size());
            globals::g_AuthTokenBytes.clear();
        }

        else
        {
            // Invalid auth method
            xiloader::console::output(xiloader::color::error, "Failed to login. No valid authentication method was provided.");
            return false;
        }

        // Request-specific content starts at byte 0x40
        switch (action)
        {
            case AuthAction::Login:
            case AuthAction::GenerateAuthToken:
            {
                break;
            }
            case AuthAction::CreateAccount:
            {
                if (globals::g_Email.length() > globals::g_Email_MaxLen)
                {
                    xiloader::console::output(xiloader::color::error, "Failed to create account. E-mail is too long.");
                    return false;
                }

                static_assert(globals::g_Email_MaxLen == 64);
                memcpy(sendBuffer + sendLength, globals::g_Email.c_str(), globals::g_Email.length());
                sendLength += globals::g_Email_MaxLen;
                globals::g_Email.clear();

                break;
            }
            case AuthAction::ChangePassword:
            {
                if (globals::g_NewPassword.length() > globals::g_Password_MaxLen)
                {
                    xiloader::console::output(xiloader::color::error, "Failed to change password. New password is too long.");
                    return false;
                }
                if (globals::g_NewPassword.length() < globals::g_Password_MinLen)
                {
                    xiloader::console::output(xiloader::color::error, "Failed to change password. New password is too short.");
                    return false;
                }

                static_assert(globals::g_Password_MaxLen == 32);
                memcpy(sendBuffer + sendLength, globals::g_NewPassword.c_str(), globals::g_NewPassword.length());
                sendLength += globals::g_Password_MaxLen;
                globals::g_NewPassword.clear();

                break;
            }
            default:
            {
                return false;
            }
        }

        // Set the final length of data in buffer
        ref<uint16_t>(sendBuffer, 0x04) = sendLength;

        // Send info to server and obtain response
        mbedtls_ssl_write(&sslState::ssl, reinterpret_cast<const unsigned char*>(sendBuffer), sendLength);
        auto bytesRead = mbedtls_ssl_read(&sslState::ssl, recvBuffer, BUFFER_SIZE);

        if (bytesRead == 0)
        {
            // Connection was closed
            xiloader::console::output(xiloader::color::error, "Connection lost with server. Closing...");
            Sleep(1000);
            exit(1);
        }

        // Handle the obtained result
        switch (static_cast<AuthResult>(recvBuffer[0]))
        {
            case AuthResult::LoginSuccess:
            {
                if (!didLoginWithToken)
                {
                    xiloader::console::output(xiloader::color::success, "Successfully logged in as %s!", globals::g_Username.c_str());
                }
                else
                {
                    xiloader::console::output(xiloader::color::success, "Successfully logged in!");
                }
                std::memcpy(&globals::g_SessionHash, recvBuffer + 1, sizeof(globals::g_SessionHash));
                globals::g_PolPort       = ref<uint16_t>(recvBuffer, 17);
                globals::g_LoginViewPort = ref<uint16_t>(recvBuffer, 19);

                return true;
            }
            case AuthResult::LoginError:
            {
                xiloader::console::output(xiloader::color::error, "Failed to login. Invalid username or password.");
                return false;
            }
            case AuthResult::LoginTokenError:
            {
                xiloader::console::output(xiloader::color::error, "Failed to login. Invalid auth token.");

                // Delete the invalid token file if provided
                if (!globals::g_AuthTokenFile.empty())
                {
                    std::remove(globals::g_AuthTokenFile.c_str());
                }

                // Exit with error code indicating invalid auth token
                Sleep(1000);
                exit(5);
            }
            case AuthResult::CreateAccountSuccess:
            {
                xiloader::console::output(xiloader::color::success, "Account successfully created!");
                return false;
            }
            case AuthResult::CreateAccountError:
            {
                xiloader::console::output(xiloader::color::error, "Failed to create the new account.");
                return false;
            }
            case AuthResult::CreateAccountErrorNameTaken:
            {
                xiloader::console::output(xiloader::color::error, "Failed to create the new account. Username already taken.");
                return false;
            }

            case AuthResult::ChangePasswordSuccess:
            {
                xiloader::console::output(xiloader::color::success, "Password updated successfully!");
                std::cout << std::endl;
                globals::g_Password.clear();
                return false;
            }
            case AuthResult::ChangePasswordError:
            {
                xiloader::console::output(xiloader::color::error, "Failed to change password.");
                std::cout << std::endl;
                globals::g_Password.clear();
                return false;
            }

            case AuthResult::GenAuthTokenSuccess:
            {
                std::string tokenStr = functions::Base64Encode(recvBuffer + 1, bytesRead - 1);
                if (tokenStr.empty())
                {
                    xiloader::console::output(xiloader::color::error, "Successfully generated auth token, but failed to encode it to a string.");
                }
                else
                {
                    xiloader::console::output(xiloader::color::success, "Successfully generated auth token:");
                    std::cout << std::endl
                              << tokenStr << std::endl
                              << std::endl;
                }

                if (bUseAutoLogin)
                {
                    // Store bytes in memory and in specified file if given
                    globals::g_AuthTokenBytes = functions::Base64Decode(tokenStr);

                    if (!globals::g_AuthTokenFile.empty())
                    {
                        std::ofstream tokenFile;
                        tokenFile.open(globals::g_AuthTokenFile, std::ios_base::out | std::ios_base::binary);
                        if (!tokenFile.is_open())
                        {
                            xiloader::console::output(xiloader::color::error, "Failed to write token to file.");
                            return false;
                        }

                        tokenFile.write((char*)&globals::g_AuthTokenBytes[0], globals::g_AuthTokenBytes.size());
                        tokenFile.flush();
                        tokenFile.close();
                        xiloader::console::output(xiloader::color::success, "Auth token has been saved to a file.");
                    }
                }

                return false;
            }

            case AuthResult::GenAuthTokenError:
            {
                xiloader::console::output(xiloader::color::error, "Failed to generate auth token. Invalid login information.");
                return false;
            }

            case AuthResult::CustomErrorMessage:
            {
                std::string message(recvBuffer + 1, recvBuffer + bytesRead);
                xiloader::console::output(xiloader::color::error, "%s", message);
                return false;
            }

            default:
            {
                xiloader::console::output(xiloader::color::error, "Unexpected server response: 0x%02X", recvBuffer[0]);
                return false;
            }
        }

        return false;
    }

}; // namespace xiloader
