/***************************************************************************
 *   Copyright © 2023 by Andrey Afletdinov <public.irkutsk@gmail.com>      *
 *                                                                         *
 *   https://github.com/AndreyBarmaley/gssapi-layer-cpp                    *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 3 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/

#include <cstring>
#include <iostream>

#include "gsslayer.h"
#include "tools.h"

class GssApiClient : public Gss::ClientContext
{
    std::vector<uint8_t> buf;
    std::string service;
    std::string ipaddr;
    int port = 0;
    int sock = 0;

public:
    GssApiClient(const std::string & ipaddr2, int port2, const std::string & service2, std::string_view msg)
        : service(service2), ipaddr(ipaddr2), port(port2)
    {
        buf.assign((uint8_t*) msg.data(), (uint8_t*) msg.data() + msg.size());
    }

    // ServiceContext override
    std::vector<uint8_t> recvToken(void) override
    {
        auto len = TCPSocket::readIntBE32(sock);
        std::cout << "token recv: " << len << std::endl;
        return TCPSocket::readData(sock, len);
    }

    // ServiceContext override
    void sendToken(const void* buf, size_t len) override
    {
        std::cout << "token send: " << len << std::endl;
        TCPSocket::writeIntBE32(sock, len);
        TCPSocket::writeData(sock, buf, len);
    }

    // ServiceContext override
    void error(const char* func, const char* subfunc, OM_uint32 code1, OM_uint32 code2) const override
    {
        std::cerr << func << ": " << subfunc << " failed, " << Gss::error2str(code1, code2) << std::endl;
    }

    int start(void)
    {
        std::cout << "service id: " << service.data() << std::endl;

        sock = TCPSocket::connect(ipaddr, port);
        std::cout << "sock fd: " << sock << std::endl;

        if(! initConnect(service, Gss::NameType::NtHostService))
            return -1;

        // client info
        // std::string name1 = Gss::exportName(srcName());
        // std::cout << "service id: " << name1 << std::endl;

        // mech types
        auto names = mechNames();
        auto mech = Gss::exportOID(mechTypes());

        std::cout << "mechanism " << mech << " supports " << names.size() << " names" << std::endl;

        for(auto & name : mechNames())
        {
            std::cout << " - mech name: " << name << std::endl;
        }

        // flags
        for(auto & f : Gss::exportFlags(supportFlags()))
        {
            std::cout << "supported flag: " << flagName(f) << std::endl;
        }

        bool res = sendMessage(buf, true /* encrypt */);
        std::cout << "send data: " << (res ? "success" : "failed") << std::endl;

        res = recvMIC(buf);
        std::cout << "recv mic: " << (res ? "verified" : "failed") << std::endl;

        return 0;
    }
};

int main(int argc, char **argv)
{
    int res = 0;
    int port = 44444;
    std::string ipaddr = "127.0.0.1";
    std::string msg = "1234567890";
    std::string service = "test";

    for(int it = 1; it < argc; ++it)
    {
        if(0 == std::strcmp(argv[it], "--port") && it + 1 < argc)
        {
            try
            {
                port = std::stoi(argv[it + 1]);
            }
            catch(const std::invalid_argument &)
            {
                std::cerr << "incorrect port number" << std::endl;
            }
            it = it + 1;
        }
        else
        if(0 == std::strcmp(argv[it], "--ipaddr") && it + 1 < argc)
        {
            ipaddr.assign(argv[it + 1]);
            it = it + 1;
        }
        else
        if(0 == std::strcmp(argv[it], "--message") && it + 1 < argc)
        {
            msg.assign(argv[it + 1]);
            it = it + 1;
        }
        else
        if(0 == std::strcmp(argv[it], "--service") && it + 1 < argc)
        {
            service.assign(argv[it + 1]);
            it = it + 1;
        }
        else
        {
            std::cout << "usage: " << argv[0] << " --ipaddr 127.0.0.1" << " --port 44444" << " --service <name>" << " --message 1234567890" << std::endl;
            return 0;
        }
    }

    try
    {
        res = GssApiClient(ipaddr, port, service, msg).start();
    }
    catch(const std::exception & err)
    {
        std::cerr << "exception: " << err.what() << std::endl;
    }

    return res;
}
