# GSS API layer c++
This is a simpe C++ interface over for GSS API (Generic Security Services API)

![structure](https://github.com/AndreyBarmaley/gssapi-layer-cpp/blob/main/classes.png)

## Service part example

```cpp
#include <sstream>
#include <cstring>
#include <iomanip>
#include <iostream>

#include "gsslayer.h"
#include "tools.h"

std::string buffer2hexstring(const uint8_t* data, size_t length, std::string_view sep = ",", bool prefix = true)
{
    std::ostringstream os;
    for(size_t it = 0; it != length; ++it)
    {
       if(prefix)
           os << "0x";
       os << std::setw(2) << std::setfill('0') << std::uppercase << std::hex << static_cast<int>(data[it]);
       if(sep.size() && it + 1 != length) os << sep;
    }
    return os.str();
}

class GssApiServer : public Gss::ServiceContext
{
    int port = 0;
    int sock = 0;
    std::string service;

public:
    GssApiServer(int port2, const std::string & service2)
        : port(port2), service(service2)
    {
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

        if(! acquireCredential(service, Gss::NameType::NtHostService))
            return -1;

        int srvfd = TCPSocket::listen("any", port);
        std::cout << "srv fd: " << srvfd << std::endl;

        sock = TCPSocket::accept(srvfd);
        std::cout << "sock fd: " << sock << std::endl;

        if(! acceptClient())
            return -1;

        // client info
        std::string name1 = Gss::exportName(srcName());
        std::cout << "client id: " << name1 << std::endl;

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

        auto buf = recvMessage();
        std::cout << "recv data: " << buffer2hexstring(buf.data(), buf.size()) << std::endl;

        auto res = sendMIC(buf);
        std::cout << "send mic: " << (res ? "success" : "failed") << std::endl;

        return 0;
    }
};
```  

API Documentation:
https://andreybarmaley.github.io/gssapi-layer-cpp/html/annotated.html
