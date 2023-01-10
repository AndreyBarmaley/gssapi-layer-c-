# GSS API layer c++
This is a simpe C++ interface over for GSS API (Generic Security Services API)

![structure](https://github.com/AndreyBarmaley/gssapi-layer-cpp/blob/main/classes.png)

API Documentation:
https://andreybarmaley.github.io/gssapi-layer-cpp/html/annotated.html

## Service part example

```cpp
#include <sstream>
#include <cstring>
#include <iomanip>
#include <iostream>

#include "gsslayer.h"
#include "tools.h"

class GssApiServer : public Gss::ServiceContext
{
    int sock = 0;

public:
    GssApiServer() = default;

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

    int start(int port, std::string_view service)
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

        auto res = sendMIC(buf.data(), buf.size());
        std::cout << "send mic: " << (res ? "success" : "failed") << std::endl;

        return 0;
    }
};
```  

## Client part example
[test examples](https://github.com/AndreyBarmaley/gssapi-layer-cpp/blob/main/test)

## Usage
```
KRB5_KTNAME=/var/tmp/krb5.keytab ./server --service ServiceName
```
output:
```
service id: ServiceName
bind addr: any, port: 44444
srv fd: 5
sock fd: 6
token recv: 627
client id: username@EXAMPLE.COM
mechanism { 1 2 840 113554 1 2 2 } supports 9 names
 - mech name: { 1 2 840 113554 1 2 2 2 }
 - mech name: { 1 3 6 1 5 6 6 }
 - mech name: { 1 2 840 113554 1 2 2 1 }
 - mech name: { 1 3 6 1 5 6 4 }
 - mech name: { 1 3 6 1 5 6 2 }
 - mech name: { 1 2 840 113554 1 2 1 4 }
 - mech name: { 1 2 840 113554 1 2 1 3 }
 - mech name: { 1 2 840 113554 1 2 1 2 }
 - mech name: { 1 2 840 113554 1 2 1 1 }
supported flag: transfer
supported flag: integrity
supported flag: confidential
supported flag: replay
token recv: 70
recv data: 0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30
token send: 28
send mic: success

```
```
./client --ipaddr 192.168.100.1 --service ServiceName@servername
```
output:
```
service id: ServiceName@servername
connect to addr: 192.168.100.1, port: 44444
sock fd: 3
token send: 627
mechanism { 1 2 840 113554 1 2 2 } supports 9 names
 - mech name: { 1 2 840 113554 1 2 2 2 }
 - mech name: { 1 3 6 1 5 6 6 }
 - mech name: { 1 2 840 113554 1 2 2 1 }
 - mech name: { 1 3 6 1 5 6 4 }
 - mech name: { 1 3 6 1 5 6 2 }
 - mech name: { 1 2 840 113554 1 2 1 4 }
 - mech name: { 1 2 840 113554 1 2 1 3 }
 - mech name: { 1 2 840 113554 1 2 1 2 }
 - mech name: { 1 2 840 113554 1 2 1 1 }
supported flag: transfer
supported flag: integrity
supported flag: confidential
supported flag: replay
token send: 70
send data: success
token recv: 28
recv mic: verified
```
