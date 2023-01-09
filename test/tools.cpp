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

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <unistd.h>

#include <cstring>
#include <iostream>
#include <exception>

#include "tools.h"

int TCPSocket::listen(std::string_view ipaddr, uint16_t port, int conn)
{
    int fd = socket(PF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);            
    if(0 > fd)
        throw std::runtime_error("create socket");
        
    int reuse = 1;
    int err = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, & reuse, sizeof(reuse));
    if(0 > err)
    {
        std::cerr << "socket reuseaddr failed, error: " << strerror(errno) << ", code: " << err << std::endl;
    }

    struct sockaddr_in sockaddr;
    memset(& sockaddr, 0, sizeof(struct sockaddr_in));

    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = htons(port);
    sockaddr.sin_addr.s_addr = ipaddr == "any" ? htonl(INADDR_ANY) : inet_addr(ipaddr.data());

    std::cout << "bind addr: " << ipaddr <<", port: " << port << std::endl;

    if(0 != bind(fd, (struct sockaddr*) &sockaddr, sizeof(struct sockaddr_in)))
        throw std::runtime_error("bind failed");

    if(0 != ::listen(fd, conn))
        throw std::runtime_error("listen failed");

    return fd;
}

int TCPSocket::accept(int fd)
{
    int sock = ::accept(fd, nullptr, nullptr);

    return sock;
}

int TCPSocket::connect(std::string_view ipaddr, uint16_t port)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);

    if(0 > sock)
        throw std::runtime_error("create socket");

    struct sockaddr_in sockaddr;
    memset(& sockaddr, 0, sizeof(struct sockaddr_in));
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_addr.s_addr = inet_addr(ipaddr.data());
    sockaddr.sin_port = htons(port);

    std::cout << "connect to addr: " << ipaddr <<", port: " << port << std::endl;

    if(0 != connect(sock, (struct sockaddr*) &sockaddr,  sizeof(struct sockaddr_in)))
        throw std::runtime_error("connect failed");

    return sock;
}

uint32_t TCPSocket::readIntBE32(int fd)
{
    // read int be32
    uint32_t buf;
    auto len = read(fd, & buf, 4);

    if(len != 4)
        throw std::runtime_error("socket read");

    return ntohl(buf);
}

void TCPSocket::writeIntBE32(int fd, uint32_t val)
{
    uint32_t buf = htonl(val);
    auto len = write(fd, & buf, 4);

    if(len != 4)
        throw std::runtime_error("socket write");
}

std::vector<uint8_t> TCPSocket::readData(int fd, size_t sz)
{
    std::vector<uint8_t> buf(sz, 0);
    auto len = read(fd, buf.data(), buf.size());

    if(len != buf.size())
        throw std::runtime_error("socket read");

    return buf;
}

void TCPSocket::writeData(int fd, const void* buf, size_t sz)
{
    auto len = write(fd, buf, sz);

    if(len != sz)
        throw std::runtime_error("socket write");
}
