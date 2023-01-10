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

#ifndef _GSS_LAYER_
#define _GSS_LAYER_

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>

#include <memory>
#include <vector>
#include <string>
#include <list>

namespace Gss
{
    enum class NameType
    {
        NoName,
        NoOid,
        NtAnonymous,
        NtExportName,
        NtHostService,
        NtMachineUid,
        NtStringUid,
        NtUserName
    };

    enum CredentialUsage
    {
        Initiate = GSS_C_INITIATE, ///< Identifies applications that only initiate security contexts
        Accept = GSS_C_ACCEPT,     ///< Identifies applications that only accept security contexts
        Both = GSS_C_BOTH          ///< Identifies applications that can initiate or accept security contexts
    };

    enum ContextFlag
    {
        Delegate = GSS_C_DELEG_FLAG,        ///< delegated credentials are available by means of the delegated_cred_handle parameter
        Mutual = GSS_C_MUTUAL_FLAG,         ///< a remote peer asked for mutual authentication
        Replay = GSS_C_REPLAY_FLAG,         ///< replay of protected messages will be detected
        Sequence = GSS_C_SEQUENCE_FLAG,     ///< out of sequence protected messages will be detected
        Confidential = GSS_C_CONF_FLAG,     ///< confidentiality service may be invoked by calling the gss_wrap() routine
        Integrity = GSS_C_INTEG_FLAG,       ///< integrity service may be invoked by calling either the gss_get_mic(3GSS) or the gss_wrap(3GSS) routine
        Anonymous = GSS_C_ANON_FLAG,        ///< the initiator does not wish to be authenticated. The src_name parameter, if requested, contains an anonymous internal name
        Protection = GSS_C_PROT_READY_FLAG, ///< the protection services specified by the states of GSS_C_CONF_FLAG and GSS_C_INTEG_FLAG are available if the accompanying major status return value is either GSS_S_COMPLETE or GSS_S_CONTINUE_NEEDED
        Transfer = GSS_C_TRANS_FLAG         ///< the resultant security context may be transferred to other processes by means of a call to gss_export_sec_context(3GSS)
    };

    struct ErrorCodes
    {
        const char* func = nullptr;
        OM_uint32 code1 = 0;
        OM_uint32 code2 = 0;
    };

    gss_name_t importName(std::string_view name, const NameType &, ErrorCodes* = nullptr);

    std::string exportName(const gss_name_t &, ErrorCodes* = nullptr);
    std::string exportOID(const gss_OID &, ErrorCodes* = nullptr);

    std::list<ContextFlag> exportFlags(int);
    const char* flagName(const ContextFlag &);

    std::string error2str(OM_uint32 code1, OM_uint32 code2);

    /// BaseContext
    class Context
    {
    protected:
        gss_OID mech_types = nullptr;
        gss_ctx_id_t context_handle = nullptr;
        gss_name_t src_name = nullptr;
        gss_name_t service_name = nullptr;
        gss_cred_id_t creds = nullptr;
        OM_uint32 support_flags = 0;
        OM_uint32 time_rec = 0;

    public:
        Context() = default;
        virtual ~Context();

        Context(const Context &) = delete;
        Context & operator= (const Context &) = delete;

        virtual std::vector<uint8_t> recvToken(void) = 0;
        virtual void sendToken(const void*, size_t) = 0;
        virtual void error(const char* func, const char* subfunc, OM_uint32 code1, OM_uint32 code2) const;

        std::vector<uint8_t>    recvMessage(void);
        bool                    sendMessage(const void*, size_t, bool encrypt = true);

        bool                    recvMIC(const void*, size_t);
        bool                    sendMIC(const void*, size_t);

        const gss_name_t &      srcName(void) const { return src_name; }
        const gss_OID &         mechTypes(void) const { return mech_types; }
        const OM_uint32 &       supportFlags(void) const { return support_flags; }
        const OM_uint32 &       timeRec(void) const { return time_rec; }

        bool acquireCredential(std::string_view, const NameType &, const CredentialUsage & = Gss::CredentialUsage::Accept);

        std::list<std::string> mechNames(void) const;
    };

    /// ServiceContext
    class ServiceContext : public Context
    {
    public:
        ServiceContext() = default;

        bool acceptClient(void);
    };

    /// ClientContext
    class ClientContext : public Context
    {
    public:
        ClientContext() = default;

        bool initConnect(std::string_view, const NameType &, int flags = GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG);
    };
}

#endif
