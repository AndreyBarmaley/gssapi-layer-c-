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

#include <sstream>
#include <iostream>

#include "gsslayer.h"

namespace Gss
{
    std::string error2str(OM_uint32 code1, OM_uint32 code2)
    {
        OM_uint32 ctx, stat;
        gss_buffer_desc msg1, msg2;

        ctx = 0;
        gss_display_status(& stat, code1, GSS_C_GSS_CODE, GSS_C_NULL_OID, & ctx, & msg1);
        ctx = 0;
        gss_display_status(& stat, code2, GSS_C_MECH_CODE, GSS_C_NULL_OID, & ctx, & msg2);

        std::ostringstream os;
        os << (const char*) msg1.value << ", (" << (const char*) msg2.value << ")";

        gss_release_buffer(& stat, & msg1);
        gss_release_buffer(& stat, & msg2);

        return os.str();
    }

    gss_name_t importName(std::string_view name, const NameType & type, ErrorCodes* err)
    {
        OM_uint32 stat;
        gss_OID oid;

        switch(type)
        {
            case NameType::NoName: oid = (gss_OID) GSS_C_NO_NAME; break;
            case NameType::NoOid: oid = GSS_C_NO_OID; break;
            case NameType::NtAnonymous: oid = GSS_C_NT_ANONYMOUS; break;
            case NameType::NtExportName: oid = GSS_C_NT_EXPORT_NAME; break;
            case NameType::NtHostService: oid = GSS_C_NT_HOSTBASED_SERVICE; break;
            case NameType::NtMachineUid: oid = GSS_C_NT_MACHINE_UID_NAME; break;
            case NameType::NtStringUid: oid = GSS_C_NT_STRING_UID_NAME; break;
            case NameType::NtUserName: oid = GSS_C_NT_USER_NAME; break;
        }
 
        gss_buffer_desc buf{ name.size(), (void*) name.data() };
        gss_name_t res = nullptr;

        auto ret = gss_import_name(& stat, & buf, oid, & res);

        if(ret == GSS_S_COMPLETE)
            return res;

        if(err)
        {
            err->func = "gss_import_name";
            err->code1 = ret;
            err->code2 = stat;
        }

        gss_release_name(& stat, & res);
        return nullptr;
    }

    std::string exportName(const gss_name_t & name, ErrorCodes* err)
    {
        OM_uint32 stat;
        gss_buffer_desc buf;
        std::string res;

        auto ret = gss_display_name(& stat, name, & buf, nullptr);

        if(ret == GSS_S_COMPLETE)
            res.assign((char*) buf.value, (char*) buf.value + buf.length);
        else
        if(err)
        {
            err->func = "gss_display_name";
            err->code1 = ret;
            err->code2 = stat;
        }

        gss_release_buffer(& stat, & buf);
        return res;
    }

    std::string exportOID(const gss_OID & oid, ErrorCodes* err)
    {
        OM_uint32 stat;
        gss_buffer_desc buf;

        auto ret = gss_oid_to_str(& stat, oid, & buf);
        std::string res;

        if(ret == GSS_S_COMPLETE)
            res.assign((char*) buf.value, (char*) buf.value + buf.length);
        else
        if(err)
        {
            err->func = "gss_display_name";
            err->code1 = ret;
            err->code2 = stat;
        }

        gss_release_buffer(& stat, & buf);
        return res;
    }

    const char* flagName(const ContextFlag & flag)
    {
        switch(flag)
        {
            case ContextFlag::Delegate: return "delegate";
            case ContextFlag::Mutual:   return "mutual";
            case ContextFlag::Replay:   return "replay";
            case ContextFlag::Sequence: return "sequence";
            case ContextFlag::Confidential: return "confidential";
            case ContextFlag::Integrity: return "integrity";
            case ContextFlag::Anonymous: return "anonymous";
            case ContextFlag::Protection: return "protection";
            case ContextFlag::Transfer: return"transfer";
            default: break;
        }

        return "unknown";
    }

    std::list<ContextFlag> exportFlags(int flags)
    {
        auto all = { ContextFlag::Delegate, ContextFlag::Mutual, ContextFlag::Replay, ContextFlag::Sequence, ContextFlag::Confidential,
                ContextFlag::Integrity, ContextFlag::Anonymous, ContextFlag::Protection, ContextFlag::Transfer };

        std::list<ContextFlag> res;

        for(auto & v : all)
            if(flags & v) res.push_front(v);

        return res;
    }

    // Context
    Context::~Context()
    {
        if(src_name)
        {
            OM_uint32 stat = 0;
            gss_release_name(& stat, & src_name);
        }

        if(context_handle)
        {
            OM_uint32 stat = 0;
            gss_delete_sec_context(& stat, & context_handle, GSS_C_NO_BUFFER);
        }
    }

    void Context::error(const char* func, const char* subfunc, OM_uint32 code1, OM_uint32 code2) const
    {
        std::cerr << func << ": " << subfunc << " failed, error: " << error2str(code1, code2) << std::endl;
    }

    std::vector<uint8_t> Context::recvMessage(void)
    {
        OM_uint32 stat;
        auto buf = recvToken();

        gss_buffer_desc in_buf{ buf.size(), (void*) buf.data() };
        gss_buffer_desc out_buf{ 0, nullptr, };

        auto ret = gss_unwrap(& stat, context_handle, & in_buf, & out_buf, nullptr, nullptr);
        std::vector<uint8_t> res;

        if(ret == GSS_S_COMPLETE)
        {
            res.assign((uint8_t*) out_buf.value, (uint8_t*) out_buf.value + out_buf.length);
        }
        else
        {
            error(__FUNCTION__, "gss_unwrap", ret, stat);
            res.clear();
        }
        
        gss_release_buffer(& stat, & out_buf);
        return res;
    }

    bool Context::sendMessage(const std::vector<uint8_t> & buf, bool encrypt)
    {
        OM_uint32 stat;

        gss_buffer_desc in_buf{ buf.size(), (void*) buf.data() };
        gss_buffer_desc out_buf{ 0, nullptr, };

        auto ret = gss_wrap(& stat, context_handle, encrypt, GSS_C_QOP_DEFAULT, & in_buf, nullptr, & out_buf);
        bool res = true;

        if(ret == GSS_S_COMPLETE)
        {
            sendToken(out_buf.value, out_buf.length);
        }
        else
        {
            error(__FUNCTION__, "gss_wrap", ret, stat);
            res = false;
        }
        
        gss_release_buffer(& stat, & out_buf);
        return res;
    }

    bool Context::recvMIC(const std::vector<uint8_t> & msg)
    {
        OM_uint32 stat;

        // recv token
        auto buf = recvToken();

        gss_buffer_desc in_buf{ msg.size(), (void*) msg.data() };
        gss_buffer_desc out_buf{ buf.size(), (void*) buf.data() };

        auto ret = gss_verify_mic(& stat, context_handle, & in_buf, & out_buf, nullptr);

        if(ret == GSS_S_COMPLETE)
            return true;

        error(__FUNCTION__, "gss_verify_mic", ret, stat);
        return false;
    }

    bool Context::sendMIC(const std::vector<uint8_t> & msg)
    {
        OM_uint32 stat;

        gss_buffer_desc in_buf{ msg.size(), (void*) msg.data() };
        gss_buffer_desc out_buf{ 0, nullptr };

        auto ret = gss_get_mic(& stat, context_handle, GSS_C_QOP_DEFAULT, & in_buf, & out_buf);
        bool res = true;

        if(ret == GSS_S_COMPLETE)
        {
            sendToken(out_buf.value, out_buf.length);
        }
        else
        {
            error(__FUNCTION__, "gss_get_mic", ret, stat);
            res = false;
        }

        gss_release_buffer(& stat, & out_buf);
        return res;
    }

    std::list<std::string> Context::mechNames(void) const
    {
        std::list<std::string> res;

        OM_uint32 stat;
        gss_OID_set mech_names;

        auto ret = gss_inquire_names_for_mech(& stat, mech_types, & mech_names);
        if(ret == GSS_S_COMPLETE)
        {
            for(int it = 0; it < mech_names->count; ++it)
            {
                ErrorCodes err;
                auto name = exportOID(& mech_names->elements[it], & err);

                if(name.empty())
                {
                    error(__FUNCTION__, err.func, err.code1, err.code2);
                }
                else
                {
                    res.push_front(name);
                }
            }
        }
        else
        {
            error(__FUNCTION__, "gss_inquire_names_for_mech", ret, stat);
        }

        gss_release_oid_set(& stat, & mech_names);
        return res;
    }

    // ServiceContext
    ServiceContext::~ServiceContext()
    {
        if(service_name)
        {
            OM_uint32 stat = 0;
            gss_release_name(& stat, & service_name);
        }

        if(creds)
        {
            OM_uint32 stat = 0;
            gss_release_cred(& stat, & creds);
        }
    }

    bool ServiceContext::acquireCredential(std::string_view name, const NameType & type, const CredentialUsage & usage)
    {
        OM_uint32 stat;

        if(service_name)
            gss_release_name(& stat, & service_name);

        ErrorCodes err;
        service_name = importName(name, type, &err);

        if(! service_name)
        {
            error(__FUNCTION__, err.func, err.code1, err.code2);
            return false;
        }

        if(creds)
            gss_release_cred(& stat, & creds);

        auto ret = gss_acquire_cred(& stat, service_name, 0, GSS_C_NULL_OID_SET, usage, & creds, nullptr, nullptr);

        if(ret == GSS_S_COMPLETE)
            return true;

        error(__FUNCTION__, "gss_acquire_cred", ret, stat);
        return false;
    }

    bool ServiceContext::acceptClient(void)
    {
        if(! creds)
            return false;

        OM_uint32 stat;
        OM_uint32 ret = GSS_S_CONTINUE_NEEDED;

        if(src_name)
            gss_release_name(& stat, & src_name);

        if(context_handle)
            gss_delete_sec_context(& stat, & context_handle, GSS_C_NO_BUFFER);

        while(ret == GSS_S_CONTINUE_NEEDED)
        {
            // recv token
            auto buf = recvToken();

            gss_buffer_desc recv_tok{ buf.size(), (void*) buf.data() };
            gss_buffer_desc send_tok{ 0, nullptr };

            ret = gss_accept_sec_context(& stat, & context_handle, creds, & recv_tok, GSS_C_NO_CHANNEL_BINDINGS,
                                     & src_name, & mech_types, & send_tok, & support_flags, & time_rec, nullptr);

            if(0 < send_tok.length)
            {
                sendToken(send_tok.value, send_tok.length);
                gss_release_buffer(& stat, & send_tok);
            }
        }

        if(ret == GSS_S_COMPLETE)
            return true;

        error(__FUNCTION__, "gss_accept_sec_context", ret, stat);
        return false;
    }

    // ClientContext
    bool ClientContext::initConnect(std::string_view name, const NameType & type, int flags)
    {
        OM_uint32 stat;

        if(src_name)
            gss_release_name(& stat, & src_name);

        ErrorCodes err;
        src_name = importName(name, type, &err);

        if(! src_name)
        {
            error(__FUNCTION__, err.func, err.code1, err.code2);
            return false;
        }

        if(context_handle)
            gss_delete_sec_context(& stat, & context_handle, GSS_C_NO_BUFFER);

        gss_channel_bindings_t input_chan_bindings = nullptr; // no channel bindings
        std::vector<uint8_t> buf;

        gss_buffer_desc recv_tok{ 0, nullptr };
        gss_buffer_desc send_tok{ name.size(), (void*) name.data() };

        OM_uint32 ret = GSS_S_CONTINUE_NEEDED;
        while(ret == GSS_S_CONTINUE_NEEDED)
        {
            ret = gss_init_sec_context(& stat, GSS_C_NO_CREDENTIAL, & context_handle, src_name, GSS_C_NULL_OID, flags,
                                    0, input_chan_bindings, & recv_tok, & mech_types, & send_tok, & support_flags, & time_rec);

            if(0 < send_tok.length)
            {
                sendToken(send_tok.value, send_tok.length);
                if(send_tok.value != name.data())
                    gss_release_buffer(& stat, & send_tok);
            }

            if(ret == GSS_S_CONTINUE_NEEDED)
            {
                buf = recvToken();
                recv_tok.length = buf.size();
                recv_tok.value = buf.data();
            }
        }

        if(ret == GSS_S_COMPLETE)
            return true;

        error(__FUNCTION__, "gss_init_sec_context", ret, stat);
        return false;
    }
}
