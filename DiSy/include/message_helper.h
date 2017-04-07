/*
author: Swoboda Daniel
matnr:    i12032
file:     message_helper.h
desc:     functions to reduce the effort of
                creating and sending DiSy protocol messages
date:     2017-03-18
class:    5AHIF
catnr:    23
*/

#ifndef MESSAGE_HELPER_H_
#define MESSAGE_HELPER_H_

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wconversion"
#include "asio.hpp"
#pragma GCC diagnostic pop

#include <fstream>
#include <iomanip>
#include <string>
#include <time.h>
#include <chrono>
#include <thread>
#include "fmt/format.h"

///////////////////////////////////////////////////////////////////////////////
//HELPER FUNCTIONS

//size_t to fixed length ascii turns 123 to '00000000000000000123'
std::string sttfla(std::size_t number) {
    std::ostringstream ostr;

    ostr << std::setfill('0') << std::setw(20) << number;

    return ostr.str();
}

//extracts the message type from a format message
std::string extract_message_type(std::string in) {
    return in.substr(0,3);
}

//extract the message size as size_t from a format message
std::size_t extract_message_size(std::string in) {
    return std::stoul(in.substr(3, 20));
}

///////////////////////////////////////////////////////////////////////////////
//SEND FUNCTIONS

//send client ecn format message
void send_client_ecn(asio::ip::tcp::socket& sock) {
    asio::write(sock, asio::buffer("ECN"+sttfla(0),23));
}

//send server ecn format message and synctime datablock
void send_server_ecn(asio::ip::tcp::socket& sock, long time) {
    DiSyProto::Synctime syn{};
    syn.set_time(time);
    asio::streambuf b;
    std::ostream os(&b);
    syn.SerializeToOstream(&os);

    asio::write(sock, asio::buffer("ECN"+sttfla(b.size()),23));
    asio::write(sock, b);
}

//send server rdr format message
void send_server_rdr(asio::ip::tcp::socket& sock) {
    asio::write(sock, asio::buffer("RDR"+sttfla(0),23));
}

//send client sdr format and datablock message
void send_client_sdr(asio::ip::tcp::socket& sock, DiSyProto::Directory dir) {
    asio::streambuf b;
    std::ostream os(&b);
    dir.SerializeToOstream(&os);

    asio::write(sock, asio::buffer("SDR"+sttfla(b.size()),23));
    asio::write(sock, b);
}

//send server rhs format and datablock message
void send_server_rhs(asio::ip::tcp::socket& sock, DiSyProto::Filelist fl) {
    asio::streambuf b;
    std::ostream os(&b);
    fl.SerializeToOstream(&os);

    asio::write(sock, asio::buffer("RHS"+sttfla(b.size()),23));
    asio::write(sock, b);
}

//send client shs format and datablock message
void send_client_shs(asio::ip::tcp::socket& sock, DiSyProto::Hashlist hl) {
    asio::streambuf b;
    std::ostream os(&b);
    hl.SerializeToOstream(&os);

    asio::write(sock, asio::buffer("SHS"+sttfla(b.size()),23));
    asio::write(sock, b);
}

//send server rfs format and datablock message
void send_client_rfs(asio::ip::tcp::socket& sock, DiSyProto::Filelist fl) {
    asio::streambuf b;
    std::ostream os(&b);
    fl.SerializeToOstream(&os);

    asio::write(sock, asio::buffer("RFS"+sttfla(b.size()),23));
    asio::write(sock, b);
}

//send efs format message
void send_efs(asio::ip::tcp::socket& sock){
    asio::write(sock, asio::buffer("EFS"+sttfla(0),23));
}

//send sfs format and datablock message
void send_sfs(asio::ip::tcp::socket& sock, DiSyProto::FileblockInfo fbi) {
    asio::streambuf b;
    std::ostream os(&b);
    fbi.SerializeToOstream(&os);

    asio::write(sock, asio::buffer("SFS"+sttfla(b.size()),23));
    asio::write(sock, b);
}

//send fileblock datablock message
void send_fileblock(asio::ip::tcp::socket& sock, DiSyProto::Fileblock fb) {
    asio::streambuf b;
    std::ostream os(&b);
    fb.SerializeToOstream(&os);

    asio::write(sock, asio::buffer("SFB"+sttfla(b.size()),23));
    asio::write(sock, b);
}

//send cdr format and datablock message
void send_cdr(asio::ip::tcp::socket& sock, DiSyProto::Dirlist dir) {
    asio::streambuf b;
    std::ostream os(&b);
    dir.SerializeToOstream(&os);

    asio::write(sock, asio::buffer("CDR"+sttfla(b.size()),23));
    asio::write(sock, b);
}

///////////////////////////////////////////////////////////////////////////////
//RECEIVE FUNCTIONS

//receive a DiSy protocol format message and return it as a string
std::string receive_format_message(asio::ip::tcp::socket& sock) {
    char response[23];
    asio::error_code error;

    sock.read_some(asio::buffer(response), error);
    if(error)
        throw(asio::system_error(error));
    return std::string(response);
}

//receive a synctime message
DiSyProto::Synctime receive_synctime(asio::ip::tcp::socket& sock, std::size_t length) {
    DiSyProto::Synctime syt{};
    asio::streambuf b;
    asio::streambuf::mutable_buffers_type bufs{b.prepare(length)};

    size_t n{read(sock, bufs)};

    b.commit(n);

    std::istream is(&b);
    syt.ParseFromIstream(&is);
    return syt;
}

//receive a directory message
DiSyProto::Directory receive_directory(asio::ip::tcp::socket& sock, std::size_t length) {
    DiSyProto::Directory dir{};
    asio::streambuf b;
    asio::streambuf::mutable_buffers_type bufs{b.prepare(length)};

    size_t n{read(sock, bufs)};

    b.commit(n);

    std::istream is(&b);
    dir.ParseFromIstream(&is);
    return dir;
}

//receive a filelist message
DiSyProto::Filelist receive_filelist(asio::ip::tcp::socket& sock, std::size_t length) {
    DiSyProto::Filelist fl{};
    asio::streambuf b;
    asio::streambuf::mutable_buffers_type bufs{b.prepare(length)};

    size_t n{read(sock, bufs)};

    b.commit(n);

    std::istream is(&b);
    fl.ParseFromIstream(&is);
    return fl;
}

//recveive a hashlist message
DiSyProto::Hashlist receive_hashlist(asio::ip::tcp::socket& sock, std::size_t length) {
    DiSyProto::Hashlist hl{};
    asio::streambuf b;
    asio::streambuf::mutable_buffers_type bufs{b.prepare(length)};

    size_t n{read(sock, bufs)};

    b.commit(n);

    std::istream is(&b);
    hl.ParseFromIstream(&is);
    return hl;
}

//receive a fileblockinfo message
DiSyProto::FileblockInfo receive_fileblockInfo(asio::ip::tcp::socket& sock, std::size_t length) {
    DiSyProto::FileblockInfo fbi{};
    asio::streambuf b;
    asio::streambuf::mutable_buffers_type bufs{b.prepare(length)};

    size_t n{read(sock, bufs)};

    b.commit(n);

    std::istream is(&b);
    fbi.ParseFromIstream(&is);
    return fbi;
}

//receive a fileblock message
DiSyProto::Fileblock receive_fileblock(asio::ip::tcp::socket& sock, std::size_t length) {
    DiSyProto::Fileblock fb{};
    asio::streambuf b;
    asio::streambuf::mutable_buffers_type bufs{b.prepare(length)};

    size_t n{read(sock, bufs)};

    b.commit(n);

    std::istream is(&b);
    fb.ParseFromIstream(&is);
        return fb;
}

//receive a dirlist message
DiSyProto::Dirlist receive_dirlist(asio::ip::tcp::socket& sock, std::size_t length) {
    DiSyProto::Dirlist dir{};
    asio::streambuf b;
    asio::streambuf::mutable_buffers_type bufs{b.prepare(length)};

    size_t n{read(sock, bufs)};

    b.commit(n);

    std::istream is(&b);
    dir.ParseFromIstream(&is);
    return dir;
}

#endif
