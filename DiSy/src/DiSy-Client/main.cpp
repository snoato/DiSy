/*
author: Swoboda Daniel
matnr:  i12032
file:   main.cpp
desc:   DiSy main file
date:   2017-03-13
class:  5AHIF
catnr:  23
*/
#include <iostream>

// used by the protobuf example below:
#include <fstream>

// only if using asio
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wconversion"
#include "asio.hpp"
#pragma GCC diagnostic pop

// only if using spdlog
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#include "spdlog/spdlog.h"
#pragma GCC diagnostic pop

// only if using fmt
#include "fmt/format.h"

#include "json.hpp"
using json = nlohmann::json;

// only if using protobuf:
#include "disy.pb.h"

//own includes
#include "file.h"
#include "config.h"
#include "message_helper.h"

using namespace std;
using asio::ip::tcp;

void usage(){
    fmt::print("Welcome to DiSy-Client Help\n");
    fmt::print("Usage: ./DiSy-Client [-h] IP [-c] [OPTION [VALUE]]...\n");
    fmt::print("Options:   -h \n");
    fmt::print("Options:   --help     Shows this help screen\n");
    fmt::print("Options:   -c         Opens configurator screen prevents -d and -p options\n");
    fmt::print("Options:   -d /home   Use this directory for the session\n");
    fmt::print("Options:   -p 666     Use the given port for the session\n");
    fmt::print("\nExample: ./DiSy-Client localhost -d . -p 565656\n");
}

int main(int argc, char *argv[]) {
    ////////////////////////////////////////////////////////////////////////////
    //Command Line Input Handling
    if(argc == 1 || ((argc > 1) && (string(argv[1]) == "-h" || string(argv[1]) == "--help"))) {
        usage();
        return 0;
    }

    string ip = string(argv[1]);
    bool manconf = false;
    string dirpath = "";
    string port = "64446";

    if((argc >= 3 && argc < 7&& string(argv[2]) == "-c") || (argc >= 4 && (string(argv[2]) == "-d" || string(argv[2]) == "-p"))){
        if(string(argv[2]) == "-c") {
            manconf = true;
        } else if(string(argv[2]) == "-d") {
            dirpath = string(argv[3]);
        } else if(string(argv[2]) == "-p") {
            port = string(argv[3]);
        } else {
            usage();
            return 0;
        }
        if (argc == 5) {
            usage();
            return 0;
        }
        if(argc == 6) {
            if(string(argv[4]) == "-d" || string(argv[4]) == "-p") {
                if(string(argv[4]) == "-d") {
                    dirpath = string(argv[5]);
                } else if(string(argv[4]) == "-p") {
                    port = string(argv[5]);
                } else {
                    usage();
                    return 0;
                }
            } else {
                usage();
                return 0;
            }
        }
    } else {
        if(argc != 2) {
            usage();
            return 0;
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    //initialize

    //create console for debugging output and set level
    auto console{spdlog::stderr_color_st("console")};
    console->set_level(spdlog::level::trace);

    //print welcome message
    console->trace("Welcome to the DiSy client");

    //load config
    console->info("Loading config file...");
    Config c{};
    if(manconf)
        c = Config{manconf, "client-c.json"};
    else {
        if(dirpath != "") {
            c = Config{manconf, dirpath};
        } else {
            c = Config{"client-c.json"};
        }
    }
    console->info("Configured for Directory {}", c.get_path());

    ////////////////////////////////////////////////////////////////////////////
    //main program

    //crawl the library into a protbuf directory
    console->info("Crawling directory...");
    DiSyProto::Directory dir;
    try {
        dir = crawl_files(c.get_path());
        console->info("Found {} files", dir.files_size());
    }
    catch (std::experimental::filesystem::v1::__cxx11::filesystem_error& e) {
        console->error("Could not open Directory. Aborting!");
        return 0;
    }

    //set up socket client
    asio::io_context io_context;

    console->info("Create socket");
    tcp::socket sock{io_context};
    console->info("Create resolver");
    tcp::resolver resolver{io_context};
    console->info("Connecting to server");
    try {
        asio::connect(sock, resolver.resolve(ip,port));
        console->info("Connected to server");
    } catch (std::system_error& e) {
        console->error("Could not connect to server");
        return 0;
    }

    ////////////////////////////////////////////////////////////////////////////
    //execute DiSy protocol

    //send connect message
    console->info("Send ECN");
    send_client_ecn(ref(sock));
    //receive server connect message
    console->info("Receive ECN");
    string ecn{receive_format_message(ref(sock))};
    if(extract_message_type(ecn) != "ECN") {
        console->error("Expected ECN, received {}", extract_message_type(ecn));
        return 0;
    }

    //save synch time
    console->info("Receive ECN datablock");
    long s_time = receive_synctime(ref(sock), extract_message_size(ecn)).time();

    //send dirlist
    console->info("Send CDR");
    send_cdr(ref(sock), crawl_directory(c.get_path()));

    //receive cdr
    console->info("Receive CDR");
    string cdr{receive_format_message(ref(sock))};
    if(extract_message_type(cdr) != "CDR") {
        console->error("Expected CDR, received {}", extract_message_type(cdr));
        return 0;
    }

    //create directories
    console->info("Create missing directories");
    create_directories(c.get_path(), receive_dirlist(ref(sock),
            extract_message_size(cdr)));

    //receive server request directory message
    console->info("Receive RDR");
    string rdr{receive_format_message(ref(sock))};
    if(extract_message_type(rdr) != "RDR") {
        console->error("Expected RDR, received {}", extract_message_type(rdr));
        return 0;
    }

    //send directory
    console->info("Send SDR");
    send_client_sdr(ref(sock), dir);

    //receive server request hash message
    console->info("Receive RHS");
    string rhs{receive_format_message(ref(sock))};
    if(extract_message_type(rhs) != "RHS") {
        console->error("Expected RHS, received {}", extract_message_type(rhs));
        return 0;
    }

    //receive request hash datablock
    console->info("Receive RHS datablock");
    DiSyProto::Filelist hash_req{receive_filelist(ref(sock),
            extract_message_size(rhs))};

    //create hashes
    console->info("Create hashes");
    DiSyProto::Hashlist hashes{create_hashlist(c.get_path(), hash_req)};

    //send hash message
    console->info("Send SHS");
    send_client_shs(ref(sock), hashes);

    //receive server request files message
    console->info("Receive RFS");
    string rfs{receive_format_message(ref(sock))};
    if(extract_message_type(rfs) != "RFS") {
        console->error("Expected RFS, received {}", extract_message_type(rfs));
        return 0;
    }

    //receive request hash datablock
    console->info("Receive RFS datablock");
    DiSyProto::Filelist file_req{receive_filelist(ref(sock),
            extract_message_size(rfs))};

    //send requested files
    console->info("Send requested files");
    send_files(ref(sock), file_req, c.get_path());
    console->info("Send EFS");
    send_efs(ref(sock));

    //receive missing files
    console->info("Receive missing files");
    receive_files(ref(sock), c.get_path());
    console->info("Receive EFS");

    //clean-up
    console->info("Directories are now synced");
    console->info("Clean-up");
    reset_modify_date(c.get_path(), s_time);
    console->info("Finished");

    ////////////////////////////////////////////////////////////////////////////
    //shutdown
    console->info("DiSy is shutting down!");

    //shut down protobuf
    google::protobuf::ShutdownProtobufLibrary();
}
