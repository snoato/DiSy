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
#include <algorithm>
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
    fmt::print("Welcome to DiSy-Server Help\n");
    fmt::print("Usage: ./DiSy-Server [-h] [-c] [OPTION [VALUE]]...\n");
    fmt::print("Options:   -h \n");
    fmt::print("Options:   --help     Shows this help screen\n");
    fmt::print("Options:   -c         Opens configurator screen prevents -d and -p options\n");
    fmt::print("Options:   -d /home   Use this directory for the session\n");
    fmt::print("Options:   -p 666     Use the given port for the session\n");
    fmt::print("\nExample: ./DiSy-Server -d . -p 565656\n");
}

int main(int argc, char *argv[]) {
    ////////////////////////////////////////////////////////////////////////////
    //Command Line Input Handling
    bool manconf{false};
    if(argc >= 2 && string(argv[1]) == "-c") {
        manconf = true;
    } else if(argc == 2 || ((argc > 2) && (string(argv[1]) == "-h" || string(argv[1]) == "--help"))) {
        usage();
        return 0;
    }

    string dirpath{""};
    short unsigned int port{64446};

    if(argc >= 3 && argc < 6 && (argc >= 3 && (string(argv[1]) == "-d" || string(argv[1]) == "-p"))){
        if(string(argv[1]) == "-d") {
            dirpath = string(argv[2]);
        } else if(string(argv[1]) == "-p") {
            port = (short unsigned int)stoi(string(argv[2]));
        } else {
            usage();
            return 0;
        }
        if (argc == 4) {
            usage();
            return 0;
        }
        if(argc == 5) {
            if(string(argv[3]) == "-d" || string(argv[3]) == "-p") {
                if(string(argv[3]) == "-d") {
                    dirpath = string(argv[4]);
                } else if(string(argv[3]) == "-p") {
                    port = (short unsigned int)stoi(string(argv[4]));
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
        if(argc > 2) {
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
    console->trace("Welcome to the DiSy server");

    //load config
    console->info("Loading config file...");
    Config c{};
    if(manconf)
        c = Config{manconf, "server-c.json"};
    else {
        if(dirpath != "") {
            c = Config{manconf, dirpath};
        } else {
            c = Config{"server-c.json"};
        }
    }
    console->info("Configured for Directory {}", c.get_path());

    ////////////////////////////////////////////////////////////////////////////
    //main program

    //crawl the library into a protbuf directory
    console->info("Crawling directory...");
    DiSyProto::Directory dir{};
    try {
        dir = crawl_files(c.get_path());
        console->info("Found {} files", dir.files_size());
    }
    catch (std::experimental::filesystem::v1::__cxx11::filesystem_error& e) {
        console->error("Could not open Directory. Aborting!");
        return 0;
    }

    //set up socket server
    asio::io_context io_context;

    console->info("Create tcp acceptor");
    tcp::acceptor a = tcp::acceptor(io_context, tcp::endpoint(tcp::v4(), port));

    console->info("Waiting for incoming connection");
    tcp::socket sock = a.accept();
    console->info("Client Connected");

    ////////////////////////////////////////////////////////////////////////////
    //execute DiSy protocol

    //receive client connect message
    console->info("Receive ECN");
    string ecn{receive_format_message(ref(sock))};
    if(extract_message_type(ecn) != "ECN") {
        console->error("Expected ECN, received {}", extract_message_type(ecn));
        return 0;
    }

    //save unix time for synch
    console->info("Create synctime");
    long s_time{time(0)};
    //send server connect message
    console->info("Send ECN");
    send_server_ecn(ref(sock), s_time);

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

    //send dirlist
    console->info("Send CDR");
    send_cdr(ref(sock), crawl_directory(c.get_path()));


    //send server rdr message
    console->info("Send RDR");
    send_server_rdr(ref(sock));

    //receive client sdr message
    console->info("Receive SDR");
    string sdr = receive_format_message(ref(sock));
    if(extract_message_type(sdr) != "SDR") {
        console->error("Expected SDR, received {}", extract_message_type(ecn));
        return 0;
    }

    //receive client sdr datablock
    console->info("Receive SDR datablock");
    DiSyProto::Directory client_dir{receive_directory(ref(sock),
            extract_message_size(sdr))};

    //create vectors and protobuf messages used later
    console->info("Comparing directories");
    vector<string> client_files;
    vector<string> server_files;
    vector<string> combnd_files;
    DiSyProto::Filelist hash_req{};
    DiSyProto::Filelist client_req{};
    DiSyProto::Filelist server_req{};

    //copy into vectors for easier comparison
    for (int i = 0; i < dir.files_size(); i++) {
        const DiSyProto::Directory::File& file = dir.files(i);
        server_files.push_back(file.name());
        combnd_files.push_back(file.name());
    }
    for (int i = 0; i < client_dir.files_size(); i++) {
        const DiSyProto::Directory::File& file = client_dir.files(i);
        client_files.push_back(file.name());
        combnd_files.push_back(file.name());
    }

    //clean the combnd_files vector
    sort( combnd_files.begin(), combnd_files.end() );
    combnd_files.erase( unique( combnd_files.begin(), combnd_files.end() ),
            combnd_files.end() );

    //find differences
    for(size_t i = 0; i < combnd_files.size(); i++) {
        auto r_server{find(begin(server_files), end(server_files), combnd_files[i])};
        auto r_client{find(begin(client_files), end(client_files), combnd_files[i])};

        fmt::print("{}: ", combnd_files[i]);
        if (r_server != end(server_files) && r_client != end(client_files)) {
            //ncompare timewise
            fmt::print("Time Compare\n");

            long i_server{find(server_files.begin(), server_files.end(),
                    combnd_files[i]) - server_files.begin()};
            long i_client{find(client_files.begin(), client_files.end(),
                    combnd_files[i]) - client_files.begin()};

            long t_server{dir.files((int)i_server).date()};
            long t_client{client_dir.files((int)i_client).date()};

            //time is unequal, compare hashes
            if(t_server != t_client) {
            fmt::print("    Hash Compare\n");
                DiSyProto::Filelist::File* file{hash_req.add_files()};
                file->set_name(combnd_files[i]);
            //time is equal, ignore them
            } else {
            fmt::print("   Considered Equal!\n");
            }

        } else if(r_server != end(server_files)) {
            //to client
            fmt::print("Send to client\n");
            DiSyProto::Filelist::File* file{server_req.add_files()};
            file->set_name(combnd_files[i]);
        } else if(r_client != end(client_files)) {
            //to server
            fmt::print("Send to Server\n");
            DiSyProto::Filelist::File* file{client_req.add_files()};
            file->set_name(combnd_files[i]);
        }
    }
    console->info("Finished comparison");

    //request hash for similar files
    console->info("Send RHS");
    send_server_rhs(ref(sock), hash_req);

    //create hashes
    console->info("Create hashes");
    DiSyProto::Hashlist hashes{create_hashlist(c.get_path(), hash_req)};

    //receive client send hash message
    console->info("Receive SHS");
    string shs{receive_format_message(ref(sock))};
    if(extract_message_type(shs) != "SHS") {
        console->error("Expected SHS, received {}", extract_message_type(shs));
        return 0;
    }

    //receive request hash datablock
    console->info("Receive SHS datablock");
    DiSyProto::Hashlist hashes_client{receive_hashlist(ref(sock),
            extract_message_size(shs))};

    //compare the hashlists
    console->info("Compare Hashlists");
    for (int i = 0; i < hashes.filehashes_size(); i++) {
        const DiSyProto::Hashlist::FileHash& filehash_s{hashes.filehashes(i)};
        const DiSyProto::Hashlist::FileHash& filehash_c{hashes_client.filehashes(i)};
        fmt::print("Comparing: {}\n", filehash_s.name());
        if(filehash_s.hash() == filehash_c.hash()) {
            fmt::print("     Hashes equal. Ignore file.");
        } else {
            fmt::print("     Hashes unequal. Request the newer one.");
            if(filehash_c.date() > filehash_s.date()) {
                fmt::print("     Client file newer");
                DiSyProto::Filelist::File* file{client_req.add_files()};
                file->set_name(filehash_s.name());
            } else {
                fmt::print("     Server file newer");
                DiSyProto::Filelist::File* file{server_req.add_files()};
                file->set_name(filehash_s.name());
            }
        }
    }
    console->info("Done comparing");

    //send server request files message - request files from client
    console->info("Send RFS");
    send_client_rfs(ref(sock), client_req);

    //receive requested files
    console->info("Receive requested files");
    receive_files(ref(sock), c.get_path());
    console->info("Receive EFS");

    //send files missing on client
    console->info("Send missing files");
    send_files(ref(sock), server_req, c.get_path());
    console->info("Send EFS");
    send_efs(ref(sock));

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
