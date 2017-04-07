/*
author: Swoboda Daniel
matnr:    i12032
file:     file.h //originally crawl.h
desc:     Contains methods to handle files
date:     2017-03-19
class:    5AHIF
catnr:    23
*/

#ifndef FILE_H_
#define FILE_H_

#include <experimental/filesystem>
#include <fstream>
#include <iostream>
#include <chrono>
#include <thread>
#include "sha256.h"
#include "disy.pb.h"
#include "fmt/format.h"

#include "message_helper.h"

#define BLOCKSIZE 16384

namespace fs = std::experimental::filesystem;

//reads the permissions of a file and converts them to a string
std::string permissions_to_string(fs::path fpath) {
    fs::perms p{fs::status(fpath).permissions()};
    std::string perms_str{""};
    perms_str+=((p & fs::perms::owner_read) != fs::perms::none ? "r" : "-");
    perms_str+=((p & fs::perms::owner_write) != fs::perms::none ? "w" : "-");
    perms_str+=((p & fs::perms::owner_exec) != fs::perms::none ? "x" : "-");
    perms_str+=((p & fs::perms::group_read) != fs::perms::none ? "r" : "-");
    perms_str+=((p & fs::perms::group_write) != fs::perms::none ? "w" : "-");
    perms_str+=((p & fs::perms::group_exec) != fs::perms::none ? "x" : "-");
    perms_str+=((p & fs::perms::others_read) != fs::perms::none ? "r" : "-");
    perms_str+=((p & fs::perms::others_write) != fs::perms::none ? "w" : "-");
    perms_str+=((p & fs::perms::others_exec) != fs::perms::none ? "x" : "-");
    return perms_str;
}

//converts a permission string to a filesystem::perms object
fs::perms string_to_permissions(std::string perms_str) {
    fs::perms perms{fs::perms::remove_perms | fs::perms::add_perms};
    std::string owner{perms_str.substr(0,3)};
    std::string group{perms_str.substr(3,3)};
    std::string others{perms_str.substr(6,3)};
    if(owner.substr(0,1) == "r")
        perms = perms | fs::perms::owner_read;
    if(owner.substr(1,1) == "w")
        perms = perms | fs::perms::owner_write;
    if(owner.substr(2,1) == "x")
        perms = perms | fs::perms::owner_exec;
    if(group.substr(0,1) == "r")
        perms = perms | fs::perms::group_read;
    if(group.substr(1,1) == "w")
        perms = perms | fs::perms::group_write;
    if(group.substr(2,1) == "x")
        perms = perms | fs::perms::group_exec;
    if(others.substr(0,1) == "r")
        perms = perms | fs::perms::others_read;
    if(others.substr(1,1) == "w")
        perms = perms | fs::perms::others_write;
    if(others.substr(2,1) == "x")
        perms = perms | fs::perms::others_exec;

    return perms;
}

//crawl every file in the current directory and all the subdirectories.
//get the change date and store them with the
//file name inside a protobuf Directory object.
DiSyProto::Directory crawl_files(std::string path){
        DiSyProto::Directory dir{};
        size_t path_size{path.size()};

        for(auto& p: fs::recursive_directory_iterator(path)){
                if(!fs::is_directory(p)){
                    DiSyProto::Directory::File* file{dir.add_files()};
                    file->set_name(p.path().string().substr(path_size));
                    file->set_date(std::chrono::system_clock::to_time_t(fs::last_write_time(p)));
                }

        }
        return dir;
}

//crawl every sub(n*)directory inside the given path, store it in an Dirlist
//and return the dirlist.
DiSyProto::Dirlist crawl_directory(std::string path) {
        DiSyProto::Dirlist dirlist{};
        size_t path_size{path.size()};

        for(auto& p: fs::recursive_directory_iterator(path)){
                if(fs::is_directory(p)){
                    DiSyProto::Dirlist::Directory* dir{dirlist.add_dir()};
                    dir->set_name(p.path().string().substr(path_size));
                    dir->set_privileges(permissions_to_string(p.path()));
                }
        }
        return dirlist;
}

//create the directories that are missing
void create_directories(std::string path, DiSyProto::Dirlist dirlist) {
    for (int i = 0; i < dirlist.dir_size(); i++) {
        const DiSyProto::Dirlist::Directory& dir{dirlist.dir(i)};
        //if directory does not exist
        if(!fs::exists(fs::path(path+dir.name()))) {
            fs::create_directories(path+dir.name());
            fs::permissions(path+dir.name(), string_to_permissions(dir.privileges()));
        }
    }
}

//Create a hashlist message based on the files given as parameter in the filelist
DiSyProto::Hashlist create_hashlist(std::string path, DiSyProto::Filelist fl) {
    DiSyProto::Hashlist hashes{};

    for (int i = 0; i < fl.files_size(); i++) {
        const DiSyProto::Filelist::File& file{fl.files(i)};
        DiSyProto::Hashlist::FileHash* hash{hashes.add_filehashes()};

        std::string whole;
        std::string line;
        std::ifstream filestrm {path+file.name()};
        if (filestrm.is_open()) {
                while ( std::getline (filestrm,line) ) {
                    whole+=line;
                }
        }
        fs::path p{path+file.name()};
        hash->set_hash(sha256(whole));
        hash->set_date(std::chrono::system_clock::to_time_t(fs::last_write_time(p)));
        hash->set_name(file.name());
    }
    return hashes;
}

//send files over tcp in fileblocks
void send_files(asio::ip::tcp::socket& sock, DiSyProto::Filelist file_req, std::string dir_path) {
    for (int i = 0; i < file_req.files_size(); i++) {
        //create, gather and calculate basic file information
        const DiSyProto::Filelist::File& file{file_req.files(i)};
        fs::path filepath{dir_path+file.name()};
        std::uintmax_t filesize{fs::file_size(filepath)};
        long int blockcount{(long int)(filesize/BLOCKSIZE)+1};

        //print file information
        fmt::print("File: {}\n", filepath.c_str());
        fmt::print("     Size:       {}\n", filesize);
        fmt::print("     Blockcount: {}\n", blockcount);

        DiSyProto::FileblockInfo fbi{DiSyProto::FileblockInfo()};
        //set the name
        fbi.set_name(file.name());
        //set the number of blocks
        fbi.set_number(blockcount);
        //get the permissions
        fbi.set_privileges(permissions_to_string(filepath));

        // send the sfs message
        send_sfs(std::ref(sock), fbi);

        char byte;
        int count = 0;
        //create filestram to read it
        std::fstream file_strm(filepath.c_str(), std::fstream::in);
        std::string datablock{};
        //read in bytes
        while (file_strm >> std::noskipws >> byte) {
            DiSyProto::Fileblock fb{};
            datablock += byte;
            count++;
            //send fileblock if blocksize is reached
            if(count == BLOCKSIZE) {
                fb.set_name(file.name());
                fb.set_data(datablock);
                send_fileblock(std::ref(sock), fb);
                //reset
                datablock.clear();
                count = 0;
            }
        }
        //send the last fileblock
        DiSyProto::Fileblock fb{};
        fb.set_name(file.name());
        fb.set_data(datablock);
        send_fileblock(std::ref(sock), fb);
    }
}

//receive all the files until an efs message comes and save them
void receive_files(asio::ip::tcp::socket& sock, std::string path) {
    //receive first sfs message or efs message if no files are to be transmitted
    std::string format{receive_format_message(std::ref(sock))};

    //while receiving files
    while(extract_message_type(format) != "EFS") {
        //receive the fileblock info
        DiSyProto::FileblockInfo fbi{receive_fileblockInfo(std::ref(sock),
                extract_message_size(format))};

        //print file to be receive
        fmt::print("File: {}\n", fbi.name());
        //if already existing, remove old file
        try {
            fs::remove(path+fbi.name());
        } catch(std::experimental::filesystem::v1::__cxx11::filesystem_error& e) {}

        //open filestream to write to
        std::ofstream filestrm;
        filestrm.open(path+fbi.name(), std::ios::out | std::ios::app);

        //for number of fileblocks receive a fileblock
        for(int i = 0; i < fbi.number(); i++){
            DiSyProto::Fileblock fb;
            //get the SFB format message
            format = receive_format_message(std::ref(sock));
            //receive the fileblock with the given size
            fb = receive_fileblock(std::ref(sock), extract_message_size(format));
            //put the fileblock data into the filestream
            filestrm << fb.data();
        }
        //close the filestream after completion
        filestrm.close();
        //apply the file permissions
        fs::permissions(path+fbi.name(), string_to_permissions(fbi.privileges()));
        //receive next format message
        format = receive_format_message(std::ref(sock));
    }
}

//reset the modify date to the given date
void reset_modify_date(std::string path, long s_time) {
    for(auto& p: fs::recursive_directory_iterator(path)){
            if(!fs::is_directory(p)){
                fs::last_write_time(p, std::chrono::system_clock::from_time_t(s_time));
            }
    }
}

#endif
