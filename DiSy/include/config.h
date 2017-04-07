/*
author: Swoboda Daniel
matnr:  i12032
file:   config.h
desc:   Used to load, store and access
          configuration files for DiSy
date:   2017-03-18
class:  5AHIF
catnr:  23
*/

#ifndef CONFIG_H_
#define CONFIG_H_

#include <fstream>
#include <iostream>
#include "fmt/format.h"

#include "json.hpp"

class Config {
public:
    Config(bool manconf, std::string path) {
        //use standard config questionnaire
        if(manconf) {
            fmt::print("Please enter the path of the directory you want to sync (w/out '/' at the end): ");
            std::cin >> path_;
            json conf_json;
            conf_json["path"] = path_;
            std::ofstream filestrm;
            filestrm.open(path);
            filestrm << conf_json.dump();
            filestrm.close();
        //use path as the path_ variable
        } else {
            path_ = path;
        }
    }
    Config(std::string path){
        //open file and read config
        try {
            std::string whole;
            std::string line;
            std::ifstream filestrm {path};
            if (filestrm.is_open()) {
              while ( std::getline (filestrm,line) ) {
                whole+=line;
              }
            }
            auto conf_json = nlohmann::json::parse(whole);
            path_ = conf_json["path"];
            //if file can't be found read from console and create new file
        } catch (std::invalid_argument& e){
            fmt::print("Couldn't read config file.");
            fmt::print("\nPlease enter the path of the directory you want to sync (w/out '/' at the end): ");
            std::cin >> path_;
            json conf_json;
            conf_json["path"] = path_;
            std::ofstream filestrm;
            filestrm.open(path);
            filestrm << conf_json.dump();
            filestrm.close();
        }
    }

    Config(){}

    //get the path of the directory to be synchronized
    std::string get_path() {
        return path_;
    }
private:
  //path to the synched directory
  std::string path_;

};

#endif
