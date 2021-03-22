#include <stdio.h>
#include <sstream>
#include <fstream>
#include <set>
#include <cstdint>
#include "CodeObject.h"
#include "Function.h"
#include "Symtab.h"
#include "Instruction.h"
#include "glog/logging.h"
#include "gflags/gflags.h"
#include <sys/stat.h>
#include <iostream>
#include <capstone/capstone.h>
#include <Dereference.h>
#include "protobuf/refInf.pb.h"
#include "protobuf/blocks.pb.h"
#include <bits/stdc++.h>


using namespace Dyninst;
using namespace SymtabAPI;
using namespace std;
using namespace InstructionAPI;
using namespace Dyninst::ParseAPI;


string getRandomString(int n){
	char alphabet[26] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};
	string res = "";
	for (int i = 0; i < n; i++){
		res = res + alphabet[rand() % 26];
	}
	return res;
}

void getEhFrameAddrs(std::set<uint64_t>& pc_sets, const char* input, map<uint64_t, uint64_t> &functions){
	std::stringstream ss;
	std::stringstream dlt;
	srand(time(NULL));
	string rs = getRandomString(10);
	ss << "readelf --debug-dump=frames " << input << " | grep pc | cut -f3 -d =  > /tmp/" << rs;
	int n = system(ss.str().c_str());
	string reFile = "/tmp/";
	reFile.append(rs);
	std::ifstream frame_file(reFile);
	std::string line;
	std::string delimiter = "..";
	if (frame_file.is_open()){
		while(std::getline(frame_file, line)){
			string start = line.substr(0, line.find(delimiter));
			string end = line.substr(line.find(delimiter));
			end = end.substr(2);
			uint64_t pc_addr = std::stoul(start, nullptr, 16);
			uint64_t func_end = std::stoul(end, nullptr, 16);
			pc_sets.insert(pc_addr);
			functions[pc_addr] = func_end;
		}
	}
	dlt << "rm " << reFile;
	int p = system(dlt.str().c_str());
}

void loadFnAddrs(char* input, map<uint64_t, uint64_t> &ref2func){
	std::ifstream file_name("./script/fn_with_reference.log");
	std::string line;
	string name = input;
	if (file_name.is_open()){
		string target_file;
		while(std::getline(file_name, line)) {
			if (line.find("data") == 1){
				target_file = line;
			}
			if (name.compare(target_file) == 0 && line.find("Target") == 0) {
				int start_index = line.find("0x") + 2;
				int end_index = line.find(",") - 1;
				int length = end_index - start_index;
				string ref = line.substr(end_index);
				int ref_start = ref.find("0x") + 2;
				uint64_t func_addr = std::stoi(line.substr(start_index, length), 0, 16);
				uint64_t ref_addr = std::stoi(ref.substr(ref_start, length), 0, 16);
				ref2func[ref_addr] = func_addr;
				//cout << hex << func_addr << " " << ref_addr << endl;
			}
		}
	}
}

