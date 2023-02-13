#include <dirent.h>
#include <unistd.h>
#include <sstream>
#include <string>
#include <vector>

#include "linux_parser.h"

using std::stof;
using std::string;
using std::to_string;
using std::stoi;
using std::vector;

// Read and get data from /os_path
string LinuxParser::OperatingSystem() {
  string line;
  string key;
  string value;
  std::ifstream filestream(kOSPath);
  if (filestream.is_open()) {
    while (std::getline(filestream, line)) {
      std::replace(line.begin(), line.end(), ' ', '_');
      std::replace(line.begin(), line.end(), '=', ' ');
      std::replace(line.begin(), line.end(), '"', ' ');
      std::istringstream linestream(line);
      while (linestream >> key >> value) {
        if (key == "PRETTY_NAME") {
          std::replace(value.begin(), value.end(), '_', ' ');
          return value;
        }
      }
    }
  }
  return value;
}

// Read and get data from /version
string LinuxParser::Kernel() {
  string os, kernel, version;
  string line;
  std::ifstream stream(kProcDirectory + kVersionFilename);
  if (stream.is_open()) {
    std::getline(stream, line);
    std::istringstream linestream(line);
    linestream >> os >> version >> kernel;
  }
  return kernel;
}

// BONUS: Update this to use std::filesystem
vector<int> LinuxParser::Pids() {
  vector<int> pids;
  DIR* directory = opendir(kProcDirectory.c_str());
  struct dirent* file;
  while ((file = readdir(directory)) != nullptr) {
    // Is this a directory?
    if (file->d_type == DT_DIR) {
      // Is every character of the name a digit?
      string filename(file->d_name);
      if (std::all_of(filename.begin(), filename.end(), isdigit)) {
        int pid = stoi(filename);
        pids.push_back(pid);
      }
    }
  }
  closedir(directory);
  return pids;
}

// Read and return the system memory utilization
float LinuxParser::MemoryUtilization() { 
  string key, line;
  int available, total, value;
  std::ifstream stream(kProcDirectory + kMeminfoFilename);
  if(stream.is_open()) {
    while (std::getline(stream, line)) {
      std::replace(line.begin(), line.end(), ':', ' ');
      std::istringstream linestream(line);
      while (linestream >> key >> value) {
        if (key == "MemTotal:") {
          total = value;
        }
        if (key == "MemAvailable:") {
          available = value;
          break;
        }
      }
    }
  }
  return available / total;
 }

// Read and return the system uptime
long LinuxParser::UpTime() { 
  long totaluptime, idletime;
  string line;
  std::ifstream stream(kProcDirectory + kUptimeFilename);
  if(stream.is_open()){
    std::getline(stream, line);
    std::istringstream linestream(line);
    linestream >> totaluptime >> idletime;
  }
  return totaluptime - idletime;
 }

// Read and return the number of jiffies for the system
long LinuxParser::Jiffies() { 
  string line, cpuType;
  vector<long> cpuJiffies = { 0, 0, 0, 0, 0, 0, 0 };
  std::ifstream stream(kProcDirectory + kStatFilename);
  if(stream.is_open()){
    std::getline(stream, line);
    std::istringstream linestream(line);
    linestream >> cpuType >> cpuJiffies[0] >> cpuJiffies[1] >> cpuJiffies[2] >> cpuJiffies[3] >> cpuJiffies[4] >> cpuJiffies[5] >> cpuJiffies[6];
  }
  return cpuJiffies[0] + cpuJiffies[1] + cpuJiffies[2] + cpuJiffies[3] + cpuJiffies[4] + cpuJiffies[5] + cpuJiffies[6];
 }

// Read and return the number of active jiffies for a PID
long LinuxParser::ActiveJiffies(int pid) { 
  string line;
  string v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15;
  std::ifstream stream(kProcDirectory + to_string(pid) + kStatFilename);
  if(stream.is_open()){
    std::getline(stream, line);
    std::istringstream linestream(line);
    linestream >> v1 >> v2 >> v3 >> v4 >> v5 >> v6 >> v7 >> v8 >> v9 >> v10 >> v11 >> v12 >> v13 >> v14 >> v15;
  }

  return stoi(v14) + stoi(v15);

 }

// Read and return the number of active jiffies for the system
long LinuxParser::ActiveJiffies() { 
  string line, cpuType;
  vector<long> cpuJiffies = { 0, 0, 0, 0, 0, 0, 0 };
  std::ifstream stream(kProcDirectory + kStatFilename);
  if(stream.is_open()){
    std::getline(stream, line);
    std::istringstream linestream(line);
    linestream >> cpuType >> cpuJiffies[0] >> cpuJiffies[1] >> cpuJiffies[2] >> cpuJiffies[3] >> cpuJiffies[4] >> cpuJiffies[5] >> cpuJiffies[6];
  }
  return cpuJiffies[0] + cpuJiffies[1] + cpuJiffies[2] + cpuJiffies[5] + cpuJiffies[6];
}

// Read and return the number of idle jiffies for the system
long LinuxParser::IdleJiffies() { 
  string line, cpuType;
  vector<long> cpuJiffies = { 0, 0, 0, 0, 0, 0, 0 };
  std::ifstream stream(kProcDirectory + kStatFilename);
  if(stream.is_open()){
    std::getline(stream, line);
    std::istringstream linestream(line);
    linestream >> cpuType >> cpuJiffies[0] >> cpuJiffies[1] >> cpuJiffies[2] >> cpuJiffies[3] >> cpuJiffies[4] >> cpuJiffies[5] >> cpuJiffies[6];
  }

  return cpuJiffies[3] + cpuJiffies[4];

}

// Read and return CPU utilization
vector<string> LinuxParser::CpuUtilization() { return {}; }

// Read and return the total number of processes
int LinuxParser::TotalProcesses() { 
  string lineName, line;
  int numberOfProcesses = 0;
  std::ifstream stream(kProcDirectory + kStatFilename);
  if (stream.is_open()) {
    while(std::getline(stream, line))
    {
      std::istringstream linestream(line);
      linestream >> lineName >> numberOfProcesses;
      if(lineName.compare("processes") == 0) {
        return numberOfProcesses;
      }
    }
  } 
  return numberOfProcesses; 
}

// Read and return the number of running processes
int LinuxParser::RunningProcesses() { 
  string lineName, line;
  int numberOfProcesses = 0;
  std::ifstream stream(kProcDirectory + kStatFilename);
  if (stream.is_open()) {
    while(std::getline(stream, line))
    {
      std::istringstream linestream(line);
      linestream >> lineName >> numberOfProcesses;
      if(lineName.compare("procs_running") == 0) {
        return numberOfProcesses;
      }
    }
  }
  return numberOfProcesses;
}

// Read and return the command associated with a process
string LinuxParser::Command(int pid) { 
  string line;
  std::ifstream stream(kProcDirectory + to_string(pid) + kCmdlineFilename);
  if (stream.is_open()) {
    std::getline(stream, line);
  }
  return line;
}

// Read and return the memory used by a process
string LinuxParser::Ram(int pid) { 
  string lineName, line, key;
  int value = 0;
  std::ifstream stream(kProcDirectory + to_string(pid) + kStatusFilename);
  if (stream.is_open()) {
    while(std::getline(stream, line))
    {
      std::replace(line.begin(), line.end(), ':', ' ');
      std::istringstream linestream(line);
      while(linestream >> key >> value) {
        if(key == "VmRSS") {
          return to_string(value / 1024); 
        }
      }
    }
  }
  return to_string(value);
}

// Read and return the user ID associated with a process
string LinuxParser::Uid(int pid) { 
  string line, lineName, userId = 0;
  std::ifstream stream(kProcDirectory + to_string(pid) +  kStatusFilename);
  if (stream.is_open()) {
    while(true){
      std::getline(stream, line);
      std::istringstream linestream(line);
      linestream >> lineName >> userId;
      if(lineName.compare("Uid:") == 0) {
        return userId;
      }
    }
  }
  return userId;
}

// Read and return the user associated with a process
string LinuxParser::User(int pid) {
  string line, uname;
  int guid, uid;
  std::ifstream stream(kPasswordPath);
  if(stream.is_open()){
    while(std::getline(stream, line)) {
      std::replace(line.begin(), line.end(), ':', ' ');
      std::istringstream linestream(line);
      while(linestream >> uname >> guid >> uid) {
        if(uid == pid) {
          return uname;
        }
      }
    }    
  }
  return uname;  
}

// Read and return the uptime of a process
long LinuxParser::UpTime(int pid) { 
  string line;
  string v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22;
  std::ifstream stream(kProcDirectory + to_string(pid) + kStatFilename);
  if(stream.is_open()){
    std::getline(stream, line);
    std::istringstream linestream(line);
    linestream >> v1 >> v2 >> v3 >> v4 >> v5 >> v6 >> v7 >> v8 >> v9 >> v10 >> v11 >> v12 >> v13 >> v14 >> v15 >> v16 >> v17 >> v18 >> v19 >> v20 >> v21 >> v22;
  }
  return LinuxParser::UpTime() - stol(v22);
}
