#include <unistd.h>
#include <cctype>
#include <sstream>
#include <string>
#include <vector>

#include "process.h"
#include "linux_parser.h"

using std::string;
using std::to_string;
using std::vector;

// Return this process's ID
int Process::Pid() { return pid_; }
Process::Process(int pid) { pid_ = pid; }

// Return this process's CPU utilization
float Process::CpuUtilization() { 
    long activeJiff = LinuxParser::ActiveJiffies(Pid());
    long total = LinuxParser::Jiffies();
    return (100 * (activeJiff / total));
}

// Return the command that generated this process
string Process::Command() { return LinuxParser::Command(Pid()); }

// Return this process's memory utilization
string Process::Ram() { return LinuxParser::Ram(Pid()); }

// Return the user (name) that generated this process
string Process::User() { return LinuxParser::User(Pid()); }

// Return the age of this process (in seconds)
long int Process::UpTime() { return LinuxParser::UpTime(Pid()); }

// Overload the "less than" comparison operator for Process objects
bool Process::operator<(Process const& a) const { 
    return LinuxParser::Ram(pid_) > LinuxParser::Ram(a.pid_); 
}