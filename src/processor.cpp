#include "processor.h"
#include "linux_parser.h"

// Return the aggregate CPU utilization
float Processor::Utilization() { 
    long activeJiff = LinuxParser::ActiveJiffies();
    long total = LinuxParser::Jiffies();
    return (100 * (activeJiff / total));
}