#include <string>

#include "format.h"

using std::string;
using std::to_string;

string Format::ElapsedTime(long seconds) { 
    int hours, minutes;
    minutes = seconds / 60;
    hours = minutes / 60;
    return to_string(hours) + ":" + to_string(minutes % 60) + ":" + to_string(seconds % 60);
 }