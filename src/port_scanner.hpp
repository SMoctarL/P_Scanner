#ifndef PORT_SCANNER_HPP
#define PORT_SCANNER_HPP

#include <string>
#include <vector>
#include <libxml/parser.h>
#include <libxml/tree.h>

using namespace std;

struct PortInfo {
    int port_number;
    string protocol;
    string state;
    string service;
};

class PortScanner {
public:
    PortScanner();
    ~PortScanner();

    void setTarget(const string& target);
    void setPortRange(int start_port, int end_port);
    
    bool scan();
    
    const vector<PortInfo>& getResults() const;

private:
    string target_;
    int start_port_;
    int end_port_;
    vector<PortInfo> results_;

    bool executeNmapCommand(string& output);
    bool parseXmlOutput(const string& xml_content);
    void parsePort(xmlNode* port_node);
};

#endif