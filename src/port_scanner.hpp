#ifndef PORT_SCANNER_HPP
#define PORT_SCANNER_HPP

#include <string>
#include <vector>
#include <libxml/parser.h>
#include <libxml/tree.h>

struct PortInfo {
    int port_number;
    std::string protocol;
    std::string state;
    std::string service;
};

class PortScanner {
public:
    PortScanner();
    ~PortScanner();

    // Configure le scan
    void setTarget(const std::string& target);
    void setPortRange(int start_port, int end_port);
    
    // Exécute le scan
    bool scan();
    
    // Récupère les résultats
    const std::vector<PortInfo>& getResults() const;

private:
    std::string target_;
    int start_port_;
    int end_port_;
    std::vector<PortInfo> results_;

    // Méthodes privées pour le traitement
    bool executeNmapCommand(std::string& output);
    bool parseXmlOutput(const std::string& xml_content);
    void parsePort(xmlNode* port_node);
};

#endif // PORT_SCANNER_HPP 