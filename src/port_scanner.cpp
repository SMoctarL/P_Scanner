#include "port_scanner.hpp"
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <array>
#include <sstream>
#include <iostream>

using pclose_deleter = int(*)(FILE*);

PortScanner::PortScanner() : start_port_(1), end_port_(1024) {
    LIBXML_TEST_VERSION
}

PortScanner::~PortScanner() {
    xmlCleanupParser();
}

void PortScanner::setTarget(const std::string& target) {
    target_ = target;
}

void PortScanner::setPortRange(int start_port, int end_port) {
    start_port_ = start_port;
    end_port_ = end_port;
}

bool PortScanner::scan() {
    results_.clear();
    std::string output;
    
    if (!executeNmapCommand(output)) {
        std::cerr << "Erreur lors de l'exécution de nmap" << std::endl;
        return false;
    }

    return parseXmlOutput(output);
}

bool PortScanner::executeNmapCommand(std::string& output) {
    // Construire la commande nmap
    std::stringstream cmd;
    #ifdef _WIN32
    cmd << "nmap -p " << start_port_ << "-" << end_port_ 
        << " -oX - " << target_;
    #else
    cmd << "sudo nmap -p " << start_port_ << "-" << end_port_ 
        << " -oX - " << target_ << " 2>/dev/null";
    #endif

    // Exécuter la commande
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, pclose_deleter> pipe(
        popen(cmd.str().c_str(), "r"), pclose);

    if (!pipe) {
        std::cerr << "Erreur: Impossible d'exécuter nmap. Assurez-vous qu'il est installé et que vous avez les droits root." << std::endl;
        return false;
    }

    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        output += buffer.data();
    }

    if (output.empty()) {
        std::cerr << "Attention: Aucune donnée reçue de nmap. Vérifiez que vous avez les droits root." << std::endl;
        return false;
    }

    return true;
}

bool PortScanner::parseXmlOutput(const std::string& xml_content) {
    xmlDoc* doc = xmlReadMemory(xml_content.c_str(), xml_content.length(), 
                               nullptr, nullptr, 0);
    if (doc == nullptr) {
        return false;
    }

    xmlNode* root = xmlDocGetRootElement(doc);
    if (root == nullptr) {
        xmlFreeDoc(doc);
        return false;
    }

    // Parcourir le document XML
    for (xmlNode* host = root->children; host; host = host->next) {
        if (host->type == XML_ELEMENT_NODE && 
            xmlStrcmp(host->name, (const xmlChar*)"host") == 0) {
            
            for (xmlNode* ports = host->children; ports; ports = ports->next) {
                if (ports->type == XML_ELEMENT_NODE && 
                    xmlStrcmp(ports->name, (const xmlChar*)"ports") == 0) {
                    
                    for (xmlNode* port = ports->children; port; port = port->next) {
                        if (port->type == XML_ELEMENT_NODE && 
                            xmlStrcmp(port->name, (const xmlChar*)"port") == 0) {
                            parsePort(port);
                        }
                    }
                }
            }
        }
    }

    xmlFreeDoc(doc);
    return true;
}

void PortScanner::parsePort(xmlNode* port_node) {
    PortInfo info;
    
    // Récupérer les attributs du port
    xmlChar* portid = xmlGetProp(port_node, (const xmlChar*)"portid");
    xmlChar* protocol = xmlGetProp(port_node, (const xmlChar*)"protocol");
    
    if (portid) {
        info.port_number = std::stoi((char*)portid);
        xmlFree(portid);
    }
    
    if (protocol) {
        info.protocol = (char*)protocol;
        xmlFree(protocol);
    }

    // Parcourir les éléments enfants pour l'état et le service
    for (xmlNode* child = port_node->children; child; child = child->next) {
        if (child->type == XML_ELEMENT_NODE) {
            if (xmlStrcmp(child->name, (const xmlChar*)"state") == 0) {
                xmlChar* state = xmlGetProp(child, (const xmlChar*)"state");
                if (state) {
                    info.state = (char*)state;
                    xmlFree(state);
                }
            }
            else if (xmlStrcmp(child->name, (const xmlChar*)"service") == 0) {
                xmlChar* name = xmlGetProp(child, (const xmlChar*)"name");
                if (name) {
                    info.service = (char*)name;
                    xmlFree(name);
                }
            }
        }
    }

    results_.push_back(info);
}

const std::vector<PortInfo>& PortScanner::getResults() const {
    return results_;
} 