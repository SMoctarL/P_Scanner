#include "port_scanner.hpp"
#include <iostream>
#include <iomanip>

void afficher_resultats(const std::vector<PortInfo>& resultats) {
    std::cout << std::setw(10) << "PORT" 
              << std::setw(15) << "PROTOCOLE" 
              << std::setw(15) << "ÉTAT" 
              << std::setw(20) << "SERVICE" << std::endl;
    std::cout << std::string(60, '-') << std::endl;

    for (const auto& port : resultats) {
        std::cout << std::setw(10) << port.port_number
                  << std::setw(15) << port.protocol
                  << std::setw(15) << port.state
                  << std::setw(20) << port.service << std::endl;
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <adresse_cible>" << std::endl;
        return 1;
    }

    try {
        PortScanner scanner;
        scanner.setTarget(argv[1]);
        scanner.setPortRange(1, 1024); // Scan des ports bien connus

        std::cout << "Démarrage du scan sur " << argv[1] << "..." << std::endl;
        
        if (scanner.scan()) {
            const auto& resultats = scanner.getResults();
            std::cout << "\nScan terminé. " << resultats.size() 
                      << " ports trouvés." << std::endl << std::endl;
            afficher_resultats(resultats);
        } else {
            std::cerr << "Erreur lors du scan." << std::endl;
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "Erreur: " << e.what() << std::endl;
        return 1;
    }

    return 0;
} 