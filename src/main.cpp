#include "port_scanner.hpp"
#include <iostream>
#include <iomanip>

using namespace std;

void afficher_resultats(const vector<PortInfo>& resultats) {
    cout << setw(10) << "PORT" 
         << setw(15) << "PROTOCOLE" 
         << setw(15) << "ÉTAT" 
         << setw(20) << "SERVICE" << endl;
    cout << string(60, '-') << endl;

    for (const auto& port : resultats) {
        cout << setw(10) << port.port_number
             << setw(15) << port.protocol
             << setw(15) << port.state
             << setw(20) << port.service << endl;
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        cerr << "Usage: " << argv[0] << " <adresse_cible>" << endl;
        return 1;
    }

    try {
        PortScanner scanner;
        scanner.setTarget(argv[1]);
        scanner.setPortRange(1, 1024);

        cout << "Démarrage du scan sur " << argv[1] << "..." << endl;
        
        if (scanner.scan()) {
            const auto& resultats = scanner.getResults();
            cout << "\nScan terminé. " << resultats.size() 
                 << " ports trouvés." << endl << endl;
            afficher_resultats(resultats);
        } else {
            cerr << "Erreur lors du scan." << endl;
            return 1;
        }
    } catch (const exception& e) {
        cerr << "Erreur: " << e.what() << endl;
        return 1;
    }

    return 0;
} 