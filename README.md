# Port Scanner

Un scanner de ports simple utilisant nmap et libxml2 pour analyser les ports ouverts sur une machine cible.

## Prérequis

- CMake (version 3.10 ou supérieure)
- Compilateur C++ supportant C++17
- nmap
- libxml2-dev

## Installation des dépendances

### Sur Windows (avec MSYS2)
```bash
pacman -S mingw-w64-x86_64-cmake
pacman -S mingw-w64-x86_64-gcc
pacman -S mingw-w64-x86_64-nmap
pacman -S mingw-w64-x86_64-libxml2
```

### Sur Linux (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install build-essential cmake nmap libxml2-dev
```

## Compilation

1. Créez un répertoire de build :
```bash
mkdir build
cd build
```

2. Configurez le projet avec CMake :
```bash
cmake ..
```

3. Compilez le projet :
```bash
cmake --build .
```

## Utilisation

Le programme prend en argument l'adresse IP ou le nom d'hôte de la cible à scanner :

```bash
./pscanner <adresse_cible>
```

Exemple :
```bash
./pscanner localhost
```

## Fonctionnalités

- Scan des ports 1-1024 (ports bien connus)
- Détection du protocole (TCP/UDP)
- Identification des services
- Affichage formaté des résultats

## Note de sécurité

Ce programme nécessite les privilèges administrateur pour fonctionner correctement avec nmap. Utilisez-le de manière responsable et uniquement sur des systèmes pour lesquels vous avez l'autorisation de faire des tests. 