cmake_minimum_required(VERSION 3.10)
project(PSCANNER)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Configuration pour MSYS2/MinGW
if(WIN32)
    set(CMAKE_PREFIX_PATH "C:/msys64/mingw64")
endif()

# Trouver la bibliothèque libxml2
find_package(LibXml2 REQUIRED)
include_directories(${LIBXML2_INCLUDE_DIR})

# Ajouter l'exécutable
add_executable(pscanner src/main.cpp src/port_scanner.cpp)

# Lier les bibliothèques
target_link_libraries(pscanner ${LIBXML2_LIBRARIES}) 