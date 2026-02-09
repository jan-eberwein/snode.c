// Simple QR code test program
#include "auth/QrCodeGenerator.h"

#include <fstream>
#include <iostream>

int main() {
    std::string testData = "otpauth://totp/Test:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Test";

    std::cout << "Generating QR code for: " << testData << std::endl;

    try {
        auto png = snodec::auth::QrCodeGenerator::generatePng(testData, 8, 4);

        std::cout << "Generated PNG with " << png.size() << " bytes" << std::endl;

        // Write to file
        std::ofstream file("/tmp/qr_test_output.png", std::ios::binary);
        file.write(reinterpret_cast<const char*>(png.data()), png.size());
        file.close();

        std::cout << "Written to /tmp/qr_test_output.png" << std::endl;

        // Print first 20 bytes in hex to verify PNG header
        std::cout << "First 20 bytes: ";
        for (size_t i = 0; i < std::min(png.size(), size_t(20)); ++i) {
            printf("%02x ", png[i]);
        }
        std::cout << std::endl;

        // PNG should start with: 89 50 4E 47 0D 0A 1A 0A
        if (png.size() >= 8 && png[0] == 0x89 && png[1] == 0x50 && png[2] == 0x4E && png[3] == 0x47 && png[4] == 0x0D && png[5] == 0x0A &&
            png[6] == 0x1A && png[7] == 0x0A) {
            std::cout << "Valid PNG header detected!" << std::endl;
        } else {
            std::cout << "ERROR: Invalid PNG header!" << std::endl;
        }

        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
