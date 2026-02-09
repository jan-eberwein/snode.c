#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace snodec {
    namespace auth {

        class QrCodeGenerator {
        public:
            // Generate a PNG image (grayscale) containing the QR code for `data`.
            // moduleSize: pixels per QR module (e.g., 6..12)
            // margin: quiet zone in modules (spec recommends 4)
            static std::vector<uint8_t> generatePng(const std::string& data, int moduleSize = 8, int margin = 4);

            // Generate a data URI (data:image/png;base64,...) for embedding in HTML.
            static std::string generateDataUri(const std::string& data, int moduleSize = 8, int margin = 4);

            // Generate QR matrix (true = dark module)
            static std::vector<std::vector<bool>> generateMatrix(const std::string& data);

            // Convenience: build otpauth URI for TOTP enrollment (Authenticator apps)
            // issuer: "SNode.C" etc. label typically "issuer:account"
            // accountName: e.g. username or email
            // secretBase32: Base32 encoded secret (no padding)
            static std::string makeTotpOtpAuthUri(const std::string& issuer,
                                                  const std::string& accountName,
                                                  const std::string& secretBase32,
                                                  int digits = 6,
                                                  int period = 30,
                                                  const std::string& algorithm = "SHA1");

        private:
            // ---------------- PNG helpers ----------------
            static std::vector<uint8_t> encodePng(const std::vector<std::vector<bool>>& matrix, int moduleSize, int margin);
            static std::vector<uint8_t> deflateStoredZlib(const std::vector<uint8_t>& data);
            static uint32_t crc32(const std::vector<uint8_t>& data);
            static std::string base64Encode(const std::vector<uint8_t>& data);

            // url encode helper (minimal)
            static std::string urlEncode(const std::string& s);

            // Optional: wipe sensitive buffers (best-effort)
            static void secureWipe(std::vector<uint8_t>& v);
        };

    } // namespace auth
} // namespace snodec
