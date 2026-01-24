#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-helper.h"
#include "ns3/network-module.h"
#include "ns3/yans-wifi-helper.h"
#include "ns3/wifi-module.h"
#include "ns3/constant-velocity-mobility-model.h"
#include <arpa/inet.h>
#include <cmath>
#include <limits>
// you should add 'crypto' and 'ssl' to cmakelist.txt file for linking
#include <cstdint>
#include <vector>
#include <cstring>
#include <stdexcept>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <map>
#include <fstream>
#include <sstream>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("ZamaAuthentication");

struct VehicleMetrics {
    uint64_t regMsg1 = 0;  // Vehicle -> TA registration request
    uint64_t regMsg2 = 0;  // TA -> Vehicle registration response
    uint64_t authMsg1 = 0; // Vehicle -> AS authentication request (encrypted)
    uint64_t authMsg2 = 0; // AS -> Vehicle authentication response
    uint64_t authMsg3 = 0; // AS -> TA verification request
    uint64_t authMsg4 = 0; // TA -> AS verification response
    double authStartTime = 0;
    double authEndTime = 0;
};

struct Metrics {
    uint32_t authAttempts = 0;
    uint32_t authSuccess = 0;
    double firstAuthStart = std::numeric_limits<double>::max();
    double lastAuthEnd = 0.0;
    std::vector<double> authDelays;
    std::map<std::string, VehicleMetrics> vehicleMetrics;
    std::string currentVehicle = "";
} g_metrics;

struct VehicleRegistrationData {
    std::string vid;
    BIGNUM *r1, *r2, *r3;
    BIGNUM *E, *F;
    BIGNUM *kesa1, *kesa2;
    BIGNUM *u, *v, *h;
    BIGNUM *K;
};

struct VehicleState {
    std::string vid;
    BIGNUM *r1, *r2, *r3;
    BIGNUM *u, *v, *h;
    BIGNUM *omega, *q1, *q2;
    BIGNUM *w1, *w2;
    BIGNUM *K;
};

struct VehicleTraceEntry {
    double time;
    std::string vehicleId;
    double x;
    double y;
    double speed;
    std::string vehicleType;
    double angle;
    std::string lane;
};

VehicleTraceEntry ParseTraceLine(const std::string& line)
{
    VehicleTraceEntry entry;
    std::istringstream ss(line);
    std::string token;
    std::vector<std::string> tokens;

    while (std::getline(ss, token, ';'))
    {
        token.erase(0, token.find_first_not_of(" \t\r\n"));
        token.erase(token.find_last_not_of(" \t\r\n") + 1);
        tokens.push_back(token);
    }

    if (tokens.size() >= 10)
    {
        try {
            entry.time = std::stod(tokens[0]);
            entry.lane = tokens[2];
            entry.angle = std::stod(tokens[3]);
            entry.vehicleType = tokens[4];
            entry.y = std::stod(tokens[6]);
            entry.x = std::stod(tokens[7]);
            entry.speed = std::stod(tokens[8]);
            entry.vehicleId = tokens[9];
        }
        catch (const std::exception& e) {
            NS_LOG_WARN("Failed to parse line: " << line << " - Error: " << e.what());
            entry.vehicleId = "";
        }
    }
    else
    {
        // NS_LOG_WARN("Insufficient tokens in line (expected 10, got " << tokens.size() << "): " << line);
    }

    return entry;
}

std::map<std::string, std::vector<VehicleTraceEntry>> LoadMobilityTraces(const std::string& filename)
{
    std::map<std::string, std::vector<VehicleTraceEntry>> traces;
    std::ifstream file(filename);

    if (!file.is_open())
    {
        NS_LOG_ERROR("Failed to open trace file: " << filename);
        return traces;
    }

    std::string line;
    std::getline(file, line);

    int lineCount = 0;
    while (std::getline(file, line))
    {
        if (line.empty()) continue;

        VehicleTraceEntry entry = ParseTraceLine(line);
        if (!entry.vehicleId.empty())
        {
            traces[entry.vehicleId].push_back(entry);
            lineCount++;
        }
    }

    file.close();

    NS_LOG_INFO("Loaded " << lineCount << " trace entries for "
                << traces.size() << " unique vehicles");

    return traces;
}

void UpdateVehiclePosition(Ptr<Node> node, double x, double y, double speed, double angle)
{
    Ptr<ConstantVelocityMobilityModel> mobility =
        node->GetObject<ConstantVelocityMobilityModel>();

    if (mobility)
    {
        mobility->SetPosition(Vector(x, y, 0.0));

        double angleRad = angle * M_PI / 180.0;
        double vx = speed * cos(angleRad);
        double vy = speed * sin(angleRad);

        mobility->SetVelocity(Vector(vx, vy, 0.0));
    }
}

void ScheduleVehicleUpdates(Ptr<Node> node,
                            const std::vector<VehicleTraceEntry>& entries)
{
    for (const auto& entry : entries)
    {
        Simulator::Schedule(Seconds(entry.time),
                          &UpdateVehiclePosition,
                          node,
                          entry.x,
                          entry.y,
                          entry.speed,
                          entry.angle);
    }
}

std::vector<std::string> GetVehicleIds(
    const std::map<std::string, std::vector<VehicleTraceEntry>>& traces,
    const std::string& typeFilter = "")
{
    std::vector<std::string> vehicleIds;

    for (const auto& kv : traces)
    {
        if (!kv.second.empty())
        {
            if (typeFilter.empty() || kv.second[0].vehicleType == typeFilter)
            {
                vehicleIds.push_back(kv.first);
            }
        }
    }

    return vehicleIds;
}

// Global parameters for Zama protocol
BIGNUM *n, *g1, *g2, *h1, *h2;

// Helper functions
BIGNUM* generate_random_bn(BIGNUM* max) {
    BIGNUM* rand = BN_new();
    BN_rand_range(rand, max);
    return rand;
}

BIGNUM* mod_exp(BIGNUM* base, BIGNUM* exp, BIGNUM* mod) {
    BIGNUM* result = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    BN_mod_exp(result, base, exp, mod, ctx);
    BN_CTX_free(ctx);
    return result;
}

BIGNUM* mod_mul(BIGNUM* a, BIGNUM* b, BIGNUM* mod) {
    BIGNUM* result = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    BN_mod_mul(result, a, b, mod, ctx);
    BN_CTX_free(ctx);
    return result;
}

BIGNUM* mod_inv(BIGNUM* a, BIGNUM* mod) {
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* inv = BN_mod_inverse(NULL, a, mod, ctx);
    BN_CTX_free(ctx);
    return inv;
}

BIGNUM* mod_add(BIGNUM* a, BIGNUM* b, BIGNUM* mod) {
    BIGNUM* result = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    BN_mod_add(result, a, b, mod, ctx);
    BN_CTX_free(ctx);
    return result;
}

BIGNUM* mod_sub(BIGNUM* a, BIGNUM* b, BIGNUM* mod) {
    BIGNUM* result = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    BN_mod_sub(result, a, b, mod, ctx);
    BN_CTX_free(ctx);
    return result;
}

std::vector<uint8_t> bn_to_bytes(BIGNUM* bn) {
    int len = BN_num_bytes(bn);
    std::vector<uint8_t> bytes(len);
    BN_bn2bin(bn, bytes.data());
    return bytes;
}

BIGNUM* bytes_to_bn(const std::vector<uint8_t>& bytes) {
    return BN_bin2bn(bytes.data(), bytes.size(), NULL);
}

std::vector<uint8_t> sha256_hash(const std::vector<uint8_t>& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(data.data(), data.size(), hash);
    return std::vector<uint8_t>(hash, hash + SHA256_DIGEST_LENGTH);
}

double ComputeEuclideanDistance(const Vector& a, const Vector& b) {
    double dx = a.x - b.x;
    double dy = a.y - b.y;
    double dz = a.z - b.z;
    return std::sqrt(dx*dx + dy*dy + dz*dz);
}

std::vector<uint8_t> aes_encrypt(const std::string& plaintext, BIGNUM* key_bn) {
    // Convert BIGNUM key to 256-bit AES key
    unsigned char aes_key[32]; // 256 bits
    memset(aes_key, 0, 32);
    int bn_size = BN_num_bytes(key_bn);
    int copy_size = std::min(bn_size, 32);
    BN_bn2bin(key_bn, aes_key + (32 - copy_size));
    
    // Generate random IV
    unsigned char iv[16];
    RAND_bytes(iv, 16);
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return std::vector<uint8_t>();
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return std::vector<uint8_t>();
    }
    
    std::vector<uint8_t> ciphertext;
    ciphertext.insert(ciphertext.end(), iv, iv + 16); // Prepend IV
    
    int len;
    int ciphertext_len;
    unsigned char buffer[1024];
    
    if (EVP_EncryptUpdate(ctx, buffer, &len, 
                         (unsigned char*)plaintext.c_str(), 
                         plaintext.length()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return std::vector<uint8_t>();
    }
    ciphertext.insert(ciphertext.end(), buffer, buffer + len);
    
    if (EVP_EncryptFinal_ex(ctx, buffer, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return std::vector<uint8_t>();
    }
    ciphertext.insert(ciphertext.end(), buffer, buffer + len);
    
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

std::string aes_decrypt(const std::vector<uint8_t>& ciphertext, BIGNUM* key_bn) {
    if (ciphertext.size() < 16) return "";
    
    // Convert BIGNUM key to 256-bit AES key
    unsigned char aes_key[32];
    memset(aes_key, 0, 32);
    int bn_size = BN_num_bytes(key_bn);
    int copy_size = std::min(bn_size, 32);
    BN_bn2bin(key_bn, aes_key + (32 - copy_size));
    
    // Extract IV from first 16 bytes
    unsigned char iv[16];
    memcpy(iv, ciphertext.data(), 16);
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "";
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    
    std::vector<uint8_t> plaintext;
    int len;
    unsigned char buffer[1024];
    
    if (EVP_DecryptUpdate(ctx, buffer, &len,
                         ciphertext.data() + 16,
                         ciphertext.size() - 16) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext.insert(plaintext.end(), buffer, buffer + len);
    
    if (EVP_DecryptFinal_ex(ctx, buffer, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext.insert(plaintext.end(), buffer, buffer + len);
    
    EVP_CIPHER_CTX_free(ctx);
    return std::string((char*)plaintext.data(), plaintext.size());
}

EVP_PKEY* generate_rsa_key(int bits = 2048) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *pkey = NULL;
    
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_PKEY_CTX");
    }
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize keygen");
    }
    
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to set key size");
    }
    
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to generate key");
    }
    
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

std::vector<uint8_t> rsa_encrypt(const std::vector<uint8_t>& plaintext, EVP_PKEY* pubkey) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pubkey, NULL);
    if (!ctx) return plaintext;
    
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return plaintext;
    }
    
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return plaintext;
    }
    
    size_t outlen;
    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, plaintext.data(), plaintext.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return plaintext;
    }
    
    std::vector<uint8_t> encrypted(outlen);
    if (EVP_PKEY_encrypt(ctx, encrypted.data(), &outlen, plaintext.data(), plaintext.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return plaintext;
    }
    
    encrypted.resize(outlen);
    EVP_PKEY_CTX_free(ctx);
    return encrypted;
}

std::vector<uint8_t> rsa_decrypt(const std::vector<uint8_t>& ciphertext, EVP_PKEY* privkey) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privkey, NULL);
    if (!ctx) return ciphertext;
    
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return ciphertext;
    }
    
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return ciphertext;
    }
    
    size_t outlen;
    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, ciphertext.data(), ciphertext.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return ciphertext;
    }
    
    std::vector<uint8_t> decrypted(outlen);
    if (EVP_PKEY_decrypt(ctx, decrypted.data(), &outlen, ciphertext.data(), ciphertext.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return ciphertext;
    }
    
    decrypted.resize(outlen);
    EVP_PKEY_CTX_free(ctx);
    return decrypted;
}

BIGNUM* hash_to_bn(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> hash = sha256_hash(data);
    return BN_bin2bn(hash.data(), hash.size(), NULL);
}

class ZamaTAApplication : public Application {
public:
    ZamaTAApplication();
    virtual ~ZamaTAApplication();

    void Setup(uint16_t regPort, uint16_t verifyPort, std::string taId);
    void SetTAId(uint32_t id) { m_taId = id; }
    void SetASAddress(Address addr) { m_asAddress = addr; }

private:
    virtual void StartApplication(void);
    virtual void StopApplication(void);

    void HandleRegistrationRequest(Ptr<Socket> socket);
    void HandleVerificationRequest(Ptr<Socket> socket);

    uint32_t m_taId;
    uint16_t m_regPort;
    uint16_t m_verifyPort;
    std::string m_taIdStr;
    Ptr<Socket> m_regSocket;
    Ptr<Socket> m_verifySocket;
    Address m_asAddress;
    std::map<std::string, VehicleRegistrationData> m_registeredVehicles;
    BIGNUM *m_x;
};

ZamaTAApplication::ZamaTAApplication() : m_taId(0), m_regPort(0), m_verifyPort(0), m_x(NULL) {
}

void ZamaTAApplication::Setup(uint16_t regPort, uint16_t verifyPort, std::string taId) {
    m_regPort = regPort;
    m_verifyPort = verifyPort;
    m_taIdStr = taId;
    m_x = generate_random_bn(n);
}

ZamaTAApplication::~ZamaTAApplication() {
    if (m_x) BN_free(m_x);
    for (auto& pair : m_registeredVehicles) {
        VehicleRegistrationData& data = pair.second;
        if (data.r1) BN_free(data.r1);
        if (data.r2) BN_free(data.r2);
        if (data.r3) BN_free(data.r3);
        if (data.E) BN_free(data.E);
        if (data.F) BN_free(data.F);
        if (data.kesa1) BN_free(data.kesa1);
        if (data.kesa2) BN_free(data.kesa2);
        if (data.u) BN_free(data.u);
        if (data.v) BN_free(data.v);
        if (data.h) BN_free(data.h);
        if (data.K) BN_free(data.K);
    }
}

void ZamaTAApplication::StartApplication(void) {
    m_regSocket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    m_regSocket->Bind(InetSocketAddress(Ipv4Address::GetAny(), m_regPort));
    m_regSocket->SetRecvCallback(MakeCallback(&ZamaTAApplication::HandleRegistrationRequest, this));

    m_verifySocket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    m_verifySocket->Bind(InetSocketAddress(Ipv4Address::GetAny(), m_verifyPort));
    m_verifySocket->SetRecvCallback(MakeCallback(&ZamaTAApplication::HandleVerificationRequest, this));
}

void ZamaTAApplication::StopApplication(void) {
    if (m_regSocket) {
        m_regSocket->Close();
    }
    if (m_verifySocket) {
        m_verifySocket->Close();
    }
}

void ZamaTAApplication::HandleRegistrationRequest(Ptr<Socket> socket) {
    Ptr<Packet> packet;
    Address from;

    while ((packet = socket->RecvFrom(from))) {
        uint32_t packetSize = packet->GetSize();
        uint8_t *buffer = new uint8_t[packetSize];
        packet->CopyData(buffer, packetSize);

        std::string vid((char*)buffer, packetSize);
        delete[] buffer;

        // NS_LOG_INFO(m_taIdStr << " received registration request from vehicle " << vid);

        // Track registration message 1 size
        if (g_metrics.vehicleMetrics.find(vid) == g_metrics.vehicleMetrics.end()) {
            g_metrics.vehicleMetrics[vid] = VehicleMetrics();
        }
        g_metrics.vehicleMetrics[vid].regMsg1 = packetSize;

        VehicleRegistrationData regData;
        regData.vid = vid;
        regData.r1 = generate_random_bn(n);
        regData.r2 = generate_random_bn(n);
        regData.r3 = BN_dup(m_x);
        regData.kesa1 = generate_random_bn(n);
        regData.kesa2 = generate_random_bn(n);

        BIGNUM* g1_x = mod_exp(g1, m_x, n);
        BIGNUM* h1_r1 = mod_exp(h1, regData.r1, n);
        regData.E = mod_mul(g1_x, h1_r1, n);
        BN_free(g1_x);
        BN_free(h1_r1);

        BIGNUM* g2_x = mod_exp(g2, m_x, n);
        BIGNUM* h2_r2 = mod_exp(h2, regData.r2, n);
        regData.F = mod_mul(g2_x, h2_r2, n);
        BN_free(g2_x);
        BN_free(h2_r2);

        regData.u = mod_exp(g1, regData.kesa2, n);
        regData.v = mod_exp(g1, regData.kesa1, n);

        BIGNUM* kesa1_kesa2 = BN_new();
        BN_CTX* ctx = BN_CTX_new();
        BN_mul(kesa1_kesa2, regData.kesa1, regData.kesa2, ctx);
        BN_CTX_free(ctx);
        
        regData.h = mod_exp(g1, kesa1_kesa2, n);
        BN_free(kesa1_kesa2);

        regData.K = generate_random_bn(n);

        m_registeredVehicles[vid] = regData;

        std::vector<uint8_t> responseData;

        std::vector<uint8_t> r1_bytes = bn_to_bytes(regData.r1);
        uint16_t r1_size = r1_bytes.size();
        responseData.push_back(r1_size & 0xFF);
        responseData.push_back((r1_size >> 8) & 0xFF);
        responseData.insert(responseData.end(), r1_bytes.begin(), r1_bytes.end());

        std::vector<uint8_t> r2_bytes = bn_to_bytes(regData.r2);
        uint16_t r2_size = r2_bytes.size();
        responseData.push_back(r2_size & 0xFF);
        responseData.push_back((r2_size >> 8) & 0xFF);
        responseData.insert(responseData.end(), r2_bytes.begin(), r2_bytes.end());

        std::vector<uint8_t> r3_bytes = bn_to_bytes(regData.r3);
        uint16_t r3_size = r3_bytes.size();
        responseData.push_back(r3_size & 0xFF);
        responseData.push_back((r3_size >> 8) & 0xFF);
        responseData.insert(responseData.end(), r3_bytes.begin(), r3_bytes.end());

        std::vector<uint8_t> k_bytes = bn_to_bytes(regData.K);
        uint16_t k_size = k_bytes.size();
        responseData.push_back(k_size & 0xFF);
        responseData.push_back((k_size >> 8) & 0xFF);
        responseData.insert(responseData.end(), k_bytes.begin(), k_bytes.end());

        std::vector<uint8_t> u_bytes = bn_to_bytes(regData.u);
        uint16_t u_size = u_bytes.size();
        responseData.push_back(u_size & 0xFF);
        responseData.push_back((u_size >> 8) & 0xFF);
        responseData.insert(responseData.end(), u_bytes.begin(), u_bytes.end());

        std::vector<uint8_t> v_bytes = bn_to_bytes(regData.v);
        uint16_t v_size = v_bytes.size();
        responseData.push_back(v_size & 0xFF);
        responseData.push_back((v_size >> 8) & 0xFF);
        responseData.insert(responseData.end(), v_bytes.begin(), v_bytes.end());

        std::vector<uint8_t> h_bytes = bn_to_bytes(regData.h);
        uint16_t h_size = h_bytes.size();
        responseData.push_back(h_size & 0xFF);
        responseData.push_back((h_size >> 8) & 0xFF);
        responseData.insert(responseData.end(), h_bytes.begin(), h_bytes.end());

        // Track registration message 2 size
        g_metrics.vehicleMetrics[vid].regMsg2 = responseData.size();

        Ptr<Packet> responsePacket = Create<Packet>(responseData.data(), responseData.size());
        socket->SendTo(responsePacket, 0, from);
    }
}

void ZamaTAApplication::HandleVerificationRequest(Ptr<Socket> socket) {
    Ptr<Packet> packet;
    Address from;

    while ((packet = socket->RecvFrom(from))) {
        uint32_t packetSize = packet->GetSize();
        std::vector<uint8_t> buffer(packetSize);
        packet->CopyData(buffer.data(), packetSize);

        // Extract request ID (first 4 bytes)
        if (buffer.size() < 4) {
            NS_LOG_ERROR("Invalid verification data - missing request ID");
            return;
        }
        
        uint32_t requestId = buffer[0] | (buffer[1] << 8) | (buffer[2] << 16) | (buffer[3] << 24);
        size_t offset = 4;
        
        if (offset + 2 > buffer.size()) {
            NS_LOG_ERROR("Invalid verification data");
            return;
        }
        uint16_t t1_size = buffer[offset] | (buffer[offset + 1] << 8);
        offset += 2;
        if (offset + t1_size > buffer.size()) {
            NS_LOG_ERROR("Invalid T1 size");
            return;
        }
        std::vector<uint8_t> t1_bytes(buffer.begin() + offset, buffer.begin() + offset + t1_size);
        BIGNUM* T1 = bytes_to_bn(t1_bytes);
        offset += t1_size;

        uint16_t t2_size = buffer[offset] | (buffer[offset + 1] << 8);
        offset += 2;
        std::vector<uint8_t> t2_bytes(buffer.begin() + offset, buffer.begin() + offset + t2_size);
        BIGNUM* T2 = bytes_to_bn(t2_bytes);
        offset += t2_size;

        uint16_t t3_size = buffer[offset] | (buffer[offset + 1] << 8);
        offset += 2;
        std::vector<uint8_t> t3_bytes(buffer.begin() + offset, buffer.begin() + offset + t3_size);
        BIGNUM* T3 = bytes_to_bn(t3_bytes);

        bool found = false;
        std::string matchedVID = "";
        BIGNUM* E_match = NULL;
        BIGNUM* F_match = NULL;
        
        for (const auto& entry : m_registeredVehicles) {
            const VehicleRegistrationData& regData = entry.second;

            BIGNUM* T1_kesa1 = mod_exp(T1, regData.kesa1, n);
            BIGNUM* T2_kesa2 = mod_exp(T2, regData.kesa2, n);
            BIGNUM* denominator = mod_mul(T1_kesa1, T2_kesa2, n);

            BIGNUM* denominator_inv = mod_inv(denominator, n);
            BIGNUM* K_computed = mod_mul(T3, denominator_inv, n);

            if (BN_cmp(K_computed, regData.K) == 0) {
                found = true;
                matchedVID = entry.first;
                E_match = BN_dup(regData.E);
                F_match = BN_dup(regData.F);
                
                // NS_LOG_INFO(m_taIdStr << " verified vehicle " << entry.first);

                BN_free(T1_kesa1);
                BN_free(T2_kesa2);
                BN_free(denominator);
                BN_free(denominator_inv);
                BN_free(K_computed);
                break;
            }

            BN_free(T1_kesa1);
            BN_free(T2_kesa2);
            BN_free(denominator);
            BN_free(denominator_inv);
            BN_free(K_computed);
        }

        if (found) {
            // Track authMsg3 (AS->TA request)
            if (g_metrics.vehicleMetrics.find(matchedVID) != g_metrics.vehicleMetrics.end()) {
                g_metrics.vehicleMetrics[matchedVID].authMsg3 = packetSize;
            }

            // Send success with E and F, prepended with request ID
            std::vector<uint8_t> response;
            
            // Add request ID
            response.push_back(requestId & 0xFF);
            response.push_back((requestId >> 8) & 0xFF);
            response.push_back((requestId >> 16) & 0xFF);
            response.push_back((requestId >> 24) & 0xFF);
            
            response.push_back(1); // success flag
            
            std::vector<uint8_t> e_bytes = bn_to_bytes(E_match);
            uint16_t e_size = e_bytes.size();
            response.push_back(e_size & 0xFF);
            response.push_back((e_size >> 8) & 0xFF);
            response.insert(response.end(), e_bytes.begin(), e_bytes.end());
            
            std::vector<uint8_t> f_bytes = bn_to_bytes(F_match);
            uint16_t f_size = f_bytes.size();
            response.push_back(f_size & 0xFF);
            response.push_back((f_size >> 8) & 0xFF);
            response.insert(response.end(), f_bytes.begin(), f_bytes.end());
            
            // Track authMsg4 (TA->AS response)
            if (g_metrics.vehicleMetrics.find(matchedVID) != g_metrics.vehicleMetrics.end()) {
                g_metrics.vehicleMetrics[matchedVID].authMsg4 = response.size();
            }

            Ptr<Packet> responsePacket = Create<Packet>(response.data(), response.size());
            socket->SendTo(responsePacket, 0, from);
            
            BN_free(E_match);
            BN_free(F_match);
        } else {
            NS_LOG_ERROR(m_taIdStr << " could not verify vehicle");
            std::vector<uint8_t> response;
            
            // Add request ID
            response.push_back(requestId & 0xFF);
            response.push_back((requestId >> 8) & 0xFF);
            response.push_back((requestId >> 16) & 0xFF);
            response.push_back((requestId >> 24) & 0xFF);
            
            response.push_back(0); // failure flag
            Ptr<Packet> responsePacket = Create<Packet>(response.data(), response.size());
            socket->SendTo(responsePacket, 0, from);
        }

        BN_free(T1);
        BN_free(T2);
        BN_free(T3);
    }
}

class ZamaVehicleApplication : public Application {
public:
    ZamaVehicleApplication();
    virtual ~ZamaVehicleApplication();

    void Setup(Ipv4Address taAddr, uint16_t regPort, uint16_t authPort, std::string taId, std::string vid);
    void SetVehicleId(std::string vid) { m_vehicleId = vid; }
    void SetTAAddress(Address addr) { m_taAddress = addr; }
    void SetASAddress(Address addr) { m_asAddress = addr; }
    void SetASPublicKey(EVP_PKEY* pubKey) { m_asPublicKey = pubKey; }

private:
    virtual void StartApplication(void);
    virtual void StopApplication(void);

    void SendRegistrationRequest();
    void HandleRegistrationResponse(Ptr<Socket> socket);
    void StartAuthentication();
    void SendAuthenticationRequest(BIGNUM* Nd);
    void HandleAuthResponse(Ptr<Socket> socket);

    std::string m_vehicleId;
    std::string m_taId;
    uint16_t m_regPort;
    uint16_t m_authPort;
    Ptr<Socket> m_regSocket;
    Ptr<Socket> m_authSocket;
    Address m_taAddress;
    Address m_asAddress;
    VehicleState m_state;
    bool m_registered;
    BIGNUM *m_Ks;
    EVP_PKEY *m_asPublicKey;
};

ZamaVehicleApplication::ZamaVehicleApplication()
    : m_registered(false), m_regPort(0), m_authPort(0), m_Ks(NULL), m_asPublicKey(NULL) {
    m_state.r1 = NULL;
    m_state.r2 = NULL;
    m_state.r3 = NULL;
    m_state.u = NULL;
    m_state.v = NULL;
    m_state.h = NULL;
    m_state.omega = NULL;
    m_state.q1 = NULL;
    m_state.q2 = NULL;
    m_state.w1 = NULL;
    m_state.w2 = NULL;
    m_state.K = NULL;
}

void ZamaVehicleApplication::Setup(Ipv4Address taAddr, uint16_t regPort, uint16_t authPort, std::string taId, std::string vid) {
    m_vehicleId = vid;
    m_taId = taId;
    m_regPort = regPort;
    m_authPort = authPort;
    m_taAddress = InetSocketAddress(taAddr, regPort);
    m_asAddress = InetSocketAddress(taAddr, authPort);
}

ZamaVehicleApplication::~ZamaVehicleApplication() {
    if (m_Ks) BN_free(m_Ks);
    if (m_state.r1) BN_free(m_state.r1);
    if (m_state.r2) BN_free(m_state.r2);
    if (m_state.r3) BN_free(m_state.r3);
    if (m_state.u) BN_free(m_state.u);
    if (m_state.v) BN_free(m_state.v);
    if (m_state.h) BN_free(m_state.h);
    if (m_state.omega) BN_free(m_state.omega);
    if (m_state.q1) BN_free(m_state.q1);
    if (m_state.q2) BN_free(m_state.q2);
    if (m_state.w1) BN_free(m_state.w1);
    if (m_state.w2) BN_free(m_state.w2);
    if (m_state.K) BN_free(m_state.K);
}

void ZamaVehicleApplication::StartApplication(void) {
    m_regSocket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    m_regSocket->Bind(InetSocketAddress(Ipv4Address::GetAny(), 0));
    m_regSocket->SetRecvCallback(MakeCallback(&ZamaVehicleApplication::HandleRegistrationResponse, this));

    m_authSocket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    m_authSocket->Bind(InetSocketAddress(Ipv4Address::GetAny(), 0));
    
    // Combined callback for both challenge and response
    m_authSocket->SetRecvCallback(MakeCallback(&ZamaVehicleApplication::HandleAuthResponse, this));

    SendRegistrationRequest();
}

void ZamaVehicleApplication::StopApplication(void) {
    if (m_regSocket) {
        m_regSocket->Close();
    }
    if (m_authSocket) {
        m_authSocket->Close();
    }
}

void ZamaVehicleApplication::SendRegistrationRequest() {
    std::string vid_str = m_vehicleId;
    Ptr<Packet> packet = Create<Packet>((uint8_t*)vid_str.c_str(), vid_str.size());
    m_regSocket->SendTo(packet, 0, m_taAddress);

    // NS_LOG_INFO("Vehicle " << m_vehicleId << " sent registration request to TA");
}

void ZamaVehicleApplication::HandleRegistrationResponse(Ptr<Socket> socket) {
    Ptr<Packet> packet;
    Address from;

    while ((packet = socket->RecvFrom(from))) {
        uint32_t packetSize = packet->GetSize();
        std::vector<uint8_t> buffer(packetSize);
        packet->CopyData(buffer.data(), packetSize);

        size_t offset = 0;

        uint16_t r1_size = buffer[offset] | (buffer[offset + 1] << 8);
        offset += 2;
        std::vector<uint8_t> r1_bytes(buffer.begin() + offset, buffer.begin() + offset + r1_size);
        m_state.r1 = bytes_to_bn(r1_bytes);
        offset += r1_size;

        uint16_t r2_size = buffer[offset] | (buffer[offset + 1] << 8);
        offset += 2;
        std::vector<uint8_t> r2_bytes(buffer.begin() + offset, buffer.begin() + offset + r2_size);
        m_state.r2 = bytes_to_bn(r2_bytes);
        offset += r2_size;

        uint16_t r3_size = buffer[offset] | (buffer[offset + 1] << 8);
        offset += 2;
        std::vector<uint8_t> r3_bytes(buffer.begin() + offset, buffer.begin() + offset + r3_size);
        m_state.r3 = bytes_to_bn(r3_bytes);
        offset += r3_size;

        uint16_t k_size = buffer[offset] | (buffer[offset + 1] << 8);
        offset += 2;
        std::vector<uint8_t> k_bytes(buffer.begin() + offset, buffer.begin() + offset + k_size);
        m_state.K = bytes_to_bn(k_bytes);
        offset += k_size;

        uint16_t u_size = buffer[offset] | (buffer[offset + 1] << 8);
        offset += 2;
        std::vector<uint8_t> u_bytes(buffer.begin() + offset, buffer.begin() + offset + u_size);
        m_state.u = bytes_to_bn(u_bytes);
        offset += u_size;

        uint16_t v_size = buffer[offset] | (buffer[offset + 1] << 8);
        offset += 2;
        std::vector<uint8_t> v_bytes(buffer.begin() + offset, buffer.begin() + offset + v_size);
        m_state.v = bytes_to_bn(v_bytes);
        offset += v_size;

        uint16_t h_size = buffer[offset] | (buffer[offset + 1] << 8);
        offset += 2;
        std::vector<uint8_t> h_bytes(buffer.begin() + offset, buffer.begin() + offset + h_size);
        m_state.h = bytes_to_bn(h_bytes);

        m_state.vid = m_vehicleId;

        m_state.omega = generate_random_bn(n);
        m_state.q1 = generate_random_bn(n);
        m_state.q2 = generate_random_bn(n);

        BIGNUM* g1_omega = mod_exp(g1, m_state.omega, n);
        BIGNUM* h1_q1 = mod_exp(h1, m_state.q1, n);
        m_state.w1 = mod_mul(g1_omega, h1_q1, n);
        BN_free(g1_omega);
        BN_free(h1_q1);

        BIGNUM* g2_omega = mod_exp(g2, m_state.omega, n);
        BIGNUM* h2_q2 = mod_exp(h2, m_state.q2, n);
        m_state.w2 = mod_mul(g2_omega, h2_q2, n);
        BN_free(g2_omega);
        BN_free(h2_q2);

        m_registered = true;
        // NS_LOG_INFO("Vehicle " << m_vehicleId << " registration complete");
        
        StartAuthentication();
    }
}

void ZamaVehicleApplication::StartAuthentication() {
    if (!m_registered) {
        NS_LOG_ERROR("Cannot authenticate: not registered");
        return;
    }

    m_Ks = generate_random_bn(n);

    // NS_LOG_INFO("Vehicle " << m_vehicleId << " initiating authentication with AS");
    
    // Send an initial packet to AS to trigger challenge
    // This can be a simple "hello" or empty packet to let AS know we're ready
    std::string hello = "AUTH_REQUEST";
    Ptr<Packet> helloPacket = Create<Packet>((uint8_t*)hello.c_str(), hello.size());
    m_authSocket->SendTo(helloPacket, 0, m_asAddress);
}

void ZamaVehicleApplication::HandleAuthResponse(Ptr<Socket> socket) {
    Ptr<Packet> packet;
    Address from;

    while ((packet = socket->RecvFrom(from))) {
        uint32_t packetSize = packet->GetSize();
        std::vector<uint8_t> buffer(packetSize);
        packet->CopyData(buffer.data(), packetSize);

        // Check if this is a challenge (has 2-byte size prefix) or final response
        if (packetSize > 2 && buffer.size() >= 2) {
            uint16_t nd_size = buffer[0] | (buffer[1] << 8);
            
            // If nd_size + 2 equals packetSize, it's a challenge
            if (nd_size + 2 == packetSize) {
                // This is a challenge with Nd
                std::vector<uint8_t> nd_bytes(buffer.begin() + 2, buffer.begin() + 2 + nd_size);
                BIGNUM* Nd = bytes_to_bn(nd_bytes);
                SendAuthenticationRequest(Nd);
                BN_free(Nd);
                return;
            }
        }
        
        std::string response = aes_decrypt(buffer, m_Ks);
        
        if (response.empty()) {
            NS_LOG_ERROR("Vehicle " << m_vehicleId << " failed to decrypt AS response");
            return;
        }
        
        // Track authMsg2 size and end time
        g_metrics.vehicleMetrics[m_vehicleId].authMsg2 = packetSize;
        double endTime = Simulator::Now().GetSeconds();
        g_metrics.vehicleMetrics[m_vehicleId].authEndTime = endTime;
        
        if (response == "success") {
            double authDelay = endTime - g_metrics.vehicleMetrics[m_vehicleId].authStartTime;
            g_metrics.authDelays.push_back(authDelay);
            
            if (endTime > g_metrics.lastAuthEnd) {
                g_metrics.lastAuthEnd = endTime;
            }
            
            g_metrics.authSuccess++;
            // NS_LOG_INFO("Vehicle " << m_vehicleId << " authentication SUCCESS (delay: "
                        // << std::fixed << std::setprecision(3) << authDelay * 1000 << " ms)");
        } else {
            NS_LOG_ERROR("Vehicle " << m_vehicleId << " authentication FAILED");
        }
    }
}


void ZamaVehicleApplication::SendAuthenticationRequest(BIGNUM* Nd) {
    // Track authentication start time
    if (g_metrics.vehicleMetrics[m_vehicleId].authStartTime == 0) {
        g_metrics.vehicleMetrics[m_vehicleId].authStartTime = Simulator::Now().GetSeconds();
        if (Simulator::Now().GetSeconds() < g_metrics.firstAuthStart) {
            g_metrics.firstAuthStart = Simulator::Now().GetSeconds();
        }
    }
    g_metrics.authAttempts++;

    std::vector<uint8_t> w1_bytes = bn_to_bytes(m_state.w1);
    std::vector<uint8_t> w2_bytes = bn_to_bytes(m_state.w2);
    std::vector<uint8_t> nd_bytes = bn_to_bytes(Nd);

    std::vector<uint8_t> hash_input;
    hash_input.insert(hash_input.end(), w1_bytes.begin(), w1_bytes.end());
    hash_input.insert(hash_input.end(), w2_bytes.begin(), w2_bytes.end());
    hash_input.insert(hash_input.end(), nd_bytes.begin(), nd_bytes.end());

    std::vector<uint8_t> hash = sha256_hash(hash_input);
    BIGNUM* C = BN_bin2bn(hash.data(), hash.size(), NULL);

    // BIGNUM* c_r3 = mod_mul(C, m_state.r3, n);
    BIGNUM* c_r3 = BN_new();
    BN_CTX* ctx1 = BN_CTX_new();
    BN_mul(c_r3, C, m_state.r3, ctx1);
    BN_CTX_free(ctx1);

    BIGNUM* D = BN_new();
    BN_add(D, m_state.omega, c_r3);
    BN_free(c_r3);

    BIGNUM* c_r1 = BN_new();
    BN_CTX* ctx2 = BN_CTX_new();
    BN_mul(c_r1, C, m_state.r1, ctx2);
    BN_CTX_free(ctx2);

    BIGNUM* D1 = BN_new();
    BN_add(D1, m_state.q1, c_r1);
    BN_free(c_r1);

    BIGNUM* c_r2 = BN_new();
    BN_CTX* ctx3 = BN_CTX_new();
    BN_mul(c_r2, C, m_state.r2, ctx3);
    BN_CTX_free(ctx3);

    BIGNUM* D2 = BN_new();
    BN_add(D2, m_state.q2, c_r2);
    BN_free(c_r2);

    BIGNUM* alpha = generate_random_bn(n);
    BIGNUM* beta = generate_random_bn(n);

    BIGNUM* T1 = mod_exp(m_state.u, alpha, n);
    BIGNUM* T2 = mod_exp(m_state.v, beta, n);

    BIGNUM* alpha_beta = BN_new();
    BN_add(alpha_beta, alpha, beta);
    BIGNUM* h_alpha_beta = mod_exp(m_state.h, alpha_beta, n);
    BIGNUM* T3 = mod_mul(m_state.K, h_alpha_beta, n);
    BN_free(alpha_beta);
    BN_free(h_alpha_beta);
    BN_free(alpha);
    BN_free(beta);

    std::vector<uint8_t> ks_bytes = bn_to_bytes(m_Ks);
    std::vector<uint8_t> c_bytes = bn_to_bytes(C);
    std::vector<uint8_t> d_bytes = bn_to_bytes(D);
    std::vector<uint8_t> d1_bytes = bn_to_bytes(D1);
    std::vector<uint8_t> d2_bytes = bn_to_bytes(D2);
    std::vector<uint8_t> t1_bytes = bn_to_bytes(T1);
    std::vector<uint8_t> t2_bytes = bn_to_bytes(T2);
    std::vector<uint8_t> t3_bytes = bn_to_bytes(T3);

    std::vector<uint8_t> plaintext;
    
    uint16_t ks_size = ks_bytes.size();
    plaintext.push_back(ks_size & 0xFF);
    plaintext.push_back((ks_size >> 8) & 0xFF);
    plaintext.insert(plaintext.end(), ks_bytes.begin(), ks_bytes.end());

    uint16_t c_size = c_bytes.size();
    plaintext.push_back(c_size & 0xFF);
    plaintext.push_back((c_size >> 8) & 0xFF);
    plaintext.insert(plaintext.end(), c_bytes.begin(), c_bytes.end());

    uint16_t d_size = d_bytes.size();
    plaintext.push_back(d_size & 0xFF);
    plaintext.push_back((d_size >> 8) & 0xFF);
    plaintext.insert(plaintext.end(), d_bytes.begin(), d_bytes.end());

    uint16_t d1_size = d1_bytes.size();
    plaintext.push_back(d1_size & 0xFF);
    plaintext.push_back((d1_size >> 8) & 0xFF);
    plaintext.insert(plaintext.end(), d1_bytes.begin(), d1_bytes.end());

    uint16_t d2_size = d2_bytes.size();
    plaintext.push_back(d2_size & 0xFF);
    plaintext.push_back((d2_size >> 8) & 0xFF);
    plaintext.insert(plaintext.end(), d2_bytes.begin(), d2_bytes.end());

    uint16_t t1_size = t1_bytes.size();
    plaintext.push_back(t1_size & 0xFF);
    plaintext.push_back((t1_size >> 8) & 0xFF);
    plaintext.insert(plaintext.end(), t1_bytes.begin(), t1_bytes.end());

    uint16_t t2_size = t2_bytes.size();
    plaintext.push_back(t2_size & 0xFF);
    plaintext.push_back((t2_size >> 8) & 0xFF);
    plaintext.insert(plaintext.end(), t2_bytes.begin(), t2_bytes.end());

    uint16_t t3_size = t3_bytes.size();
    plaintext.push_back(t3_size & 0xFF);
    plaintext.push_back((t3_size >> 8) & 0xFF);
    plaintext.insert(plaintext.end(), t3_bytes.begin(), t3_bytes.end());

    // Encrypt with AS public key
    std::vector<uint8_t> encrypted = rsa_encrypt(plaintext, m_asPublicKey);
    
    // Track authMsg1 size (encrypted message)
    g_metrics.vehicleMetrics[m_vehicleId].authMsg1 = encrypted.size();
    
    Ptr<Packet> authPacket = Create<Packet>(encrypted.data(), encrypted.size());
    m_authSocket->SendTo(authPacket, 0, m_asAddress);

    BN_free(C);
    BN_free(D);
    BN_free(D1);
    BN_free(D2);
    BN_free(T1);
    BN_free(T2);
    BN_free(T3);

    // NS_LOG_INFO("Vehicle " << m_vehicleId << " sent authentication request to AS");
}

class ZamaASApplication : public Application {
public:
    ZamaASApplication();
    virtual ~ZamaASApplication();

    void Setup(uint16_t authPort, uint16_t taPort, std::string asId);
    void SetASId(uint32_t id) { m_asId = id; }
    void SetTAAddress(Address addr) { m_taAddress = addr; }
    EVP_PKEY* GetPublicKey() { return m_privateKey; }

private:
    virtual void StartApplication(void);
    virtual void StopApplication(void);

    void HandleAuthRequest(Ptr<Socket> socket);
    void SendAuthChallenge(const Address& vehicleAddr);
    void HandleTAResponse(Ptr<Socket> socket);
    void VerifyWithTA(BIGNUM* T1, BIGNUM* T2, BIGNUM* T3,
                      BIGNUM* C, BIGNUM* D, BIGNUM* D1, BIGNUM* D2,
                      BIGNUM* Nd, BIGNUM* Ks, const Address& vehicleAddr);

    struct PendingVerification {
        Address vehicleAddr;
        std::vector<BIGNUM*> data;  // C, D, D1, D2, Nd, Ks
        BIGNUM* T1;
        BIGNUM* T2;
        BIGNUM* T3;
    };
    std::map<uint32_t, PendingVerification> m_pendingVerificationsByRequestId;
    uint32_t m_nextRequestId = 0;
    std::map<Address, uint32_t> m_addressToRequestId; 

    uint32_t m_asId;
    std::string m_asIdStr;
    uint16_t m_authPort;
    uint16_t m_taPort;
    Ptr<Socket> m_socket;
    Ptr<Socket> m_taSocket;
    Address m_taAddress;
    EVP_PKEY *m_privateKey;
    std::map<Address, BIGNUM*> m_addressToChallengeMap;
    std::map<Address, std::vector<BIGNUM*>> m_pendingVerifications;
};

ZamaASApplication::ZamaASApplication() : m_asId(0), m_authPort(0), m_taPort(0), m_privateKey(NULL) {
    m_privateKey = generate_rsa_key(2048);
}

void ZamaASApplication::Setup(uint16_t authPort, uint16_t taPort, std::string asId) {
    m_authPort = authPort;
    m_taPort = taPort;
    m_asIdStr = asId;
}

ZamaASApplication::~ZamaASApplication() {
    if (m_privateKey) EVP_PKEY_free(m_privateKey);
    for (auto& pair : m_addressToChallengeMap) {
        if (pair.second) BN_free(pair.second);
    }
    for (auto& pair : m_pendingVerifications) {
        for (auto bn : pair.second) {
            if (bn) BN_free(bn);
        }
    }
}

void ZamaASApplication::StartApplication(void) {
    m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    m_socket->Bind(InetSocketAddress(Ipv4Address::GetAny(), m_authPort));
    m_socket->SetRecvCallback(MakeCallback(&ZamaASApplication::HandleAuthRequest, this));

    m_taSocket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    m_taSocket->Bind(InetSocketAddress(Ipv4Address::GetAny(), 0));
    m_taSocket->SetRecvCallback(MakeCallback(&ZamaASApplication::HandleTAResponse, this));
}

void ZamaASApplication::StopApplication(void) {
    if (m_socket) {
        m_socket->Close();
    }
    if (m_taSocket) {
        m_taSocket->Close();
    }
}

void ZamaASApplication::HandleAuthRequest(Ptr<Socket> socket) {
    Ptr<Packet> packet;
    Address from;

    while ((packet = socket->RecvFrom(from))) {
        uint32_t packetSize = packet->GetSize();
        std::vector<uint8_t> buffer(packetSize);
        packet->CopyData(buffer.data(), packetSize);

        // Check if this is initial auth request (small text message)
        if (m_addressToChallengeMap.find(from) == m_addressToChallengeMap.end()) {
            // First contact - check if it's an initial request
            if (packetSize < 20) {  // Small packet = initial request
                std::string msg((char*)buffer.data(), packetSize);
                // NS_LOG_INFO(m_asIdStr << " received initial auth request from vehicle");
            }
            SendAuthChallenge(from);
            return;
        }

        // Check if this is still a small packet (could be retransmitted initial request)
        if (packetSize < 20) {
            NS_LOG_WARN(m_asIdStr << " received duplicate initial request, resending challenge");
            SendAuthChallenge(from);
            return;
        }

        // This should be the encrypted authentication data
        // NS_LOG_INFO(m_asIdStr << " received encrypted authentication data (" << packetSize << " bytes)");

        // Decrypt with AS private key
        std::vector<uint8_t> decrypted = rsa_decrypt(buffer, m_privateKey);
        buffer = decrypted;

        size_t offset = 0;
        
        if (offset + 2 > buffer.size()) {
            NS_LOG_ERROR("Invalid authentication data format");
            return;
        }
        uint16_t ks_size = buffer[offset] | (buffer[offset + 1] << 8);
        offset += 2;
        if (offset + ks_size > buffer.size()) {
            NS_LOG_ERROR("Invalid Ks size");
            return;
        }
        std::vector<uint8_t> ks_bytes(buffer.begin() + offset, buffer.begin() + offset + ks_size);
        BIGNUM* Ks = bytes_to_bn(ks_bytes);
        offset += ks_size;

        uint16_t c_size = buffer[offset] | (buffer[offset + 1] << 8);
        offset += 2;
        std::vector<uint8_t> c_bytes(buffer.begin() + offset, buffer.begin() + offset + c_size);
        BIGNUM* C = bytes_to_bn(c_bytes);
        offset += c_size;

        uint16_t d_size = buffer[offset] | (buffer[offset + 1] << 8);
        offset += 2;
        std::vector<uint8_t> d_bytes(buffer.begin() + offset, buffer.begin() + offset + d_size);
        BIGNUM* D = bytes_to_bn(d_bytes);
        offset += d_size;

        uint16_t d1_size = buffer[offset] | (buffer[offset + 1] << 8);
        offset += 2;
        std::vector<uint8_t> d1_bytes(buffer.begin() + offset, buffer.begin() + offset + d1_size);
        BIGNUM* D1 = bytes_to_bn(d1_bytes);
        offset += d1_size;

        uint16_t d2_size = buffer[offset] | (buffer[offset + 1] << 8);
        offset += 2;
        std::vector<uint8_t> d2_bytes(buffer.begin() + offset, buffer.begin() + offset + d2_size);
        BIGNUM* D2 = bytes_to_bn(d2_bytes);
        offset += d2_size;

        uint16_t t1_size = buffer[offset] | (buffer[offset + 1] << 8);
        offset += 2;
        std::vector<uint8_t> t1_bytes(buffer.begin() + offset, buffer.begin() + offset + t1_size);
        BIGNUM* T1 = bytes_to_bn(t1_bytes);
        offset += t1_size;

        uint16_t t2_size = buffer[offset] | (buffer[offset + 1] << 8);
        offset += 2;
        std::vector<uint8_t> t2_bytes(buffer.begin() + offset, buffer.begin() + offset + t2_size);
        BIGNUM* T2 = bytes_to_bn(t2_bytes);
        offset += t2_size;

        uint16_t t3_size = buffer[offset] | (buffer[offset + 1] << 8);
        offset += 2;
        std::vector<uint8_t> t3_bytes(buffer.begin() + offset, buffer.begin() + offset + t3_size);
        BIGNUM* T3 = bytes_to_bn(t3_bytes);

        BIGNUM* Nd = NULL;
        if (m_addressToChallengeMap.find(from) != m_addressToChallengeMap.end()) {
            Nd = m_addressToChallengeMap[from];
        } else {
            NS_LOG_ERROR("No challenge found for this address");
            BN_free(Ks); BN_free(C); BN_free(D); BN_free(D1); BN_free(D2);
            BN_free(T1); BN_free(T2); BN_free(T3);
            return;
        }

        // Store pending verification data
        std::vector<BIGNUM*> pendingData;
        pendingData.push_back(BN_dup(C));
        pendingData.push_back(BN_dup(D));
        pendingData.push_back(BN_dup(D1));
        pendingData.push_back(BN_dup(D2));
        pendingData.push_back(BN_dup(Nd));
        pendingData.push_back(BN_dup(Ks));
        m_pendingVerifications[from] = pendingData;

        VerifyWithTA(T1, T2, T3, C, D, D1, D2, Nd, Ks, from);

        BN_free(Ks);
        BN_free(C);
        BN_free(D);
        BN_free(D1);
        BN_free(D2);
        BN_free(T1);
        BN_free(T2);
        BN_free(T3);
    }
}

void ZamaASApplication::SendAuthChallenge(const Address& vehicleAddr) {
    BIGNUM* Nd = generate_random_bn(n);

    m_addressToChallengeMap[vehicleAddr] = Nd;

    std::vector<uint8_t> nd_bytes = bn_to_bytes(Nd);
    uint16_t nd_size = nd_bytes.size();
    std::vector<uint8_t> challengeData;
    challengeData.push_back(nd_size & 0xFF);
    challengeData.push_back((nd_size >> 8) & 0xFF);
    challengeData.insert(challengeData.end(), nd_bytes.begin(), nd_bytes.end());

    Ptr<Packet> challengePacket = Create<Packet>(challengeData.data(), challengeData.size());
    m_socket->SendTo(challengePacket, 0, vehicleAddr);

    // NS_LOG_INFO(m_asIdStr << " sent authentication challenge");
}

void ZamaASApplication::HandleTAResponse(Ptr<Socket> socket) {
    Ptr<Packet> packet;
    Address from;

    while ((packet = socket->RecvFrom(from))) {
        uint32_t packetSize = packet->GetSize();
        std::vector<uint8_t> buffer(packetSize);
        packet->CopyData(buffer.data(), packetSize);

        if (buffer.size() < 5) {  // Need at least: 4 bytes requestId + 1 byte success flag
            NS_LOG_ERROR("Invalid TA response size");
            return;
        }
        
        // Extract request ID
        uint32_t requestId = buffer[0] | (buffer[1] << 8) | (buffer[2] << 16) | (buffer[3] << 24);
        uint8_t success = buffer[4];
        
        if (success != 1) {
            NS_LOG_ERROR("TA verification failed for RequestID: " << requestId);
            
            // Clean up pending verification
            if (m_pendingVerificationsByRequestId.find(requestId) != m_pendingVerificationsByRequestId.end()) {
                PendingVerification& pending = m_pendingVerificationsByRequestId[requestId];
                
                // Send failure to vehicle
                std::vector<uint8_t> encrypted = aes_encrypt("failure", pending.data[5]); // Ks is at index 5
                Ptr<Packet> responsePacket = Create<Packet>(encrypted.data(), encrypted.size());
                m_socket->SendTo(responsePacket, 0, pending.vehicleAddr);
                
                // Clean up
                BN_free(pending.T1);
                BN_free(pending.T2);
                BN_free(pending.T3);
                for (auto bn : pending.data) BN_free(bn);
                m_pendingVerificationsByRequestId.erase(requestId);
            }
            return;
        }

        // Parse E and F from TA response
        size_t offset = 5;
        
        uint16_t e_size = buffer[offset] | (buffer[offset + 1] << 8);
        offset += 2;
        std::vector<uint8_t> e_bytes(buffer.begin() + offset, buffer.begin() + offset + e_size);
        BIGNUM* E = bytes_to_bn(e_bytes);
        offset += e_size;
        
        uint16_t f_size = buffer[offset] | (buffer[offset + 1] << 8);
        offset += 2;
        std::vector<uint8_t> f_bytes(buffer.begin() + offset, buffer.begin() + offset + f_size);
        BIGNUM* F = bytes_to_bn(f_bytes);

        // FIX: Find the correct pending verification using request ID
        if (m_pendingVerificationsByRequestId.find(requestId) == m_pendingVerificationsByRequestId.end()) {
            NS_LOG_ERROR("No pending verification found for RequestID: " << requestId);
            BN_free(E);
            BN_free(F);
            return;
        }
        
        PendingVerification& pending = m_pendingVerificationsByRequestId[requestId];
        Address vehicleAddr = pending.vehicleAddr;
        std::vector<BIGNUM*>& pendingData = pending.data;
        
        BIGNUM* C = pendingData[0];
        BIGNUM* D = pendingData[1];
        BIGNUM* D1 = pendingData[2];
        BIGNUM* D2 = pendingData[3];
        BIGNUM* Nd = pendingData[4];
        BIGNUM* Ks = pendingData[5];


        // Correct computation of E^(-C) and F^(-C)
        BIGNUM* E_inv = mod_inv(E, n);
        BIGNUM* E_neg_C = mod_exp(E_inv, C, n);  // (E^-1)^C = E^(-C)
        BN_free(E_inv);

        BIGNUM* g1_D = mod_exp(g1, D, n);
        BIGNUM* h1_D1 = mod_exp(h1, D1, n);
        BIGNUM* w1_computed = mod_mul(mod_mul(g1_D, h1_D1, n), E_neg_C, n);

        BIGNUM* F_inv = mod_inv(F, n);
        BIGNUM* F_neg_C = mod_exp(F_inv, C, n);  // (F^-1)^C = F^(-C)
        BN_free(F_inv);

        BIGNUM* g2_D = mod_exp(g2, D, n);
        BIGNUM* h2_D2 = mod_exp(h2, D2, n);
        BIGNUM* w2_computed = mod_mul(mod_mul(g2_D, h2_D2, n), F_neg_C, n);

        std::vector<uint8_t> hash_input;
        std::vector<uint8_t> w1_comp_bytes = bn_to_bytes(w1_computed);
        std::vector<uint8_t> w2_comp_bytes = bn_to_bytes(w2_computed);
        std::vector<uint8_t> nd_bytes = bn_to_bytes(Nd);
        
        hash_input.insert(hash_input.end(), w1_comp_bytes.begin(), w1_comp_bytes.end());
        hash_input.insert(hash_input.end(), w2_comp_bytes.begin(), w2_comp_bytes.end());
        hash_input.insert(hash_input.end(), nd_bytes.begin(), nd_bytes.end());
        
        std::vector<uint8_t> hash_result = sha256_hash(hash_input);
        BIGNUM* C_computed = bytes_to_bn(hash_result);
        
        bool verificationSuccess = (BN_cmp(C, C_computed) == 0);

        // FIX: Encrypt response with session key Ks
        if (verificationSuccess) {
            std::vector<uint8_t> encrypted = aes_encrypt("success", Ks);
            Ptr<Packet> responsePacket = Create<Packet>(encrypted.data(), encrypted.size());
            m_socket->SendTo(responsePacket, 0, vehicleAddr);

            // NS_LOG_INFO(m_asIdStr << " sent encrypted authentication SUCCESS to vehicle");
        } else {
            std::vector<uint8_t> encrypted = aes_encrypt("failure", Ks);
            Ptr<Packet> responsePacket = Create<Packet>(encrypted.data(), encrypted.size());
            m_socket->SendTo(responsePacket, 0, vehicleAddr);

            NS_LOG_ERROR(m_asIdStr << " authentication FAILED for vehicle");
        }

        // Clean up
        BN_free(g1_D);
        BN_free(h1_D1);
        BN_free(g2_D);
        BN_free(h2_D2);
        // BN_free(E_C);
        BN_free(E_neg_C);
        BN_free(F_neg_C);
        BN_free(w1_computed);
        BN_free(w2_computed);
        BN_free(C_computed);
        // BN_free(C_inv);
        BN_free(E);
        BN_free(F);
        BN_free(pending.T1);
        BN_free(pending.T2);
        BN_free(pending.T3);
        
        for (auto bn : pendingData) {
            BN_free(bn);
        }

        m_pendingVerificationsByRequestId.erase(requestId);
        m_addressToChallengeMap.erase(vehicleAddr);
        m_addressToRequestId.erase(vehicleAddr);
    }
}

void ZamaASApplication::VerifyWithTA(BIGNUM* T1, BIGNUM* T2, BIGNUM* T3,
                                      BIGNUM* C, BIGNUM* D, BIGNUM* D1, BIGNUM* D2,
                                      BIGNUM* Nd, BIGNUM* Ks, const Address& vehicleAddr) {
    // Generate unique request ID
    uint32_t requestId = m_nextRequestId++;
    
    // Store pending verification with proper structure
    PendingVerification pending;
    pending.vehicleAddr = vehicleAddr;
    pending.T1 = BN_dup(T1);
    pending.T2 = BN_dup(T2);
    pending.T3 = BN_dup(T3);
    
    std::vector<BIGNUM*> pendingData;
    pendingData.push_back(BN_dup(C));
    pendingData.push_back(BN_dup(D));
    pendingData.push_back(BN_dup(D1));
    pendingData.push_back(BN_dup(D2));
    pendingData.push_back(BN_dup(Nd));
    pendingData.push_back(BN_dup(Ks));
    pending.data = pendingData;
    
    m_pendingVerificationsByRequestId[requestId] = pending;
    m_addressToRequestId[vehicleAddr] = requestId;
    
    // Prepare data for TA
    std::vector<uint8_t> t1_bytes = bn_to_bytes(T1);
    std::vector<uint8_t> t2_bytes = bn_to_bytes(T2);
    std::vector<uint8_t> t3_bytes = bn_to_bytes(T3);
    std::vector<uint8_t> taData;
    
    // Add request ID as first 4 bytes
    taData.push_back(requestId & 0xFF);
    taData.push_back((requestId >> 8) & 0xFF);
    taData.push_back((requestId >> 16) & 0xFF);
    taData.push_back((requestId >> 24) & 0xFF);
    
    uint16_t t1_size = t1_bytes.size();
    taData.push_back(t1_size & 0xFF);
    taData.push_back((t1_size >> 8) & 0xFF);
    taData.insert(taData.end(), t1_bytes.begin(), t1_bytes.end());

    uint16_t t2_size = t2_bytes.size();
    taData.push_back(t2_size & 0xFF);
    taData.push_back((t2_size >> 8) & 0xFF);
    taData.insert(taData.end(), t2_bytes.begin(), t2_bytes.end());

    uint16_t t3_size = t3_bytes.size();
    taData.push_back(t3_size & 0xFF);
    taData.push_back((t3_size >> 8) & 0xFF);
    taData.insert(taData.end(), t3_bytes.begin(), t3_bytes.end());

    Ptr<Packet> taPacket = Create<Packet>(taData.data(), taData.size());
    m_taSocket->SendTo(taPacket, 0, m_taAddress);
    
    // NS_LOG_INFO(m_asIdStr << " sent T1,T2,T3 to TA for verification (RequestID: " << requestId << ")");
}

uint32_t CalculateRequiredTAs(double areaWidth, double areaHeight, double txPower)
{
    double effectiveRange;
    if (txPower <= 33) effectiveRange = 350.0;
    else if (txPower <= 37) effectiveRange = 450.0;
    else effectiveRange = 550.0;

    double overlapFactor = 0.7;
    double effectiveCoverage = effectiveRange * overlapFactor;

    uint32_t nRows = std::ceil(areaHeight / effectiveCoverage);
    uint32_t nCols = std::ceil(areaWidth / effectiveCoverage);

    NS_LOG_INFO("Coverage analysis:");
    NS_LOG_INFO("  Effective range: " << effectiveRange << "m");
    NS_LOG_INFO("  Grid: " << nRows << " rows × " << nCols << " cols");
    NS_LOG_INFO("  Recommended TAs: " << (nRows * nCols));

    return nRows * nCols;
}

void DistributeTAsInGrid(NodeContainer& taNodes,
                          double minX, double maxX,
                          double minY, double maxY,
                          MobilityHelper& taMobility)
{
    uint32_t nTAs = taNodes.GetN();

    uint32_t nCols = std::ceil(std::sqrt(nTAs * (maxX - minX) / (maxY - minY)));
    uint32_t nRows = std::ceil((double)nTAs / nCols);

    double xSpacing = (maxX - minX) / (nCols + 1);
    double ySpacing = (maxY - minY) / (nRows + 1);

    Ptr<ListPositionAllocator> taPositionAlloc = CreateObject<ListPositionAllocator>();

    uint32_t taIndex = 0;
    for (uint32_t row = 0; row < nRows && taIndex < nTAs; ++row)
    {
        for (uint32_t col = 0; col < nCols && taIndex < nTAs; ++col)
        {
            double x = minX + xSpacing * (col + 1);
            double y = minY + ySpacing * (row + 1);
            taPositionAlloc->Add(Vector(x, y, 0.0));
            // NS_LOG_INFO("TA " << taIndex << " positioned at (" << x << ", " << y << ")");
            taIndex++;
        }
    }

    taMobility.SetPositionAllocator(taPositionAlloc);
    taMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    taMobility.Install(taNodes);
}

int main(int argc, char* argv[]) {
    std::string traceFile = "scratch/traces.csv";
    uint32_t maxVehicles = 50;
    uint32_t nTAs = 0;
    uint32_t nASs = 0;
    double simTime = 3000.0;
    double txPower = 33.0;
    std::string vehicleTypeFilter = "";

    CommandLine cmd(__FILE__);
    cmd.AddValue("vehicles", "Number of vehicles", maxVehicles);
    cmd.AddValue("tas", "Number of Trust Authorities (0 = auto)", nTAs);
    cmd.AddValue("txpower", "Transmission power in dBm", txPower);
    cmd.AddValue("time", "Simulation time", simTime);
    cmd.Parse(argc, argv);

    EVP_PKEY* as_rsa = generate_rsa_key();

    BN_CTX *ctx = BN_CTX_new();
    n = BN_new();
    BN_generate_prime_ex(n, 2048, 0, NULL, NULL, NULL);
    g1 = generate_random_bn(n);
    g2 = generate_random_bn(n);
    h1 = generate_random_bn(n);
    h2 = generate_random_bn(n);
    BN_CTX_free(ctx);

    LogComponentEnable("ZamaAuthentication", LOG_LEVEL_INFO);

    std::map<std::string, std::vector<VehicleTraceEntry>> mobilityTraces;
    mobilityTraces = LoadMobilityTraces(traceFile);
    std::vector<std::string> vehicleIds = GetVehicleIds(mobilityTraces, vehicleTypeFilter);

    if (vehicleIds.empty()) {
        NS_LOG_ERROR("No vehicles found in trace file!");
        return 1;
    }

    if (vehicleIds.size() > maxVehicles) {
        vehicleIds.resize(maxVehicles);
    }

    uint32_t nVehicles = vehicleIds.size();
    NS_LOG_INFO("Using " << nVehicles << " vehicles from trace file");

    double minX = std::numeric_limits<double>::max();
    double maxX = std::numeric_limits<double>::min();
    double minY = std::numeric_limits<double>::max();
    double maxY = std::numeric_limits<double>::min();

    for (const auto& vid : vehicleIds) {
        for (const auto& entry : mobilityTraces[vid]) {
            minX = std::min(minX, entry.x);
            maxX = std::max(maxX, entry.x);
            minY = std::min(minY, entry.y);
            maxY = std::max(maxY, entry.y);
        }
    }

    double areaWidth = maxX - minX;
    double areaHeight = maxY - minY;

    if (nTAs == 0) {
        nTAs = CalculateRequiredTAs(areaWidth, areaHeight, txPower);
        NS_LOG_INFO("Auto-calculated " << nTAs << " TAs for coverage");
    }

    nASs = nTAs;

    NodeContainer vehicleNodes;
    vehicleNodes.Create(nVehicles);
    NodeContainer taNodes;
    taNodes.Create(nTAs);
    NodeContainer asNodes;
    asNodes.Create(nASs);

    MobilityHelper vehicleMobility;
    vehicleMobility.SetMobilityModel("ns3::ConstantVelocityMobilityModel");
    vehicleMobility.Install(vehicleNodes);

    for (uint32_t i = 0; i < nVehicles; ++i) {
        const std::string& vehicleId = vehicleIds[i];
        const auto& traces = mobilityTraces[vehicleId];

        if (!traces.empty()) {
            Ptr<ConstantVelocityMobilityModel> mobility =
                vehicleNodes.Get(i)->GetObject<ConstantVelocityMobilityModel>();

            const auto& firstEntry = traces[0];
            mobility->SetPosition(Vector(firstEntry.x, firstEntry.y, 0.0));

            double angleRad = firstEntry.angle * M_PI / 180.0;
            double vx = firstEntry.speed * cos(angleRad);
            double vy = firstEntry.speed * sin(angleRad);
            mobility->SetVelocity(Vector(vx, vy, 0.0));

            ScheduleVehicleUpdates(vehicleNodes.Get(i), traces);
        }
    }

    MobilityHelper taMobility;
    DistributeTAsInGrid(taNodes, minX, maxX, minY, maxY, taMobility);

    MobilityHelper asMobility;
    DistributeTAsInGrid(asNodes, minX, maxX, minY, maxY, asMobility);

    YansWifiChannelHelper wifiChannel = YansWifiChannelHelper::Default();
    YansWifiPhyHelper wifiPhy;
    wifiPhy.SetChannel(wifiChannel.Create());
    wifiPhy.Set("TxPowerStart", DoubleValue(txPower));
    wifiPhy.Set("TxPowerEnd", DoubleValue(txPower));

    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211p);
    wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                "DataMode", StringValue("OfdmRate6MbpsBW10MHz"),
                                "ControlMode", StringValue("OfdmRate6MbpsBW10MHz"));

    WifiMacHelper wifiMac;
    wifiMac.SetType("ns3::AdhocWifiMac");

    NetDeviceContainer vehicleDevices = wifi.Install(wifiPhy, wifiMac, vehicleNodes);
    NetDeviceContainer taDevices = wifi.Install(wifiPhy, wifiMac, taNodes);
    NetDeviceContainer asDevices = wifi.Install(wifiPhy, wifiMac, asNodes);

    InternetStackHelper internet;
    internet.Install(vehicleNodes);
    internet.Install(taNodes);
    internet.Install(asNodes);

    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.0.0", "255.255.0.0");
    Ipv4InterfaceContainer vehicleInterfaces = ipv4.Assign(vehicleDevices);
    Ipv4InterfaceContainer taInterfaces = ipv4.Assign(taDevices);
    Ipv4InterfaceContainer asInterfaces = ipv4.Assign(asDevices);

    // Standard port configuration
    const uint16_t TA_REG_PORT = 8080;
    const uint16_t TA_VERIFY_PORT = 8081;
    const uint16_t AS_AUTH_PORT = 9090;

    // Install TA Applications with standard ports
    for (uint32_t i = 0; i < nTAs; ++i) {
        Ptr<ZamaTAApplication> taApp = CreateObject<ZamaTAApplication>();
        taApp->SetTAId(i);
        
        taApp->Setup(TA_REG_PORT, TA_VERIFY_PORT, "TA" + std::to_string(i));
        
        // Set AS address for this TA (co-located AS)
        taApp->SetASAddress(InetSocketAddress(asInterfaces.GetAddress(i), AS_AUTH_PORT));
        
        taNodes.Get(i)->AddApplication(taApp);
        taApp->SetStartTime(Seconds(0.5));
        taApp->SetStopTime(Seconds(simTime));
        
        // NS_LOG_INFO("TA " << i << " (" << taInterfaces.GetAddress(i) 
        //             << ") listening on ports " << TA_REG_PORT << " (reg) and " 
        //             << TA_VERIFY_PORT << " (verify)");
    }

    // Install AS Applications with standard ports
    for (uint32_t i = 0; i < nASs; ++i) {
        Ptr<ZamaASApplication> asApp = CreateObject<ZamaASApplication>();
        asApp->SetASId(i);
        
        asApp->Setup(AS_AUTH_PORT, TA_VERIFY_PORT, "AS" + std::to_string(i));
        
        // Set TA address for this AS (co-located TA)
        asApp->SetTAAddress(InetSocketAddress(taInterfaces.GetAddress(i), TA_VERIFY_PORT));
        
        asNodes.Get(i)->AddApplication(asApp);
        asApp->SetStartTime(Seconds(0.5));
        asApp->SetStopTime(Seconds(simTime));
        
        // NS_LOG_INFO("AS " << i << " (" << asInterfaces.GetAddress(i) 
        //             << ") listening on port " << AS_AUTH_PORT
        //             << ", sends TA verifications to port " << TA_VERIFY_PORT);
    }

    // Install Vehicle Applications with standard ports
    for (uint32_t i = 0; i < nVehicles; ++i) {
        Ptr<MobilityModel> vMobility = vehicleNodes.Get(i)->GetObject<MobilityModel>();
        Vector vPos = vMobility->GetPosition();

        uint32_t nearestTA = 0;
        double minDist = std::numeric_limits<double>::max();

        for (uint32_t j = 0; j < nTAs; ++j) {
            Ptr<MobilityModel> taMobility = taNodes.Get(j)->GetObject<MobilityModel>();
            Vector taPos = taMobility->GetPosition();
            double dist = ComputeEuclideanDistance(vPos, taPos);

            if (dist < minDist) {
                minDist = dist;
                nearestTA = j;
            }
        }

        Ptr<ZamaVehicleApplication> vApp = CreateObject<ZamaVehicleApplication>();
        vApp->SetVehicleId(vehicleIds[i]);
        
        vApp->Setup(taInterfaces.GetAddress(nearestTA), 
                    TA_REG_PORT,    // Registration port
                    AS_AUTH_PORT,   // Authentication port
                    "TA" + std::to_string(nearestTA), 
                    vehicleIds[i]);
        
        vApp->SetTAAddress(InetSocketAddress(taInterfaces.GetAddress(nearestTA), TA_REG_PORT));
        vApp->SetASAddress(InetSocketAddress(asInterfaces.GetAddress(nearestTA), AS_AUTH_PORT));
        
        // Get AS public key
        Ptr<ZamaASApplication> asApp = asNodes.Get(nearestTA)->GetApplication(0)->GetObject<ZamaASApplication>();
        vApp->SetASPublicKey(asApp->GetPublicKey());
        
        vehicleNodes.Get(i)->AddApplication(vApp);
        vApp->SetStartTime(Seconds(2.0 + i * 0.1));
        vApp->SetStopTime(Seconds(simTime));
    }

    NS_LOG_INFO("Starting simulation with " << nVehicles << " vehicles, "
                << nTAs << " TAs, and " << nASs << " AS");
    // NS_LOG_INFO("Port configuration: TA_REG=" << TA_REG_PORT 
    //             << ", TA_VERIFY=" << TA_VERIFY_PORT 
    //             << ", AS_AUTH=" << AS_AUTH_PORT);

    double maxTraceTime = 0.0;
    for (const auto& vid : vehicleIds)
    {
        if (!mobilityTraces[vid].empty())
        {
            maxTraceTime = std::max(maxTraceTime, mobilityTraces[vid].back().time);
        }
    }

    if (simTime < maxTraceTime)
    {
        simTime = maxTraceTime + 10.0;
    }

    Simulator::Stop(Seconds(simTime));
    Simulator::Run();
    
    NS_LOG_UNCOND("\n==== Simulation Metrics ====");
    NS_LOG_UNCOND("Total vehicles: " << nVehicles);
    NS_LOG_UNCOND("Authentication attempts: " << g_metrics.authAttempts);
    NS_LOG_UNCOND("Authentication success: " << g_metrics.authSuccess);
    if (g_metrics.authAttempts > 0) {
        NS_LOG_UNCOND("Success ratio: "
                      << (double)g_metrics.authSuccess / g_metrics.authAttempts * 100.0 << "%");
    }

    NS_LOG_UNCOND("\n--- Time Cost (Critical for Comparison) ---");
    if (!g_metrics.authDelays.empty()) {
        double sumDelay = 0.0;
        double minDelay = std::numeric_limits<double>::max();
        double maxDelay = 0.0;

        for (double delay : g_metrics.authDelays) {
            sumDelay += delay;
            minDelay = std::min(minDelay, delay);
            maxDelay = std::max(maxDelay, delay);
        }

        double avgDelay = sumDelay / g_metrics.authDelays.size();

        NS_LOG_UNCOND("Average authentication delay: "
                      << std::fixed << std::setprecision(3) << avgDelay * 1000 << " ms");
        NS_LOG_UNCOND("Min authentication delay: "
                      << std::fixed << std::setprecision(3) << minDelay * 1000 << " ms");
        NS_LOG_UNCOND("Max authentication delay: "
                      << std::fixed << std::setprecision(3) << maxDelay * 1000 << " ms");

        double totalSystemTime = g_metrics.lastAuthEnd - g_metrics.firstAuthStart;
        NS_LOG_UNCOND("Total system authentication time: "
                      << std::fixed << std::setprecision(3) << totalSystemTime << " s");
        NS_LOG_UNCOND("  (Time from first vehicle start to last vehicle authenticated)");
    }

    NS_LOG_UNCOND("\n--- Communication Overhead ---");
    if (!g_metrics.vehicleMetrics.empty()) {
        const VehicleMetrics& vm = g_metrics.vehicleMetrics.begin()->second;
        uint64_t totalOverhead = vm.regMsg1 + vm.regMsg2 + vm.authMsg1 + vm.authMsg2 + vm.authMsg3 + vm.authMsg4;

        NS_LOG_UNCOND("Registration phase:");
        NS_LOG_UNCOND("  Vehicle → TA (regMsg1): " << vm.regMsg1 << " bytes");
        NS_LOG_UNCOND("  TA → Vehicle (regMsg2): " << vm.regMsg2 << " bytes");
        NS_LOG_UNCOND("Authentication phase:");
        NS_LOG_UNCOND("  Vehicle → AS (authMsg1): " << vm.authMsg1 << " bytes");
        NS_LOG_UNCOND("  AS → Vehicle (authMsg2): " << vm.authMsg2 << " bytes");
        NS_LOG_UNCOND("  AS → TA (authMsg3): " << vm.authMsg3 << " bytes");
        NS_LOG_UNCOND("  TA → AS (authMsg4): " << vm.authMsg4 << " bytes");
        NS_LOG_UNCOND("Total overhead per vehicle: " << totalOverhead << " bytes");
        NS_LOG_UNCOND("Total network overhead (all vehicles): "
                      << totalOverhead * g_metrics.authSuccess << " bytes");
    }
    
    NS_LOG_INFO("\nZama authentication simulation completed!");
    Simulator::Destroy();

    BN_free(n);
    BN_free(g1);
    BN_free(g2);
    BN_free(h1);
    BN_free(h2);
    EVP_PKEY_free(as_rsa);

    return 0;
}
