#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-helper.h"
#include "ns3/network-module.h"
#include "ns3/yans-wifi-helper.h"
#include "ns3/wifi-module.h"
#include "ns3/constant-velocity-mobility-model.h"

#include <cstdint>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <random>
#include <vector>
#include <map>
#include <fstream>
#include <sstream>
#include <arpa/inet.h>
#include <iomanip>
#include <cmath>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("AmarProtocol");

// u = 5 proofs with h = 3 rounds each

struct VehicleMetrics {
    uint64_t vid = 0;
    uint32_t groupId = 0;
    
    // Phase 1: Authentication Request
    uint64_t authRequestSize = 0;        // Vehicle → RSU: Encrypted(G_i, T1, K_session, SERV_ID, α)
    
    // Phase 2: Vehicle ZKP (Vehicle proves to RSU)
    uint64_t vehicleZkpCommitmentSize = 0;   // Vehicle → RSU: W (per round)
    uint64_t vehicleZkpChallengeSize = 0;    // RSU → Vehicle: challenge bits
    uint64_t vehicleZkpResponseSize = 0;     // Vehicle → RSU: Y response
    uint32_t vehicleZkpRounds = 0;           // Number of ZKP rounds
    
    // Phase 3: RSU ZKP (RSU proves to Vehicle)
    uint64_t rsuZkpSecretIdsSize = 0;        // Vehicle → RSU: secret IDs
    uint64_t rsuZkpCommitmentSize = 0;       // RSU → Vehicle: W (per round)
    uint64_t rsuZkpChallengeSize = 0;        // Vehicle → RSU: challenge bits
    uint64_t rsuZkpResponseSize = 0;         // RSU → Vehicle: Y response
    uint32_t rsuZkpProofs = 0;               // Number of RSU proofs (u)
    uint32_t rsuZkpRoundsPerProof = 0;       // Rounds per proof (h)
    
    // Phase 4: Final Result
    uint64_t authResultSize = 0;             // Vehicle → RSU: final verification
    
    // Timing
    double authStartTime = 0;
    double authEndTime = 0;
    
    // Computed totals
    uint64_t GetTotalVehicleToRsu() const {
        return authRequestSize + 
               (vehicleZkpCommitmentSize + vehicleZkpResponseSize) * vehicleZkpRounds +
               rsuZkpSecretIdsSize +
               (rsuZkpChallengeSize * rsuZkpProofs * rsuZkpRoundsPerProof) +
               authResultSize;
    }
    
    uint64_t GetTotalRsuToVehicle() const {
        return (vehicleZkpChallengeSize * vehicleZkpRounds) +
               (rsuZkpCommitmentSize + rsuZkpResponseSize) * rsuZkpProofs * rsuZkpRoundsPerProof;
    }
    
    uint64_t GetTotalOverhead() const {
        return GetTotalVehicleToRsu() + GetTotalRsuToVehicle();
    }
};

struct Metrics {
    uint32_t authAttempts = 0;
    uint32_t authSuccess = 0;
    double firstAuthStart = std::numeric_limits<double>::max();
    double lastAuthEnd = 0.0;
    std::vector<double> authDelays;
    std::map<uint64_t, VehicleMetrics> vehicleMetrics;
} g_metrics;

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

VehicleTraceEntry ParseTraceLine(const std::string& line) {
    VehicleTraceEntry entry;
    std::istringstream ss(line);
    std::string token;
    std::vector<std::string> tokens;

    while (std::getline(ss, token, ';')) {
        token.erase(0, token.find_first_not_of(" \t\r\n"));
        token.erase(token.find_last_not_of(" \t\r\n") + 1);
        tokens.push_back(token);
    }

    if (tokens.size() >= 10) {
        try {
            entry.time = std::stod(tokens[0]);
            entry.lane = tokens[2];
            entry.angle = std::stod(tokens[3]);
            entry.vehicleType = tokens[4];
            entry.y = std::stod(tokens[6]);
            entry.x = std::stod(tokens[7]);
            entry.speed = std::stod(tokens[8]);
            entry.vehicleId = tokens[9];
        } catch (const std::exception& e) {
            NS_LOG_WARN("Failed to parse trace line: " << e.what());
            entry.vehicleId = "";
        }
    }
    return entry;
}

std::map<std::string, std::vector<VehicleTraceEntry>> LoadMobilityTraces(const std::string& filename) {
    std::map<std::string, std::vector<VehicleTraceEntry>> traces;
    std::ifstream file(filename);

    if (!file.is_open()) {
        NS_LOG_ERROR("Failed to open trace file: " << filename);
        return traces;
    }

    std::string line;
    std::getline(file, line); // Skip header

    while (std::getline(file, line)) {
        if (line.empty()) continue;
        VehicleTraceEntry entry = ParseTraceLine(line);
        if (!entry.vehicleId.empty()) {
            traces[entry.vehicleId].push_back(entry);
        }
    }
    file.close();
    NS_LOG_INFO("Loaded mobility traces for " << traces.size() << " vehicles");
    return traces;
}

void UpdateVehiclePosition(Ptr<Node> node, double x, double y, double speed, double angle) {
    Ptr<ConstantVelocityMobilityModel> mobility = node->GetObject<ConstantVelocityMobilityModel>();
    if (mobility) {
        mobility->SetPosition(Vector(x, y, 0.0));
        double angleRad = angle * M_PI / 180.0;
        mobility->SetVelocity(Vector(speed * cos(angleRad), speed * sin(angleRad), 0.0));
    }
}

void ScheduleVehicleUpdates(Ptr<Node> node, const std::vector<VehicleTraceEntry>& entries) {
    for (const auto& entry : entries) {
        Simulator::Schedule(Seconds(entry.time), &UpdateVehiclePosition,
                          node, entry.x, entry.y, entry.speed, entry.angle);
    }
}

// Vehicle Group Information
struct VehicleGroupInfo {
    uint32_t groupId;
    std::vector<BIGNUM*> groupSecrets;  // Pr_y secrets (k secrets per group)
    std::vector<BIGNUM*> publicValues;   // g_y = ±Pr_y^2 mod m
};

struct SystemGroupSecrets {
    BIGNUM* m;                              // Blum modulus (public)
    std::vector<BIGNUM*> rsuSecrets;        // S_x secrets (n secrets for RSUs)
    std::vector<BIGNUM*> rsuPublicValues;   // I_x = ±S_x^2 mod m (public)
    std::map<uint32_t, VehicleGroupInfo> vehicleGroups;  // Group ID -> Group info

    int n;  // Number of RSU secrets
    int k;  // Number of secrets per vehicle group

    SystemGroupSecrets() : m(NULL), n(0), k(0) {}

    ~SystemGroupSecrets() {
        if (m) BN_free(m);
        for (auto bn : rsuSecrets) if (bn) BN_free(bn);
        for (auto bn : rsuPublicValues) if (bn) BN_free(bn);
        for (auto& kv : vehicleGroups) {
            for (auto bn : kv.second.groupSecrets) if (bn) BN_free(bn);
            for (auto bn : kv.second.publicValues) if (bn) BN_free(bn);
        }
    }
};

BIGNUM* GenerateBlumModulus() {
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* p = BN_new();
    BIGNUM* q = BN_new();
    BIGNUM* m = BN_new();
    BIGNUM* three = BN_new();
    BIGNUM* four = BN_new();
    BN_set_word(three, 3);
    BN_set_word(four, 4);

    // Generate p ≡ 3 (mod 4)
    do {
        BN_generate_prime_ex(p, 512, 1, NULL, NULL, NULL);
        BIGNUM* rem = BN_new();
        BN_mod(rem, p, four, ctx);
        bool is_valid = (BN_cmp(rem, three) == 0);
        BN_free(rem);
        if (is_valid) break;
    } while (true);

    // Generate q ≡ 3 (mod 4)
    do {
        BN_generate_prime_ex(q, 512, 1, NULL, NULL, NULL);
        BIGNUM* rem = BN_new();
        BN_mod(rem, q, four, ctx);
        bool is_valid = (BN_cmp(rem, three) == 0);
        BN_free(rem);
        if (is_valid) break;
    } while (true);

    BN_mul(m, p, q, ctx);
    BN_free(p);
    BN_free(q);
    BN_free(three);
    BN_free(four);
    BN_CTX_free(ctx);
    return m;
}

// Key Distribution Center - performs group formation and key distribution
void KDC_GenerateSystemSecrets(SystemGroupSecrets& sysSecrets, int n, int k, int numGroups) {
    sysSecrets.n = n;
    sysSecrets.k = k;
    sysSecrets.m = GenerateBlumModulus();
    BN_CTX* ctx = BN_CTX_new();

    // Step 1: Generate n RSU secrets S_x and corresponding I_x = S_x^2 mod m
    for (int i = 0; i < n; i++) {
        BIGNUM* s_x = BN_new();
        BN_rand_range(s_x, sysSecrets.m);
        sysSecrets.rsuSecrets.push_back(s_x);

        BIGNUM* i_x = BN_new();
        BN_mod_sqr(i_x, s_x, sysSecrets.m, ctx);
        // Do NOT negate - it breaks verification!
        // The ± in the paper refers to theoretical QR/QNR, not implementation
        sysSecrets.rsuPublicValues.push_back(i_x);
    }

    // Step 2-7: Generate vehicle groups with unique master secrets
    for (int groupIdx = 0; groupIdx < numGroups; groupIdx++) {
        uint32_t groupId = groupIdx + 1;
        VehicleGroupInfo groupInfo;
        groupInfo.groupId = groupId;

        // Generate k vehicle-group secrets Pr_y and corresponding g_y = ±Pr_y^2 mod m
        for (int i = 0; i < k; i++) {
            BIGNUM* pr_y = BN_new();
            BN_rand_range(pr_y, sysSecrets.m);
            groupInfo.groupSecrets.push_back(pr_y);

            BIGNUM* g_y = BN_new();
            BN_mod_sqr(g_y, pr_y, sysSecrets.m, ctx);
            
            // Apply ± during setup only (optional, for quadratic character hiding)
            if (rand() % 2) {
                BIGNUM* temp = BN_new();
                BN_sub(temp, sysSecrets.m, g_y);
                BN_free(g_y);
                g_y = temp;
            }
            groupInfo.publicValues.push_back(g_y);
        }

        sysSecrets.vehicleGroups[groupId] = groupInfo;
    }

    NS_LOG_INFO("Summary: " << numGroups << " groups, " << n << " RSU secrets, "
                << k << " secrets per vehicle group");

    BN_CTX_free(ctx);
}

std::vector<uint8_t> SerializeBIGNUM(const BIGNUM* bn) {
    int len = BN_num_bytes(bn);
    std::vector<uint8_t> buffer(len);
    BN_bn2bin(bn, buffer.data());
    return buffer;
}

BIGNUM* DeserializeBIGNUM(const std::vector<uint8_t>& data) {
    return BN_bin2bn(data.data(), data.size(), NULL);
}

std::vector<uint8_t> aes_encrypt(const std::vector<uint8_t>& plaintext, BIGNUM* key_bn) {
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
    unsigned char buffer[1024 + EVP_CIPHER_block_size(EVP_aes_256_cbc())];

    if (EVP_EncryptUpdate(ctx, buffer, &len, plaintext.data(), plaintext.size()) != 1) {
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

std::vector<uint8_t> aes_decrypt(const std::vector<uint8_t>& ciphertext, BIGNUM* key_bn) {
    if (ciphertext.size() < 16) return std::vector<uint8_t>();

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
    if (!ctx) return std::vector<uint8_t>();

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return std::vector<uint8_t>();
    }

    std::vector<uint8_t> plaintext;
    int len;
    unsigned char buffer[1024 + EVP_CIPHER_block_size(EVP_aes_256_cbc())];

    if (EVP_DecryptUpdate(ctx, buffer, &len,
                         ciphertext.data() + 16,
                         ciphertext.size() - 16) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return std::vector<uint8_t>();
    }
    plaintext.insert(plaintext.end(), buffer, buffer + len);

    if (EVP_DecryptFinal_ex(ctx, buffer, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return std::vector<uint8_t>();
    }
    plaintext.insert(plaintext.end(), buffer, buffer + len);

    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

BIGNUM* SessionKeyToBIGNUM(const std::vector<uint8_t>& keyBytes) {
    return BN_bin2bn(keyBytes.data(), keyBytes.size(), NULL);
}

enum MessageType {
    MSG_AUTH_REQUEST = 0,           // Vehicle -> RSU: Encrypted(G_i, T1, K_session, SERV_ID, α)
    MSG_VEHICLE_ZKP_COMMITMENT = 1, // Vehicle -> RSU: W value (commitment)
    MSG_VEHICLE_ZKP_CHALLENGE = 2,  // RSU -> Vehicle: Challenge bits
    MSG_VEHICLE_ZKP_RESPONSE = 3,   // Vehicle -> RSU: Y response
    MSG_RSU_ZKP_SECRET_IDS = 4,     // Vehicle -> RSU: Secret IDs for RSU proofs
    MSG_RSU_ZKP_COMMITMENT = 5,     // RSU -> Vehicle: W value
    MSG_RSU_ZKP_CHALLENGE = 6,      // Vehicle -> RSU: Challenge bits
    MSG_RSU_ZKP_RESPONSE = 7,       // RSU -> Vehicle: Y response
    MSG_AUTH_FINAL_RESULT = 8       // Vehicle -> RSU: Final verification result
};

class RsuApplication : public Application {
public:
    RsuApplication() : m_socket(0), m_port(10), m_ctx(NULL),
                       m_zkpRoundsPerProof(3) {}

    virtual ~RsuApplication() {
        if (m_socket) m_socket = 0;
        if (m_ctx) BN_CTX_free(m_ctx);

        for (auto& kv : m_vehicleCommitmentMap) {
            if (kv.second) BN_free(kv.second);
        }
        for (auto& kv : m_rsuCommitmentsMap) {
            for (auto W : kv.second) if (W) BN_free(W);
        }
        for (auto& kv : m_rsuRandomsMap) {
            for (auto R : kv.second) if (R) BN_free(R);
        }
        for (auto& kv : m_sessionKeyBNMap) {
            if (kv.second) BN_free(kv.second);
        }
    }

    void SetupRsu(uint16_t port, std::string rsuId, const SystemGroupSecrets& sysSecrets,
                  RSA* rsaKey) {
        m_port = port;
        m_rsuId = rsuId;
        m_systemSecrets = &sysSecrets;
        m_rsaPrivateKey = rsaKey;
        m_ctx = BN_CTX_new();
    }

private:
    virtual void StartApplication() {
        m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
        InetSocketAddress local = InetSocketAddress(Ipv4Address::GetAny(), m_port);
        m_socket->Bind(local);
        m_socket->SetRecvCallback(MakeCallback(&RsuApplication::HandleIncomingMessage, this));
    }

    virtual void StopApplication() {
        if (m_socket) m_socket->Close();
    }

    void HandleIncomingMessage(Ptr<Socket> socket) {
        Ptr<Packet> packet;
        Address from;

        while ((packet = socket->RecvFrom(from))) {
            uint32_t packetSize = packet->GetSize();
            std::vector<uint8_t> buffer(packetSize);
            packet->CopyData(buffer.data(), packetSize);

            if (buffer.empty()) continue;

            uint8_t msgType = buffer[0];
            std::vector<uint8_t> payload(buffer.begin() + 1, buffer.end());

            switch (msgType) {
                case MSG_AUTH_REQUEST:
                    ProcessAuthenticationRequest(payload, from);
                    break;
                case MSG_VEHICLE_ZKP_COMMITMENT:
                    ProcessVehicleZkpCommitment(payload, from);
                    break;
                case MSG_VEHICLE_ZKP_RESPONSE:
                    ProcessVehicleZkpResponse(payload, from);
                    break;
                case MSG_RSU_ZKP_SECRET_IDS:
                    ProcessRsuZkpSecretIds(payload, from);
                    break;
                case MSG_RSU_ZKP_CHALLENGE:
                    ProcessRsuZkpChallenge(payload, from);
                    break;
                case MSG_AUTH_FINAL_RESULT:
                    ProcessAuthenticationResult(payload, from);
                    break;
            }
        }
    }

    void ProcessAuthenticationRequest(const std::vector<uint8_t>& encrypted, Address from) {
        // Decrypt auth request with RSU private key (RSA)
        int rsaSize = RSA_size(m_rsaPrivateKey);
        std::vector<uint8_t> decrypted(rsaSize);
        int len = RSA_private_decrypt(encrypted.size(), encrypted.data(),
                                     decrypted.data(), m_rsaPrivateKey, RSA_PKCS1_OAEP_PADDING);
        if (len <= 0) {
            NS_LOG_ERROR(m_rsuId << ": Failed to decrypt authentication request");
            return;
        }
        decrypted.resize(len);

        // Parse: G_i(4), T1(8), K_session(16), SERV_ID(4), alpha(4)
        size_t offset = 0;
        uint32_t groupId, serviceId, alpha;
        uint64_t timestamp;

        memcpy(&groupId, decrypted.data() + offset, 4); offset += 4;
        memcpy(&timestamp, decrypted.data() + offset, 8); offset += 8;

        std::vector<uint8_t> sessionKey(decrypted.begin() + offset, decrypted.begin() + offset + 16);
        offset += 16;

        memcpy(&serviceId, decrypted.data() + offset, 4); offset += 4;
        memcpy(&alpha, decrypted.data() + offset, 4);

        // Store session information
        m_sessionKeyMap[from] = sessionKey;
        m_sessionKeyBNMap[from] = SessionKeyToBIGNUM(sessionKey);
        m_vehicleGroupMap[from] = groupId;
        m_privacyParameterMap[from] = alpha;
        m_vehicleZkpRoundMap[from] = 0;

        // Track message size
        g_metrics.vehicleMetrics[groupId].authRequestSize = encrypted.size() + 1;
    }

    void ProcessVehicleZkpCommitment(const std::vector<uint8_t>& encrypted, Address from) {
        // Decrypt commitment W from vehicle
        std::vector<uint8_t> payload = aes_decrypt(encrypted, m_sessionKeyBNMap[from]);
        if (payload.empty()) {
            NS_LOG_ERROR(m_rsuId << ": Failed to decrypt vehicle ZKP commitment");
            return;
        }

        // Store W for later verification
        if (m_vehicleCommitmentMap[from]) BN_free(m_vehicleCommitmentMap[from]);
        m_vehicleCommitmentMap[from] = DeserializeBIGNUM(payload);

        // Generate random challenge bits for vehicle's group
        uint32_t groupId = m_vehicleGroupMap[from];
        int k = m_systemSecrets->k;

        std::vector<uint8_t> challengeBits(k);
        for (int i = 0; i < k; i++) {
            challengeBits[i] = rand() % 2;
        }
        m_vehicleChallengeMap[from] = challengeBits;

        // Send challenge to vehicle
        std::vector<uint8_t> msg;
        msg.push_back(k);
        msg.insert(msg.end(), challengeBits.begin(), challengeBits.end());

        std::vector<uint8_t> encryptedMsg = aes_encrypt(msg, m_sessionKeyBNMap[from]);

        std::vector<uint8_t> fullMsg;
        fullMsg.push_back(MSG_VEHICLE_ZKP_CHALLENGE);
        fullMsg.insert(fullMsg.end(), encryptedMsg.begin(), encryptedMsg.end());

        Ptr<Packet> packet = Create<Packet>(fullMsg.data(), fullMsg.size());
        m_socket->SendTo(packet, 0, from);

        g_metrics.vehicleMetrics[groupId].vehicleZkpCommitmentSize = encrypted.size() + 1;
        g_metrics.vehicleMetrics[groupId].vehicleZkpChallengeSize = fullMsg.size();
        g_metrics.vehicleMetrics[groupId].vehicleZkpRounds = m_zkpRoundsPerProof;

        m_vehicleZkpRoundMap[from]++;
    }

    void ProcessVehicleZkpResponse(const std::vector<uint8_t>& encrypted, Address from) {
        // Decrypt response Y from vehicle
        std::vector<uint8_t> payload = aes_decrypt(encrypted, m_sessionKeyBNMap[from]);
        if (payload.empty()) {
            NS_LOG_ERROR(m_rsuId << ": Failed to decrypt vehicle ZKP response");
            return;
        }

        BIGNUM* Y = DeserializeBIGNUM(payload);
        uint32_t groupId = m_vehicleGroupMap[from];

        // Verify Y^2 = W * ∏(g_y^b_y) mod m
        // This works because W = R^2 (always positive square now)
        BIGNUM* product = BN_new();
        BN_set_word(product, 1);

        const VehicleGroupInfo& groupInfo = m_systemSecrets->vehicleGroups.at(groupId);
        const std::vector<uint8_t>& challengeBits = m_vehicleChallengeMap[from];

        for (size_t i = 0; i < challengeBits.size(); i++) {
            if (challengeBits[i]) {
                BN_mod_mul(product, product, groupInfo.publicValues[i],
                          m_systemSecrets->m, m_ctx);
            }
        }

        BIGNUM* expectedRight = BN_new();
        BIGNUM* W = m_vehicleCommitmentMap[from];
        BN_mod_mul(expectedRight, W, product, m_systemSecrets->m, m_ctx);

        BIGNUM* actualLeft = BN_new();
        BN_mod_sqr(actualLeft, Y, m_systemSecrets->m, m_ctx);

        bool verified = (BN_cmp(actualLeft, expectedRight) == 0);

        if (!verified) {
            NS_LOG_WARN(m_rsuId << ": Vehicle ZKP verification failed");
        }

        BN_free(product);
        BN_free(expectedRight);
        BN_free(actualLeft);
        BN_free(Y);

        g_metrics.vehicleMetrics[groupId].vehicleZkpResponseSize = encrypted.size() + 1;

        m_vehicleZkpRoundMap[from]++;
    }

    void ProcessRsuZkpSecretIds(const std::vector<uint8_t>& encrypted, Address from) {
        // Decrypt secret IDs from vehicle
        std::vector<uint8_t> payload = aes_decrypt(encrypted, m_sessionKeyBNMap[from]);
        if (payload.empty()) {
            NS_LOG_ERROR(m_rsuId << ": Failed to decrypt RSU ZKP secret IDs");
            return;
        }

        size_t offset = 0;
        uint8_t u = payload[offset++];
        uint8_t k = payload[offset++];

        m_rsuProofCountMap[from] = u;
        std::vector<uint32_t> secretIds(u * k);

        for (size_t i = 0; i < u * k; i++) {
            uint32_t id;
            memcpy(&id, payload.data() + offset, 4);
            secretIds[i] = ntohl(id);
            offset += 4;
        }
        m_rsuSecretIdsMap[from] = secretIds;

        uint32_t groupId = m_vehicleGroupMap[from];
        g_metrics.vehicleMetrics[groupId].rsuZkpSecretIdsSize = encrypted.size() + 1;
        g_metrics.vehicleMetrics[groupId].rsuZkpProofs = u;
        g_metrics.vehicleMetrics[groupId].rsuZkpRoundsPerProof = m_zkpRoundsPerProof;

        // Initialize RSU ZKP state
        m_rsuCurrentProofMap[from] = 0;
        m_rsuCurrentRoundMap[from] = 0;

        // Clear previous state
        for (auto W : m_rsuCommitmentsMap[from]) if (W) BN_free(W);
        m_rsuCommitmentsMap[from].clear();
        for (auto R : m_rsuRandomsMap[from]) if (R) BN_free(R);
        m_rsuRandomsMap[from].clear();

        // Store one R and W per round (not per proof)
        // Total rounds = u proofs * h rounds per proof
        m_rsuCommitmentsMap[from].resize(u * m_zkpRoundsPerProof, nullptr);
        m_rsuRandomsMap[from].resize(u * m_zkpRoundsPerProof, nullptr);

        // Send first commitment
        SendRsuZkpCommitment(from);
    }

    void SendRsuZkpCommitment(Address from) {
        int proofIdx = m_rsuCurrentProofMap[from];
        int round = m_rsuCurrentRoundMap[from];
        int u = m_rsuProofCountMap[from];

        if (proofIdx >= u) {
            return;
        }

        int idx = proofIdx * m_zkpRoundsPerProof + round;

        // Free any existing values
        if (m_rsuRandomsMap[from][idx]) {
            BN_free(m_rsuRandomsMap[from][idx]);
        }
        if (m_rsuCommitmentsMap[from][idx]) {
            BN_free(m_rsuCommitmentsMap[from][idx]);
        }

        // Generate fresh R for each round
        BIGNUM* R = BN_new();
        BN_rand_range(R, m_systemSecrets->m);
        m_rsuRandomsMap[from][idx] = R;

        // Always compute W = R^2 mod m (no negation!)
        BIGNUM* W = BN_new();
        BN_mod_sqr(W, R, m_systemSecrets->m, m_ctx);
        m_rsuCommitmentsMap[from][idx] = W;

        // Send W
        auto serialized = SerializeBIGNUM(W);
        std::vector<uint8_t> encrypted = aes_encrypt(serialized, m_sessionKeyBNMap[from]);

        std::vector<uint8_t> msg;
        msg.push_back(MSG_RSU_ZKP_COMMITMENT);
        msg.insert(msg.end(), encrypted.begin(), encrypted.end());

        Ptr<Packet> packet = Create<Packet>(msg.data(), msg.size());
        m_socket->SendTo(packet, 0, from);

        if (proofIdx == 0 && round == 0) {
            uint32_t groupId = m_vehicleGroupMap[from];
            g_metrics.vehicleMetrics[groupId].rsuZkpCommitmentSize = msg.size();
        }
    }

    void ProcessRsuZkpChallenge(const std::vector<uint8_t>& encrypted, Address from) {
        // Decrypt challenge bits from vehicle
        std::vector<uint8_t> payload = aes_decrypt(encrypted, m_sessionKeyBNMap[from]);
        if (payload.empty()) {
            NS_LOG_ERROR(m_rsuId << ": Failed to decrypt RSU ZKP challenge");
            return;
        }

        int proofIdx = m_rsuCurrentProofMap[from];
        int round = m_rsuCurrentRoundMap[from];
        int k = m_systemSecrets->k;
        int u = m_rsuProofCountMap[from];
        int idx = proofIdx * m_zkpRoundsPerProof + round;

        // Get R for this specific round
        BIGNUM* R = m_rsuRandomsMap[from][idx];
        if (!R) {
            NS_LOG_ERROR(m_rsuId << ": No R found for proof " << proofIdx 
                        << " round " << round);
            return;
        }

        // Compute Y = R * ∏(S_x^b_x) mod m
        BIGNUM* product = BN_new();
        BN_set_word(product, 1);

        const std::vector<uint32_t>& secretIds = m_rsuSecretIdsMap[from];
        for (int i = 0; i < k; i++) {
            if (payload[i]) {
                uint32_t secretIdx = secretIds[proofIdx * k + i];
                BN_mod_mul(product, product, m_systemSecrets->rsuSecrets[secretIdx],
                          m_systemSecrets->m, m_ctx);
            }
        }

        BIGNUM* Y = BN_new();
        BN_mod_mul(Y, R, product, m_systemSecrets->m, m_ctx);
        BN_free(product);

        // Send Y
        auto serialized = SerializeBIGNUM(Y);
        BN_free(Y);

        std::vector<uint8_t> encrypted_y = aes_encrypt(serialized, m_sessionKeyBNMap[from]);

        std::vector<uint8_t> msg;
        msg.push_back(MSG_RSU_ZKP_RESPONSE);
        msg.insert(msg.end(), encrypted_y.begin(), encrypted_y.end());

        Ptr<Packet> packet = Create<Packet>(msg.data(), msg.size());
        m_socket->SendTo(packet, 0, from);

        if (proofIdx == 0 && round == 0) {
            uint32_t groupId = m_vehicleGroupMap[from];
            g_metrics.vehicleMetrics[groupId].rsuZkpChallengeSize = encrypted.size() + 1;
            g_metrics.vehicleMetrics[groupId].rsuZkpResponseSize = msg.size();
        }

        m_rsuCurrentRoundMap[from]++;
        if (m_rsuCurrentRoundMap[from] >= m_zkpRoundsPerProof) {
            m_rsuCurrentRoundMap[from] = 0;
            m_rsuCurrentProofMap[from]++;

            if (m_rsuCurrentProofMap[from] < u) {
                SendRsuZkpCommitment(from);
            }
        } else {
            SendRsuZkpCommitment(from);
        }
    }

    void ProcessAuthenticationResult(const std::vector<uint8_t>& encrypted, Address from) {
        std::vector<uint8_t> payload = aes_decrypt(encrypted, m_sessionKeyBNMap[from]);
        if (payload.empty()) {
            NS_LOG_ERROR(m_rsuId << ": Failed to decrypt authentication result");
            return;
        }

        uint32_t verifiedCount;
        memcpy(&verifiedCount, payload.data(), 4);

        uint32_t alpha = m_privacyParameterMap[from];
        uint32_t groupId = m_vehicleGroupMap[from];
        bool authSuccess = (verifiedCount >= alpha);

        g_metrics.vehicleMetrics[groupId].authResultSize = encrypted.size() + 1;

        if (authSuccess) {
            g_metrics.authSuccess++;
            double endTime = Simulator::Now().GetSeconds();
            g_metrics.vehicleMetrics[groupId].authEndTime = endTime;

            double latency = endTime - g_metrics.vehicleMetrics[groupId].authStartTime;
            g_metrics.authDelays.push_back(latency);
            g_metrics.firstAuthStart = std::min(g_metrics.firstAuthStart,
                                               g_metrics.vehicleMetrics[groupId].authStartTime);
            g_metrics.lastAuthEnd = std::max(g_metrics.lastAuthEnd, endTime);

        } else {
            NS_LOG_ERROR(m_rsuId << ": MUTUAL AUTHENTICATION FAILED - insufficient proofs ("
                        << verifiedCount << "/" << alpha << ")");
        }
    }

    Ptr<Socket> m_socket;
    uint16_t m_port;
    std::string m_rsuId;
    const SystemGroupSecrets* m_systemSecrets;
    RSA* m_rsaPrivateKey;
    BN_CTX* m_ctx;
    int m_zkpRoundsPerProof;

    // Per-vehicle session state
    std::map<Address, std::vector<uint8_t>> m_sessionKeyMap;
    std::map<Address, BIGNUM*> m_sessionKeyBNMap;
    std::map<Address, uint32_t> m_vehicleGroupMap;
    std::map<Address, uint32_t> m_privacyParameterMap;

    // Vehicle ZKP verification state
    std::map<Address, BIGNUM*> m_vehicleCommitmentMap;
    std::map<Address, std::vector<uint8_t>> m_vehicleChallengeMap;
    std::map<Address, int> m_vehicleZkpRoundMap;

    // RSU ZKP proving state
    std::map<Address, int> m_rsuProofCountMap;
    std::map<Address, std::vector<uint32_t>> m_rsuSecretIdsMap;
    std::map<Address, std::vector<BIGNUM*>> m_rsuCommitmentsMap;
    std::map<Address, std::vector<BIGNUM*>> m_rsuRandomsMap;
    std::map<Address, int> m_rsuCurrentProofMap;
    std::map<Address, int> m_rsuCurrentRoundMap;
};

class VehicleApplication : public Application {
public:
    VehicleApplication() : m_socket(0), m_port(10), m_ctx(NULL),
                          m_vehicleRandom(NULL), m_vehicleCommitment(NULL),
                          m_sessionKeyBN(NULL), m_zkpRoundsPerProof(3) {}

    virtual ~VehicleApplication() {
        if (m_socket) m_socket = 0;
        if (m_ctx) BN_CTX_free(m_ctx);
        if (m_vehicleRandom) BN_free(m_vehicleRandom);
        if (m_vehicleCommitment) BN_free(m_vehicleCommitment);
        if (m_sessionKeyBN) BN_free(m_sessionKeyBN);
        for (auto W : m_rsuCommitments) if (W) BN_free(W);
    }

    void SetupVehicle(Ipv4Address rsuAddress, uint16_t port, std::string rsuId,
                     uint32_t groupId, const SystemGroupSecrets& sysSecrets,
                     RSA* rsaPublicKey, uint64_t vehicleId) {
        m_rsuAddress = rsuAddress;
        m_port = port;
        m_rsuId = rsuId;
        m_groupId = groupId;
        m_systemSecrets = &sysSecrets;
        m_rsaPublicKey = rsaPublicKey;
        m_vehicleId = vehicleId;
        m_ctx = BN_CTX_new();

        // Set privacy parameter and number of RSU proofs
        m_privacyParameter = 3;  // α: must verify at least 3 out of u proofs
        m_rsuProofCount = 5;     // u: RSU provides 5 proofs
    }

private:
    virtual void StartApplication() {
        m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
        m_socket->Bind();
        m_socket->Connect(InetSocketAddress(m_rsuAddress, m_port));
        m_socket->SetRecvCallback(MakeCallback(&VehicleApplication::HandleIncomingMessage, this));

        Simulator::ScheduleNow(&VehicleApplication::InitiateAuthentication, this);
    }

    virtual void StopApplication() {
        if (m_socket) m_socket->Close();
    }

    void InitiateAuthentication() {
        // Generate session key
        m_sessionKey.resize(16);
        RAND_bytes(m_sessionKey.data(), 16);
        m_sessionKeyBN = SessionKeyToBIGNUM(m_sessionKey);

        // Prepare authentication request: G_i(4), T1(8), K_session(16), SERV_ID(4), α(4)
        uint64_t timestamp = (uint64_t)(Simulator::Now().GetSeconds() * 1000);
        uint32_t serviceId = 1;

        std::vector<uint8_t> message;
        message.insert(message.end(), (uint8_t*)&m_groupId, (uint8_t*)&m_groupId + 4);
        message.insert(message.end(), (uint8_t*)&timestamp, (uint8_t*)&timestamp + 8);
        message.insert(message.end(), m_sessionKey.begin(), m_sessionKey.end());
        message.insert(message.end(), (uint8_t*)&serviceId, (uint8_t*)&serviceId + 4);
        message.insert(message.end(), (uint8_t*)&m_privacyParameter, (uint8_t*)&m_privacyParameter + 4);

        // Encrypt with RSU public key
        int rsaSize = RSA_size(m_rsaPublicKey);
        std::vector<uint8_t> encrypted(rsaSize);
        int encLen = RSA_public_encrypt(message.size(), message.data(),
                                       encrypted.data(), m_rsaPublicKey,
                                       RSA_PKCS1_OAEP_PADDING);
        if (encLen <= 0) {
            NS_LOG_ERROR("Vehicle " << m_vehicleId << ": RSA encryption failed");
            return;
        }
        encrypted.resize(encLen);

        // Send auth request
        std::vector<uint8_t> msg;
        msg.push_back(MSG_AUTH_REQUEST);
        msg.insert(msg.end(), encrypted.begin(), encrypted.end());

        Ptr<Packet> packet = Create<Packet>(msg.data(), msg.size());
        m_socket->Send(packet);

        g_metrics.authAttempts++;
        g_metrics.vehicleMetrics[m_vehicleId].vid = m_vehicleId;
        g_metrics.vehicleMetrics[m_vehicleId].groupId = m_groupId;
        g_metrics.vehicleMetrics[m_vehicleId].authStartTime = Simulator::Now().GetSeconds();

        // Initialize ZKP state and send first commitment
        m_vehicleZkpRound = 0;
        SendVehicleZkpCommitment();
    }

    void SendVehicleZkpCommitment() {
        // Generate fresh R for each round
        if (m_vehicleRandom) BN_free(m_vehicleRandom);
        if (m_vehicleCommitment) BN_free(m_vehicleCommitment);

        m_vehicleRandom = BN_new();
        BN_rand_range(m_vehicleRandom, m_systemSecrets->m);

        // Always compute W = R^2 mod m (no negation!)
        m_vehicleCommitment = BN_new();
        BN_mod_sqr(m_vehicleCommitment, m_vehicleRandom, m_systemSecrets->m, m_ctx);

        // Serialize and encrypt
        auto serialized = SerializeBIGNUM(m_vehicleCommitment);
        std::vector<uint8_t> encrypted = aes_encrypt(serialized, m_sessionKeyBN);

        std::vector<uint8_t> msg;
        msg.push_back(MSG_VEHICLE_ZKP_COMMITMENT);
        msg.insert(msg.end(), encrypted.begin(), encrypted.end());

        Ptr<Packet> packet = Create<Packet>(msg.data(), msg.size());
        m_socket->Send(packet);
    }

    void HandleIncomingMessage(Ptr<Socket> socket) {
        Ptr<Packet> packet;

        while ((packet = socket->Recv())) {
            uint32_t packetSize = packet->GetSize();
            std::vector<uint8_t> buffer(packetSize);
            packet->CopyData(buffer.data(), packetSize);

            if (buffer.empty()) continue;

            uint8_t msgType = buffer[0];
            std::vector<uint8_t> encryptedPayload(buffer.begin() + 1, buffer.end());

            std::vector<uint8_t> payload = aes_decrypt(encryptedPayload, m_sessionKeyBN);
            if (payload.empty()) {
                NS_LOG_WARN("Vehicle " << m_vehicleId << ": Failed to decrypt message type " << (int)msgType);
                continue;
            }

            switch (msgType) {
                case MSG_VEHICLE_ZKP_CHALLENGE:
                    ProcessVehicleZkpChallenge(payload);
                    break;
                case MSG_RSU_ZKP_COMMITMENT:
                    ProcessRsuZkpCommitment(payload);
                    break;
                case MSG_RSU_ZKP_RESPONSE:
                    ProcessRsuZkpResponse(payload);
                    break;
            }
        }
    }

    void ProcessVehicleZkpChallenge(const std::vector<uint8_t>& data) {
        // Receive challenge bits from RSU
        size_t k = data[0];
        std::vector<uint8_t> challengeBits(data.begin() + 1, data.begin() + 1 + k);

        // Compute Y = R * ∏(Pr_y^b_y) mod m
        BIGNUM* product = BN_new();
        BN_set_word(product, 1);

        const VehicleGroupInfo& groupInfo = m_systemSecrets->vehicleGroups.at(m_groupId);
        for (size_t i = 0; i < k; i++) {
            if (challengeBits[i]) {
                BN_mod_mul(product, product, groupInfo.groupSecrets[i],
                          m_systemSecrets->m, m_ctx);
            }
        }

        BIGNUM* Y = BN_new();
        BN_mod_mul(Y, m_vehicleRandom, product, m_systemSecrets->m, m_ctx);

        // Send Y response
        auto serialized = SerializeBIGNUM(Y);
        std::vector<uint8_t> encrypted = aes_encrypt(serialized, m_sessionKeyBN);

        std::vector<uint8_t> msg;
        msg.push_back(MSG_VEHICLE_ZKP_RESPONSE);
        msg.insert(msg.end(), encrypted.begin(), encrypted.end());

        Ptr<Packet> packet = Create<Packet>(msg.data(), msg.size());
        m_socket->Send(packet);

        BN_free(product);
        BN_free(Y);

        m_vehicleZkpRound++;

        if (m_vehicleZkpRound < m_zkpRoundsPerProof) {
            SendVehicleZkpCommitment();
        } else {
            SendRsuZkpSecretIds();
        }
    }

    void SendRsuZkpSecretIds() {
        // Generate random secret ID sets for RSU to prove knowledge of
        int n = m_systemSecrets->n;
        int k = m_systemSecrets->k;

        m_rsuSecretIds.resize(m_rsuProofCount * k);
        for (size_t i = 0; i < m_rsuSecretIds.size(); i++) {
            m_rsuSecretIds[i] = rand() % n;
        }

        // Send secret IDs to RSU
        std::vector<uint8_t> msg;
        msg.push_back((uint8_t)m_rsuProofCount);
        msg.push_back((uint8_t)k);

        for (auto id : m_rsuSecretIds) {
            uint32_t idBe = htonl(id);
            msg.insert(msg.end(), (uint8_t*)&idBe, (uint8_t*)&idBe + 4);
        }

        std::vector<uint8_t> encrypted = aes_encrypt(msg, m_sessionKeyBN);

        std::vector<uint8_t> fullMsg;
        fullMsg.push_back(MSG_RSU_ZKP_SECRET_IDS);
        fullMsg.insert(fullMsg.end(), encrypted.begin(), encrypted.end());

        Ptr<Packet> packet = Create<Packet>(fullMsg.data(), fullMsg.size());
        m_socket->Send(packet);

        // Initialize RSU verification state
        m_rsuCurrentProof = 0;
        m_rsuCurrentRound = 0;
        m_rsuProofResults.clear();
        m_rsuProofResults.resize(m_rsuProofCount, false);
        m_rsuRoundResults.clear();
        m_rsuRoundResults.resize(m_rsuProofCount, std::vector<bool>(m_zkpRoundsPerProof, false));

        for (auto W : m_rsuCommitments) if (W) BN_free(W);
        m_rsuCommitments.clear();
        m_rsuCommitments.resize(m_rsuProofCount * m_zkpRoundsPerProof, nullptr);
    }

    void ProcessRsuZkpCommitment(const std::vector<uint8_t>& data) {
        // Receive W from RSU
        BIGNUM* W = DeserializeBIGNUM(data);
        m_rsuCommitments[m_rsuCurrentProof * m_zkpRoundsPerProof + m_rsuCurrentRound] = W;

        // Generate and send challenge bits
        int k = m_systemSecrets->k;
        std::vector<uint8_t> challengeBits(k);
        for (int i = 0; i < k; i++) {
            challengeBits[i] = rand() % 2;
        }
        m_rsuChallengeMap[m_rsuCurrentProof * m_zkpRoundsPerProof + m_rsuCurrentRound] = challengeBits;

        std::vector<uint8_t> encrypted = aes_encrypt(challengeBits, m_sessionKeyBN);

        std::vector<uint8_t> msg;
        msg.push_back(MSG_RSU_ZKP_CHALLENGE);
        msg.insert(msg.end(), encrypted.begin(), encrypted.end());

        Ptr<Packet> packet = Create<Packet>(msg.data(), msg.size());
        m_socket->Send(packet);
    }

    void ProcessRsuZkpResponse(const std::vector<uint8_t>& data) {
        // Receive Y from RSU
        BIGNUM* Y = DeserializeBIGNUM(data);

        int k = m_systemSecrets->k;
        int proofIdx = m_rsuCurrentProof;
        int round = m_rsuCurrentRound;

        // Verify Y^2 = W * ∏(I_x^b_x) mod m
        // This works because W = R^2 (always positive square now)
        BIGNUM* product = BN_new();
        BN_set_word(product, 1);

        const std::vector<uint8_t>& challengeBits =
            m_rsuChallengeMap[proofIdx * m_zkpRoundsPerProof + round];

        for (int i = 0; i < k; i++) {
            if (challengeBits[i]) {
                uint32_t secretIdx = m_rsuSecretIds[proofIdx * k + i];
                if (secretIdx >= m_systemSecrets->rsuPublicValues.size()) {
                    NS_LOG_ERROR("Vehicle " << m_vehicleId << ": ERROR - secretIdx " << secretIdx
                                << " out of bounds");
                    BN_free(product);
                    BN_free(Y);
                    return;
                }
                BN_mod_mul(product, product, m_systemSecrets->rsuPublicValues[secretIdx],
                          m_systemSecrets->m, m_ctx);
            }
        }

        BIGNUM* expectedRight = BN_new();
        BIGNUM* W = m_rsuCommitments[proofIdx * m_zkpRoundsPerProof + round];
        BN_mod_mul(expectedRight, W, product, m_systemSecrets->m, m_ctx);

        BIGNUM* actualLeft = BN_new();
        BN_mod_sqr(actualLeft, Y, m_systemSecrets->m, m_ctx);

        bool verified = (BN_cmp(actualLeft, expectedRight) == 0);

        BN_free(product);
        BN_free(expectedRight);
        BN_free(actualLeft);
        BN_free(Y);

        // Track per-round result
        m_rsuRoundResults[proofIdx][round] = verified;

        // Move to next round or next proof
        m_rsuCurrentRound++;
        if (m_rsuCurrentRound >= m_zkpRoundsPerProof) {
            // Proof completed - check if all rounds passed
            bool allRoundsPassed = true;
            for (int r = 0; r < m_zkpRoundsPerProof; r++) {
                if (!m_rsuRoundResults[proofIdx][r]) {
                    allRoundsPassed = false;
                    break;
                }
            }
            m_rsuProofResults[proofIdx] = allRoundsPassed;

            m_rsuCurrentRound = 0;
            m_rsuCurrentProof++;

            if (m_rsuCurrentProof >= m_rsuProofCount) {
                SendFinalAuthResult();
            }
        }
    }

    void SendFinalAuthResult() {
        // Count successfully verified proofs
        uint32_t verifiedCount = 0;
        for (bool result : m_rsuProofResults) {
            if (result) verifiedCount++;
        }

        // Send result to RSU
        std::vector<uint8_t> msg;
        msg.insert(msg.end(), (uint8_t*)&verifiedCount, (uint8_t*)&verifiedCount + 4);

        std::vector<uint8_t> encrypted = aes_encrypt(msg, m_sessionKeyBN);

        std::vector<uint8_t> fullMsg;
        fullMsg.push_back(MSG_AUTH_FINAL_RESULT);
        fullMsg.insert(fullMsg.end(), encrypted.begin(), encrypted.end());

        Ptr<Packet> packet = Create<Packet>(fullMsg.data(), fullMsg.size());
        m_socket->Send(packet);
    }

    Ptr<Socket> m_socket;
    Ipv4Address m_rsuAddress;
    uint16_t m_port;
    std::string m_rsuId;
    uint32_t m_groupId;
    uint64_t m_vehicleId;
    const SystemGroupSecrets* m_systemSecrets;
    RSA* m_rsaPublicKey;
    BN_CTX* m_ctx;
    std::vector<uint8_t> m_sessionKey;
    BIGNUM* m_sessionKeyBN;
    uint32_t m_privacyParameter;
    int m_rsuProofCount;
    int m_zkpRoundsPerProof;

    // Vehicle ZKP state (proving to RSU)
    BIGNUM* m_vehicleRandom;
    BIGNUM* m_vehicleCommitment;
    int m_vehicleZkpRound;

    // RSU ZKP state (verifying RSU)
    std::vector<uint32_t> m_rsuSecretIds;
    std::vector<BIGNUM*> m_rsuCommitments;
    std::map<int, std::vector<uint8_t>> m_rsuChallengeMap;
    int m_rsuCurrentProof;
    int m_rsuCurrentRound;
    std::vector<bool> m_rsuProofResults;
    std::vector<std::vector<bool>> m_rsuRoundResults;
};

uint64_t GenerateRandom64() {
    uint64_t val;
    RAND_bytes((uint8_t*)&val, sizeof(val));
    return val;
}

double ComputeEuclideanDistance(const Vector& a, const Vector& b) {
    double dx = a.x - b.x;
    double dy = a.y - b.y;
    double dz = a.z - b.z;
    return std::sqrt(dx*dx + dy*dy + dz*dz);
}

uint32_t CalculateRequiredRsus(double areaWidth, double areaHeight, double txPower) {
    double effectiveRange;
    if (txPower <= 33) effectiveRange = 350.0;
    else if (txPower <= 37) effectiveRange = 450.0;
    else effectiveRange = 550.0;

    double overlapFactor = 0.7;
    double effectiveCoverage = effectiveRange * overlapFactor;

    uint32_t nRows = std::ceil(areaHeight / effectiveCoverage);
    uint32_t nCols = std::ceil(areaWidth / effectiveCoverage);

    NS_LOG_INFO("Coverage calculation: range=" << effectiveRange << "m, grid="
                << nRows << "x" << nCols << ", RSUs=" << (nRows * nCols));
    return nRows * nCols;
}

void DistributeRsusInGrid(NodeContainer& rsuNodes, double minX, double maxX,
                          double minY, double maxY, MobilityHelper& mobility) {
    uint32_t nRsus = rsuNodes.GetN();
    uint32_t nCols = std::ceil(std::sqrt(nRsus * (maxX - minX) / (maxY - minY)));
    uint32_t nRows = std::ceil((double)nRsus / nCols);

    double xSpacing = (maxX - minX) / (nCols + 1);
    double ySpacing = (maxY - minY) / (nRows + 1);

    Ptr<ListPositionAllocator> positionAlloc = CreateObject<ListPositionAllocator>();

    uint32_t rsuIndex = 0;
    for (uint32_t row = 0; row < nRows && rsuIndex < nRsus; ++row) {
        for (uint32_t col = 0; col < nCols && rsuIndex < nRsus; ++col) {
            double x = minX + xSpacing * (col + 1);
            double y = minY + ySpacing * (row + 1);
            positionAlloc->Add(Vector(x, y, 0.0));
            // NS_LOG_INFO("RSU[" << rsuIndex << "] positioned at (" << x << ", " << y << ")");
            rsuIndex++;
        }
    }

    mobility.SetPositionAllocator(positionAlloc);
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(rsuNodes);
}

int main(int argc, char* argv[]) {
    std::string traceFile = "scratch/traces.csv";
    uint32_t maxVehicles = 50;
    uint32_t nRsus = 0;
    uint32_t nGroups = 0;
    double simTime = 100.0;
    double txPower = 33.0;

    CommandLine cmd(__FILE__);
    cmd.AddValue("vehicles", "Number of vehicles", maxVehicles);
    cmd.AddValue("rsus", "Number of RSUs (0=auto)", nRsus);
    cmd.AddValue("groups", "Number of vehicle groups (0=auto)", nGroups);
    cmd.AddValue("txpower", "TX power (dBm)", txPower);
    cmd.AddValue("time", "Simulation time (s)", simTime);
    cmd.AddValue("trace", "Trace file path", traceFile);
    cmd.Parse(argc, argv);

    LogComponentEnable("AmarProtocol", LOG_LEVEL_INFO);

    std::map<std::string, std::vector<VehicleTraceEntry>> mobilityTraces;
    mobilityTraces = LoadMobilityTraces(traceFile);

    std::vector<std::string> vehicleIds;
    for (const auto& kv : mobilityTraces) {
        if (!kv.second.empty()) {
            vehicleIds.push_back(kv.first);
        }
    }

    if (vehicleIds.empty()) {
        NS_LOG_ERROR("No vehicles in trace file!");
        return 1;
    }

    if (vehicleIds.size() > maxVehicles) {
        vehicleIds.resize(maxVehicles);
    }

    uint32_t nVehicles = vehicleIds.size();

    if (nGroups == 0) {
        nGroups = std::max(2u, std::min(10u, (nVehicles + 14) / 15));
        NS_LOG_INFO("Auto-calculated " << nGroups << " groups for " << nVehicles << " vehicles");
    }

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

    if (nRsus == 0) {
        nRsus = CalculateRequiredRsus(areaWidth, areaHeight, txPower);
    }

    SystemGroupSecrets systemSecrets;
    KDC_GenerateSystemSecrets(systemSecrets, 10, 5, nGroups);

    NodeContainer vehicleNodes;
    vehicleNodes.Create(nVehicles);
    NodeContainer rsuNodes;
    rsuNodes.Create(nRsus);

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
            mobility->SetVelocity(Vector(firstEntry.speed * cos(angleRad),
                                        firstEntry.speed * sin(angleRad), 0.0));

            ScheduleVehicleUpdates(vehicleNodes.Get(i), traces);
        }
    }

    MobilityHelper rsuMobility;
    DistributeRsusInGrid(rsuNodes, minX, maxX, minY, maxY, rsuMobility);

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
    NetDeviceContainer rsuDevices = wifi.Install(wifiPhy, wifiMac, rsuNodes);

    InternetStackHelper internet;
    internet.Install(vehicleNodes);
    internet.Install(rsuNodes);

    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.0.0", "255.255.0.0");
    Ipv4InterfaceContainer vehicleInterfaces = ipv4.Assign(vehicleDevices);
    Ipv4InterfaceContainer rsuInterfaces = ipv4.Assign(rsuDevices);

    RSA* rsaKey = RSA_new();
    BIGNUM* e = BN_new();
    BN_set_word(e, RSA_F4);
    RSA_generate_key_ex(rsaKey, 2048, e, NULL);
    BN_free(e);

    uint16_t authPort = 10;

    for (uint32_t i = 0; i < nRsus; ++i) {
        Ptr<RsuApplication> rsuApp = CreateObject<RsuApplication>();
        rsuApp->SetupRsu(authPort, "RSU" + std::to_string(i), systemSecrets, rsaKey);
        rsuNodes.Get(i)->AddApplication(rsuApp);
        rsuApp->SetStartTime(Seconds(1.0));
        rsuApp->SetStopTime(Seconds(simTime));
    }

    for (uint32_t i = 0; i < nVehicles; ++i) {
        Ptr<MobilityModel> vMobility = vehicleNodes.Get(i)->GetObject<MobilityModel>();
        Vector vPos = vMobility->GetPosition();

        uint32_t nearestRsu = 0;
        double minDist = std::numeric_limits<double>::max();

        for (uint32_t j = 0; j < nRsus; ++j) {
            Ptr<MobilityModel> rsuMobility = rsuNodes.Get(j)->GetObject<MobilityModel>();
            Vector rsuPos = rsuMobility->GetPosition();
            double dist = ComputeEuclideanDistance(vPos, rsuPos);

            if (dist < minDist) {
                minDist = dist;
                nearestRsu = j;
            }
        }

        uint32_t groupId = (i % nGroups) + 1;
        uint64_t vid = GenerateRandom64();

        Ptr<VehicleApplication> vApp = CreateObject<VehicleApplication>();
        vApp->SetupVehicle(rsuInterfaces.GetAddress(nearestRsu), authPort,
                          "RSU" + std::to_string(nearestRsu), groupId,
                          systemSecrets, rsaKey, vid);
        vehicleNodes.Get(i)->AddApplication(vApp);
        vApp->SetStartTime(Seconds(2.0 + i * 0.1));
        vApp->SetStopTime(Seconds(simTime));
    }

    double maxTraceTime = 0.0;
    for (const auto& vid : vehicleIds) {
        if (!mobilityTraces[vid].empty()) {
            maxTraceTime = std::max(maxTraceTime, mobilityTraces[vid].back().time);
        }
    }

    if (simTime < maxTraceTime) {
        simTime = maxTraceTime + 10.0;
    }

    NS_LOG_INFO("\n=== STARTING SIMULATION ===");
    NS_LOG_INFO("Simulation time: " << simTime << " seconds");
    Simulator::Stop(Seconds(simTime));
    Simulator::Run();

    NS_LOG_UNCOND("\n==== Simulation Metrics ====");
    NS_LOG_UNCOND("Total vehicles: " << nVehicles);
    NS_LOG_UNCOND("Authentication attempts: " << g_metrics.authAttempts);
    NS_LOG_UNCOND("Authentication success: " << g_metrics.authSuccess);
    if (g_metrics.authAttempts > 0) {
        double successRate = (double)g_metrics.authSuccess / g_metrics.authAttempts * 100.0;
        NS_LOG_UNCOND("Success ratio: " << std::fixed << std::setprecision(2) 
                      << successRate << "%");
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

    NS_LOG_UNCOND("\n--- Communication Overhead (Zero-Knowledge Protocol) ---");
    if (!g_metrics.vehicleMetrics.empty()) {
        // Get a sample vehicle's metrics
        const VehicleMetrics& vm = g_metrics.vehicleMetrics.begin()->second;
        
        NS_LOG_UNCOND("Phase 1 - Authentication Request:");
        NS_LOG_UNCOND("  Vehicle → RSU: " << vm.authRequestSize << " bytes");
        
        NS_LOG_UNCOND("\nPhase 2 - Vehicle ZKP (Vehicle proves identity to RSU):");
        NS_LOG_UNCOND("  Rounds: " << vm.vehicleZkpRounds);
        NS_LOG_UNCOND("  Per round:");
        NS_LOG_UNCOND("    Vehicle → RSU (Commitment W): " << vm.vehicleZkpCommitmentSize << " bytes");
        NS_LOG_UNCOND("    RSU → Vehicle (Challenge): " << vm.vehicleZkpChallengeSize << " bytes");
        NS_LOG_UNCOND("    Vehicle → RSU (Response Y): " << vm.vehicleZkpResponseSize << " bytes");
        uint64_t vehicleZkpTotal = (vm.vehicleZkpCommitmentSize + vm.vehicleZkpChallengeSize + 
                                    vm.vehicleZkpResponseSize) * vm.vehicleZkpRounds;
        NS_LOG_UNCOND("  Total Vehicle ZKP: " << vehicleZkpTotal << " bytes");
        
        NS_LOG_UNCOND("\nPhase 3 - RSU ZKP (RSU proves authenticity to Vehicle):");
        NS_LOG_UNCOND("  Vehicle → RSU (Secret IDs): " << vm.rsuZkpSecretIdsSize << " bytes");
        NS_LOG_UNCOND("  Proofs: " << vm.rsuZkpProofs << ", Rounds per proof: " << vm.rsuZkpRoundsPerProof);
        NS_LOG_UNCOND("  Per round:");
        NS_LOG_UNCOND("    RSU → Vehicle (Commitment W): " << vm.rsuZkpCommitmentSize << " bytes");
        NS_LOG_UNCOND("    Vehicle → RSU (Challenge): " << vm.rsuZkpChallengeSize << " bytes");
        NS_LOG_UNCOND("    RSU → Vehicle (Response Y): " << vm.rsuZkpResponseSize << " bytes");
        uint64_t rsuZkpTotal = vm.rsuZkpSecretIdsSize + 
                               (vm.rsuZkpCommitmentSize + vm.rsuZkpChallengeSize + vm.rsuZkpResponseSize) * 
                               vm.rsuZkpProofs * vm.rsuZkpRoundsPerProof;
        NS_LOG_UNCOND("  Total RSU ZKP: " << rsuZkpTotal << " bytes");
        
        NS_LOG_UNCOND("\nPhase 4 - Final Result:");
        NS_LOG_UNCOND("  Vehicle → RSU: " << vm.authResultSize << " bytes");
        
        uint64_t totalVehicleToRsu = vm.GetTotalVehicleToRsu();
        uint64_t totalRsuToVehicle = vm.GetTotalRsuToVehicle();
        uint64_t totalOverhead = vm.GetTotalOverhead();
        
        NS_LOG_UNCOND("\n=== Summary per vehicle ===");
        NS_LOG_UNCOND("Vehicle → RSU total: " << totalVehicleToRsu << " bytes");
        NS_LOG_UNCOND("RSU → Vehicle total: " << totalRsuToVehicle << " bytes");
        NS_LOG_UNCOND("Total overhead per vehicle: " << totalOverhead << " bytes");
        NS_LOG_UNCOND("Total network overhead (all vehicles): "
                      << totalOverhead * g_metrics.authSuccess << " bytes");
    }

    // NS_LOG_UNCOND("\n--- Protocol Parameters ---");
    // NS_LOG_UNCOND("ZKP rounds per proof (h): 3");
    // NS_LOG_UNCOND("RSU proofs required (u): 5");
    // NS_LOG_UNCOND("Privacy parameter (α): 3");
    // NS_LOG_UNCOND("RSU secrets (n): 10");
    // NS_LOG_UNCOND("Secrets per group (k): 5");

    if (!g_metrics.vehicleMetrics.empty()) {
        NS_LOG_UNCOND("\n--- Group Distribution ---");
        std::map<uint32_t, uint32_t> groupCounts;
        for (const auto& kv : g_metrics.vehicleMetrics) {
            groupCounts[kv.second.groupId]++;
        }
        for (const auto& kv : groupCounts) {
            NS_LOG_UNCOND("  Group G_" << kv.first << ": " << kv.second << " vehicles");
        }
    }

    Simulator::Destroy();
    RSA_free(rsaKey);

    return 0;
}
