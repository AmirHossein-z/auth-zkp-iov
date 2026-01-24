#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-helper.h"
#include "ns3/network-module.h"
#include "ns3/yans-wifi-helper.h"
#include "ns3/wifi-module.h"
#include "ns3/constant-velocity-mobility-model.h"

// you should add 'crypto' and 'ssl' to cmakelist.txt file for linking
#include <cstdint>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <random>
#include <vector>
#include <map>
#include <fstream>
#include <sstream>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("IoVAuthentication");

struct VehicleMetrics {
    uint64_t regMsg1 = 0;
    uint64_t regMsg2 = 0;
    uint64_t authMsg1 = 0;
    uint64_t authMsg2 = 0;
    double authStartTime = 0;
    double authEndTime = 0;
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
    double time;              // timestep_time
    std::string vehicleId;    // vehicle_id
    double x;                 // vehicle_x
    double y;                 // vehicle_y
    double speed;             // vehicle_speed
    std::string vehicleType;  // vehicle_type bus, vehicle,...
    double angle;             // vehicle_angle
    std::string lane;         // vehicle_lane
};

VehicleTraceEntry ParseTraceLine(const std::string& line)
{
    VehicleTraceEntry entry;
    std::istringstream ss(line);
    std::string token;
    std::vector<std::string> tokens;

    while (std::getline(ss, token, ';'))
    {
        // Remove leading/trailing whitespace
        token.erase(0, token.find_first_not_of(" \t\r\n"));
        token.erase(token.find_last_not_of(" \t\r\n") + 1);
        tokens.push_back(token);
    }

    // Expected format: 0: timestep_time, 1: vehicle_slope, 2: vehicle_lane, 3: vehicle_angle, 4: vehicle_type
    // 5: vehicle_pos, 6: vehicle_y, 7: vehicle_x, 8: vehicle_speed, 9: vehicle_id

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
            entry.vehicleId = "";  // Mark as invalid
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

// Schedule all position updates for a vehicle
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
            // Check vehicle type if filter is specified
            if (typeFilter.empty() || kv.second[0].vehicleType == typeFilter)
            {
                vehicleIds.push_back(kv.first);
            }
        }
    }

    return vehicleIds;
}

struct RegistrationResponse
{
    std::vector<uint8_t> kpub;
    std::vector<uint8_t> r;
    std::vector<uint8_t> u;
    std::vector<uint8_t> v;
    std::vector<uint8_t> h;
};

struct AuthenticationRequest
{
    std::vector<uint8_t> A;
    std::vector<uint8_t> phi;
    std::vector<uint8_t> T1;
    std::vector<uint8_t> T2;
    std::vector<uint8_t> T3;
};

struct VehicleRegistrationData
{
    uint64_t VID;
    std::vector<uint8_t> kpub;
    std::vector<uint8_t> r;
    std::vector<uint8_t> u;
    std::vector<uint8_t> v;
    std::vector<uint8_t> h;
};

struct TARegistrationData
{
    uint64_t VID;
    uint64_t kesa1;
    uint64_t kesa2;
    std::vector<uint8_t> kpub;
    std::vector<uint8_t> r;
};

uint64_t GenerateRandom64()
{
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;
    return dis(gen);
}


BIGNUM* uint64_to_bn(uint64_t value)
{
    BIGNUM* bn = BN_new();
    BN_set_word(bn, value);
    return bn;
}

std::vector<uint8_t> SerializePoint(const EC_GROUP* group, const EC_POINT* point)
{
    size_t len = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
    std::vector<uint8_t> buffer(len);
    EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, buffer.data(), len, NULL);
    return buffer;
}

std::vector<uint8_t> SerializeBIGNUM(const BIGNUM* bn)
{
    int len = BN_num_bytes(bn);
    std::vector<uint8_t> buffer(len);
    BN_bn2bin(bn, buffer.data());
    return buffer;
}

EC_POINT* DeserializePoint(const EC_GROUP* group, const std::vector<uint8_t>& data)
{
    EC_POINT* point = EC_POINT_new(group);
    EC_POINT_oct2point(group, point, data.data(), data.size(), NULL);
    return point;
}

BIGNUM* DeserializeBIGNUM(const std::vector<uint8_t>& data)
{
    return BN_bin2bn(data.data(), data.size(), NULL);
}

std::vector<uint8_t> ComputeHash(const std::vector<uint8_t>& G_bytes,
                                  const std::vector<uint8_t>& A_bytes,
                                  uint64_t VID,
                                  const std::vector<uint8_t>& kpub_bytes)
{
    std::vector<uint8_t> data;
    data.insert(data.end(), G_bytes.begin(), G_bytes.end());
    data.insert(data.end(), A_bytes.begin(), A_bytes.end());

    uint8_t vid_bytes[8];
    memcpy(vid_bytes, &VID, 8);
    data.insert(data.end(), vid_bytes, vid_bytes + 8);

    data.insert(data.end(), kpub_bytes.begin(), kpub_bytes.end());

    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), hash.data());

    return hash;
}

// Hash function for authentication response H(T1 || T2 || T3 || VID)
std::vector<uint8_t> ComputeAuthResponseHash(const std::vector<uint8_t>& T1_bytes,
                                              const std::vector<uint8_t>& T2_bytes,
                                              const std::vector<uint8_t>& T3_bytes,
                                              uint64_t VID)
{
    std::vector<uint8_t> data;
    data.insert(data.end(), T1_bytes.begin(), T1_bytes.end());
    data.insert(data.end(), T2_bytes.begin(), T2_bytes.end());
    data.insert(data.end(), T3_bytes.begin(), T3_bytes.end());

    uint8_t vid_bytes[8];
    memcpy(vid_bytes, &VID, 8);
    data.insert(data.end(), vid_bytes, vid_bytes + 8);

    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), hash.data());

    return hash;
}

RegistrationResponse HandleRegistration(uint64_t vehicleVID, TARegistrationData& storedData)
{
    RegistrationResponse response;

    uint64_t kesa1 = GenerateRandom64();
    uint64_t kesa2 = GenerateRandom64();

    // NS_LOG_INFO("TA generated kesa1: " << kesa1 << ", kesa2: " << kesa2);

    EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (eckey == NULL) {
        NS_LOG_ERROR("Failed to create EC_KEY");
        return response;
    }

    if (!EC_KEY_generate_key(eckey)) {
        NS_LOG_ERROR("Failed to generate EC key");
        EC_KEY_free(eckey);
        return response;
    }

    const EC_GROUP* group = EC_KEY_get0_group(eckey);
    const BIGNUM* r_bn = EC_KEY_get0_private_key(eckey);
    const EC_POINT* Kpub = EC_KEY_get0_public_key(eckey);

    response.kpub = SerializePoint(group, Kpub);
    response.r = SerializeBIGNUM(r_bn);

    BIGNUM* kesa2_bn = uint64_to_bn(kesa2);
    EC_POINT* u_point = EC_POINT_new(group);
    EC_POINT_mul(group, u_point, kesa2_bn, NULL, NULL, NULL);
    response.u = SerializePoint(group, u_point);

    BIGNUM* kesa1_bn = uint64_to_bn(kesa1);
    EC_POINT* v_point = EC_POINT_new(group);
    EC_POINT_mul(group, v_point, kesa1_bn, NULL, NULL, NULL);
    response.v = SerializePoint(group, v_point);

    BIGNUM* product = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    BN_mod_mul(product, kesa1_bn, kesa2_bn, EC_GROUP_get0_order(group), ctx);

    EC_POINT* h_point = EC_POINT_new(group);
    EC_POINT_mul(group, h_point, product, NULL, NULL, NULL);
    response.h = SerializePoint(group, h_point);

    // Store registration data for later authentication
    storedData.VID = vehicleVID;
    storedData.kesa1 = kesa1;
    storedData.kesa2 = kesa2;
    storedData.kpub = response.kpub;
    storedData.r = response.r;

    BN_free(kesa1_bn);
    BN_free(kesa2_bn);
    BN_free(product);
    BN_CTX_free(ctx);
    EC_POINT_free(u_point);
    EC_POINT_free(v_point);
    EC_POINT_free(h_point);
    EC_KEY_free(eckey);

    return response;
}

class TaApplication : public Application
{
public:
    TaApplication() : m_socket(0), m_port(9), m_authPort(10) {}
    virtual ~TaApplication() { m_socket = 0; m_authSocket = 0; }


    void Setup(uint16_t port, uint16_t authPort, std::string taId)
    {
        m_port = port;
        m_authPort = authPort;
        m_taId = taId;
    }

private:
    virtual void StartApplication()
    {
        // Registration socket
        m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
        InetSocketAddress local = InetSocketAddress(Ipv4Address::GetAny(), m_port);
        m_socket->Bind(local);
        m_socket->SetRecvCallback(MakeCallback(&TaApplication::HandleRegistration, this));

        // Authentication socket
        m_authSocket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
        InetSocketAddress authLocal = InetSocketAddress(Ipv4Address::GetAny(), m_authPort);
        m_authSocket->Bind(authLocal);
        m_authSocket->SetRecvCallback(MakeCallback(&TaApplication::HandleAuthentication, this));

        // NS_LOG_INFO("TA Application started on port " << m_port << " (registration) and " << m_authPort << " (authentication)");
    }

    virtual void StopApplication()
    {
        if (m_socket) m_socket->Close();
        if (m_authSocket) m_authSocket->Close();
    }

    void HandleRegistration(Ptr<Socket> socket)
    {
        Ptr<Packet> packet;
        Address from;

        while ((packet = socket->RecvFrom(from)))
        {
            uint8_t buffer[8];
            packet->CopyData(buffer, 8);
            uint64_t vehicleVID = *reinterpret_cast<uint64_t*>(buffer);

            g_metrics.vehicleMetrics[vehicleVID].regMsg1 = packet->GetSize();

            TARegistrationData storedData;
            RegistrationResponse regResponse = ::HandleRegistration(vehicleVID, storedData);
            m_registrationDB[storedData.kpub] = storedData;

            SendRegistrationResponse(socket, from, regResponse, vehicleVID);
        }
    }

    void HandleAuthentication(Ptr<Socket> socket)
    {
        Ptr<Packet> packet;
        Address from;

        while ((packet = socket->RecvFrom(from)))
        {
            // NS_LOG_INFO("TA received authentication request");

            // Parse authentication request
            uint32_t packetSize = packet->GetSize();
            std::vector<uint8_t> buffer(packetSize);
            packet->CopyData(buffer.data(), packetSize);

            AuthenticationRequest authReq = ParseAuthRequest(buffer);

            // Verify authentication
            bool authenticated = VerifyAuthentication(authReq);

            if (authenticated)
            {
                // NS_LOG_INFO("=== Authentication Successful ===");
                SendAuthResponse(socket, from,authReq.T1, authReq.T2, authReq.T3);
            }
            else
            {
                // NS_LOG_ERROR("=== Authentication Failed ===");
            }
        }
    }

    AuthenticationRequest ParseAuthRequest(const std::vector<uint8_t>& buffer)
    {
        AuthenticationRequest req;
        size_t offset = 0;

        // Extract A
        uint16_t a_size = buffer[offset] | (buffer[offset + 1] << 8);
        offset += 2;
        req.A = std::vector<uint8_t>(buffer.begin() + offset, buffer.begin() + offset + a_size);
        offset += a_size;

        // Extract phi
        uint16_t phi_size = buffer[offset] | (buffer[offset + 1] << 8);
        offset += 2;
        req.phi = std::vector<uint8_t>(buffer.begin() + offset, buffer.begin() + offset + phi_size);
        offset += phi_size;

        // Extract T1
        uint16_t t1_size = buffer[offset] | (buffer[offset + 1] << 8);
        offset += 2;
        req.T1 = std::vector<uint8_t>(buffer.begin() + offset, buffer.begin() + offset + t1_size);
        offset += t1_size;

        // Extract T2
        uint16_t t2_size = buffer[offset] | (buffer[offset + 1] << 8);
        offset += 2;
        req.T2 = std::vector<uint8_t>(buffer.begin() + offset, buffer.begin() + offset + t2_size);
        offset += t2_size;

        // Extract T3
        uint16_t t3_size = buffer[offset] | (buffer[offset + 1] << 8);
        offset += 2;
        req.T3 = std::vector<uint8_t>(buffer.begin() + offset, buffer.begin() + offset + t3_size);

        return req;
    }

    bool VerifyAuthentication(const AuthenticationRequest& authReq)
    {
        EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
        const EC_GROUP* group = EC_KEY_get0_group(eckey);
        BN_CTX* ctx = BN_CTX_new();

        // Deserialize points
        EC_POINT* T1 = DeserializePoint(group, authReq.T1);
        EC_POINT* T2 = DeserializePoint(group, authReq.T2);
        EC_POINT* T3 = DeserializePoint(group, authReq.T3);
        EC_POINT* A = DeserializePoint(group, authReq.A);
        BIGNUM* phi = DeserializeBIGNUM(authReq.phi);

        // Calculate k_computed_pub = T3 - (kesa1 * T1 + kesa2 * T2)
        EC_POINT* temp1 = EC_POINT_new(group);
        EC_POINT* temp2 = EC_POINT_new(group);
        EC_POINT* k_computed_pub = EC_POINT_new(group);

        // Find matching registration in database
        TARegistrationData* matchedData = nullptr;
        for (auto& pair : m_registrationDB)
        {
            BIGNUM* kesa1_bn = uint64_to_bn(pair.second.kesa1);
            BIGNUM* kesa2_bn = uint64_to_bn(pair.second.kesa2);

            // temp1 = kesa1 * T1
            EC_POINT_mul(group, temp1, NULL, T1, kesa1_bn, ctx);
            // temp2 = kesa2 * T2
            EC_POINT_mul(group, temp2, NULL, T2, kesa2_bn, ctx);
            // temp1 = temp1 + temp2
            EC_POINT_add(group, temp1, temp1, temp2, ctx);
            // k_computed_pub = T3 - temp1
            EC_POINT_invert(group, temp1, ctx);
            EC_POINT_add(group, k_computed_pub, T3, temp1, ctx);

            // Compare with stored kpub
            EC_POINT* stored_kpub = DeserializePoint(group, pair.second.kpub);
            if (EC_POINT_cmp(group, k_computed_pub, stored_kpub, ctx) == 0)
            {
                matchedData = &pair.second;
                EC_POINT_free(stored_kpub);
                BN_free(kesa1_bn);
                BN_free(kesa2_bn);
                break;
            }

            EC_POINT_free(stored_kpub);
            BN_free(kesa1_bn);
            BN_free(kesa2_bn);
        }

        if (!matchedData)
        {
            NS_LOG_ERROR("No matching registration found");
            EC_POINT_free(temp1);
            EC_POINT_free(temp2);
            EC_POINT_free(k_computed_pub);
            EC_POINT_free(T1);
            EC_POINT_free(T2);
            EC_POINT_free(T3);
            EC_POINT_free(A);
            BN_free(phi);
            BN_CTX_free(ctx);
            EC_KEY_free(eckey);
            return false;
        }

        // Get generator point G
        const EC_POINT* G = EC_GROUP_get0_generator(group);
        std::vector<uint8_t> G_bytes = SerializePoint(group, G);

        // Compute sigma = H(G || A || VID || k_computed_pub)
        std::vector<uint8_t> k_computed_pub_bytes = SerializePoint(group, k_computed_pub);
        std::vector<uint8_t> sigma_hash = ComputeHash(G_bytes, authReq.A, matchedData->VID, k_computed_pub_bytes);

        // Convert hash to BIGNUM (use first 32 bytes as scalar)
        BIGNUM* sigma = BN_bin2bn(sigma_hash.data(), sigma_hash.size(), NULL);
        BN_mod(sigma, sigma, EC_GROUP_get0_order(group), ctx);

        // Compute P = phi * G - sigma * k_computed_pub
        EC_POINT* P = EC_POINT_new(group);
        EC_POINT* phi_G = EC_POINT_new(group);
        EC_POINT* sigma_kpub = EC_POINT_new(group);

        EC_POINT_mul(group, phi_G, phi, NULL, NULL, ctx);
        EC_POINT_mul(group, sigma_kpub, NULL, k_computed_pub, sigma, ctx);
        EC_POINT_invert(group, sigma_kpub, ctx);
        EC_POINT_add(group, P, phi_G, sigma_kpub, ctx);

        // Check if P == A
        bool verified = (EC_POINT_cmp(group, P, A, ctx) == 0);

        if (verified)
        {
            m_lastAuthenticatedVID = matchedData->VID;
            m_lastT2 = authReq.T2;
            m_lastT3 = authReq.T3;
            m_lastT1 = authReq.T1;
        }

        // Cleanup
        EC_POINT_free(temp1);
        EC_POINT_free(temp2);
        EC_POINT_free(k_computed_pub);
        EC_POINT_free(T1);
        EC_POINT_free(T2);
        EC_POINT_free(T3);
        EC_POINT_free(A);
        EC_POINT_free(P);
        EC_POINT_free(phi_G);
        EC_POINT_free(sigma_kpub);
        BN_free(phi);
        BN_free(sigma);
        BN_CTX_free(ctx);
        EC_KEY_free(eckey);

        return verified;
    }

    void SendRegistrationResponse(Ptr<Socket> socket, Address from, const RegistrationResponse& regResponse, uint64_t vehicleVID)
    {
        std::vector<uint8_t> responseData;

        uint16_t kpub_size = regResponse.kpub.size();
        responseData.push_back(kpub_size & 0xFF);
        responseData.push_back((kpub_size >> 8) & 0xFF);
        responseData.insert(responseData.end(), regResponse.kpub.begin(), regResponse.kpub.end());

        uint16_t r_size = regResponse.r.size();
        responseData.push_back(r_size & 0xFF);
        responseData.push_back((r_size >> 8) & 0xFF);
        responseData.insert(responseData.end(), regResponse.r.begin(), regResponse.r.end());

        uint16_t u_size = regResponse.u.size();
        responseData.push_back(u_size & 0xFF);
        responseData.push_back((u_size >> 8) & 0xFF);
        responseData.insert(responseData.end(), regResponse.u.begin(), regResponse.u.end());

        uint16_t v_size = regResponse.v.size();
        responseData.push_back(v_size & 0xFF);
        responseData.push_back((v_size >> 8) & 0xFF);
        responseData.insert(responseData.end(), regResponse.v.begin(), regResponse.v.end());

        uint16_t h_size = regResponse.h.size();
        responseData.push_back(h_size & 0xFF);
        responseData.push_back((h_size >> 8) & 0xFF);
        responseData.insert(responseData.end(), regResponse.h.begin(), regResponse.h.end());

        g_metrics.vehicleMetrics[vehicleVID].regMsg2 = responseData.size();

        Ptr<Packet> responsePacket = Create<Packet>(responseData.data(), responseData.size());
        socket->SendTo(responsePacket, 0, from);
    }

    void SendAuthResponse(Ptr<Socket> socket, Address from,const std::vector<uint8_t>& T1, const std::vector<uint8_t>& T2, const std::vector<uint8_t>& T3)
    {
        // Compute H(T1 || T2 || T3 || VID)
        std::vector<uint8_t> authHash = ComputeAuthResponseHash(T1, T2, T3, m_lastAuthenticatedVID);

        g_metrics.vehicleMetrics[m_lastAuthenticatedVID].authMsg2 += authHash.size();

        Ptr<Packet> responsePacket = Create<Packet>(authHash.data(), authHash.size());
        socket->SendTo(responsePacket, 0, from);
    }

    Ptr<Socket> m_socket;
    Ptr<Socket> m_authSocket;
    uint16_t m_port;
    uint16_t m_authPort;
    std::string m_taId;
    std::map<std::vector<uint8_t>, TARegistrationData> m_registrationDB;
    uint64_t m_lastAuthenticatedVID;
    std::vector<uint8_t> m_lastT1;
    std::vector<uint8_t> m_lastT2;
    std::vector<uint8_t> m_lastT3;
};

class VehicleApplication : public Application
{
public:
    VehicleApplication() : m_socket(0), m_authSocket(0), m_port(9), m_authPort(10), m_registered(false) {}
    virtual ~VehicleApplication() { m_socket = 0; m_authSocket = 0; }

    void Setup(Ipv4Address taAddress, uint16_t port, uint16_t authPort, std::string taId)
    {
        m_taAddress = taAddress;
        m_port = port;
        m_authPort = authPort;
        m_vid = GenerateRandom64();
        m_taId = taId;  // Store TA identifier for verification
    }

private:
    virtual void StartApplication()
    {
        // Registration socket
        m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
        m_socket->Bind();
        m_socket->Connect(InetSocketAddress(m_taAddress, m_port));
        m_socket->SetRecvCallback(MakeCallback(&VehicleApplication::HandleRegistrationResponse, this));

        // Authentication socket
        m_authSocket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
        m_authSocket->Bind();
        m_authSocket->Connect(InetSocketAddress(m_taAddress, m_authPort));
        m_authSocket->SetRecvCallback(MakeCallback(&VehicleApplication::HandleAuthResponse, this));

        // NS_LOG_INFO("Vehicle generated VID: " << m_vid);

        // Start with registration
        SendVID();
    }

    virtual void StopApplication()
    {
        if (m_socket) m_socket->Close();
        if (m_authSocket) m_authSocket->Close();
    }

    void SendVID()
    {
        Ptr<Packet> packet = Create<Packet>((uint8_t*)&m_vid, 8);
        m_socket->Send(packet);
    }

    void HandleRegistrationResponse(Ptr<Socket> socket)
    {
        Ptr<Packet> packet;

        while ((packet = socket->Recv()))
        {
            uint32_t packetSize = packet->GetSize();
            std::vector<uint8_t> buffer(packetSize);
            packet->CopyData(buffer.data(), packetSize);

            size_t offset = 0;

            // Extract and store registration data
            uint16_t kpub_size = buffer[offset] | (buffer[offset + 1] << 8);
            offset += 2;
            m_regData.kpub = std::vector<uint8_t>(buffer.begin() + offset, buffer.begin() + offset + kpub_size);
            offset += kpub_size;

            uint16_t r_size = buffer[offset] | (buffer[offset + 1] << 8);
            offset += 2;
            m_regData.r = std::vector<uint8_t>(buffer.begin() + offset, buffer.begin() + offset + r_size);
            offset += r_size;

            uint16_t u_size = buffer[offset] | (buffer[offset + 1] << 8);
            offset += 2;
            m_regData.u = std::vector<uint8_t>(buffer.begin() + offset, buffer.begin() + offset + u_size);
            offset += u_size;

            uint16_t v_size = buffer[offset] | (buffer[offset + 1] << 8);
            offset += 2;
            m_regData.v = std::vector<uint8_t>(buffer.begin() + offset, buffer.begin() + offset + v_size);
            offset += v_size;

            uint16_t h_size = buffer[offset] | (buffer[offset + 1] << 8);
            offset += 2;
            m_regData.h = std::vector<uint8_t>(buffer.begin() + offset, buffer.begin() + offset + h_size);

            m_regData.VID = m_vid;
            m_registered = true;

            // NS_LOG_INFO("=== Vehicle Registration Complete ===");

            // Simulator::Schedule(Seconds(1.0), &VehicleApplication::StartAuthentication, this);
            StartAuthentication();
        }
    }

    void StartAuthentication()
    {
        if (!m_registered)
        {
            NS_LOG_ERROR("Cannot authenticate: not registered");
            return;
        }

        // NS_LOG_INFO("=== Starting Authentication Phase ===");

        EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
        const EC_GROUP* group = EC_KEY_get0_group(eckey);
        BN_CTX* ctx = BN_CTX_new();

        // Generate random F
        BIGNUM* F = BN_new();
        BN_rand_range(F, EC_GROUP_get0_order(group));

        // Calculate A = F * G
        const EC_POINT* G = EC_GROUP_get0_generator(group);
        EC_POINT* A = EC_POINT_new(group);
        EC_POINT_mul(group, A, F, NULL, NULL, ctx);

        std::vector<uint8_t> A_bytes = SerializePoint(group, A);
        std::vector<uint8_t> G_bytes = SerializePoint(group, G);

        // Compute sigma = H(G || A || VID || kpub)
        std::vector<uint8_t> sigma_hash = ComputeHash(G_bytes, A_bytes, m_vid, m_regData.kpub);
        BIGNUM* sigma = BN_bin2bn(sigma_hash.data(), sigma_hash.size(), NULL);
        BN_mod(sigma, sigma, EC_GROUP_get0_order(group), ctx);

        // Compute phi = F + sigma * r
        BIGNUM* r = DeserializeBIGNUM(m_regData.r);
        BIGNUM* phi = BN_new();
        BN_mod_mul(phi, sigma, r, EC_GROUP_get0_order(group), ctx);
        BN_mod_add(phi, F, phi, EC_GROUP_get0_order(group), ctx);

        // Generate random alpha, beta
        BIGNUM* alpha = BN_new();
        BIGNUM* beta = BN_new();
        BN_rand_range(alpha, EC_GROUP_get0_order(group));
        BN_rand_range(beta, EC_GROUP_get0_order(group));

        // Calculate T1 = alpha * u
        EC_POINT* u = DeserializePoint(group, m_regData.u);
        EC_POINT* T1 = EC_POINT_new(group);
        EC_POINT_mul(group, T1, NULL, u, alpha, ctx);

        // Calculate T2 = beta * v
        EC_POINT* v = DeserializePoint(group, m_regData.v);
        EC_POINT* T2 = EC_POINT_new(group);
        EC_POINT_mul(group, T2, NULL, v, beta, ctx);

        // Calculate T3 = kpub + (alpha + beta) * h
        BIGNUM* alpha_plus_beta = BN_new();
        BN_mod_add(alpha_plus_beta, alpha, beta, EC_GROUP_get0_order(group), ctx);

        EC_POINT* h = DeserializePoint(group, m_regData.h);
        EC_POINT* kpub = DeserializePoint(group, m_regData.kpub);
        EC_POINT* temp = EC_POINT_new(group);
        EC_POINT* T3 = EC_POINT_new(group);

        EC_POINT_mul(group, temp, NULL, h, alpha_plus_beta, ctx);
        EC_POINT_add(group, T3, kpub, temp, ctx);

        // Serialize authentication request
        AuthenticationRequest authReq;
        authReq.A = A_bytes;
        authReq.phi = SerializeBIGNUM(phi);
        authReq.T1 = SerializePoint(group, T1);
        authReq.T2 = SerializePoint(group, T2);
        authReq.T3 = SerializePoint(group, T3);

        // Store for verification
        m_lastT1 = authReq.T1;
        m_lastT2 = authReq.T2;
        m_lastT3 = authReq.T3;

        SendAuthRequest(authReq);

        // Cleanup
        BN_free(F);
        BN_free(sigma);
        BN_free(r);
        BN_free(phi);
        BN_free(alpha);
        BN_free(beta);
        BN_free(alpha_plus_beta);
        EC_POINT_free(A);
        EC_POINT_free(T1);
        EC_POINT_free(T2);
        EC_POINT_free(T3);
        EC_POINT_free(u);
        EC_POINT_free(v);
        EC_POINT_free(h);
        EC_POINT_free(kpub);
        EC_POINT_free(temp);
        BN_CTX_free(ctx);
        EC_KEY_free(eckey);
    }

    void SendAuthRequest(const AuthenticationRequest& authReq)
    {
        std::vector<uint8_t> requestData;

        // A
        uint16_t a_size = authReq.A.size();
        requestData.push_back(a_size & 0xFF);
        requestData.push_back((a_size >> 8) & 0xFF);
        requestData.insert(requestData.end(), authReq.A.begin(), authReq.A.end());

        // phi
        uint16_t phi_size = authReq.phi.size();
        requestData.push_back(phi_size & 0xFF);
        requestData.push_back((phi_size >> 8) & 0xFF);
        requestData.insert(requestData.end(), authReq.phi.begin(), authReq.phi.end());

        // T1
        uint16_t t1_size = authReq.T1.size();
        requestData.push_back(t1_size & 0xFF);
        requestData.push_back((t1_size >> 8) & 0xFF);
        requestData.insert(requestData.end(), authReq.T1.begin(), authReq.T1.end());

        // T2
        uint16_t t2_size = authReq.T2.size();
        requestData.push_back(t2_size & 0xFF);
        requestData.push_back((t2_size >> 8) & 0xFF);
        requestData.insert(requestData.end(), authReq.T2.begin(), authReq.T2.end());

        // T3
        uint16_t t3_size = authReq.T3.size();
        requestData.push_back(t3_size & 0xFF);
        requestData.push_back((t3_size >> 8) & 0xFF);
        requestData.insert(requestData.end(), authReq.T3.begin(), authReq.T3.end());

        g_metrics.authAttempts++;
        g_metrics.vehicleMetrics[m_vid].authStartTime = Simulator::Now().GetSeconds();
        g_metrics.vehicleMetrics[m_vid].authMsg1 = requestData.size();

        Ptr<Packet> requestPacket = Create<Packet>(requestData.data(), requestData.size());
        m_authSocket->Send(requestPacket);
    }

    void HandleAuthResponse(Ptr<Socket> socket)
    {
        Ptr<Packet> packet;

        while ((packet = socket->Recv()))
        {
            std::vector<uint8_t> receivedHash(SHA256_DIGEST_LENGTH);
            packet->CopyData(receivedHash.data(), SHA256_DIGEST_LENGTH);

            // Compute expected hash: H(T1 || T2 || T3 || VID)
            std::vector<uint8_t> expectedHash = ComputeAuthResponseHash(m_lastT1, m_lastT2, m_lastT3, m_vid);

            // Verify hash equality
            bool verified = (receivedHash == expectedHash);

            if (verified)
            {
                g_metrics.authSuccess++;
                double endTime = Simulator::Now().GetSeconds();
                g_metrics.vehicleMetrics[m_vid].authEndTime = endTime;

                double latency = endTime - g_metrics.vehicleMetrics[m_vid].authStartTime;
                g_metrics.authDelays.push_back(latency);

                g_metrics.firstAuthStart = std::min(g_metrics.firstAuthStart,
                                                    g_metrics.vehicleMetrics[m_vid].authStartTime);
                g_metrics.lastAuthEnd = std::max(g_metrics.lastAuthEnd, endTime);

            }
            else
            {
            }
        }
    }

    Ptr<Socket> m_socket;
    Ptr<Socket> m_authSocket;
    Ipv4Address m_taAddress;
    uint16_t m_port;
    uint16_t m_authPort;
    uint64_t m_vid;
    std::string m_taId;  // Added TA identifier
    VehicleRegistrationData m_regData;
    bool m_registered;
    std::vector<uint8_t> m_lastT1;
    std::vector<uint8_t> m_lastT2;
    std::vector<uint8_t> m_lastT3;
};

uint32_t CalculateRequiredTAs(double areaWidth, double areaHeight, double txPower)
{
    // Estimate effective range based on tx power (in dBm)
    // 33 dBm ≈ 300-400m, 40 dBm ≈ 500-600m in urban environments
    double effectiveRange;
    if (txPower <= 33) effectiveRange = 350.0;  // Conservative estimate
    else if (txPower <= 37) effectiveRange = 450.0;
    else effectiveRange = 550.0;

    // Calculate grid dimensions with overlap for reliability
    double overlapFactor = 0.7;  // 30% overlap between coverage areas
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

    // Calculate grid dimensions
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

int main(int argc, char* argv[])
{
    std::string traceFile = "scratch/traces.csv";
    uint32_t maxVehicles = 50;
    uint32_t nTAs = 0;
    double simTime = 3000.0;
    double txPower = 33.0;
    std::string vehicleTypeFilter = "";

    CommandLine cmd(__FILE__);
    cmd.AddValue("vehicles", "Number of vehicles", maxVehicles);
    cmd.AddValue("tas", "Number of Trust Authorities (0 = auto)", nTAs);
    cmd.AddValue("txpower", "Transmission power in dBm", txPower);
    cmd.AddValue("time", "Simulation time", simTime);
    cmd.Parse(argc, argv);

    // Enable logging
    LogComponentEnable("IoVAuthentication", LOG_LEVEL_INFO);

    // Load traces
    std::map<std::string, std::vector<VehicleTraceEntry>> mobilityTraces;
    mobilityTraces = LoadMobilityTraces(traceFile);
    std::vector<std::string> vehicleIds = GetVehicleIds(mobilityTraces, vehicleTypeFilter);

    if (vehicleIds.empty())
    {
        NS_LOG_ERROR("No vehicles found in trace file!");
        return 1;
    }

    if (vehicleIds.size() > maxVehicles)
    {
        vehicleIds.resize(maxVehicles);
    }

    uint32_t nVehicles = vehicleIds.size();
    NS_LOG_INFO("Using " << nVehicles << " vehicles from trace file");

    // Calculate bounding box
    double minX = std::numeric_limits<double>::max();
    double maxX = std::numeric_limits<double>::min();
    double minY = std::numeric_limits<double>::max();
    double maxY = std::numeric_limits<double>::min();

    for (const auto& vid : vehicleIds)
    {
        for (const auto& entry : mobilityTraces[vid])
        {
            minX = std::min(minX, entry.x);
            maxX = std::max(maxX, entry.x);
            minY = std::min(minY, entry.y);
            maxY = std::max(maxY, entry.y);
        }
    }

    double areaWidth = maxX - minX;
    double areaHeight = maxY - minY;

    // NS_LOG_INFO("Vehicle movement area: X[" << minX << ", " << maxX << "], "
    //             << "Y[" << minY << ", " << maxY << "]");
    // NS_LOG_INFO("Area dimensions: " << areaWidth << "m × " << areaHeight << "m");

    // Auto-calculate TAs if needed
    if (nTAs == 0)
    {
        nTAs = CalculateRequiredTAs(areaWidth, areaHeight, txPower);
        NS_LOG_INFO("Auto-calculated " << nTAs << " TAs for coverage");
    }

    // NOW create nodes with correct count
    NodeContainer vehicleNodes;
    vehicleNodes.Create(nVehicles);
    NodeContainer taNodes;
    taNodes.Create(nTAs);

    // Setup vehicle mobility
    MobilityHelper vehicleMobility;
    vehicleMobility.SetMobilityModel("ns3::ConstantVelocityMobilityModel");
    vehicleMobility.Install(vehicleNodes);

    // Set initial positions and schedule updates for each vehicle
    for (uint32_t i = 0; i < nVehicles; ++i)
    {
        const std::string& vehicleId = vehicleIds[i];
        const auto& traces = mobilityTraces[vehicleId];

        if (!traces.empty())
        {
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

    // Distribute TAs in grid
    MobilityHelper taMobility;
    DistributeTAsInGrid(taNodes, minX, maxX, minY, maxY, taMobility);

    // Setup WiFi
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

    // Setup Internet stack
    InternetStackHelper internet;
    internet.Install(vehicleNodes);
    internet.Install(taNodes);

    // Assign IP addresses
    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.0.0", "255.255.0.0");
    Ipv4InterfaceContainer vehicleInterfaces = ipv4.Assign(vehicleDevices);
    Ipv4InterfaceContainer taInterfaces = ipv4.Assign(taDevices);

    NS_LOG_INFO("Starting simulation with " << nVehicles << " vehicles and "
                << nTAs << " TAs");

    // Application setup
    uint16_t regPort = 9;
    uint16_t authPort = 10;

    // Install TA Applications
    for (uint32_t i = 0; i < nTAs; ++i)
    {
        Ptr<TaApplication> taApp = CreateObject<TaApplication>();
        taApp->Setup(regPort, authPort, "TA" + std::to_string(i));
        taNodes.Get(i)->AddApplication(taApp);
        taApp->SetStartTime(Seconds(1.0));
        taApp->SetStopTime(Seconds(simTime));
    }

    // Install Vehicle Applications
    for (uint32_t i = 0; i < nVehicles; ++i)
    {
        // Find nearest TA based on initial position
        Ptr<MobilityModel> vMobility = vehicleNodes.Get(i)->GetObject<MobilityModel>();
        Vector vPos = vMobility->GetPosition();

        uint32_t nearestTA = 0;
        double minDist = std::numeric_limits<double>::max();

        for (uint32_t j = 0; j < nTAs; ++j)
        {
            Ptr<MobilityModel> taMobility = taNodes.Get(j)->GetObject<MobilityModel>();
            Vector taPos = taMobility->GetPosition();
            double dist = CalculateDistance(vPos, taPos);

            if (dist < minDist)
            {
                minDist = dist;
                nearestTA = j;
            }
        }

        Ptr<VehicleApplication> vApp = CreateObject<VehicleApplication>();
        vApp->Setup(taInterfaces.GetAddress(nearestTA),
                    regPort,
                    authPort,
                    "TA" + std::to_string(nearestTA));
        vehicleNodes.Get(i)->AddApplication(vApp);
        vApp->SetStartTime(Seconds(2.0 + i * 0.1));
        vApp->SetStopTime(Seconds(simTime));
    }

    // Calculate adjusted simulation time
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
        uint32_t totalOverhead = vm.regMsg1 + vm.regMsg2 + vm.authMsg1 + vm.authMsg2;

        NS_LOG_UNCOND("Registration phase:");
        NS_LOG_UNCOND("  Vehicle → TA: " << vm.regMsg1 << " bytes");
        NS_LOG_UNCOND("  TA → Vehicle: " << vm.regMsg2 << " bytes");
        NS_LOG_UNCOND("Authentication phase:");
        NS_LOG_UNCOND("  Vehicle → TA: " << vm.authMsg1 << " bytes");
        NS_LOG_UNCOND("  TA → Vehicle: " << vm.authMsg2 << " bytes");
        NS_LOG_UNCOND("Total overhead per vehicle: " << totalOverhead << " bytes");
        NS_LOG_UNCOND("Total network overhead (all vehicles): "
                      << totalOverhead * g_metrics.authSuccess << " bytes");
    }

    NS_LOG_INFO("\nSimulation completed!");
    Simulator::Destroy();

    return 0;
}
