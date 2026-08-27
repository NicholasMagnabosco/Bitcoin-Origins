#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <openssl/sha.h>

#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <algorithm>

#pragma comment(lib, "ws2_32.lib")

struct MiningJob
{
    uint32_t jobId;
    uint32_t version;

    std::string prevHash;
    std::string merkleRoot;

    uint32_t nTime;
    uint32_t nBits;

    std::string target;

    int height;
};

static std::atomic<bool> g_found(false);
static std::atomic<bool> g_stale(false);
static std::atomic<uint64_t> g_hashes(0);
static std::atomic<uint32_t> g_foundNonce(0);


// ------------------------------------------------------------
// TCP helpers
// ------------------------------------------------------------

bool SendLine(SOCKET s, const std::string& text)
{
    std::string data = text + "\n";

    const char* p = data.c_str();
    int remaining = (int)data.size();

    while (remaining > 0)
    {
        int sent = send(s, p, remaining, 0);

        if (sent <= 0)
            return false;

        p += sent;
        remaining -= sent;
    }

    return true;
}


bool RecvLine(SOCKET s, std::string& line)
{
    line.clear();

    char ch;

    while (true)
    {
        int ret = recv(s, &ch, 1, 0);

        if (ret <= 0)
            return false;

        if (ch == '\n')
            break;

        if (ch != '\r')
            line += ch;
    }

    return true;
}


// ------------------------------------------------------------
// Hex helpers
// ------------------------------------------------------------

int HexDigit(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';

    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;

    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;

    return -1;
}


bool HexToBytes(
    const std::string& hex,
    std::vector<unsigned char>& out)
{
    if (hex.size() % 2 != 0)
        return false;

    out.resize(hex.size() / 2);

    for (size_t i = 0; i < out.size(); i++)
    {
        int hi = HexDigit(hex[i * 2]);
        int lo = HexDigit(hex[i * 2 + 1]);

        if (hi < 0 || lo < 0)
            return false;

        out[i] = (unsigned char)((hi << 4) | lo);
    }

    return true;
}


std::string BytesToHex(
    const unsigned char* data,
    size_t size)
{
    std::ostringstream ss;

    ss << std::hex << std::setfill('0');

    for (size_t i = 0; i < size; i++)
        ss << std::setw(2) << (unsigned int)data[i];

    return ss.str();
}


// ------------------------------------------------------------
// Bitcoin serialization helpers
// ------------------------------------------------------------

void WriteLE32(unsigned char* p, uint32_t value)
{
    p[0] = (unsigned char)(value);
    p[1] = (unsigned char)(value >> 8);
    p[2] = (unsigned char)(value >> 16);
    p[3] = (unsigned char)(value >> 24);
}


bool WriteReversedHash(
    unsigned char* output,
    const std::string& hex)
{
    std::vector<unsigned char> bytes;

    if (!HexToBytes(hex, bytes))
        return false;

    if (bytes.size() != 32)
        return false;

    std::reverse(bytes.begin(), bytes.end());

    for (int i = 0; i < 32; i++)
        output[i] = bytes[i];

    return true;
}


// ------------------------------------------------------------
// SHA256d with SHA-256 midstate
// ------------------------------------------------------------

void PrepareSHA256Midstate(
    const unsigned char header[80],
    SHA256_CTX& midstate)
{
    SHA256_Init(&midstate);

    SHA256_Update(
        &midstate,
        header,
        64
    );
}


void SHA256DFromMidstate(
    const SHA256_CTX& midstate,
    const unsigned char tail[16],
    unsigned char output[32])
{
    unsigned char first[32];

    SHA256_CTX ctxFirst = midstate;

    SHA256_Update(
        &ctxFirst,
        tail,
        16
    );

    SHA256_Final(
        first,
        &ctxFirst
    );

    SHA256_CTX ctxSecond;

    SHA256_Init(&ctxSecond);

    SHA256_Update(
        &ctxSecond,
        first,
        32
    );

    SHA256_Final(
        output,
        &ctxSecond
    );
}


// Convert raw SHA256 digest into normal Bitcoin displayed order
void DigestToBitcoinHash(
    const unsigned char digest[32],
    unsigned char hash[32])
{
    for (int i = 0; i < 32; i++)
        hash[i] = digest[31 - i];
}


// Both hash and target are big-endian arrays here
bool HashMeetsTarget(
    const unsigned char hash[32],
    const unsigned char target[32])
{
    for (int i = 0; i < 32; i++)
    {
        if (hash[i] < target[i])
            return true;

        if (hash[i] > target[i])
            return false;
    }

    return true;
}


// ------------------------------------------------------------
// Parse WORK response
// ------------------------------------------------------------

bool ParseWork(
    const std::string& line,
    MiningJob& job)
{
    std::istringstream ss(line);

    std::string command;
    std::string bitsString;

    ss >> command;

    if (command != "WORK")
        return false;

    ss
        >> job.jobId
        >> job.version
        >> job.prevHash
        >> job.merkleRoot
        >> job.nTime
        >> bitsString
        >> job.target
        >> job.height;

    if (ss.fail())
        return false;

    job.nBits =
        (uint32_t)std::stoul(bitsString, nullptr, 16);

    return true;
}


// ------------------------------------------------------------
// Build canonical Bitcoin 80-byte block header
// ------------------------------------------------------------

bool BuildHeader(
    const MiningJob& job,
    unsigned char header[80])
{
    WriteLE32(header + 0, job.version);

    if (!WriteReversedHash(header + 4, job.prevHash))
        return false;

    if (!WriteReversedHash(header + 36, job.merkleRoot))
        return false;

    WriteLE32(header + 68, job.nTime);
    WriteLE32(header + 72, job.nBits);

    WriteLE32(header + 76, 0);

    return true;
}


// ------------------------------------------------------------
// Worker
// ------------------------------------------------------------

void MiningThread(
    const unsigned char baseHeader[80],
    const unsigned char target[32],
    uint64_t nonceStart,
    uint64_t nonceEnd)
{
    SHA256_CTX midstate;

    PrepareSHA256Midstate(
        baseHeader,
        midstate
    );

    unsigned char tail[16];

    memcpy(
        tail,
        baseHeader + 64,
        16
    );

    uint64_t localCounter = 0;

    for (uint64_t nonce = nonceStart;
         nonce <= nonceEnd &&
         !g_found.load() &&
         !g_stale.load();
         nonce++)
    {
        WriteLE32(
            tail + 12,
            (uint32_t)nonce
        );

        unsigned char digest[32];
        unsigned char bitcoinHash[32];

        SHA256DFromMidstate(
            midstate,
            tail,
            digest
        );

        DigestToBitcoinHash(
            digest,
            bitcoinHash
        );

        localCounter++;

        if ((localCounter & 0xFFF) == 0)
        {
            g_hashes.fetch_add(4096);
            localCounter = 0;
        }

        if (HashMeetsTarget(
                bitcoinHash,
                target))
        {
            if (localCounter)
            {
                g_hashes.fetch_add(localCounter);
                localCounter = 0;
            }

            bool expected = false;

            if (g_found.compare_exchange_strong(
                    expected,
                    true))
            {
                g_foundNonce.store(
                    (uint32_t)nonce
                );

                std::cout
                    << "\n\n[FOUND]\n"
                    << "Nonce : "
                    << (uint32_t)nonce
                    << "\nHash  : "
                    << BytesToHex(
                        bitcoinHash,
                        32)
                    << "\n";
            }

            return;
        }
    }

    if (localCounter)
        g_hashes.fetch_add(localCounter);
}


// ------------------------------------------------------------
// Mine one job
// ------------------------------------------------------------

bool MineJob(
    const MiningJob& job,
    uint32_t& nonceOut,
    SOCKET s)
{
    unsigned char header[80];

    if (!BuildHeader(job, header))
    {
        std::cerr << "Could not build block header.\n";
        return false;
    }

    std::vector<unsigned char> targetBytes;

    if (!HexToBytes(job.target, targetBytes) ||
        targetBytes.size() != 32)
    {
        std::cerr << "Invalid target received from node.\n";
        return false;
    }

    unsigned int threadCount =
        std::thread::hardware_concurrency();

    if (threadCount == 0)
        threadCount = 1;

    std::cout
        << "\n============================================\n"
        << "       Bitcoin Origins CPU Miner\n"
        << "============================================\n\n"
        << "Height     : " << job.height << "\n"
        << "Job ID     : " << job.jobId << "\n"
        << "Threads    : " << threadCount << "\n"
        << "nTime      : " << job.nTime << "\n"
        << "nBits      : 0x"
        << std::hex << std::setw(8) << std::setfill('0')
        << job.nBits
        << std::dec << "\n"
        << "Target     : " << job.target << "\n"
        << "Prev hash  : " << job.prevHash << "\n"
        << "Merkle root: " << job.merkleRoot << "\n\n";

    g_found.store(false);
    g_stale.store(false);
    g_hashes.store(0);
    g_foundNonce.store(0);

    const uint64_t totalNonces =
        0x100000000ULL;

    uint64_t range =
        totalNonces / threadCount;

    std::vector<std::thread> workers;

    auto start =
        std::chrono::steady_clock::now();

    for (unsigned int i = 0;
         i < threadCount;
         i++)
    {
        uint64_t first =
            range * i;

        uint64_t last;

        if (i == threadCount - 1)
            last = 0xFFFFFFFFULL;
        else
            last = (range * (i + 1)) - 1;

        workers.emplace_back(
            MiningThread,
            header,
            targetBytes.data(),
            first,
            last
        );
    }

    uint64_t lastHashes = 0;
    unsigned int nSecondsSinceCheck = 0;

    while (!g_found.load() && !g_stale.load())
    {
        std::this_thread::sleep_for(
            std::chrono::seconds(1));

        if (g_found.load() || g_stale.load())
            break;

        uint64_t hashes =
            g_hashes.load();

        uint64_t delta =
            hashes - lastHashes;

        lastHashes = hashes;

        double mh =
            (double)delta / 1000000.0;

        std::cout
            << "\rHashrate: "
            << std::fixed
            << std::setprecision(2)
            << mh
            << " MH/s     "
            << std::flush;

        if (hashes >= totalNonces)
            break;

        nSecondsSinceCheck++;

        if (nSecondsSinceCheck >= 5)
        {
            nSecondsSinceCheck = 0;

            std::ostringstream check;

            check
                << "CHECKJOB "
                << job.jobId;

            if (!SendLine(s, check.str()))
            {
                std::cerr
                    << "\nConnection lost while checking job.\n";

                g_stale.store(true);
                break;
            }

            std::string reply;

            if (!RecvLine(s, reply))
            {
                std::cerr
                    << "\nConnection lost while checking job.\n";

                g_stale.store(true);
                break;
            }

            if (reply == "STALE")
            {
                g_stale.store(true);
                break;
            }
        }
    }

    for (auto& worker : workers)
        worker.join();

    auto end =
        std::chrono::steady_clock::now();

    double seconds =
        std::chrono::duration<double>(
            end - start).count();

    uint64_t hashes =
        g_hashes.load();

    double averageMH =
        ((double)hashes / seconds)
        / 1000000.0;

    std::cout
        << "\nHashes     : "
        << hashes
        << "\nElapsed    : "
        << std::fixed
        << std::setprecision(2)
        << seconds
        << " s"
        << "\nAverage    : "
        << std::fixed
        << std::setprecision(2)
        << averageMH
        << " MH/s\n";

    if (g_stale.load())
    {
        std::cout
            << "Work became stale. Requesting new work.\n";

        return false;
    }

    if (!g_found.load())
    {
        std::cout
            << "Nonce range exhausted. Requesting new work.\n";

        return false;
    }

    nonceOut =
        g_foundNonce.load();

    return true;
}


// ------------------------------------------------------------
// main
// ------------------------------------------------------------

int main()
{
    std::cout
        << "Bitcoin Origins External CPU Miner\n"
        << "Connecting to 127.0.0.1:17475...\n";

    WSADATA wsa;

    if (WSAStartup(
            MAKEWORD(2, 2),
            &wsa) != 0)
    {
        std::cerr << "WSAStartup failed.\n";
        return 1;
    }

    SOCKET s =
        socket(
            AF_INET,
            SOCK_STREAM,
            IPPROTO_TCP);

    if (s == INVALID_SOCKET)
    {
        std::cerr << "socket() failed.\n";
        WSACleanup();
        return 1;
    }

    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(17475);

    inet_pton(
        AF_INET,
        "127.0.0.1",
        &addr.sin_addr);

    if (connect(
            s,
            (sockaddr*)&addr,
            sizeof(addr)) == SOCKET_ERROR)
    {
        std::cerr
            << "Could not connect to Bitcoin Origins node.\n";

        closesocket(s);
        WSACleanup();

        return 1;
    }

    std::cout << "Connected!\n";

    while (true)
    {
        if (!SendLine(s, "GETWORK"))
        {
            std::cerr << "Connection lost.\n";
            break;
        }

        std::string line;

        if (!RecvLine(s, line))
        {
            std::cerr << "Connection lost.\n";
            break;
        }

        MiningJob job;

        if (!ParseWork(line, job))
        {
            std::cerr
                << "Invalid WORK response:\n"
                << line << "\n";

            break;
        }

        uint32_t nonce;

        if (!MineJob(job, nonce, s))
        {
            continue;
        }

        std::ostringstream submit;

        submit
            << "SUBMIT "
            << job.jobId
            << " "
            << nonce;

        std::cout
            << "\nSubmitting nonce "
            << nonce
            << "...\n";

        if (!SendLine(s, submit.str()))
        {
            std::cerr
                << "Submit failed: connection lost.\n";

            break;
        }

        std::string result;

        if (!RecvLine(s, result))
        {
            std::cerr
                << "Connection lost after submit.\n";

            break;
        }

        std::cout
            << "Node response: "
            << result
            << "\n\n";

        if (result == "ACCEPTED")
        {
            std::cout
                << "*** BLOCK ACCEPTED BY BITCOIN ORIGINS ***\n\n";
        }
        else if (result == "STALE")
        {
            std::cout
                << "Work became stale. Getting a new job...\n";
        }
        else
        {
            std::cout
                << "Block rejected. Getting new work...\n";
        }
    }

    closesocket(s);
    WSACleanup();

    return 0;
}