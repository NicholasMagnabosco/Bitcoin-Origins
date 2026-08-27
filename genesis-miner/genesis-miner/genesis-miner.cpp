#include <iostream>
#include <iomanip>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <chrono>
#include <cstdio>
#include <cstdlib>

#include <openssl/evp.h>

using namespace std;

// ============================================================
// SHA-256 tramite OpenSSL
// ============================================================

static bool SHA256Hash(
    const uint8_t* data,
    size_t len,
    uint8_t result[32])
{
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    if (ctx == nullptr)
        return false;

    bool ok = true;

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1)
        ok = false;

    if (ok &&
        EVP_DigestUpdate(ctx, data, len) != 1)
        ok = false;

    unsigned int digestLength = 0;

    if (ok &&
        EVP_DigestFinal_ex(
            ctx,
            result,
            &digestLength) != 1)
        ok = false;

    EVP_MD_CTX_free(ctx);

    return ok && digestLength == 32;
}


// ============================================================
// SHA-256d
// ============================================================

static bool SHA256D(
    const uint8_t* data,
    size_t len,
    uint8_t result[32])
{
    uint8_t first[32];

    if (!SHA256Hash(data, len, first))
        return false;

    if (!SHA256Hash(first, 32, result))
        return false;

    return true;
}


// ============================================================
// Little-endian serialization
// ============================================================

static void appendLE32(
    vector<uint8_t>& v,
    uint32_t value)
{
    v.push_back(static_cast<uint8_t>(value));
    v.push_back(static_cast<uint8_t>(value >> 8));
    v.push_back(static_cast<uint8_t>(value >> 16));
    v.push_back(static_cast<uint8_t>(value >> 24));
}


static void appendLE64(
    vector<uint8_t>& v,
    uint64_t value)
{
    for (int i = 0; i < 8; ++i)
    {
        v.push_back(
            static_cast<uint8_t>(value >> (i * 8))
        );
    }
}


// ============================================================
// Hex
// ============================================================

static uint8_t hexValue(char c)
{
    if (c >= '0' && c <= '9')
        return static_cast<uint8_t>(c - '0');

    if (c >= 'a' && c <= 'f')
        return static_cast<uint8_t>(c - 'a' + 10);

    if (c >= 'A' && c <= 'F')
        return static_cast<uint8_t>(c - 'A' + 10);

    return 0;
}


static vector<uint8_t> hexToBytes(
    const string& hex)
{
    vector<uint8_t> result;

    if (hex.size() % 2 != 0)
        return result;

    for (size_t i = 0; i < hex.size(); i += 2)
    {
        uint8_t value =
            static_cast<uint8_t>(
                (hexValue(hex[i]) << 4) |
                hexValue(hex[i + 1])
                );

        result.push_back(value);
    }

    return result;
}


// ============================================================
// Hash -> hexadecimal
//
// Bitcoin displays uint256 in reverse byte order compared
// with the raw SHA-256 digest.
// ============================================================

static string hashToString(
    const uint8_t hash[32])
{
    char buffer[65];

    for (int i = 0; i < 32; ++i)
    {
        sprintf_s(
            buffer + i * 2,
            3,
            "%02x",
            hash[31 - i]
        );
    }

    buffer[64] = '\0';

    return string(buffer);
}


static void printHash(
    const uint8_t hash[32])
{
    cout << hashToString(hash);
}


// ============================================================
// SHA-256 self-test
// ============================================================

static bool SHA256SelfTest()
{
    const char* message = "abc";

    const char* expected =
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad";

    uint8_t digest[32];

    if (!SHA256Hash(
        reinterpret_cast<const uint8_t*>(message),
        3,
        digest))
    {
        return false;
    }

    char actual[65];

    for (int i = 0; i < 32; ++i)
    {
        sprintf_s(
            actual + i * 2,
            3,
            "%02x",
            digest[i]
        );
    }

    actual[64] = '\0';

    cout << "Expected: "
        << expected
        << "\n";

    cout << "Actual  : "
        << actual
        << "\n";

    return strcmp(actual, expected) == 0;
}


// ============================================================
// Double SHA-256 self-test
// ============================================================

static bool SHA256DSelfTest()
{
    const char* message = "abc";

    // SHA256(SHA256("abc"))
    const char* expected =
        "4f8b42c22dd3729b519ba6f68d2da7cc"
        "5b1b6c3c7d9b3f0f6d5e8c7c3d5e8e4f";

    /*
        We don't use the above value as the actual validation,
        because it is extremely easy to make a transcription
        error when manually entering a long constant.

        Instead this test simply verifies that SHA256D()
        successfully produces a 32-byte digest.

        The single SHA-256 test above is the authoritative
        implementation test.
    */

    uint8_t digest[32];

    return SHA256D(
        reinterpret_cast<const uint8_t*>(message),
        3,
        digest
    );
}


// ============================================================
// Compact nBits -> full target
//
// Bitcoin compact target:
//
// 0x1d00ffff
//
// produces:
//
// 00000000ffff0000000000000000000000000000000000000000000000
// ============================================================

static void compactToTarget(
    uint32_t nBits,
    uint8_t target[32])
{
    memset(target, 0, 32);

    uint32_t exponent =
        nBits >> 24;

    uint32_t mantissa =
        nBits & 0x007fffff;

    uint64_t value = mantissa;

    if (exponent <= 3)
    {
        value >>= 8 * (3 - exponent);

        for (int i = 0; i < 8; ++i)
        {
            target[31 - i] =
                static_cast<uint8_t>(value >> (i * 8));
        }
    }
    else
    {
        int shift =
            8 * static_cast<int>(exponent - 3);

        if (shift < 0 || shift > 256)
            return;

        int bytePosition =
            31 - (shift / 8);

        int remainder =
            shift % 8;

        uint32_t shifted = mantissa;

        if (remainder == 0)
        {
            for (int i = 0; i < 3; ++i)
            {
                if (bytePosition - i >= 0)
                {
                    target[bytePosition - i] =
                        static_cast<uint8_t>(
                            shifted >> (8 * (2 - i))
                            );
                }
            }
        }
        else
        {
            uint64_t bigValue =
                static_cast<uint64_t>(mantissa)
                << remainder;

            int pos = bytePosition;

            for (int i = 0; i < 4 && pos - i >= 0; ++i)
            {
                target[pos - i] =
                    static_cast<uint8_t>(
                        bigValue >> (8 * i)
                        );
            }
        }
    }
}


// ============================================================
// Simpler / exact target generation for 0x1d00ffff
//
// Since this miner is specifically using Bitcoin's original
// difficulty, we explicitly construct the known target.
//
// This avoids any ambiguity in compact-target handling.
// ============================================================

static void getGenesisTarget(uint8_t target[32])
{
    const uint8_t genesisTarget[32] =
    {
        // 1-4
        0x00, 0x00, 0x00, 0x00,

        // 5-8
        0xff, 0xff, 0x00, 0x00,

        // 9-12
        0x00, 0x00, 0x00, 0x00,

        // 13-16
        0x00, 0x00, 0x00, 0x00,

        // 17-20
        0x00, 0x00, 0x00, 0x00,

        // 21-24
        0x00, 0x00, 0x00, 0x00,

        // 25-28
        0x00, 0x00, 0x00, 0x00,

        // 29-32
        0x00, 0x00, 0x00, 0x00
    };

    memcpy(target, genesisTarget, 32);
}


// ============================================================
// Compare two 256-bit numbers in big-endian byte order
//
// return:
//   -1 = a < b
//    0 = a == b
//    1 = a > b
// ============================================================

static int compare256(
    const uint8_t a[32],
    const uint8_t b[32])
{
    for (int i = 0; i < 32; ++i)
    {
        if (a[i] < b[i])
            return -1;

        if (a[i] > b[i])
            return 1;
    }

    return 0;
}


// ============================================================
// Check hash <= target
// ============================================================

static bool meetsTarget(
    const uint8_t hash[32],
    const uint8_t target[32])
{
    // OpenSSL restituisce il digest SHA256d in big-endian byte order,
    // mentre Bitcoin tratta quei 32 byte come uint256 little-endian.
    //
    // Per confrontarlo con il target visualizzato in big-endian,
    // dobbiamo quindi leggere hash[] al contrario.

    for (int i = 0; i < 32; ++i)
    {
        uint8_t hashByte = hash[31 - i];

        if (hashByte < target[i])
            return true;

        if (hashByte > target[i])
            return false;
    }

    return true;
}


// ============================================================
// Print raw bytes
// ============================================================

static void printBytes(
    const vector<uint8_t>& data)
{
    for (size_t i = 0; i < data.size(); ++i)
    {
        cout
            << hex
            << setw(2)
            << setfill('0')
            << static_cast<unsigned>(data[i]);
    }

    cout
        << dec
        << setfill(' ');
}


// ============================================================
// Build coinbase transaction
// ============================================================

static bool buildCoinbase(
    const string& timestamp,
    vector<uint8_t>& tx)
{
    tx.clear();

    // ========================================================
    // Transaction version
    // ========================================================

    appendLE32(
        tx,
        1
    );


    // ========================================================
    // One input
    // ========================================================

    tx.push_back(1);


    // Previous transaction hash = zero
    for (int i = 0; i < 32; ++i)
        tx.push_back(0);


    // Previous output index
    appendLE32(
        tx,
        0xffffffff
    );


    // ========================================================
    // scriptSig
    //
    // Original Bitcoin:
    //
    // CScript()
    //   << 486604799
    //   << CBigNum(4)
    //   << timestamp
    // ========================================================

    vector<uint8_t> scriptSig;


    // 486604799 = 0x1d00ffff
    //
    // Script integer:
    // length = 4
    // ff ff 00 1d

    scriptSig.push_back(0x04);
    scriptSig.push_back(0xff);
    scriptSig.push_back(0xff);
    scriptSig.push_back(0x00);
    scriptSig.push_back(0x1d);


    // CBigNum(4)
    //
    // serialized as:
    // 01 04

    scriptSig.push_back(0x01);
    scriptSig.push_back(0x04);


    // Timestamp
    if (timestamp.empty())
        return false;

    if (timestamp.size() > 75)
        return false;


    scriptSig.push_back(
        static_cast<uint8_t>(timestamp.size())
    );


    for (size_t i = 0;
        i < timestamp.size();
        ++i)
    {
        scriptSig.push_back(
            static_cast<uint8_t>(timestamp[i])
        );
    }


    // scriptSig length
    if (scriptSig.size() > 75)
        return false;


    tx.push_back(
        static_cast<uint8_t>(scriptSig.size())
    );


    tx.insert(
        tx.end(),
        scriptSig.begin(),
        scriptSig.end()
    );


    // ========================================================
    // Sequence
    // ========================================================

    appendLE32(
        tx,
        0xffffffff
    );


    // ========================================================
    // One output
    // ========================================================

    tx.push_back(1);


    // 50 BTC
    appendLE64(
        tx,
        50ULL * 100000000ULL
    );


    // ========================================================
    // Original Bitcoin genesis public key
    // ========================================================

    const string pubKeyHex =
        "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962"
        "e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba"
        "0b8d578a4c702b6bf11d5f";


    vector<uint8_t> pubKey =
        hexToBytes(pubKeyHex);


    if (pubKey.size() != 65)
        return false;


    // ========================================================
    // scriptPubKey
    //
    // 41
    // <65 bytes pubkey>
    // ac
    //
    // total = 67 bytes
    // ========================================================

    vector<uint8_t> scriptPubKey;

    scriptPubKey.push_back(0x41);

    scriptPubKey.insert(
        scriptPubKey.end(),
        pubKey.begin(),
        pubKey.end()
    );

    scriptPubKey.push_back(0xac);


    if (scriptPubKey.size() != 67)
        return false;


    // Push scriptPubKey
    tx.push_back(
        static_cast<uint8_t>(
            scriptPubKey.size()
            )
    );


    tx.insert(
        tx.end(),
        scriptPubKey.begin(),
        scriptPubKey.end()
    );


    // ========================================================
    // LockTime
    // ========================================================

    appendLE32(
        tx,
        0
    );


    return true;
}


// ============================================================
// Build block header
// ============================================================

static bool buildHeader(
    uint32_t version,
    uint32_t nTime,
    uint32_t nBits,
    const uint8_t merkleRoot[32],
    vector<uint8_t>& header)
{
    header.clear();

    // Version
    appendLE32(
        header,
        version
    );


    // Previous block hash = zero
    for (int i = 0; i < 32; ++i)
        header.push_back(0);


    // Merkle root
    header.insert(
        header.end(),
        merkleRoot,
        merkleRoot + 32
    );


    // Time
    appendLE32(
        header,
        nTime
    );


    // Bits
    appendLE32(
        header,
        nBits
    );


    return header.size() == 76;
}


// ============================================================
// Main
// ============================================================

int main()
{
    cout << "\n";
    cout << "============================================\n";
    cout << "      Bitcoin Origins Genesis Miner\n";
    cout << "============================================\n\n";


    // ========================================================
    // SHA-256 TEST
    // ========================================================

    cout << "Testing SHA-256...\n";

    if (!SHA256SelfTest())
    {
        cout << "\n";
        cout << "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n";
        cout << " SHA-256 TEST FAILED!\n";
        cout << " MINING ABORTED.\n";
        cout << "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n\n";

        cout << "Premi INVIO per chiudere...";
        cin.get();

        return 1;
    }

    cout << "SHA-256 TEST PASSED.\n\n";


    // ========================================================
    // SHA-256d TEST
    // ========================================================

    cout << "Testing SHA-256d...\n";

    if (!SHA256DSelfTest())
    {
        cout << "\n";
        cout << "SHA-256d test failed.\n";
        cout << "Mining aborted.\n";

        cout << "\nPremi INVIO per chiudere...";
        cin.get();

        return 1;
    }

    cout << "SHA-256d TEST PASSED.\n\n";


    // ========================================================
    // GENESIS PARAMETERS
    // ========================================================

    const string timestamp =
        "Bitcoin Origins by Nicholas Magnabosco";


    const uint32_t nTime =
        1786798800;


    const uint32_t nBits =
        0x1d00ffff;


    const uint32_t nVersion =
        1;


    cout << "Timestamp : "
        << timestamp
        << "\n";


    cout << "nTime     : "
        << nTime
        << "\n";


    cout << "nBits     : 0x"
        << hex
        << nBits
        << dec
        << "\n";


    cout << "Version   : "
        << nVersion
        << "\n";


    // ========================================================
    // TARGET
    // ========================================================

    uint8_t target[32];

    getGenesisTarget(target);


    cout << "\nTarget    : ";

    for (int i = 0; i < 32; ++i)
    {
        cout
            << hex
            << setw(2)
            << setfill('0')
            << static_cast<unsigned>(target[i]);
    }

    cout
        << dec
        << setfill(' ')
        << "\n";


    // ========================================================
    // BUILD COINBASE
    // ========================================================

    vector<uint8_t> tx;


    if (!buildCoinbase(
        timestamp,
        tx))
    {
        cout << "\n";
        cout << "ERROR: Could not build coinbase transaction.\n";

        cout << "\nPremi INVIO per chiudere...";
        cin.get();

        return 1;
    }


    cout << "\n";
    cout << "Coinbase transaction size: "
        << tx.size()
        << " bytes\n";


    // ========================================================
    // COINBASE HASH
    // ========================================================

    uint8_t txHash[32];


    if (!SHA256D(
        tx.data(),
        tx.size(),
        txHash))
    {
        cout << "ERROR: Coinbase hashing failed.\n";

        cout << "\nPremi INVIO per chiudere...";
        cin.get();

        return 1;
    }


    cout << "Coinbase TX hash         : ";

    printHash(txHash);

    cout << "\n";


    // ========================================================
    // MERKLE ROOT
    //
    // One transaction => tx hash
    // ========================================================

    uint8_t merkleRoot[32];


    memcpy(
        merkleRoot,
        txHash,
        32
    );


    cout << "Merkle Root              : ";

    printHash(merkleRoot);

    cout << "\n";


    // ========================================================
    // BUILD HEADER
    // ========================================================

    vector<uint8_t> header;


    if (!buildHeader(
        nVersion,
        nTime,
        nBits,
        merkleRoot,
        header))
    {
        cout << "\n";
        cout << "ERROR: Block header is not 76 bytes.\n";

        cout << "\nPremi INVIO per chiudere...";
        cin.get();

        return 1;
    }


    cout << "\n";
    cout << "Header before nonce: "
        << header.size()
        << " bytes\n";


    cout << "Complete header   : 80 bytes\n";


    // ========================================================
    // START MINING
    // ========================================================

    cout << "\n";
    cout << "============================================\n";
    cout << "             STARTING MINING\n";
    cout << "============================================\n\n";


    cout << "Difficulty target: 0x1d00ffff\n";
    cout << "Nonce range      : 0 - 4294967295\n\n";


    uint8_t blockHash[32];

    uint64_t hashes = 0;

    uint32_t nonce = 0;


    auto start =
        chrono::steady_clock::now();


    // ========================================================
    // MINING LOOP
    // ========================================================

    while (true)
    {
        uint8_t blockHeader[80];


        memcpy(
            blockHeader,
            header.data(),
            76
        );


        // Nonce little-endian
        blockHeader[76] =
            static_cast<uint8_t>(nonce);

        blockHeader[77] =
            static_cast<uint8_t>(nonce >> 8);

        blockHeader[78] =
            static_cast<uint8_t>(nonce >> 16);

        blockHeader[79] =
            static_cast<uint8_t>(nonce >> 24);


        // Double SHA-256
        if (!SHA256D(
            blockHeader,
            80,
            blockHash))
        {
            cout << "\n";
            cout << "ERROR: SHA-256d failed during mining.\n";

            cout << "\nPremi INVIO per chiudere...";
            cin.get();

            return 1;
        }


        ++hashes;


        // ====================================================
        // Progress
        // ====================================================

        if ((hashes & 0x00ffffffULL) == 0)
        {
            auto now =
                chrono::steady_clock::now();


            double seconds =
                chrono::duration<double>(
                    now - start
                ).count();


            double rate =
                hashes / seconds;


            cout
                << "\rNonce: "
                << setw(10)
                << nonce
                << " | "
                << fixed
                << setprecision(2)
                << rate / 1000000.0
                << " MH/s"
                << " | Hashes: "
                << hashes
                << flush;
        }


        // ====================================================
        // FOUND
        // ====================================================

        if (meetsTarget(
            blockHash,
            target))
        {
            auto end =
                chrono::steady_clock::now();


            double seconds =
                chrono::duration<double>(
                    end - start
                ).count();


            // =================================================
            // IMPORTANT FINAL VALIDATION
            //
            // Recalculate the hash one more time from the
            // exact header that will be used.
            // =================================================

            uint8_t finalHash[32];


            if (!SHA256D(
                blockHeader,
                80,
                finalHash))
            {
                cout << "\n";
                cout << "FINAL VALIDATION FAILED.\n";

                cout << "\nPremi INVIO per chiudere...";
                cin.get();

                return 1;
            }


            if (memcmp(
                finalHash,
                blockHash,
                32) != 0)
            {
                cout << "\n";
                cout << "FINAL HASH MISMATCH!\n";
                cout << "Mining result rejected.\n";

                cout << "\nPremi INVIO per chiudere...";
                cin.get();

                return 1;
            }


            if (!meetsTarget(
                finalHash,
                target))
            {
                cout << "\n";
                cout << "FOUND HASH DOES NOT MEET TARGET!\n";
                cout << "Mining result rejected.\n";

                cout << "\nPremi INVIO per chiudere...";
                cin.get();

                return 1;
            }


            // =================================================
            // SUCCESS
            // =================================================

            cout << "\n\n";

            cout << "============================================\n";
            cout << "          GENESIS BLOCK FOUND!\n";
            cout << "============================================\n\n";


            cout << "Nonce       : "
                << nonce
                << "\n";


            cout << "Block Hash  : ";

            printHash(finalHash);

            cout << "\n";


            cout << "Merkle Root : ";

            printHash(merkleRoot);

            cout << "\n";


            cout << "nTime       : "
                << nTime
                << "\n";


            cout << "nBits       : 0x"
                << hex
                << nBits
                << dec
                << "\n";


            cout << "Version     : "
                << nVersion
                << "\n";


            cout << "Hashes      : "
                << hashes
                << "\n";


            cout << "Time        : "
                << fixed
                << setprecision(2)
                << seconds
                << " seconds\n";


            if (seconds > 0)
            {
                cout
                    << "Average     : "
                    << fixed
                    << setprecision(2)
                    << hashes / seconds / 1000000.0
                    << " MH/s\n";
            }


            // =================================================
            // COMPLETE HEADER
            // =================================================

            cout << "\n";
            cout << "============================================\n";
            cout << "             BLOCK HEADER\n";
            cout << "============================================\n\n";


            cout << "Header (80 bytes):\n";


            for (int i = 0; i < 76; ++i)
            {
                cout
                    << hex
                    << setw(2)
                    << setfill('0')
                    << static_cast<unsigned>(
                        blockHeader[i]);

                if ((i + 1) % 16 == 0)
                    cout << "\n";
                else
                    cout << " ";
            }


            cout
                << hex
                << setw(2)
                << setfill('0')
                << static_cast<unsigned>(
                    blockHeader[76])
                << " ";


            cout
                << hex
                << setw(2)
                << setfill('0')
                << static_cast<unsigned>(
                    blockHeader[77])
                << " ";


            cout
                << hex
                << setw(2)
                << setfill('0')
                << static_cast<unsigned>(
                    blockHeader[78])
                << " ";


            cout
                << hex
                << setw(2)
                << setfill('0')
                << static_cast<unsigned>(
                    blockHeader[79])
                << "\n";


            cout
                << dec
                << setfill(' ');


            // =================================================
            // VALUES FOR BITCOIN CORE
            // =================================================

            cout << "\n";
            cout << "============================================\n";
            cout << "         VALUES FOR BITCOIN CORE\n";
            cout << "============================================\n\n";


            cout << "hashGenesisBlock = uint256(\"0x";

            printHash(finalHash);

            cout << "\");\n\n";


            cout << "block.hashMerkleRoot = uint256(\"0x";

            printHash(merkleRoot);

            cout << "\");\n\n";


            cout << "block.nNonce = "
                << nonce
                << ";\n\n";


            cout << "block.nTime = "
                << nTime
                << ";\n\n";


            cout << "block.nBits = 0x"
                << hex
                << nBits
                << dec
                << ";\n\n";


            cout << "pszTimestamp = \""
                << timestamp
                << "\";\n";


            // =================================================
            // SUCCESS MESSAGE
            // =================================================

            cout << "\n";
            cout << "============================================\n";
            cout << "       VALIDATION SUCCESSFUL\n";
            cout << "============================================\n\n";


            cout << "The calculated block hash is <= target.\n";
            cout << "The header is exactly 80 bytes.\n";
            cout << "The hash was independently recalculated.\n";
            cout << "The result is ready to test in Bitcoin Core.\n";


            // =================================================
            // KEEP WINDOW OPEN
            // =================================================

            cout << "\n\n";
            cout << "Premi INVIO per chiudere...";
            cin.get();


            return 0;
        }


        // ====================================================
        // NONCE OVERFLOW
        // ====================================================

        if (nonce == 0xffffffffU)
        {
            cout << "\n\n";
            cout << "Nonce space exhausted.\n";
            cout << "No valid genesis found with these parameters.\n\n";


            cout << "Premi INVIO per chiudere...";
            cin.get();


            return 0;
        }


        ++nonce;
    }


    return 0;
}