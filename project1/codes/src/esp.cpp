#include "esp.h"

#include <linux/pfkeyv2.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <numeric>

#include "hmac.h"
#include "transport.h"

EspHeader esp_hdr_rec;

namespace esp {
constexpr int BYTES_PER_WORD = 8;
constexpr int BITS_PER_BYTE = 8;
constexpr int BYTE_ALIGNMENT_LENGTH = 4;
};  // namespace esp

bool get_sadb_key_in_response(sadb_msg* resp, int nbytes, uint8_t* key) {
    if (resp->sadb_msg_errno != 0) {
        fprintf(stderr, "[ERROR] SADB_DUMP error with errno: %d\n",
                resp->sadb_msg_errno);
        return false;
    }

    nbytes -= sizeof(sadb_msg);
    sadb_ext* ext = reinterpret_cast<sadb_ext*>(resp + 1);

    while (nbytes > 0) {
        if (ext->sadb_ext_type == SADB_EXT_KEY_AUTH) {
            sadb_key* key_ext = reinterpret_cast<sadb_key*>(ext);
            memcpy(key, key_ext + 1,
                   key_ext->sadb_key_bits / esp::BITS_PER_BYTE);
            // printf("[DEBUG] key =");
            // for (int i = 0; i < key_ext->sadb_key_bits / BITS_PER_BYTE; ++i)
            // {
            //     printf(" %02x", key[i]);
            // }
            // puts("");
            return false;  // skip the responses intentionally
        }

        nbytes -= ext->sadb_ext_len * esp::BYTES_PER_WORD;
        ext = reinterpret_cast<sadb_ext*>(
            reinterpret_cast<uint8_t*>(ext) +
            (ext->sadb_ext_len * esp::BYTES_PER_WORD));
    }

    if (resp->sadb_msg_seq == 0) {
        return false;  // no more response
    }

    return true;
}

/**
 * @brief Retrieve authentication key from security association database (SADB)
 * @details Ref: RFC2367 Section 2.3.4 & 2.4 & 3.1.1
 *
 * @param type Type of security assotiation
 * @param key Output, the retrieved key
 */
void get_ik(int type, uint8_t* key) {
    uint8_t buf[4096]{};

    int fd = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);

    sadb_msg msg{
        .sadb_msg_version = PF_KEY_V2,
        .sadb_msg_type = SADB_DUMP,
        .sadb_msg_satype = static_cast<uint8_t>(type),
        .sadb_msg_len = sizeof(sadb_msg) / esp::BYTES_PER_WORD,
        .sadb_msg_pid = static_cast<uint32_t>(getpid()),
    };

    write(fd, &msg, sizeof(msg));

    bool has_more = true;
    while (has_more) {
        int nbytes = read(fd, buf, sizeof(buf));
        has_more = get_sadb_key_in_response(reinterpret_cast<sadb_msg*>(buf),
                                            nbytes, key);
    }

    close(fd);
}

void Esp::get_key() { get_ik(SADB_SATYPE_ESP, this->esp_key.data()); }

uint8_t* Esp::set_padpl() {
    // Fill up self->pad and self->pad_len (Ref. RFC4303 Section 2.4)

    std::iota(this->pad.begin(), this->pad.begin() + this->tlr.pad_len, 1);

    return this->pad.data();
}

uint8_t* Esp::set_auth(HmacFn hmac) {
    if (!hmac) {
        fprintf(stderr, "Invalid arguments of %s().\n", __func__);
        return NULL;
    }

    uint8_t buff[BUFSIZE];
    size_t esp_keylen = 16;
    size_t nb = 0;  // Number of bytes to be hashed
    ssize_t ret;

    // Put everything needed to be authenticated into buff and add up nb
    uint8_t* cursor = buff;

    memcpy(cursor, &this->hdr, sizeof(EspHeader));
    cursor += sizeof(EspHeader);

    memcpy(cursor, this->pl.data(), this->plen);
    cursor += this->plen;

    memcpy(cursor, this->pad.data(), this->tlr.pad_len);
    cursor += this->tlr.pad_len;

    memcpy(cursor, &this->tlr, sizeof(EspTrailer));
    cursor += sizeof(EspTrailer);

    nb = cursor - buff;

    ret = hmac(this->esp_key.data(), esp_keylen, buff, nb, this->auth.data());

    if (ret == -1) {
        fprintf(stderr, "Error occurs when try to compute authentication data");
        return NULL;
    }

    this->authlen = ret;
    return this->auth.data();
}
/**
 * @brief Collect information from esp_pkt
 * @param esp_pkt pointer to esp data
 * @param esp_len length of esp packet data
 *
 * @returns payload of ESP
 */
uint8_t* Esp::dissect(uint8_t* esp_pkt, size_t esp_len) {
    this->hdr.spi = ntohl(reinterpret_cast<uint32_t*>(esp_pkt)[0]);
    this->hdr.seq = ntohl(reinterpret_cast<uint32_t*>(esp_pkt)[1]);
    uint8_t* payload_start = esp_pkt + sizeof(EspHeader);

    // Store authentication data (length: 12)
    uint8_t* current_position = esp_pkt + esp_len - HMAC96AUTHLEN;
    memcpy(this->auth.data(), current_position, HMAC96AUTHLEN);

    // Store ESP trailer
    current_position -= 2;
    this->tlr.pad_len = current_position[0];
    this->tlr.nxt = current_position[1];

    // Store padding (?)
    current_position -= this->tlr.pad_len;
    memcpy(this->pad.data(), current_position, this->tlr.pad_len);

    this->plen = current_position - payload_start;
    memcpy(this->pl.data(), payload_start, this->plen);

    return this->pl.data();
}

Esp* Esp::fmt_rep(Proto p) {
    // Fill up ESP header and trailer (prepare to send)

    this->hdr.spi = htonl(this->hdr.spi);
    this->hdr.seq = htonl(this->hdr.seq + 1);

    this->tlr.pad_len =
        (this->plen + sizeof(EspTrailer)) % esp::BYTE_ALIGNMENT_LENGTH;
    this->tlr.nxt = p;

    return this;
}

Esp::Esp() : authlen{HMAC96AUTHLEN} {}
