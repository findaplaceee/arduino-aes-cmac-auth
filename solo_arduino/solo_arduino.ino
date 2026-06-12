/*
  AES-128-CMAC for Arduino Mega 2560

  Программа:
  - принимает сообщение через Serial Monitor;
  - вычисляет AES-128-CMAC;
  - выводит MAC в HEX.

  Ключ:
  "1234567890abcdef"
  16 символов = 16 байт = 128 бит.
*/

#include <Arduino.h>
#include <string.h>

// ===================== AES-128 =====================

#define AES_BLOCKLEN 16
#define AES_KEYLEN 16
#define AES_keyExpSize 176

struct AES_ctx {
  uint8_t RoundKey[AES_keyExpSize];
};

static const uint8_t sbox[256] = {
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t Rcon[11] = {
  0x8d,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
};

static uint8_t getSBoxValue(uint8_t num) {
  return sbox[num];
}

static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key) {
  uint8_t i, j, k;
  uint8_t tempa[4];

  for (i = 0; i < AES_KEYLEN; ++i) {
    RoundKey[i] = Key[i];
  }

  for (i = 4; i < 44; ++i) {
    k = (i - 1) * 4;

    tempa[0] = RoundKey[k + 0];
    tempa[1] = RoundKey[k + 1];
    tempa[2] = RoundKey[k + 2];
    tempa[3] = RoundKey[k + 3];

    if (i % 4 == 0) {
      uint8_t t = tempa[0];
      tempa[0] = tempa[1];
      tempa[1] = tempa[2];
      tempa[2] = tempa[3];
      tempa[3] = t;

      tempa[0] = getSBoxValue(tempa[0]);
      tempa[1] = getSBoxValue(tempa[1]);
      tempa[2] = getSBoxValue(tempa[2]);
      tempa[3] = getSBoxValue(tempa[3]);

      tempa[0] = tempa[0] ^ Rcon[i / 4];
    }

    j = i * 4;
    k = (i - 4) * 4;

    RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
    RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
    RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
    RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
  }
}

static void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key) {
  KeyExpansion(ctx->RoundKey, key);
}

static void AddRoundKey(uint8_t round, uint8_t* state, const uint8_t* RoundKey) {
  for (uint8_t i = 0; i < 16; ++i) {
    state[i] ^= RoundKey[(round * 16) + i];
  }
}

static void SubBytes(uint8_t* state) {
  for (uint8_t i = 0; i < 16; ++i) {
    state[i] = getSBoxValue(state[i]);
  }
}

static void ShiftRows(uint8_t* state) {
  uint8_t temp;

  temp = state[1];
  state[1] = state[5];
  state[5] = state[9];
  state[9] = state[13];
  state[13] = temp;

  temp = state[2];
  state[2] = state[10];
  state[10] = temp;

  temp = state[6];
  state[6] = state[14];
  state[14] = temp;

  temp = state[3];
  state[3] = state[15];
  state[15] = state[11];
  state[11] = state[7];
  state[7] = temp;
}

static uint8_t xtime(uint8_t x) {
  return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

static void MixColumns(uint8_t* state) {
  uint8_t Tmp, Tm, t;

  for (uint8_t i = 0; i < 4; ++i) {
    uint8_t* col = state + i * 4;

    t = col[0];
    Tmp = col[0] ^ col[1] ^ col[2] ^ col[3];

    Tm = col[0] ^ col[1];
    Tm = xtime(Tm);
    col[0] ^= Tm ^ Tmp;

    Tm = col[1] ^ col[2];
    Tm = xtime(Tm);
    col[1] ^= Tm ^ Tmp;

    Tm = col[2] ^ col[3];
    Tm = xtime(Tm);
    col[2] ^= Tm ^ Tmp;

    Tm = col[3] ^ t;
    Tm = xtime(Tm);
    col[3] ^= Tm ^ Tmp;
  }
}

static void Cipher(uint8_t* state, const uint8_t* RoundKey) {
  AddRoundKey(0, state, RoundKey);

  for (uint8_t round = 1; round < 10; ++round) {
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(round, state, RoundKey);
  }

  SubBytes(state);
  ShiftRows(state);
  AddRoundKey(10, state, RoundKey);
}

static void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf) {
  Cipher(buf, ctx->RoundKey);
}

// ===================== AES-CMAC =====================

static void xor_128(const uint8_t* a, const uint8_t* b, uint8_t* out) {
  for (uint8_t i = 0; i < 16; i++) {
    out[i] = a[i] ^ b[i];
  }
}

static void leftshift_onebit(const uint8_t* input, uint8_t* output) {
  uint8_t overflow = 0;

  for (int8_t i = 15; i >= 0; i--) {
    output[i] = (input[i] << 1) | overflow;
    overflow = (input[i] & 0x80) ? 1 : 0;
  }
}

static void generate_subkeys(const uint8_t* key, uint8_t* K1, uint8_t* K2) {
  const uint8_t const_Rb[16] = {
    0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x87
  };

  uint8_t L[16] = {0};

  AES_ctx ctx;
  AES_init_ctx(&ctx, key);

  // L = AES_K(0^128)
  AES_ECB_encrypt(&ctx, L);

  if ((L[0] & 0x80) == 0) {
    leftshift_onebit(L, K1);
  } else {
    uint8_t tmp[16];
    leftshift_onebit(L, tmp);
    xor_128(tmp, const_Rb, K1);
  }

  if ((K1[0] & 0x80) == 0) {
    leftshift_onebit(K1, K2);
  } else {
    uint8_t tmp[16];
    leftshift_onebit(K1, tmp);
    xor_128(tmp, const_Rb, K2);
  }
}

static void padding(const uint8_t* lastb, uint8_t length, uint8_t* pad) {
  for (uint8_t i = 0; i < 16; i++) {
    if (i < length) {
      pad[i] = lastb[i];
    } else if (i == length) {
      pad[i] = 0x80;
    } else {
      pad[i] = 0x00;
    }
  }
}

void aes_cmac(const uint8_t* key, const uint8_t* message, uint16_t length, uint8_t* mac) {
  uint8_t K1[16];
  uint8_t K2[16];
  uint8_t X[16] = {0};
  uint8_t Y[16];
  uint8_t M_last[16];

  generate_subkeys(key, K1, K2);

  uint16_t n = (length + 15) / 16;
  bool complete;

  if (n == 0) {
    n = 1;
    complete = false;
  } else {
    complete = (length % 16 == 0);
  }

  if (complete) {
    xor_128(&message[16 * (n - 1)], K1, M_last);
  } else {
    uint8_t padded[16];
    uint8_t last_len = length % 16;

    if (length == 0) {
      uint8_t empty_block[16] = {0};
      padding(empty_block, 0, padded);
    } else {
      padding(&message[16 * (n - 1)], last_len, padded);
    }

    xor_128(padded, K2, M_last);
  }

  AES_ctx ctx;
  AES_init_ctx(&ctx, key);

  for (uint16_t i = 0; i < n - 1; i++) {
    xor_128(X, &message[16 * i], Y);
    memcpy(X, Y, 16);
    AES_ECB_encrypt(&ctx, X);
  }

  xor_128(X, M_last, Y);
  memcpy(mac, Y, 16);
  AES_ECB_encrypt(&ctx, mac);
}

// ===================== Arduino =====================

// Текстовый ключ AES-128.
// Должно быть ровно 16 символов.
// 16 символов = 16 байт = 128 бит.
uint8_t key[16] = "1234567890abcdef";

void printHex(const uint8_t* data, uint8_t len) {
  for (uint8_t i = 0; i < len; i++) {
    if (data[i] < 0x10) {
      Serial.print("0");
    }
    Serial.print(data[i], HEX);
  }
  Serial.println();
}

void setup() {
  Serial.begin(9600);

  Serial.println("AES-128-CMAC for Arduino Mega 2560");
  Serial.println("Key: 1234567890abcdef");
  Serial.println();

  uint8_t mac[16];

  // Проверка на пустом сообщении
  aes_cmac(key, NULL, 0, mac);

  Serial.print("CMAC empty message: ");
  printHex(mac, 16);

  Serial.println();
  Serial.println("Enter message and press Enter:");
}

void loop() {
  if (Serial.available()) {
    String input = Serial.readStringUntil('\n');
    input.trim();

    uint8_t mac[16];

    aes_cmac(
      key,
      (const uint8_t*)input.c_str(),
      input.length(),
      mac
    );

    Serial.print("Message: ");
    Serial.println(input);

    Serial.print("AES-CMAC: ");
    printHex(mac, 16);

    Serial.println();
    Serial.println("Enter next message:");
  }
}