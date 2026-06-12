/*
  Arduino Mega 2560 — UART receiver + AES-CMAC verifier

  ПК отправляет строку:
  message|MAC_HEX

  Например:
  hello|3A4F...

  Arduino:
  1. принимает пакет по Serial;
  2. отделяет сообщение от MAC;
  3. вычисляет AES-CMAC от сообщения;
  4. сравнивает полученный MAC с принятым;
  5. выводит MAC OK или MAC ERROR.

  Скорость UART: 9600 baud
*/

#include <Arduino.h>
#include <AES.h>
#include <AES_CMAC.h>

// AES-128 ключ.
// 16 символов = 16 байт = 128 бит.
const uint8_t key[16] = {
  '1', '2', '3', '4',
  '5', '6', '7', '8',
  '9', '0', 'a', 'b',
  'c', 'd', 'e', 'f'
};

// Объекты AES и CMAC.
AESTiny128 aes128;
AES_CMAC cmac(aes128);

// Перевод одного HEX-символа в число.
int hexCharToValue(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}

// Перевод HEX-строки длиной 32 символа в 16 байт.
bool hexStringToBytes(String hex, uint8_t* out) {
  hex.trim();

  if (hex.length() != 32) {
    return false;
  }

  for (uint8_t i = 0; i < 16; i++) {
    int high = hexCharToValue(hex[i * 2]);
    int low  = hexCharToValue(hex[i * 2 + 1]);

    if (high < 0 || low < 0) {
      return false;
    }

    out[i] = (uint8_t)((high << 4) | low);
  }

  return true;
}

// Перевод массива байтов в HEX-строку.
String bytesToHex(const uint8_t* data, uint8_t len) {
  String result = "";

  for (uint8_t i = 0; i < len; i++) {
    if (data[i] < 0x10) {
      result += "0";
    }
    result += String(data[i], HEX);
  }

  result.toUpperCase();
  return result;
}

// Безопасное сравнение двух MAC по байтам.
bool compareMac(const uint8_t* a, const uint8_t* b) {
  uint8_t diff = 0;

  for (uint8_t i = 0; i < 16; i++) {
    diff |= a[i] ^ b[i];
  }

  return diff == 0;
}

void setup() {
  Serial.begin(9600);

  Serial.println("Arduino Mega 2560 AES-CMAC UART verifier");
  Serial.println("Waiting for packet: message|MAC_HEX");
  Serial.println();
}

void loop() {
  if (Serial.available()) {
    String packet = Serial.readStringUntil('\n');
    packet.trim();

    if (packet.length() == 0) {
      return;
    }

    int separatorIndex = packet.indexOf('|');

    if (separatorIndex == -1) {
      Serial.println("ERROR: wrong packet format");
      Serial.println("Expected: message|MAC_HEX");
      return;
    }

    String message = packet.substring(0, separatorIndex);
    String receivedMacHex = packet.substring(separatorIndex + 1);
    receivedMacHex.trim();

    uint8_t receivedMac[16];
    uint8_t calculatedMac[16];

    bool macParsed = hexStringToBytes(receivedMacHex, receivedMac);

    if (!macParsed) {
      Serial.println("ERROR: MAC must be 32 HEX characters");
      return;
    }

    // Вычисляем AES-CMAC от принятого сообщения.
    cmac.generateMAC(
      calculatedMac,
      key,
      (uint8_t*)message.c_str(),
      message.length()
    );

    String calculatedMacHex = bytesToHex(calculatedMac, 16);

    Serial.println("----- RECEIVED PACKET -----");
    Serial.print("Message: ");
    Serial.println(message);

    Serial.print("Received MAC:   ");
    Serial.println(receivedMacHex);

    Serial.print("Calculated MAC: ");
    Serial.println(calculatedMacHex);

    if (compareMac(receivedMac, calculatedMac)) {
      Serial.println("RESULT: MAC OK");
    } else {
      Serial.println("RESULT: MAC ERROR");
    }

    Serial.println("---------------------------");
    Serial.println();
  }
}