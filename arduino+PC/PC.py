"""
PC sender for Arduino Mega 2560 AES-CMAC UART test

ПК:
1. берёт сообщение;
2. вычисляет AES-CMAC;
3. отправляет в Arduino пакет формата:
   message|MAC_HEX
4. читает ответ Arduino.

Перед запуском:
pip install pyserial pycryptodome
"""

import time
import serial
from Crypto.Hash import CMAC
from Crypto.Cipher import AES



PORT = "COM7"

BAUDRATE = 9600

# Такой же ключ, как в Arduino.
# 16 байт = 128 бит.
KEY = b"1234567890abcdef"


def calculate_aes_cmac(message: str) -> str:
    """
    Вычисляет AES-CMAC от строки.
    Возвращает MAC в HEX-формате.
    """
    cobj = CMAC.new(KEY, ciphermod=AES)
    cobj.update(message.encode("utf-8"))
    return cobj.hexdigest().upper()


def send_packet(message: str):
    mac_hex = calculate_aes_cmac(message)
    packet = f"{message}|{mac_hex}\n"

    print("Sending packet:")
    print(packet.strip())
    print()

    with serial.Serial(PORT, BAUDRATE, timeout=2) as ser:
        # Arduino перезагружается при открытии Serial,
        # поэтому даём ей время запуститься.
        time.sleep(3)

        ser.write(packet.encode("utf-8"))

        print("Arduino response:")
        start_time = time.time()

        while time.time() - start_time < 5:
            line = ser.readline().decode("utf-8", errors="ignore").strip()
            if line:
                print(line)


if __name__ == "__main__":
    print("AES-CMAC UART sender")
    print("Type message and press Enter.")
    print("Type exit to quit.")
    print()

    while True:
        msg = input("Message: ")

        if msg.lower() == "exit":
            break

        send_packet(msg)
        print()