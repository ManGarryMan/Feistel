#!/usr/bin/env python3
"""
Учебный блочный шифр на основе обобщённой сети Фейстеля (Type-1, 4 части).

Параметры:
  - блок 128 бит = 4 части (A, B, C, D) по 32 бита
  - ключ 256 бит = 8 подключей по 32 бита
  - 32 раунда, расписание ключей как в «Магме»: K1..K8 x3, затем K8..K1
  - функция F: (A + K) mod 2^32 -> S-блок AES для каждого из 4 байт -> сдвиг влево на 11
  - режим CBC, паддинг PKCS7


Раунд:    (A, B, C, D) -> (D, A, B xor F(A, K), C)
Обратный: (A, B, C, D) -> (B, C xor F(B, K), D, A)
"""
from __future__ import annotations

import base64
import hashlib
import os
import struct

MASK32 = 0xFFFFFFFF
BLOCK_SIZE = 16      # байт
ROUNDS = 32
SALT_SIZE = 16
PBKDF2_ITERATIONS = 200_000

# S-блок AES (таблица 16x16 = 256 байт). Строка — старшие 4 бита входного байта,
# столбец — младшие 4 бита. Например, байт 0x53: строка 5, столбец 3 -> 0xED.
SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76"  # 0
    "ca82c97dfa5947f0add4a2af9ca472c0"  # 1
    "b7fd9326363ff7cc34a5e5f171d83115"  # 2
    "04c723c31896059a071280e2eb27b275"  # 3
    "09832c1a1b6e5aa0523bd6b329e32f84"  # 4
    "53d100ed20fcb15b6acbbe394a4c58cf"  # 5
    "d0efaafb434d338545f9027f503c9fa8"  # 6
    "51a3408f929d38f5bcb6da2110fff3d2"  # 7
    "cd0c13ec5f974417c4a77e3d645d1973"  # 8
    "60814fdc222a908846eeb814de5e0bdb"  # 9
    "e0323a0a4906245cc2d3ac629195e479"  # A
    "e7c8376d8dd54ea96c56f4ea657aae08"  # B
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a"  # C
    "703eb5664803f60e613557b986c11d9e"  # D
    "e1f8981169d98e949b1e87e9ce5528df"  # E
    "8ca1890dbfe6426841992d0fb054bb16"  # F
)


# ---------------------------------------------------------------- ядро шифра

def _substitute(x: int) -> int:
    """Прогоняет 32-битное слово через S-блок AES: каждый из 4 байт заменяется по таблице."""
    return (
        (SBOX[(x >> 24) & 0xFF] << 24)
        | (SBOX[(x >> 16) & 0xFF] << 16)
        | (SBOX[(x >> 8) & 0xFF] << 8)
        | SBOX[x & 0xFF]
    )


def round_function(a: int, k: int) -> int:
    """F(A, K): сложение с ключом, S-блок AES по байтам, циклический сдвиг влево на 11."""
    x = (a + k) & MASK32
    x = _substitute(x)
    return ((x << 11) | (x >> 21)) & MASK32


def key_schedule(key: bytes) -> list[int]:
    """256-битный ключ -> 32 раундовых ключа (K1..K8 три раза, затем K8..K1)."""
    if len(key) != 32:
        raise ValueError("ключ должен быть 32 байта (256 бит)")
    sub = [int.from_bytes(key[4 * i:4 * i + 4], "big") for i in range(8)]
    return sub * 3 + sub[::-1]


def encrypt_block(block: bytes, round_keys: list[int]) -> bytes:
    a, b, c, d = struct.unpack(">4I", block)
    for k in round_keys:
        a, b, c, d = d, a, b ^ round_function(a, k), c
    return struct.pack(">4I", a, b, c, d)


def decrypt_block(block: bytes, round_keys: list[int]) -> bytes:
    a, b, c, d = struct.unpack(">4I", block)
    for k in reversed(round_keys):
        a, b, c, d = b, c ^ round_function(b, k), d, a
    return struct.pack(">4I", a, b, c, d)


# ------------------------------------------------- режим CBC, паддинг, пароль

def _xor(x: bytes, y: bytes) -> bytes:
    return bytes(p ^ q for p, q in zip(x, y))


def pad(data: bytes) -> bytes:
    n = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([n]) * n


def unpad(data: bytes) -> bytes:
    if not data or len(data) % BLOCK_SIZE:
        raise ValueError("неверная длина данных")
    n = data[-1]
    if n < 1 or n > BLOCK_SIZE or data[-n:] != bytes([n]) * n:
        raise ValueError("неверный паддинг")
    return data[:-n]


def cbc_encrypt(data: bytes, round_keys: list[int], iv: bytes) -> bytes:
    prev, out = iv, []
    for i in range(0, len(data), BLOCK_SIZE):
        prev = encrypt_block(_xor(data[i:i + BLOCK_SIZE], prev), round_keys)
        out.append(prev)
    return b"".join(out)


def cbc_decrypt(data: bytes, round_keys: list[int], iv: bytes) -> bytes:
    prev, out = iv, []
    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i:i + BLOCK_SIZE]
        out.append(_xor(decrypt_block(block, round_keys), prev))
        prev = block
    return b"".join(out)


def derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=32
    )


def encrypt_text(text: str, password: str) -> str:
    """Текст + пароль -> base64( соль | IV | шифртекст )."""
    salt, iv = os.urandom(SALT_SIZE), os.urandom(BLOCK_SIZE)
    rks = key_schedule(derive_key(password, salt))
    ct = cbc_encrypt(pad(text.encode("utf-8")), rks, iv)
    return base64.b64encode(salt + iv + ct).decode("ascii")


def decrypt_text(b64: str, password: str) -> str:
    try:
        raw = base64.b64decode(b64.strip())
    except Exception:
        raise ValueError("это не похоже на base64")
    head = SALT_SIZE + BLOCK_SIZE
    if len(raw) < head + BLOCK_SIZE or (len(raw) - head) % BLOCK_SIZE:
        raise ValueError("данные повреждены или имеют неверную длину")
    salt, iv, ct = raw[:SALT_SIZE], raw[SALT_SIZE:head], raw[head:]
    rks = key_schedule(derive_key(password, salt))
    try:
        return unpad(cbc_decrypt(ct, rks, iv)).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        raise ValueError("неверный ключ или данные повреждены")


# ----------------------------------------------------------- ввод и вывод

def read_multiline(prompt: str) -> str:
    print(f"{prompt} (закончите пустой строкой):")
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line == "":
            break
        lines.append(line)
    return "\n".join(lines)


def read_file(path: str) -> str:
    path = path.strip().strip('"').strip("'")
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def get_source(what: str) -> str | None:
    """Спрашивает, откуда брать данные: клавиатура или файл."""
    choice = input(f"{what}: 1 — с клавиатуры, 2 — из файла [1]: ").strip() or "1"
    if choice == "2":
        try:
            return read_file(input("Путь к файлу: "))
        except (OSError, UnicodeDecodeError) as e:
            print(f"Не удалось прочитать файл: {e}")
            return None
    return read_multiline(what)


def get_password() -> str | None:
    pw = input("Ключ (пароль): ")
    if not pw:
        print("Ключ не может быть пустым.")
        return None
    return pw


def offer_save(result: str) -> None:
    path = input("Сохранить результат в файл? Путь или Enter, чтобы пропустить: ").strip()
    if not path:
        return
    try:
        with open(path.strip('"').strip("'"), "w", encoding="utf-8") as f:
            f.write(result)
        print("Сохранено.")
    except OSError as e:
        print(f"Не удалось сохранить: {e}")


def do_encrypt() -> None:
    text = get_source("Текст для шифрования")
    if not text:
        print("Пустой текст, нечего шифровать.")
        return
    pw = get_password()
    if pw is None:
        return
    result = encrypt_text(text, pw)
    print("\nШифртекст (base64):")
    print(result)
    offer_save(result)


def do_decrypt() -> None:
    data = get_source("Шифртекст (base64)")
    if not data:
        print("Пустой ввод.")
        return
    data = "".join(data.split())  # убираем переводы строк и пробелы
    pw = get_password()
    if pw is None:
        return
    try:
        result = decrypt_text(data, pw)
    except ValueError as e:
        print(f"Ошибка: {e}")
        return
    print("\nРасшифрованный текст:")
    print(result)
    offer_save(result)


def main() -> None:
    while True:
        print(
            "\n=== Шифр Фейстеля (4 части, S-блок AES) ===\n"
            "1 — зашифровать\n"
            "2 — расшифровать\n"
            "0 — выход"
        )
        try:
            choice = input("Выбор: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if choice == "1":
            do_encrypt()
        elif choice == "2":
            do_decrypt()
        elif choice == "0":
            break
        else:
            print("Неизвестный пункт меню.")


if __name__ == "__main__":
    main()