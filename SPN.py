"""
SPN Cipher — рабочая учебная реализация Substitution-Permutation Network.

Зафиксированная архитектура:
- размер блока: 128 бит (16 байт)
- длина ключа: 64 / 128 / 256 / 512 бит
- число раундов: задаётся пользователем, минимум 8
- S-box: 8 бит, таблица AES (FIPS-197) — проверенная, не самодельная
- P-box: битовая перестановка 128 бит, задана аффинной формулой
  (доказуемо биективна, не "от фонаря")
- сложение с раундовым ключом: XOR
- padding: PKCS#7-подобный (заполнитель — длина паддинга, не нули)
- финализация: в последнем раунде P-box не применяется (как в AES)
- режим: блоки шифруются независимо (ECB) — если нужен режим со
  сцеплением (CBC и т.п.), это отдельный слой поверх encrypt/decrypt
"""

from dataclasses import dataclass
from pathlib import Path


# =========================================================
# Конфигурация
# =========================================================

SUPPORTED_KEY_SIZES = (64, 128, 256, 512)
BLOCK_SIZE_BITS = 128
BLOCK_SIZE_BYTES = BLOCK_SIZE_BITS // 8  # 16


@dataclass
class SPNConfig:
    key_size_bits: int = 128
    rounds: int = 10

    def __post_init__(self):
        if self.key_size_bits not in SUPPORTED_KEY_SIZES:
            raise ValueError(f"key_size_bits должен быть одним из {SUPPORTED_KEY_SIZES}")
        if self.rounds < 8:
            raise ValueError("rounds должно быть не меньше 8")


# =========================================================
# S-box — таблица AES (FIPS-197), 8 бит
# =========================================================

AES_SBOX = [
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
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]

AES_INV_SBOX = [0] * 256
for _i, _v in enumerate(AES_SBOX):
    AES_INV_SBOX[_v] = _i


# =========================================================
# P-box — битовая перестановка 128 бит
# =========================================================
# Аффинная перестановка позиций битов: new_pos = (5 * old_pos + 3) mod 128.
# Биективна, так как gcd(5, 128) == 1 — доказуемое свойство, а не
# перестановка "от фонаря". Обратная таблица строится напрямую из прямой.

_PBOX_A = 5
_PBOX_B = 3

PBOX = [(_PBOX_A * i + _PBOX_B) % BLOCK_SIZE_BITS for i in range(BLOCK_SIZE_BITS)]

INV_PBOX = [0] * BLOCK_SIZE_BITS
for _i, _new_pos in enumerate(PBOX):
    INV_PBOX[_new_pos] = _i


# =========================================================
# Padding — PKCS#7
# =========================================================

def pad(data: bytes) -> bytes:
    """Дополняет данные до кратности блоку. Заполнитель — не нули,
    а сама длина паддинга, повторённая нужное число раз (PKCS#7).
    Паддинг добавляется всегда, даже если данные уже кратны блоку —
    иначе unpad не сможет однозначно отличить паддинг от его отсутствия."""
    pad_len = BLOCK_SIZE_BYTES - (len(data) % BLOCK_SIZE_BYTES)
    return data + bytes([pad_len]) * pad_len


def unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("Нечего распаковывать — пустые данные")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE_BYTES or len(data) < pad_len:
        raise ValueError("Некорректный padding")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Повреждённый padding")
    return data[:-pad_len]


# =========================================================
# Основной класс шифра
# =========================================================

class SPNCipher:
    def __init__(self, config: SPNConfig):
        self.config = config
        self.sbox = AES_SBOX
        self.inv_sbox = AES_INV_SBOX
        self.pbox = PBOX
        self.inv_pbox = INV_PBOX
        self.round_keys: list[bytes] = []

    # ---------------------------------------------------
    # Ввод/вывод данных
    # ---------------------------------------------------

    def load_bytes(self, data: bytes) -> bytes:
        """Принять произвольные байты произвольной длины — как есть."""
        return data

    def load_file(self, path: str | Path) -> bytes:
        """Прочитать произвольный файл (текстовый/бинарный) в байты."""
        return Path(path).read_bytes()

    def save_file(self, path: str | Path, data: bytes) -> None:
        Path(path).write_bytes(data)

    # ---------------------------------------------------
    # Ключ
    # ---------------------------------------------------

    def set_key(self, key: bytes) -> None:
        """Проверка длины ключа + запуск key schedule."""
        if len(key) * 8 != self.config.key_size_bits:
            raise ValueError(
                f"Длина ключа должна быть {self.config.key_size_bits} бит "
                f"({self.config.key_size_bits // 8} байт), получено {len(key)} байт"
            )
        self.round_keys = self.expand_key(key)

    def expand_key(self, key: bytes) -> list[bytes]:
        """
        Key schedule: растягивает ключ ЛЮБОЙ поддерживаемой длины
        (64/128/256/512 бит) до self.config.rounds раундовых ключей
        длиной BLOCK_SIZE_BYTES байт каждый.

        Для каждого раунда: берём байт материала (циклически, с учётом
        текущего сдвига), пропускаем через S-box (нелинейность) и
        XOR-им с раундовой константой (номер раунда + позиция байта) —
        чтобы раунды не были симметричны друг другу. После раунда
        материал циклически сдвигается на 1 байт.
        """
        round_keys = []
        material = bytearray(key)

        for round_index in range(self.config.rounds):
            chunk = bytearray(BLOCK_SIZE_BYTES)
            for i in range(BLOCK_SIZE_BYTES):
                src_byte = material[i % len(material)]
                sub_byte = self.sbox[src_byte]
                round_const = (round_index * BLOCK_SIZE_BYTES + i) & 0xFF
                chunk[i] = sub_byte ^ round_const
            round_keys.append(bytes(chunk))
            material = material[1:] + material[:1]  # сдвиг материала

        return round_keys

    # ---------------------------------------------------
    # S-box
    # ---------------------------------------------------

    def substitute(self, block: bytes) -> bytes:
        return bytes(self.sbox[b] for b in block)

    def inverse_substitute(self, block: bytes) -> bytes:
        return bytes(self.inv_sbox[b] for b in block)

    # ---------------------------------------------------
    # P-box
    # ---------------------------------------------------

    def permute(self, block: bytes) -> bytes:
        return self._apply_bit_permutation(block, self.pbox)

    def inverse_permute(self, block: bytes) -> bytes:
        return self._apply_bit_permutation(block, self.inv_pbox)

    @staticmethod
    def _apply_bit_permutation(block: bytes, table: list[int]) -> bytes:
        value = int.from_bytes(block, "big")
        result = 0
        for old_pos in range(BLOCK_SIZE_BITS):
            bit = (value >> (BLOCK_SIZE_BITS - 1 - old_pos)) & 1
            new_pos = table[old_pos]
            result |= bit << (BLOCK_SIZE_BITS - 1 - new_pos)
        return result.to_bytes(BLOCK_SIZE_BYTES, "big")

    # ---------------------------------------------------
    # Сложение с раундовым ключом
    # ---------------------------------------------------

    def add_round_key(self, block: bytes, round_key: bytes) -> bytes:
        """XOR блока с раундовым ключом — самообратная операция."""
        return bytes(b ^ k for b, k in zip(block, round_key))

    # ---------------------------------------------------
    # Один раунд (прямой / обратный)
    # ---------------------------------------------------

    def encrypt_round(self, block: bytes, round_key: bytes, is_last: bool) -> bytes:
        block = self.add_round_key(block, round_key)
        block = self.substitute(block)
        if not is_last:
            block = self.permute(block)
        return block

    def decrypt_round(self, block: bytes, round_key: bytes, is_last: bool) -> bytes:
        if not is_last:
            block = self.inverse_permute(block)
        block = self.inverse_substitute(block)
        block = self.add_round_key(block, round_key)
        return block

    # ---------------------------------------------------
    # Шифрование/расшифрование одного блока
    # ---------------------------------------------------

    def encrypt_block(self, block: bytes) -> bytes:
        n = self.config.rounds
        for i in range(n):
            block = self.encrypt_round(block, self.round_keys[i], is_last=(i == n - 1))
        return block

    def decrypt_block(self, block: bytes) -> bytes:
        n = self.config.rounds
        for i in reversed(range(n)):
            block = self.decrypt_round(block, self.round_keys[i], is_last=(i == n - 1))
        return block

    # ---------------------------------------------------
    # Шифрование/расшифрование всего сообщения
    # ---------------------------------------------------

    def encrypt(self, data: bytes) -> bytes:
        data = pad(data)
        result = bytearray()
        for i in range(0, len(data), BLOCK_SIZE_BYTES):
            result += self.encrypt_block(data[i:i + BLOCK_SIZE_BYTES])
        return bytes(result)

    def decrypt(self, data: bytes) -> bytes:
        if len(data) % BLOCK_SIZE_BYTES != 0:
            raise ValueError("Длина шифротекста не кратна размеру блока")
        result = bytearray()
        for i in range(0, len(data), BLOCK_SIZE_BYTES):
            result += self.decrypt_block(data[i:i + BLOCK_SIZE_BYTES])
        return unpad(bytes(result))


# =========================================================
# Сбор пользовательского ввода (клавиатура / файл)
# =========================================================

def input_data_source() -> tuple[str, str]:
    """
    Спросить, откуда брать данные: с клавиатуры (текст) или из файла.
    Возвращает (source_type, value):
      source_type == "text" -> value — сам введённый текст
      source_type == "file" -> value — путь к файлу
    """
    choice = input("Источник данных — (1) ввести текст / (2) путь к файлу: ").strip()

    if choice == "1":
        text = input("Введите текст: ")
        return "text", text

    if choice == "2":
        path = input("Введите путь к текстовому файлу: ").strip()
        return "file", path

    raise ValueError("Некорректный выбор источника данных")


def text_to_bytes(text: str) -> bytes:
    """Текст с клавиатуры (str) переводится в байты (UTF-8) для подачи в шифр."""
    return text.encode("utf-8")


def derive_key_bytes(key_str: str, key_size_bits: int) -> bytes:
    """
    Ключ с клавиатуры (произвольная строка) переводится в байты нужной длины.
    Строка кодируется в UTF-8, затем циклически повторяется до нужной длины
    (если введено меньше байт, чем нужно) или обрезается (если больше).
    """
    if not key_str:
        raise ValueError("Ключ не может быть пустым")

    key_bytes = key_str.encode("utf-8")
    needed = key_size_bits // 8

    out = bytearray()
    i = 0
    while len(out) < needed:
        out.append(key_bytes[i % len(key_bytes)])
        i += 1

    return bytes(out[:needed])


def input_key_size() -> int:
    """Спросить длину ключа — должна быть одной из SUPPORTED_KEY_SIZES."""
    raw = input(f"Длина ключа {SUPPORTED_KEY_SIZES} (бит): ").strip()
    key_size = int(raw)

    if key_size not in SUPPORTED_KEY_SIZES:
        raise ValueError(f"Длина ключа должна быть одной из {SUPPORTED_KEY_SIZES}")

    return key_size


def input_key(key_size_bits: int) -> str:
    """Спросить сам ключ с клавиатуры (строка -> в байты дальше)."""
    key_str = input(f"Введите ключ ({key_size_bits} бит / {key_size_bits // 8} байт): ")
    return key_str


def input_rounds() -> int:
    """Спросить число раундов — не меньше 8."""
    raw = input("Число раундов (не меньше 8): ").strip()
    rounds = int(raw)

    if rounds < 8:
        raise ValueError("Число раундов должно быть не меньше 8")

    return rounds


def input_output_path() -> str:
    """Спросить, куда сохранить результат (зашифрованный/расшифрованный файл)."""
    path = input("Путь для сохранения результата: ").strip()
    return path


# =========================================================
# Интерактивный запуск
# =========================================================

def main() -> None:
    print("=== SPN Cipher ===")

    operation = input("Действие — (1) зашифровать / (2) расшифровать: ").strip()
    if operation not in ("1", "2"):
        raise ValueError("Некорректный выбор действия")

    source_type, value = input_data_source()

    if source_type == "text":
        if operation == "2":
            # для расшифрования текст с клавиатуры — это hex-запись шифротекста
            data = bytes.fromhex(value.strip())
        else:
            data = text_to_bytes(value)
    else:
        data = Path(value).read_bytes()

    key_size = input_key_size()
    key = derive_key_bytes(input_key(key_size), key_size)
    rounds = input_rounds()

    cfg = SPNConfig(key_size_bits=key_size, rounds=rounds)
    cipher = SPNCipher(cfg)
    cipher.set_key(key)

    if operation == "1":
        result = cipher.encrypt(data)
        print("\nШифротекст (hex):")
        print(result.hex())
    else:
        result = cipher.decrypt(data)
        try:
            print("\nРасшифрованный текст:")
            print(result.decode("utf-8"))
        except UnicodeDecodeError:
            print("\nРасшифрованные байты (не текст, hex):")
            print(result.hex())

    if input("\nСохранить результат в файл? (y/n): ").strip().lower() == "y":
        out_path = input_output_path()
        Path(out_path).write_bytes(result)
        print(f"Сохранено: {out_path}")


if __name__ == "__main__":
    main()