import argparse
import dataclasses
import hashlib
import io
import pathlib
import struct

@dataclasses.dataclass
class RSDKFileInfo:
    hash: bytes
    offset: int
    size: int
    encrypted: bool
    filename: str = ""

files: dict[bytes, RSDKFileInfo] = {}

ENC_KEY_1 = 0xAAAAAAAB
ENC_KEY_2 = 0x24924925

def reverse_hash(hash: bytes):
    return struct.pack(">4I", *struct.unpack("<4I", hash))

def mul_unsigned_high(arg1: int, arg2: int):
    return int((arg1 * arg2) >> 32)

def generate_eload_key(key: int):
    return reverse_hash(hashlib.md5(str(key).encode()).digest())

def decrypt_file(data: bytes, info: RSDKFileInfo):
    key1 = generate_eload_key(info.size)
    key2 = generate_eload_key((info.size >> 1) + 1)
    key1pos = 0
    key2pos = 8
    nybble_swap = 0
    xor_value = (info.size & 0x1FC) >> 2

    decoded = bytearray()
    for c in data:
        c = key2[key2pos] ^ xor_value ^ c
        if nybble_swap:
            c = ((c << 4) + (c >> 4)) & 0xFF
        c ^= key1[key1pos]

        decoded.append(c)

        key1pos += 1
        key2pos += 1
        if key1pos <= 0xF:
            if key2pos > 0xC:
                key2pos = 0
                nybble_swap ^= 0x1
        elif key2pos <= 0x8:
            key1pos = 0
            nybble_swap ^= 0x1
        else:
            xor_value += 2
            xor_value &= 0x7F

            if nybble_swap != 0:
                temp_key1 = mul_unsigned_high(ENC_KEY_1, xor_value)
                temp_key2 = mul_unsigned_high(ENC_KEY_2, xor_value)
                nybble_swap = 0

                temp1 = temp_key2 + (xor_value - temp_key2) // 2
                temp2 = temp_key1 // 8 * 3

                key1pos = xor_value - temp1 // 4 * 7
                key2pos = xor_value - temp2 * 4 + 2
            else:
                temp_key1 = mul_unsigned_high(ENC_KEY_1, xor_value)
                temp_key2 = mul_unsigned_high(ENC_KEY_2, xor_value)
                nybble_swap = 1

                temp1 = temp_key2 + (xor_value - temp_key2) // 2
                temp2 = temp_key1 // 8 * 3

                key1pos = xor_value - temp2 * 4 + 3
                key2pos = xor_value - temp1 // 4 * 7

    return bytes(decoded)

def find_files(file: io.BufferedReader):
    assert file.read(5) == b"RSDKv", "Not a valid RSDK file"
    assert file.read(1) == b"B", "This extractor only supports RSDKvB (Sonic 1/2 2013)."

    filecount: int = struct.unpack("<H", file.read(2))[0]
    for _ in range(filecount):
        hash = reverse_hash(file.read(16))
        offset: int = struct.unpack("<I", file.read(4))[0]
        filesize: int = struct.unpack("<I", file.read(4))[0]
        encrypted = bool(filesize & 0x80000000)
        filesize &= 0x7FFFFFFF

        info = RSDKFileInfo(hash, offset, filesize, encrypted)
        files[hash] = info

def find_file(path: str):
    path_hash = hashlib.md5(path.lower().encode()).digest()
    file = files.get(path_hash)
    
    if file is not None and not file.filename:
        file.filename = path

    return file

def parse_args():
    parser = argparse.ArgumentParser(description="Extracts files from an RSDK asset file.")

    parser.add_argument("output", help="The folder that the RSDK file contents should be dumped to.")
    parser.add_argument(
        "-f", 
        "--file", 
        help="The path to the RSDK file to extract.", 
        default="Data.rsdk"
    )

    return parser.parse_args()

def main():
    args = parse_args()

    input = pathlib.Path(args.file)
    output = pathlib.Path(args.output)

    if not input.exists():
        raise ValueError(f"Invalid RSDK file {args.file}! Are you in the same directory?")

    if not output.exists():
        raise ValueError(f"Invalid output path {args.output}!")
    
    rsdk_filepaths = []
    with open("rsdk_files_list.txt", "r") as f:
        rsdk_filepaths = [s.strip() for s in f.readlines()]

    rsdk_file = input.open("rb")

    find_files(rsdk_file)
    for filepath in rsdk_filepaths:
        info = find_file(filepath)

        if info is None:
            continue

        print("Found file", filepath, "with hash", info.hash)

        rsdk_file.seek(info.offset)
        data = rsdk_file.read(info.size)

        if info.encrypted:
            print("File", filepath, "is encrypted! Decrypting")
            data = decrypt_file(data, info)

        full_output = output / filepath
        print("Saving file", filepath, "to", full_output)

        if not full_output.parent.exists():
            full_output.parent.mkdir(parents=True)

        with full_output.open("wb") as f:
            f.write(data)

if __name__ == "__main__":
    main()
