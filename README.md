# Moe XCOM

Just my poorly organized thoughts and code snippets on reverse engineering Blue Archive

Any help is appreciated

## Viewing/extracing Unity assets

i.e. `com.nexon.bluearchive\files\PUB\Resource\Preload\Android\*.bundle`

Use [AssetStudio](https://github.com/Perfare/AssetStudio)

## Decompiling source code

It looks like no major scripting is used there, unlike with, for example, [Azur Lane](https://github.com/Dimbreath/AzurLaneData)

All code is actually written in C# in Unity, and then compiled with IL2CPP into libil2cpp.so, so no way to extract IL or C# sources

Use [Il2CppDumper](https://github.com/Perfare/Il2CppDumper) to extract C# types and [generate script](https://github.com/djkaty/Il2CppInspector/blob/master/README.md#adding-metadata-to-your-ghidra-workflow) to use with [Ghidra SRE](https://github.com/NationalSecurityAgency/ghidra)

Read [this](https://katyscode.wordpress.com/2020/06/24/il2cpp-part-1/) and [this](https://katyscode.wordpress.com/2020/12/27/il2cpp-part-2/)

## Unpacking password-protected table bundles

Get list from files/TableBundles/TableCatalog.json

stored file name: xxHash64(zip-original-name), etc: `3622299440866786438` => `Excel.zip`

password: (Pseudocode)
```python
import base64
import xxhash
from mt19937 import MT19937 # pip install mt19937

# Get list from files/TableBundles/TableCatalog.json
table_catalog = {...} # assume this is a dictionary mapping file IDs to filenames

def unpack_table_bundle(file_id):
    # retrieve original filename from file ID using xxHash64
    filename = xxhash.xxh64(str(file_id).encode()).hexdigest() + '.zip'

    # create password for zip file using xxHash32 and Mersenne Twister RNG
    key = xxhash.xxh32(filename.encode()).intdigest()
    mt = MT19937(key)
    password = base64.b64encode(mt.random_bytes(15)).decode()

    # TODO: extract contents of the password-protected zip file using the password

    return contents
```

See IDA function `TableService$$LoadBytes`

## Reading unpacked above `.bytes` files

Ref: [FlatBuffers](https://google.github.io/flatbuffers)  
.fbs from il2cppDumper: [here](unpack.fbs), the generator will provided if needs  
unpack steps: (partial code, issue welcome if full-code needed)  
```python
import os
import struct
import json
import base64
import xxhash
import flatbuffers # pip install flatbuffers

# Define FlatBuffer schema
# The flatbuffers schema is not shown in the original code, so this is just a placeholder
SCHEMA = """\
table ScenarioCharacterNameExcelTable {
  name: string;
  id: int;
}
"""

# Define decryption functions
def create_key(name: str, length: int) -> bytes:
    key = xxhash.xxh32(name.encode()).intdigest()
    arr = bytearray(struct.pack(f'{len(name)}sI', name.encode(), key))
    mt = MT19937(key)
    for i in range(length):
        arr.append(mt.extract_number() & 0xff)
    return bytes(arr)

def b_arr_as_u64_arr(b_arr: bytes) -> list[int]:
    return list(struct.unpack(f'{len(b_arr) // 8}Q', b_arr))

def decode_any_scalar(v: int, key: bytes) -> int:
    if v == 0:
        return v
    if isinstance(v, int):
        if v.bit_length() <= 32:
            v ^= b_arr_as_any_first_uint32(key)
        else:
            v ^= b_arr_as_any_first_uint64(key)
    return v

def decode_str(data: bytes, key: bytes) -> str:
    if not data:
        return '""'
    raw = base64.standard_b64decode(data)
    xor(raw, key)
    decoded = ''.join(chr(c) for c in struct.unpack(f'{len(raw) // 2}H', raw))
    return json.dumps(decoded)

def xor(b_arr: bytearray, key: bytes) -> None:
    for i, b in enumerate(b_arr):
        b_arr[i] = b ^ key[i % len(key)]


# Load data from file
class ScenarioCharacterNameExcelTable:
    def __init__(self, name: str = '', id: int = 0):
        self.name = name
        self.id = id

table = ScenarioCharacterNameExcelTable()
name = type(table).__name__ # "ScenarioCharacterNameExcelTable"
data = open(name.lower() + '.bytes', 'rb').read()
key = create_key(name, len(data))

# Decrypt data
arr = b_arr_as_u64_arr(data)
key_arr = b_arr_as_u64_arr(key)
for i in range(len(arr)):
    arr[i] ^= key_arr[i]
for i in range(len(data) - len(data) % 8, len(data)):
    data[i] ^= key[i % len(key)]
    
# Deserialize data using FlatBuffers
table = flatbuffers.binary_readers.read_object(arr, table, SCHEMA)

# Decrypt values in table
table.name = decode_str(table.name.encode(), create_key_by_string(name.replace('ExcelTable', ''), 8))
table.id = decode_any_scalar(table.id, key)

print(table.name, table.id)
```

Python code by ChatGPT

# copyright Yostar
