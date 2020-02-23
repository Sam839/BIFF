# BIFF
Binary Interchange File Format 

# Warning
To work, you need module `multimethod` (https://pypi.org/project/multimethod/)

# BIFF classes
```
# FlagsBIFF
FlagsBIFF.FL_NONE = 0
FlagsBIFF.FL_DEFAULT = 1
FlagsBIFF.FL_ENCRYPTED_ICE = 2
FlagsBIFF.FL_COMPRESSED_ZLIB = 8
FlagsBIFF.FL_COMPRESSED_DEFLATE = 16

# BIFF
BIFF(io:IOBase) # Supports `Decode`
BIFF(data:bytes) # Supports `Decode`
BIFF(data:ByteArray) # Supports `Decode`
BIFF(name:bytes, description:bytes, data:dict) # Supports `Encode`
BIFF(name:str, description:str, data:dict) # Supports `Encode`

# ByteArray
ByteArray(src:int) # Bytes array of size given by the parameter initialized with null bytes
ByteArray(src:bytes) # Mutable copy of src
ByteArray(src:bytearray) # Mutable copy of src
ByteArray(src:*bytearray) # Mutable copy of src
ByteArray(src:str) # Converted mutable copy of src
ByteArray(src:list) # Converted to ByteArray

# BinaryIO
BinaryIO(initial_bytes) # Buffered I/O implementation using an in-memory bytes buffer.
```

# Methods of BIFF classes
```
# BIFF
BIFF->IO # @property
BIFF->Encode() # Encoding data
BIFF->Decode() # Decoding data

# ByteArray
ByteArray->__setitem__(key, value:int)
ByteArray->__setitem__(key, value:bytes)
ByteArray->__setitem__(key, value:bytearray)
ByteArray->append(data:int)
ByteArray->append(data:bytes)
ByteArray->append(data:bytearray)

# BinaryIO
BinaryIO->CurPos() # Get current position
BinaryIO->EndPos() # Get end position
BinaryIO->GetData() # Get all data from the IO buffer
```

# Example
```
from BIFF import BIFF, FlagsBIFF

# Encode
bf = BIFF("Name for BIFF data packet", "Description for BIFF data packet", {
	# <DATA NAME>: <DATA>
	b'Test.txt': 'Hello, World!',
	b'\xde\xed\xbe\xef': b'0xDEEDBEEF',
	'tester': b'No',
})
data = bf.Encode(FlagsBIFF.FL_ENCRYPTED_ICE | FlagsBIFF.FL_COMPRESSED_DEFLATE)

# Decode
bf = BIFF(data)
data = bf.Decode()

# BIFF
print('#' * 32)
print('[+] BIFF UUID: {}'.format(data['BIFF']['uuid']))
print('[+] BIFF UUID VALID: {}'.format(data['BIFF']['verified']))
print('[+] BIFF VERSION: {}'.format(data['BIFF']['biff_version']))
print('[+] BIFF ENCODER VERSION: {}'.format(data['BIFF']['encoder_version']))
print('[+] BIFF ENCODER FLAGS: {}'.format(data['BIFF']['encoder_flags']))
print('[+] BIFF TIME: {}'.format(data['BIFF']['time']))
print('[+] BIFF NAME: {}'.format(data['BIFF']['name']))
print('[+] BIFF DESCRIPTION: {}'.format(data['BIFF']['description']))
# DATA
for data_name in data['DATA']:
	print('#' * 32)
	print('[+] DATA NAME: {}'.format(data_name))
	print('[+] DATA SIZE: {}'.format(data['DATA'][data_name]['size']))
	print('[+] DATA SHA512: {}'.format(data['DATA'][data_name]['sha512']))
	print('[+] DATA TIME: {}'.format(data['DATA'][data_name]['time']))
	print('[+] DATA: {}'.format(data['DATA'][data_name]['data']))
	print('[+] DATA HASH VALID: {}'.format(data['DATA'][data_name]['verified']))
```
```
################################
[+] BIFF UUID: 0a8f2fe8-87ba-5235-8fbc-9fc82c694485      
[+] BIFF UUID VALID: True
[+] BIFF VERSION: 211
[+] BIFF ENCODER VERSION: 111
[+] BIFF ENCODER FLAGS: 18
[+] BIFF TIME: 17/02/2020 02:13:48.776285
[+] BIFF NAME: b'Name for BIFF data packet'
[+] BIFF DESCRIPTION: b'Description for BIFF data packet'
################################
[+] DATA NAME: b'Test.txt'
[+] DATA SIZE: 13
[+] DATA SHA512: 374D794A95CDCFD8B35993185FEF9BA368F160D8DAF432D08BA9F1ED1E5ABE6CC69291E0FA2FE0006A52570EF18C19DEF4E617C33CE52EF0A6E5FBE318CB0387
[+] DATA TIME: 17/02/2020 02:13:48.777037
[+] DATA: b'Hello, World!'
[+] DATA HASH VALID: True
################################
[+] DATA NAME: b'\xde\xed\xbe\xef'
[+] DATA SIZE: 10
[+] DATA SHA512: 8FC0519229554E885E2C752C56E80960FA4C2E2E4585B9D5A02AD694F21DF192F304E707DD6504C6EB2BFCA704DDDB419CF49C7347144609EE1551F187D688F3
[+] DATA TIME: 17/02/2020 02:13:48.777784
[+] DATA: b'0xDEEDBEEF'
[+] DATA HASH VALID: True
```
