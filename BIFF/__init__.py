from struct import pack as STRUCT_PACK, unpack as STRUCT_UNPACK
from io import BytesIO, SEEK_CUR, SEEK_END, IOBase
from typing import Tuple, Dict, NoReturn, Any
from datetime import datetime
from time import time

try:
	from multimethod import multimethod
except:
	raise RuntimeError('Error. Module not found! Install `multimethod` (pip install multimethod)')

from hashlib import sha512 as SHA_512_NEW
@multimethod
def SHA512(data:bytes) -> bytes:
	return SHA_512_NEW(data).digest()
@multimethod
def SHA512(data:str) -> bytes:
	return SHA_512_NEW(data.encode()).digest()
@multimethod
def SHA512(data:int) -> bytes:
	return SHA_512_NEW(str(data)).digest()


__name__ = 'BIFF'
__description__ = 'Binary Interchange File Format'
__version__ = '1.0.0'

__all__ = [
	'BIFF',
	'ByteArray',
	'BinaryIO',
	'SHA512',
]

def TimeFromStamp(stamp:int) -> str:
	return datetime.fromtimestamp(stamp).strftime('%d/%m/%Y %H:%M:%S')


class MetaClass(type):
	def ModifyIt(name:str, bases:Tuple, attrs:Dict) -> Tuple:
		return name, bases, attrs
	def __new__(cls, name:str, bases:Tuple, attrs:Dict) -> object:
		name, bases, attrs = cls.ModifyIt(name, bases, attrs)
		return super(MetaClass, cls).__new__(cls, name, bases, attrs)

class ByteArray(bytearray, metaclass=MetaClass):
	@multimethod
	def __init__(self, src:int) -> NoReturn:
		super().__init__(src)
	@multimethod
	def __init__(self, src:bytes) -> NoReturn:
		super().__init__(src)
	@multimethod
	def __init__(self, src:bytearray) -> NoReturn:
		super().__init__(src)
	@multimethod
	def __init__(self, src:str) -> NoReturn:
		super().__init__(src.encode())
	def ToBytes(self) -> bytes:
		return bytes(self)
	@multimethod
	def __setitem__(self, key:Any, value:int) -> NoReturn:
		return super().__setitem__(key, chr(value).encode())
	@multimethod
	def __setitem__(self, key:Any, value:bytes) -> NoReturn:
		if isinstance(key, slice):
			return super().__setitem__(key, value[slice(0, key.stop, key.step)])
		else:
			return super().__setitem__(key, value)
	@multimethod
	def __setitem__(self, key:Any, value:str) -> NoReturn:
		if isinstance(key, slice):
			return super().__setitem__(key, value[slice(0, key.stop, key.step)].encode())
		else:
			return super().__setitem__(key, value.encode())
	@multimethod
	def __setitem__(self, key:Any, value:bytearray) -> NoReturn:
		if isinstance(key, slice):
			return super().__setitem__(key, value[slice(0, key.stop, key.step)])
		else:
			return super().__setitem__(key, value)
	@multimethod
	def append(self, data:int) -> NoReturn:
		super().append(data)
	@multimethod
	def append(self, data:bytes) -> NoReturn:
		for byte in data:
			super().append(byte)
	@multimethod
	def append(self, data:bytearray) -> NoReturn:
		for byte in data:
			super().append(byte)

class BinaryIO(BytesIO, metaclass=MetaClass):
	def CurPos(self) -> int:
		return self.seek(0, SEEK_CUR)
	def EndPos(self) -> int:
		return self.seek(0, SEEK_END)
	def GetData(self) -> int:
		current = self.CurPos()
		self.seek(0)
		data = self.read()
		self.seek(current)
		return ByteArray(data)


class BaseBinaryFormat(object, metaclass=MetaClass):
	# INIT
	__IO:IOBase = None
	__FORMAT:str = None
	def __init__(self, io:IOBase, fmat:str='>') -> NoReturn:
		self.__IO = io
		self.__FORMAT = fmat
		return
	def __DEFAULT_FORMAT(self, type:str) -> str:
		return f'{self.__FORMAT}{type}'.encode()
	# Read
	def ReadBool(self) -> bool:
		'''
		SizeInBytes = 1
		Min = 0
		Max = 1
		'''
		return STRUCT_UNPACK(self.__DEFAULT_FORMAT('b'), self.__IO.read(1))[0]
	def ReadShortInt(self) -> int:
		'''
		SizeInBytes = 2
		Min = -32768
		Max =  32767
		'''
		return STRUCT_UNPACK(self.__DEFAULT_FORMAT('h'), self.__IO.read(2))[0]	
	def ReadUnsignedShortInt(self) -> int:
		'''
		SizeInBytes = 2
		Min = 0
		Max = 65535
		'''
		return STRUCT_UNPACK(self.__DEFAULT_FORMAT('H'), self.__IO.read(2))[0]
	def ReadInt(self) -> int:
		'''
		SizeInBytes = 4
		Min = -2147483648
		Max =  2147483647
		'''
		return STRUCT_UNPACK(self.__DEFAULT_FORMAT('i'), self.__IO.read(4))[0]
	def ReadUnsignedInt(self) -> int:
		'''
		SizeInBytes = 4
		Min = 0
		Max = 4294967295
		'''
		return STRUCT_UNPACK(self.__DEFAULT_FORMAT('I'), self.__IO.read(4))[0]
	def ReadLongInt(self) -> int:
		'''
		SizeInBytes = 4
		Min = -2147483648
		Max =  2147483647
		'''
		return STRUCT_UNPACK(self.__DEFAULT_FORMAT('l'), self.__IO.read(4))[0]
	def ReadUnsignedLongInt(self) -> int:
		'''
		SizeInBytes = 4
		Min = 0
		Max = 4294967295
		'''
		return STRUCT_UNPACK(self.__DEFAULT_FORMAT('L'), self.__IO.read(4))[0]
	def ReadLongLongInt(self) -> int:
		'''
		SizeInBytes = 8
		Min = -9223372036854775808
		Max =  9223372036854775807
		'''
		return STRUCT_UNPACK(self.__DEFAULT_FORMAT('q'), self.__IO.read(8))[0]
	def ReadUnsignedLongLongInt(self) -> int:
		'''
		SizeInBytes = 8
		Min = 0
		Max = 18446744073709551615
		'''
		return STRUCT_UNPACK(self.__DEFAULT_FORMAT('Q'), self.__IO.read(8))[0]
	def ReadFloat(self) -> float:
		'''
		SizeInBytes = 4
		Min = 1.17549e-38
		Max = 3.40282e+38
		'''
		return STRUCT_UNPACK(self.__DEFAULT_FORMAT('f'), self.__IO.read(4))[0]
	def ReadDouble(self) -> float:
		'''
		SizeInBytes = 8
		Min = 2.22507e-308
		Max = 1.79769e+308
		'''
		return STRUCT_UNPACK(self.__DEFAULT_FORMAT('d'), self.__IO.read(4))[0]
	# Write
	def WriteBool(self, value:bool) -> int:
		'''
		SizeInBytes = 1
		Min = 0
		Max = 1
		'''
		return self.__IO.write(STRUCT_PACK(self.__DEFAULT_FORMAT('b'), value))
	def WriteShortInt(self, value:int) -> int:
		'''
		SizeInBytes = 2
		Min = -32768
		Max =  32767
		'''
		return self.__IO.write(STRUCT_PACK(self.__DEFAULT_FORMAT('h'), value))
	def WriteUnsignedShortInt(self, value:int) -> int:
		'''
		SizeInBytes = 2
		Min = 0
		Max = 65535
		'''
		return self.__IO.write(STRUCT_PACK(self.__DEFAULT_FORMAT('H'), value))
	def WriteInt(self, value:int) -> int:
		'''
		SizeInBytes = 4
		Min = -2147483648
		Max =  2147483647
		'''
		return self.__IO.write(STRUCT_PACK(self.__DEFAULT_FORMAT('i'), value))
	def WriteUnsignedInt(self, value:int) -> int:
		'''
		SizeInBytes = 4
		Min = 0
		Max = 4294967295
		'''
		return self.__IO.write(STRUCT_PACK(self.__DEFAULT_FORMAT('I'), value))
	def WriteLongInt(self, value:int) -> int:
		'''
		SizeInBytes = 4
		Min = -2147483648
		Max =  2147483647
		'''
		return self.__IO.write(STRUCT_PACK(self.__DEFAULT_FORMAT('l'), value))
	def WriteUnsignedLongInt(self, value:int) -> int:
		'''
		SizeInBytes = 4
		Min = 0
		Max = 4294967295
		'''
		return self.__IO.write(STRUCT_PACK(self.__DEFAULT_FORMAT('L'), value))
	def WriteLongLongInt(self, value:int) -> int:
		'''
		SizeInBytes = 8
		Min = -9223372036854775808
		Max =  9223372036854775807
		'''
		return self.__IO.write(STRUCT_PACK(self.__DEFAULT_FORMAT('q'), value))
	def WriteUnsignedLongLongInt(self, value:int) -> int:
		'''
		SizeInBytes = 8
		Min = 0
		Max = 18446744073709551615
		'''
		return self.__IO.write(STRUCT_PACK(self.__DEFAULT_FORMAT('Q'), value))
	def WriteFloat(self, value:float) -> int:
		'''
		SizeInBytes = 4
		Min = 1.17549e-38
		Max = 3.40282e+38
		'''
		return self.__IO.write(STRUCT_PACK(self.__DEFAULT_FORMAT('f'), value))
	def WriteDouble(self, value:float) -> int:
		'''
		SizeInBytes = 8
		Min = 2.22507e-308
		Max = 1.79769e+308
		'''
		return self.__IO.write(STRUCT_PACK(self.__DEFAULT_FORMAT('d'), value))

class BinaryFormat(BaseBinaryFormat, metaclass=MetaClass):
	# INIT
	__IO:IOBase = None
	@multimethod
	def __init__(self, io:IOBase, static:bool) -> NoReturn:
		self.__IO = io
		self.__STATIC_IO = static
		super().__init__(io)
		return
	@multimethod
	def __init__(self) -> NoReturn:
		self.__IO = BinaryIO()
		self.__STATIC_IO = True
		super().__init__(io)
		return
	# IO
	def __GetIO(self) -> IOBase:
		return self.__IO
	def __SetIO(self, new_io:IOBase) -> NoReturn:
		if self.__STATIC_IO != True:
			self.__IO = new_io
	IO = property(__GetIO, __SetIO)
	# Read
	def ReadByte(self) -> bytes:
		return self.__IO.read(1)
	def ReadString(self, offset:int=-1, size:int=256, back_to_current:bool=False) -> bytes:
		if offset != -1:
			if back_to_current:
				current = self.__IO.seek(0, SEEK_CUR)
			self.__IO.seek(offset)
			data = self.__IO.read(size).strip(b'\x00')
			if back_to_current:
				self.__IO.seek(current)
			return data
		else:
			return self.__IO.read(size).strip(b'\x00')
	def BFReadString(self, offset:int=-1, size:int=256, back_to_current:bool=False) -> object:
		if offset != -1:
			if back_to_current:
				current = self.__IO.seek(0, SEEK_CUR)
			self.__IO.seek(offset)
			data = self.__IO.read(size).strip(b'\x00')
			if back_to_current:
				self.__IO.seek(current)
			return BinaryFormat(BinaryIO(data), True)
		else:
			return BinaryFormat(BinaryIO(self.__IO.read(size).strip(b'\x00')), True)
	def ReadRAW(self, offset:int=-1, size:int=2048, back_to_current:bool=False) -> bytes:
		if offset != -1:
			if back_to_current:
				current = self.__IO.seek(0, SEEK_CUR)
			self.__IO.seek(offset)
			data = self.__IO.read(size)
			if back_to_current:
				self.__IO.seek(current)
			return data
		else:
			return self.__IO.read(size)
	def BFReadRAW(self, offset:int=-1, size:int=2048, back_to_current:bool=False) -> object:
		if offset != -1:
			if back_to_current:
				current = self.__IO.seek(0, SEEK_CUR)
			self.__IO.seek(offset)
			data = self.__IO.read(size)
			if back_to_current:
				self.__IO.seek(current)
			return BinaryFormat(BinaryIO(data), True)
		else:
			return BinaryFormat(BinaryIO(self.__IO.read(size)), True)
	# Write
	def WriteByte(self, byte:bytes) -> int:
		return self.__IO.write(byte[0])
	def WriteString(self, data:bytes, size:int=256) -> int:
		buf = ByteArray(size)
		buf[0:len(data)] = data
		return self.__IO.write(buf)
	def WriteRAW(self, data:bytes, size:int=2048) -> int:
		buf = ByteArray(size)
		buf[0:len(data)] = data
		return self.__IO.write(buf)

class BIFF(object, metaclass=MetaClass):
	__IO:IOBase = None
	__BF:BinaryFormat = None
	__NAME:bytes = None
	__DESC:bytes = None
	__FILES:Dict = None
	__HEADER:ByteArray = ByteArray('BIFF\x47\xCB\x7F\x0F')
	__IsEncoded:bool = False
	__VERSION:int = 100
	@multimethod
	def __init__(self, io:IOBase) -> NoReturn:
		self.__IO = io
		self.__BF = BinaryFormat(io, True)
		if self.__BF.ReadRAW(size=len(self.__HEADER), back_to_current=True) == self.__HEADER:
			self.__IsEncoded = True
		return
	@multimethod
	def __init__(self, data:bytes) -> NoReturn:
		self.__IO = BinaryIO(data)
		self.__BF = BinaryFormat(self.__IO, True)
		if self.__BF.ReadRAW(size=len(self.__HEADER), back_to_current=True) == self.__HEADER:
			self.__IsEncoded = True
		return
	@multimethod
	def __init__(self, data:ByteArray) -> NoReturn:
		self.__IO = BinaryIO(data)
		self.__BF = BinaryFormat(self.__IO, True)
		if self.__BF.ReadRAW(size=len(self.__HEADER), back_to_current=True) == self.__HEADER:
			self.__IsEncoded = True
		return
	@multimethod
	def __init__(self, name:bytes, desc:bytes, files:Dict) -> NoReturn:
		self.__IO = BinaryIO()
		self.__BF = BinaryFormat(self.__IO, True)
		self.__NAME = name
		self.__DESC = desc
		self.__FILES = files
		return
	@multimethod
	def __init__(self, name:str, desc:str, files:Dict) -> NoReturn:
		self.__IO = BinaryIO()
		self.__BF = BinaryFormat(self.__IO, True)
		self.__NAME = name.encode()
		self.__DESC = desc.encode()
		self.__FILES = files
		return
	def __GetIO(self) -> IOBase:
		return self.__IO
	def __SetIO(self, new_io:IOBase) -> NoReturn:
		self.__IO = new_io
	IO = property(__GetIO, __SetIO)
	def Encode(self) -> bool:
		if self.__IsEncoded:
			return False
		self.__BF.WriteString(self.__HEADER, size=len(self.__HEADER)) # HEADER
		self.__BF.WriteString(self.__NAME, size=256) # NAME
		self.__BF.WriteString(self.__DESC, size=256) # DESC
		self.__BF.WriteUnsignedLongLongInt(int(time())) # TIME
		self.__BF.WriteUnsignedShortInt(self.__VERSION) # VER
		self.__BF.WriteUnsignedLongLongInt(len(self.__FILES)) # F_CNT
		for f_name in self.__FILES:
			f_data = self.__FILES[f_name]
			f_hash = SHA512(f_data)
			self.__BF.WriteString(f_name, size=256) # F_NAME
			self.__BF.WriteUnsignedLongLongInt(int(time())) # F_TIME
			self.__BF.WriteString(f_hash, size=64) # F_HASH
			self.__BF.WriteUnsignedLongLongInt(len(f_data)) # F_LEN
			self.__BF.WriteRAW(f_data, size=len(f_data)) # F_DATA
		current = self.__IO.seek(0, SEEK_CUR)
		self.__IO.seek(0)
		data = self.__IO.read()
		self.__IO.seek(current)
		return data
	def Decode(self) -> bool:
		if self.__IsEncoded != True:
			return False
		name = self.__BF.ReadString(size=256) # NAME
		desc = self.__BF.ReadString(size=256) # DESC
		time = self.__BF.ReadUnsignedLongLongInt() # TIME
		ver = self.__BF.ReadUnsignedShortInt() # VER
		f_cnt = self.__BF.ReadUnsignedLongLongInt() # F_CNT
		files = dict()
		for i in range(f_cnt):
			f_name = self.__BF.ReadString(size=256).decode() # F_NAME
			f_time = self.__BF.ReadUnsignedLongLongInt() # F_TIME
			f_hash = self.__BF.ReadRAW(size=64) # F_HASH
			f_size = self.__BF.ReadUnsignedLongLongInt() # F_LEN
			files[f_name] = dict()
			files[f_name]['time'] = TimeFromStamp(f_time)
			files[f_name]['size'] = f_size
			files[f_name]['data'] = self.__BF.ReadRAW(size=f_size) # F_DATA
			files[f_name]['sha512'] = f_hash.hex().upper()
			files[f_name]['verified'] = (f_hash == SHA512(files[f_name]['data']))
		return {'info': {'name': name, 'desc': desc, 'ver': ver, 'time': TimeFromStamp(time)}, 'files': files}