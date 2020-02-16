from uuid import UUID
from struct import pack as STRUCT_PACK, unpack as STRUCT_UNPACK
from io import BytesIO, SEEK_CUR, SEEK_END, IOBase
from typing import NoReturn
from types import FunctionType
from datetime import datetime
from time import time_ns

XDR_UUID = UUID('0a8f2fe8-87ba-5235-8fbc-9fc82c694485') # DO NOT EDIT!

try:
	from multimethod import multimethod
except ModuleNotFoundError:
	raise Exception('Error. Module not found! Install `multimethod` (pip install multimethod)')

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
__version__ = '2.0.0'

__all__ = [
	'BIFF',
	'ByteArray',
	'BinaryIO',
	'SHA512',
]

def NanoSecondsToStamp(ns:int) -> float:
	return ns * 1e-9

def TimeFromStamp(stamp:float) -> str:
	return datetime.fromtimestamp(stamp).strftime('%d/%m/%Y %H:%M:%S.%f')

class MetaClass(type):
	def ModifyIt(name:str, bases:tuple, attrs:dict) -> tuple:
		return name, bases, attrs
	def __new__(cls, name:str, bases:tuple, attrs:dict) -> object:
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
	def __init__(self, *src:bytearray) -> NoReturn:
		super().__init__()
		for array in src:
			super().extend(array)
	@multimethod
	def __init__(self, src:str) -> NoReturn:
		super().__init__(src.encode())
	def ToBytes(self) -> bytes:
		return bytes(self)
	@multimethod
	def __init__(self, src:list) -> NoReturn:
		bf = bytearray(len(src))
		cnt = 0
		for pbyte in src:
			if (0 < pbyte < 255):
				bf[cnt] = pbyte
			else:
				if pbyte > 255:
					bf[cnt] = 255
				if pbyte < 0:
					bf[cnt] = 0
			cnt += 1
		super().__init__(bf)
	@multimethod
	def __setitem__(self, key, value:int) -> NoReturn:
		return super().__setitem__(key, chr(value).encode())
	@multimethod
	def __setitem__(self, key, value:bytes) -> NoReturn:
		if isinstance(key, slice):
			return super().__setitem__(key, value[slice(0, key.stop, key.step)])
		else:
			return super().__setitem__(key, value)
	@multimethod
	def __setitem__(self, key, value:str) -> NoReturn:
		if isinstance(key, slice):
			return super().__setitem__(key, value[slice(0, key.stop, key.step)].encode())
		else:
			return super().__setitem__(key, value.encode())
	@multimethod
	def __setitem__(self, key, value:bytearray) -> NoReturn:
		if isinstance(key, slice):
			return super().__setitem__(key, value[slice(0, key.stop, key.step)])
		else:
			return super().__setitem__(key, value)
	@multimethod
	def append(self, data:int) -> NoReturn:
		super().append(data)
	@multimethod
	def append(self, data:bytes) -> NoReturn:
		super().extend(data)
	@multimethod
	def append(self, data:bytearray) -> NoReturn:
		super().extend(data)


class BinaryBits(object, metaclass=MetaClass):
	@staticmethod
	def GetBits(num:int, bits_cnt:int=64) -> list:
		bits = [ 0x00 ] * bits_cnt
		mask = 1 << (bits_cnt - 1)
		i = 0
		while mask > 0:
			bits[i] = int((num & mask) != 0)
			mask >>= 1
			i += 1
		return bits
	@staticmethod
	def GetNum(bits:list) -> int:
		out = 0
		for i in range(len(bits)):
			out = (out << 1) | bits[i]
		return out
	@staticmethod
	def GetBit(num:int, pos:int) -> int:
		bit = num & (1 << pos)
		return int(bool(bit))
	@staticmethod
	def SetBit(num:int, pos:int) -> int:
		mask = 1 << pos
		return num | mask
	@staticmethod
	def ClearBit(num:int, pos:int) -> int:
		mask = 1 << pos
		return num & ~mask
	@staticmethod
	def SetSubSets(subsets:list) -> int:
		num = 0
		for subset in subsets:
			num = num | (1 << subset)
		return num
	@staticmethod
	def GetSubSets(num:int, stop:int=64) -> list:
		subsets = list()
		for i in range(stop):
			subsets.append(int(num & (1 << i) != 0))
		return subsets
	@staticmethod
	def CountBits(num:int) -> int:
		c = 0
		while num:
			c += 1
			num >>= 1
		return c
	@staticmethod
	def BigIntToBits(num:int, bits_cnt:int=8) -> list:
		bits = BinaryBits.GetBits(num, BinaryBits.CountBits(num))
		return [bits[i:i + bits_cnt] for i in range(0, len(bits), bits_cnt)]
	@staticmethod
	def BitsToBigInt(bits:list) -> int:
		total_bits = list()
		for current_bits in bits:
			total_bits.extend(current_bits)
		return BinaryBits.GetNum(total_bits)


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
	def ReadBool(self, offset:int=-1, back_to_current:bool=False) -> bool:
		'''
		SizeInBytes = 1
		Min = 0
		Max = 1
		'''
		if (offset != -1) | (back_to_current != False):
			if back_to_current:
				current = self.__IO.seek(0, SEEK_CUR)
			if offset != -1:
				self.__IO.seek(offset)
			data = STRUCT_UNPACK(self.__DEFAULT_FORMAT('b'), self.__IO.read(1))[0]
			if back_to_current:
				self.__IO.seek(current)
			return data
		else:
			return STRUCT_UNPACK(self.__DEFAULT_FORMAT('b'), self.__IO.read(1))[0]
	def ReadShortInt(self, offset:int=-1, back_to_current:bool=False) -> int:
		'''
		SizeInBytes = 2
		Min = -32768
		Max =  32767
		'''
		if (offset != -1) | (back_to_current != False):
			if back_to_current:
				current = self.__IO.seek(0, SEEK_CUR)
			if offset != -1:
				self.__IO.seek(offset)
			data = STRUCT_UNPACK(self.__DEFAULT_FORMAT('h'), self.__IO.read(2))[0]
			if back_to_current:
				self.__IO.seek(current)
			return data
		else:
			return STRUCT_UNPACK(self.__DEFAULT_FORMAT('h'), self.__IO.read(2))[0]
	def ReadUnsignedShortInt(self, offset:int=-1, back_to_current:bool=False) -> int:
		'''
		SizeInBytes = 2
		Min = 0
		Max = 65535
		'''
		if (offset != -1) | (back_to_current != False):
			if back_to_current:
				current = self.__IO.seek(0, SEEK_CUR)
			if offset != -1:
				self.__IO.seek(offset)
			data = STRUCT_UNPACK(self.__DEFAULT_FORMAT('H'), self.__IO.read(2))[0]
			if back_to_current:
				self.__IO.seek(current)
			return data
		else:
			return STRUCT_UNPACK(self.__DEFAULT_FORMAT('H'), self.__IO.read(2))[0]
	def ReadInt(self, offset:int=-1, back_to_current:bool=False) -> int:
		'''
		SizeInBytes = 4
		Min = -2147483648
		Max =  2147483647
		'''
		if (offset != -1) | (back_to_current != False):
			if back_to_current:
				current = self.__IO.seek(0, SEEK_CUR)
			if offset != -1:
				self.__IO.seek(offset)
			data = STRUCT_UNPACK(self.__DEFAULT_FORMAT('i'), self.__IO.read(4))[0]
			if back_to_current:
				self.__IO.seek(current)
			return data
		else:
			return STRUCT_UNPACK(self.__DEFAULT_FORMAT('i'), self.__IO.read(4))[0]
	def ReadUnsignedInt(self, offset:int=-1, back_to_current:bool=False) -> int:
		'''
		SizeInBytes = 4
		Min = 0
		Max = 4294967295
		'''
		if (offset != -1) | (back_to_current != False):
			if back_to_current:
				current = self.__IO.seek(0, SEEK_CUR)
			if offset != -1:
				self.__IO.seek(offset)
			data = STRUCT_UNPACK(self.__DEFAULT_FORMAT('I'), self.__IO.read(4))[0]
			if back_to_current:
				self.__IO.seek(current)
			return data
		else:
			return STRUCT_UNPACK(self.__DEFAULT_FORMAT('I'), self.__IO.read(4))[0]
	def ReadLongInt(self, offset:int=-1, back_to_current:bool=False) -> int:
		'''
		SizeInBytes = 4
		Min = -2147483648
		Max =  2147483647
		'''
		if (offset != -1) | (back_to_current != False):
			if back_to_current:
				current = self.__IO.seek(0, SEEK_CUR)
			if offset != -1:
				self.__IO.seek(offset)
			data = STRUCT_UNPACK(self.__DEFAULT_FORMAT('l'), self.__IO.read(4))[0]
			if back_to_current:
				self.__IO.seek(current)
			return data
		else:
			return STRUCT_UNPACK(self.__DEFAULT_FORMAT('l'), self.__IO.read(4))[0]
	def ReadUnsignedLongInt(self, offset:int=-1, back_to_current:bool=False) -> int:
		'''
		SizeInBytes = 4
		Min = 0
		Max = 4294967295
		'''
		if (offset != -1) | (back_to_current != False):
			if back_to_current:
				current = self.__IO.seek(0, SEEK_CUR)
			if offset != -1:
				self.__IO.seek(offset)
			data = STRUCT_UNPACK(self.__DEFAULT_FORMAT('L'), self.__IO.read(4))[0]
			if back_to_current:
				self.__IO.seek(current)
			return data
		else:
			return STRUCT_UNPACK(self.__DEFAULT_FORMAT('L'), self.__IO.read(4))[0]
	def ReadLongLongInt(self, offset:int=-1, back_to_current:bool=False) -> int:
		'''
		SizeInBytes = 8
		Min = -9223372036854775808
		Max =  9223372036854775807
		'''
		if (offset != -1) | (back_to_current != False):
			if back_to_current:
				current = self.__IO.seek(0, SEEK_CUR)
			if offset != -1:
				self.__IO.seek(offset)
			data = STRUCT_UNPACK(self.__DEFAULT_FORMAT('q'), self.__IO.read(8))[0]
			if back_to_current:
				self.__IO.seek(current)
			return data
		else:
			return STRUCT_UNPACK(self.__DEFAULT_FORMAT('q'), self.__IO.read(8))[0]
	def ReadUnsignedLongLongInt(self, offset:int=-1, back_to_current:bool=False) -> int:
		'''
		SizeInBytes = 8
		Min = 0
		Max = 18446744073709551615
		'''
		if (offset != -1) | (back_to_current != False):
			if back_to_current:
				current = self.__IO.seek(0, SEEK_CUR)
			if offset != -1:
				self.__IO.seek(offset)
			data = STRUCT_UNPACK(self.__DEFAULT_FORMAT('Q'), self.__IO.read(8))[0]
			if back_to_current:
				self.__IO.seek(current)
			return data
		else:
			return STRUCT_UNPACK(self.__DEFAULT_FORMAT('Q'), self.__IO.read(8))[0]
	def ReadFloat(self, offset:int=-1, back_to_current:bool=False) -> float:
		'''
		SizeInBytes = 4
		Min = 1.17549e-38
		Max = 3.40282e+38
		'''
		if (offset != -1) | (back_to_current != False):
			if back_to_current:
				current = self.__IO.seek(0, SEEK_CUR)
			if offset != -1:
				self.__IO.seek(offset)
			data = STRUCT_UNPACK(self.__DEFAULT_FORMAT('f'), self.__IO.read(4))[0]
			if back_to_current:
				self.__IO.seek(current)
			return data
		else:
			return STRUCT_UNPACK(self.__DEFAULT_FORMAT('f'), self.__IO.read(4))[0]
	def ReadDouble(self, offset:int=-1, back_to_current:bool=False) -> float:
		'''
		SizeInBytes = 8
		Min = 2.22507e-308
		Max = 1.79769e+308
		'''
		if (offset != -1) | (back_to_current != False):
			if back_to_current:
				current = self.__IO.seek(0, SEEK_CUR)
			if offset != -1:
				self.__IO.seek(offset)
			data = STRUCT_UNPACK(self.__DEFAULT_FORMAT('d'), self.__IO.read(8))[0]
			if back_to_current:
				self.__IO.seek(current)
			return data
		else:
			return STRUCT_UNPACK(self.__DEFAULT_FORMAT('d'), self.__IO.read(8))[0]
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
		super().__init__(self.__IO)
		return
	# IO
	def __GetIO(self) -> IOBase:
		return self.__IO
	def __SetIO(self, new_io:IOBase) -> NoReturn:
		if self.__STATIC_IO != True:
			self.__IO = new_io
	IO = property(__GetIO, __SetIO)
	# Read
	def ReadBits(self) -> list:
		return BinaryBits.CountBits(self.__IO.read(1))
	def ReadByte(self) -> bytes:
		return self.__IO.read(1)
	def ReadString(self, offset:int=-1, size:int=256, back_to_current:bool=False) -> bytes:
		if (offset != -1) | (back_to_current != False):
			if back_to_current:
				current = self.__IO.seek(0, SEEK_CUR)
			if offset != -1:
				self.__IO.seek(offset)
			data = self.__IO.read(size).strip(b'\x00')
			if back_to_current:
				self.__IO.seek(current)
			return data
		else:
			return self.__IO.read(size).strip(b'\x00')
	def BFReadString(self, offset:int=-1, size:int=256, back_to_current:bool=False) -> object:
		if (offset != -1) | (back_to_current != False):
			if back_to_current:
				current = self.__IO.seek(0, SEEK_CUR)
			if offset != -1:
				self.__IO.seek(offset)
			data = self.__IO.read(size).strip(b'\x00')
			if back_to_current:
				self.__IO.seek(current)
			return BinaryFormat(BinaryIO(data), True)
		else:
			return BinaryFormat(BinaryIO(self.__IO.read(size).strip(b'\x00')), True)
	def ReadRAW(self, offset:int=-1, size:int=2048, back_to_current:bool=False) -> bytes:
		if (offset != -1) | (back_to_current != False):
			if back_to_current:
				current = self.__IO.seek(0, SEEK_CUR)
			if offset != -1:
				self.__IO.seek(offset)
			data = self.__IO.read(size)
			if back_to_current:
				self.__IO.seek(current)
			return data
		else:
			return self.__IO.read(size)
	def BFReadRAW(self, offset:int=-1, size:int=2048, back_to_current:bool=False) -> object:
		if (offset != -1) | (back_to_current != False):
			if back_to_current:
				current = self.__IO.seek(0, SEEK_CUR)
			if offset != -1:
				self.__IO.seek(offset)
			data = self.__IO.read(size)
			if back_to_current:
				self.__IO.seek(current)
			return BinaryFormat(BinaryIO(data), True)
		else:
			return BinaryFormat(BinaryIO(self.__IO.read(size)), True)
	# Write
	def WriteBits(self, bits:list) -> int:
		return self.__IO.write(chr(BinaryBits.GetNum(bits)).encode()[0])
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
	__DESCRIPTION:bytes = None
	__DATA:dict = None
	__BIFF_HEADER:ByteArray = ByteArray('BIFF\xbf\xff\x97\xe2')
	__DATA_HEADER:ByteArray = ByteArray('DATA\xc8\x0e\x92\xee')
	__DELIMITER:ByteArray = ByteArray('\x82')
	__IsEncoded:bool = False
	__IsSupport:bool = False
	__BIFF_VERSION:int = 210
	__BIFF_ENCODER_VERSION:int = 110
	@multimethod
	def __init__(self, io:IOBase) -> NoReturn:
		self.__IO = io
		self.__BF = BinaryFormat(io, True)
		if self.__BF.ReadRAW(size=len(self.__BIFF_HEADER), back_to_current=True) == self.__BIFF_HEADER:
			self.__IsEncoded = True
			if ((self.__BF.ReadUnsignedShortInt(offset=len(self.__BIFF_HEADER) + len(self.__DELIMITER) + 16, back_to_current=True) == self.__BIFF_VERSION) & (self.__BF.ReadUnsignedShortInt(offset=len(self.__BIFF_HEADER) + len(self.__DELIMITER) + 18, back_to_current=True) == self.__BIFF_ENCODER_VERSION)):
				self.__IsSupport = True
		return
	@multimethod
	def __init__(self, data:bytes) -> NoReturn:
		self.__IO = BinaryIO(data)
		self.__BF = BinaryFormat(self.__IO, True)
		if self.__BF.ReadRAW(size=len(self.__BIFF_HEADER), back_to_current=True) == self.__BIFF_HEADER:
			self.__IsEncoded = True
			if ((self.__BF.ReadUnsignedShortInt(offset=len(self.__BIFF_HEADER) + len(self.__DELIMITER) + 16, back_to_current=True) == self.__BIFF_VERSION) & (self.__BF.ReadUnsignedShortInt(offset=len(self.__BIFF_HEADER) + len(self.__DELIMITER) + 18, back_to_current=True) == self.__BIFF_ENCODER_VERSION)):
				self.__IsSupport = True
		return
	@multimethod
	def __init__(self, data:ByteArray) -> NoReturn:
		self.__IO = BinaryIO(data)
		self.__BF = BinaryFormat(self.__IO, True)
		if self.__BF.ReadRAW(size=len(self.__BIFF_HEADER), back_to_current=True) == self.__BIFF_HEADER:
			self.__IsEncoded = True
			if ((self.__BF.ReadUnsignedShortInt(offset=len(self.__BIFF_HEADER) + len(self.__DELIMITER) + 16, back_to_current=True) == self.__BIFF_VERSION) & (self.__BF.ReadUnsignedShortInt(offset=len(self.__BIFF_HEADER) + len(self.__DELIMITER) + 18, back_to_current=True) == self.__BIFF_ENCODER_VERSION)):
				self.__IsSupport = True
		return
	@multimethod
	def __init__(self, name:bytes, description:bytes, data:dict) -> NoReturn:
		self.__IO = BinaryIO()
		self.__BF = BinaryFormat(self.__IO, True)
		self.__NAME = name
		self.__DESCRIPTION = description
		self.__DATA = data
		return
	@multimethod
	def __init__(self, name:str, description:str, data:dict) -> NoReturn:
		self.__IO = BinaryIO()
		self.__BF = BinaryFormat(self.__IO, True)
		self.__NAME = name.encode()
		self.__DESCRIPTION = description.encode()
		self.__DATA = data
		return
	def __GetIO(self) -> IOBase:
		return self.__IO
	def __SetIO(self, new_io:IOBase) -> NoReturn:
		self.__IO = new_io
	IO = property(__GetIO, __SetIO)
	def Encode(self) -> bool:
		if self.__IsEncoded:
			return False
		self.__BF.WriteRAW(self.__BIFF_HEADER, size=len(self.__BIFF_HEADER)) # BIFF HEADER
		self.__BF.WriteRAW(self.__DELIMITER, size=len(self.__DELIMITER)) # DELIMITER
		self.__BF.WriteRAW(XDR_UUID.bytes, size=16) # XDR_UUID
		self.__BF.WriteUnsignedShortInt(self.__BIFF_VERSION) # BIFF VERSION
		self.__BF.WriteUnsignedShortInt(self.__BIFF_ENCODER_VERSION) # ENCODER VERSION
		bits = BinaryBits.BigIntToBits(time_ns(), 64)
		self.__BF.WriteUnsignedLongLongInt(len(bits)) # TIME PART COUNT
		for ptime in bits:
			self.__BF.WriteUnsignedLongLongInt(BinaryBits.GetNum(ptime)) # TIME PART
		self.__BF.WriteUnsignedLongLongInt(len(self.__NAME)) # NAME SIZE
		self.__BF.WriteUnsignedLongLongInt(len(self.__DESCRIPTION)) # DESCRIPTION SIZE
		self.__BF.WriteUnsignedLongLongInt(len(self.__DATA)) # DATA COUNT
		self.__BF.WriteRAW(self.__DELIMITER, size=len(self.__DELIMITER)) # DELIMITER
		self.__BF.WriteString(self.__NAME, size=len(self.__NAME)) # NAME
		self.__BF.WriteRAW(self.__DELIMITER, size=len(self.__DELIMITER)) # DELIMITER
		self.__BF.WriteString(self.__DESCRIPTION, size=len(self.__DESCRIPTION)) # DESCRIPTION
		self.__BF.WriteRAW(self.__DELIMITER, size=len(self.__DELIMITER)) # DELIMITER
		for d_name in self.__DATA:
			self.__BF.WriteRAW(self.__DATA_HEADER, size=len(self.__DATA_HEADER)) # DATA HEADER
			self.__BF.WriteRAW(self.__DELIMITER, size=len(self.__DELIMITER)) # DELIMITER
			self.__BF.WriteUnsignedLongLongInt(len(d_name)) # DATA NAME SIZE
			d_data = self.__DATA[d_name]
			self.__BF.WriteUnsignedLongLongInt(len(d_data)) # DATA SIZE
			d_hash = SHA512(d_data)
			self.__BF.WriteRAW(d_hash, size=64) # DATA HASH
			bits = BinaryBits.BigIntToBits(time_ns(), 64)
			self.__BF.WriteUnsignedLongLongInt(len(bits)) # DATA TIME PART COUNT
			for time_p in bits:
				self.__BF.WriteUnsignedLongLongInt(BinaryBits.GetNum(time_p)) # DATA TIME PART (Time)
			self.__BF.WriteRAW(self.__DELIMITER, size=len(self.__DELIMITER)) # DELIMITER
			self.__BF.WriteRAW(d_name, size=len(d_name)) # DATA NAME
			self.__BF.WriteRAW(self.__DELIMITER, size=len(self.__DELIMITER)) # DELIMITER
			self.__BF.WriteRAW(d_data, size=len(d_data)) # DATA
		current = self.__IO.seek(0, SEEK_CUR)
		self.__IO.seek(0)
		data = self.__IO.read()
		self.__IO.seek(current)
		return data
	def Decode(self) -> bool:
		if self.__IsEncoded != True:
			return False
		if self.__IsSupport != True:
			return False
		header = self.__BF.ReadRAW(size=len(self.__BIFF_HEADER)) # BIFF HEADER
		self.__BF.ReadRAW(size=len(self.__DELIMITER)) # DELIMITER
		uuid = self.__BF.ReadRAW(size=16) # XDR_UUID
		biff_version = self.__BF.ReadUnsignedShortInt() # BIFF VERSION
		encoder_version = self.__BF.ReadUnsignedShortInt() # ENCODER VERSION
		ptime_cnt = self.__BF.ReadUnsignedLongLongInt() # TIME PART COUNT
		bits = []
		for i in range(ptime_cnt):
			bits.append(BinaryBits.GetBits(self.__BF.ReadUnsignedLongLongInt()))
		time = NanoSecondsToStamp(BinaryBits.BitsToBigInt(bits)) # TIME PART (Time)
		name_size = self.__BF.ReadUnsignedLongLongInt() # NAME SIZE
		desc_size = self.__BF.ReadUnsignedLongLongInt() # DESCRIPTION SIZE
		data_cnt = self.__BF.ReadUnsignedLongLongInt() # DATA COUNT
		self.__BF.ReadRAW(size=len(self.__DELIMITER)) # DELIMITER
		name = self.__BF.ReadString(size=name_size) # NAME
		self.__BF.ReadRAW(size=len(self.__DELIMITER)) # DELIMITER
		description = self.__BF.ReadString(size=desc_size) # DESCRIPTION
		self.__BF.ReadRAW(size=len(self.__DELIMITER)) # DELIMITER
		data = dict()
		for i in range(data_cnt):
			d_header = self.__BF.ReadRAW(size=len(self.__DATA_HEADER)) # DATA HEADER
			if d_header != self.__DATA_HEADER:
				continue
			self.__BF.ReadRAW(size=len(self.__DELIMITER)) # DELIMITER
			d_name_size = self.__BF.ReadUnsignedLongLongInt() # DATA NAME SIZE
			d_size = self.__BF.ReadUnsignedLongLongInt() # DATA SIZE
			d_hash = self.__BF.ReadRAW(size=64) # DATA HASH
			ptime_cnt = self.__BF.ReadUnsignedLongLongInt() # DATA TIME PART COUNT
			bits = []
			for i in range(ptime_cnt):
				bits.append(BinaryBits.GetBits(self.__BF.ReadUnsignedLongLongInt()))
			d_time = NanoSecondsToStamp(BinaryBits.BitsToBigInt(bits)) # DATA TIME PART (Time)
			self.__BF.ReadRAW(size=len(self.__DELIMITER)) # DELIMITER
			d_name = self.__BF.ReadRAW(size=d_name_size) # DATA NAME
			self.__BF.ReadRAW(size=len(self.__DELIMITER)) # DELIMITER
			d_data = self.__BF.ReadRAW(size=d_size) # DATA
			data[d_name] = dict()
			data[d_name]['size'] = d_size
			data[d_name]['sha512'] = d_hash.hex().upper()
			data[d_name]['time'] = TimeFromStamp(d_time)
			data[d_name]['data'] = d_data
			data[d_name]['verified'] = (d_hash == SHA512(d_data))
		return {'BIFF': {'uuid': UUID(bytes=uuid).__str__(), 'verified': (uuid == XDR_UUID.bytes), 'version': biff_version, 'time': TimeFromStamp(time), 'name': name, 'description': description}, 'DATA': data}