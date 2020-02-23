from uuid import UUID
from datetime import datetime
from time import time_ns
from struct import pack as STRUCT_PACK, unpack as STRUCT_UNPACK
from io import BytesIO, SEEK_CUR, SEEK_END, IOBase
from typing import NoReturn
from types import FunctionType
from enum import IntEnum
from zlib import compress as ZLIB_COMPRESS, decompress as ZLIB_DECOMPRESS, compressobj as ZLIB_COMPRESS_OBJ, decompressobj as ZLIB_DECOMPRESS_OBJ, DEFLATED as ZLIB_DEFLATED, MAX_WBITS as ZLIB_MAX_WBITS, DEF_MEM_LEVEL as ZLIB_DEF_MEM_LEVEL, Z_DEFAULT_STRATEGY as ZLIB_DEFAULT_STRATEGY

XDR_UUID = UUID('0a8f2fe8-87ba-5235-8fbc-9fc82c694485') # DO NOT EDIT!

try:
	from multimethod import multimethod
except ModuleNotFoundError:
	raise Exception('Error. Module not found! Install `multimethod` (pip install multimethod)')

class IceKey(object):
	# Modulo values for the S-boxes
	__rMOD = [
		[ 0x14D, 0x139, 0x1F9, 0x171 ],
		[ 0x17B, 0x177, 0x13F, 0x187 ],
		[ 0x169, 0x1BD, 0x1C9, 0x18D ],
		[ 0x18D, 0x1A9, 0x18B, 0x1F9 ],
	]
	# XOR values for the S-boxes
	__rXOR = [
		[ 0x83, 0x85, 0x9B, 0xCD ],
		[ 0xCC, 0xA7, 0xAD, 0x41 ],
		[ 0x4B, 0x2E, 0xD4, 0x33 ],
		[ 0xEA, 0xCB, 0x2E, 0x04 ],
	]
	# Expanded permutation values for the P-box
	__rPBOX = [
		0x00000001, 0x00000080, 0x00000400, 0x00002000,
		0x00080000, 0x00200000, 0x01000000, 0x40000000,
		0x00000008, 0x00000020, 0x00000100, 0x00004000,
		0x00010000, 0x00800000, 0x04000000, 0x20000000,
		0x00000004, 0x00000010, 0x00000200, 0x00008000,
		0x00020000, 0x00400000, 0x08000000, 0x10000000,
		0x00000002, 0x00000040, 0x00000800, 0x00001000,
		0x00040000, 0x00100000, 0x02000000, 0x80000000,
	]
	# The key rotation schedule
	__rKEYROT = [
		0, 1, 2, 3, 2, 1, 3, 0,
		1, 3, 2, 0, 3, 1, 0, 2,
	]
	__rKEY_SCHEDULE = dict()
	__rSBOX = dict()
	__rSBOX_INITIALISED = False
	__rSIZE = 0
	__rROUNDS = 0
	'''
	Galois Field multiplication of a by b, modulo m.
	Just like arithmetic multiplication, except that additions and subtractions are replaced by XOR.
	'''
	def gf_mult(self, a:int, b:int, m:int) -> int:
		res = 0
		while b:
			if b & 1:
				res ^= a
			a <<= 1
			b >>= 1
			if a >= 256:
				a ^= m
		return res
	'''
	Galois Field exponentiation.
	Raise the base to the power of 7, modulo m.
	'''
	def gf_exp7(self, b:int, m:int) -> int:
		if b == 0:
			return 0
		x = self.gf_mult(b, b, m)
		x = self.gf_mult(b, x, m)
		x = self.gf_mult(x, x, m)
		return self.gf_mult(b, x, m)
	'''
	Carry out the ICE 32-bit P-box permutation.
	'''
	def perm32(self, x:int) -> int:
		res = 0
		i = 0
		while x:
			if (x & 1):
				res |= self.__rPBOX[i % len(self.__rPBOX)]
			i += 1
			x >>= 1
		return res
	'''
	Create a new ICE object.
	'''
	def __init__(self, n:int, key:bytes):
		if self.__rSBOX_INITIALISED != True:
			self.__rSBOX.clear()
			for i in range(0, 4):
				self.__rSBOX[i] = dict()
				for l in range(0, 1024):
					self.__rSBOX[i][l] = 0x00
			for i in range(0, 1024):
				col = (i >> 1) & 0xFF
				row = (i & 0x1) | ((i & 0x200) >> 8)
				self.__rSBOX[0][i] = self.perm32(self.gf_exp7(col ^ self.__rXOR[0][row], self.__rMOD[0][row]) << 24)
				self.__rSBOX[1][i] = self.perm32(self.gf_exp7(col ^ self.__rXOR[1][row], self.__rMOD[1][row]) << 16)
				self.__rSBOX[2][i] = self.perm32(self.gf_exp7(col ^ self.__rXOR[2][row], self.__rMOD[2][row]) << 8)
				self.__rSBOX[3][i] = self.perm32(self.gf_exp7(col ^ self.__rXOR[3][row], self.__rMOD[3][row]))
			self.__rSBOX_INITIALISED = True
		if n < 1:
			self.__rSIZE = 1
			self.__rROUNDS = 8
		else:
			self.__rSIZE = n
			self.__rROUNDS = n * 16
		for i in range(0, self.__rROUNDS):
			self.__rKEY_SCHEDULE[i] = dict()
			for j in range(0, 4):
				self.__rKEY_SCHEDULE[i][j] = 0x00
		if self.__rROUNDS == 8:
			kb = [ 0x00 ] * 4
			for i in range(0, 4):
				kb[3 - i] = (key[i * 2] << 8) | key[i * 2 + 1]
			for i in range(0, 8):
				kr = self.__rKEYROT[i]
				isk = self.__rKEY_SCHEDULE[i]
				for j in range(0, 15):
					for k in range(0, 4): 
						bit = kb[(kr + k) & 3] & 1
						isk[j % 3] = (isk[j % 3] << 1) | bit
						kb[(kr + k) & 3] = (kb[(kr + k) & 3] >> 1) | ((bit ^ 1) << 15)
		for i in range(0, self.__rSIZE):
			kb = [ 0x00 ] * 4
			for j in range(0, 4):
				kb[3 - j] = (key[i * 8 + j * 2] << 8) | key[i * 8 + j * 2 + 1]
			for l in range(0, 8):
				kr = self.__rKEYROT[l]
				isk = self.__rKEY_SCHEDULE[((i * 8) + l) % len(self.__rKEY_SCHEDULE)]
				for j in range(0, 15):
					for k in range(0, 4):
						bit = kb[(kr + k) & 3] & 1
						isk[j % 3] = (isk[j % 3] << 1) | bit
						kb[(kr + k) & 3] = (kb[(kr + k) & 3] >> 1) | ((bit ^ 1) << 15)
			for l in range(0, 8):
				kr = self.__rKEYROT[8 + l]
				isk = self.__rKEY_SCHEDULE[((self.__rROUNDS - 8 - i * 8) + l) % len(self.__rKEY_SCHEDULE)]
				for j in range(0, 15): 
					for k in range(0, 4):
						bit = kb[(kr + k) & 3] & 1
						isk[j % 3] = (isk[j % 3] << 1) | bit
						kb[(kr + k) & 3] = (kb[(kr + k) & 3] >> 1) | ((bit ^ 1) << 15)
	'''
	The single round ICE f function.
	'''
	def _ice_f(self, p:int, sk:int) -> int:
		tl = ((p >> 16) & 0x3FF) | (((p >> 14) | (p << 18)) & 0xFFC00)
		tr = (p & 0x3FF) | ((p << 2) & 0xFFC00)
		al = sk[2] & (tl ^ tr)
		ar = al ^ tr
		al ^= tl
		al ^= sk[0]
		ar ^= sk[1]
		return self.__rSBOX[0][al >> 10] | self.__rSBOX[1][al & 0x3FF] | self.__rSBOX[2][ar >> 10] | self.__rSBOX[3][ar & 0x3FF]
	'''
	Return the key size, in bytes.
	'''
	def KeySize(self) -> int:
		return self.__rSIZE * 8
	'''
	Return the block size, in bytes.
	'''
	def BlockSize(self) -> int:
		return 8
	'''
	Encrypt a block of 8 bytes of data with the given ICE key.
	'''
	def EncryptBlock(self, data:list) -> list:
		out = [ 0x00 ] * 8
		l = 0
		r = 0
		for i in range(0, 4):
			l |= (data[i] & 0xFF) << (24 - i * 8)
			r |= (data[i + 4] & 0xFF) << (24 - i * 8)
		for i in range(0, self.__rROUNDS, 2):
			l ^= self._ice_f(r, self.__rKEY_SCHEDULE[i])
			r ^= self._ice_f(l, self.__rKEY_SCHEDULE[i + 1])
		for i in range(0, 4):
			out[3 - i] = r & 0xFF
			out[7 - i] = l & 0xFF
			r >>= 8
			l >>= 8
		return out
	'''
	Decrypt a block of 8 bytes of data with the given ICE key.
	'''
	def DecryptBlock(self, data:list) -> list:
		out = [ 0x00 ] * 8
		l = 0
		r = 0
		for i in range(0, 4):
			l |= (data[i] & 0xFF) << (24 - i * 8)
			r |= (data[i + 4] & 0xFF) << (24 - i * 8)
		for i in range(self.__rROUNDS - 1, 0, -2):
			l ^= self._ice_f(r, self.__rKEY_SCHEDULE[i])
			r ^= self._ice_f(l, self.__rKEY_SCHEDULE[i - 1])
		for i in range(0, 4):
			out[3 - i] = r & 0xFF
			out[7 - i] = l & 0xFF
			r >>= 8
			l >>= 8
		return out
	'''
	Encrypt the data byte array with the given ICE key.
	'''
	def Encrypt(self, data:bytes) -> bytes:
		out = []
		blocksize = self.BlockSize()
		bytesleft = len(data)
		i = 0
		while bytesleft >= blocksize:
			out.extend(self.EncryptBlock(data[i:i + blocksize]))
			bytesleft -= blocksize
			i += blocksize
		if bytesleft > 0:
			out.extend(data[len(data)-bytesleft:len(data)])
		return bytes(out)
	'''
	Decrypt the data byte array with the given ICE key.
	'''
	def Decrypt(self, data:bytes) -> bytes:
		out = []
		blocksize = self.BlockSize()
		bytesleft = len(data)
		i = 0
		while bytesleft >= blocksize:
			out.extend(self.DecryptBlock(data[i:i + blocksize]))
			bytesleft -= blocksize
			i += blocksize
		if bytesleft > 0:
			out.extend(data[len(data)-bytesleft:len(data)])
		return bytes(out)


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
__version__ = '2.1.0'

__all__ = [
	'FlagsBIFF',
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
	def ToggleBit(num:int, pos:int) -> int:
		mask = 1 << pos
		return num ^ mask
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
		subsets.reverse()
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


class FlagsBIFF(IntEnum):
	FL_NONE = 0
	FL_DEFAULT = (1 << 0)
	FL_ENCRYPTED_ICE = (1 << 1)
#	FL_ENCRYPTED_AES = (1 << 2)
	FL_COMPRESSED_ZLIB = (1 << 3)
	FL_COMPRESSED_DEFLATE = (1 << 4)
#	FL_RESERVED = (1 << 5)
#	FL_RESERVED = (1 << 6)
#	FL_RESERVED = (1 << 7)
	@staticmethod
	def FlagsToSubSets(flags:int) -> list:
		if flags == 0:
			return [ FlagsBIFF.FL_NONE ]
		out = []
		subsets = BinaryBits.GetSubSets(flags, stop=8)
		if subsets[3]:
			out.append(FlagsBIFF.FL_COMPRESSED_DEFLATE)
		if subsets[4]:
			out.append(FlagsBIFF.FL_COMPRESSED_ZLIB)
		#if subsets[5]:
		#	out.append(FlagsBIFF.FL_ENCRYPTED_AES)
		if subsets[6]:
			out.append(FlagsBIFF.FL_ENCRYPTED_ICE)
		if subsets[7]:
			out.append(FlagsBIFF.FL_DEFAULT)
		return out

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
	__BIFF_VERSION:int = 211
	__BIFF_ENCODER_VERSION:int = 111
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
	def Encode(self, encoder_flags:int=FlagsBIFF.FL_NONE, ice_password:bytes=XDR_UUID.bytes) -> bool:
		if self.__IsEncoded:
			return False
		self.__BF.WriteRAW(self.__BIFF_HEADER, size=len(self.__BIFF_HEADER)) # BIFF HEADER
		self.__BF.WriteRAW(self.__DELIMITER, size=len(self.__DELIMITER)) # DELIMITER
		self.__BF.WriteRAW(XDR_UUID.bytes, size=16) # XDR_UUID
		self.__BF.WriteUnsignedShortInt(self.__BIFF_VERSION) # BIFF VERSION
		self.__BF.WriteUnsignedShortInt(self.__BIFF_ENCODER_VERSION) # ENCODER VERSION
		self.__BF.WriteUnsignedShortInt(encoder_flags) # ENCODER FLAGS
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
			d_data = self.__DATA[d_name]
			if isinstance(d_name, str):
				d_name = d_name.encode()
			if ((type(d_name) != bytes) & (type(d_name) != bytearray) & (type(d_name) != ByteArray)):
				d_name = str(d_name).encode()
			if isinstance(d_data, str):
				d_data = d_data.encode()
			if ((type(d_data) != bytes) & (type(d_data) != bytearray) & (type(d_data) != ByteArray)):
				d_data = str(d_data).encode()
			settings = dict()
			settings['FL_ENCRYPTED_ICE'] = False
			settings['FL_COMPRESSED_ZLIB'] = False
			settings['FL_COMPRESSED_DEFLATE'] = False
			for setting in FlagsBIFF.FlagsToSubSets(encoder_flags):
				if setting == FlagsBIFF.FL_ENCRYPTED_ICE:
					settings['FL_ENCRYPTED_ICE'] = True
				if setting == FlagsBIFF.FL_COMPRESSED_ZLIB:
					settings['FL_COMPRESSED_ZLIB'] = True
				if setting == FlagsBIFF.FL_COMPRESSED_DEFLATE:
					settings['FL_COMPRESSED_DEFLATE'] = True
			d_hash = SHA512(d_data)
			if settings['FL_COMPRESSED_ZLIB']:
				d_data = ZLIB_COMPRESS(d_data)
			if settings['FL_COMPRESSED_DEFLATE']:
				obj = ZLIB_COMPRESS_OBJ(9, ZLIB_DEFLATED, -ZLIB_MAX_WBITS, ZLIB_DEF_MEM_LEVEL, ZLIB_DEFAULT_STRATEGY)
				c_data = ByteArray(obj.compress(d_data))
				c_data.extend(obj.flush())
				d_data = c_data
			if settings['FL_ENCRYPTED_ICE']:
				d_data = IceKey(8, SHA512(ice_password)).Encrypt(d_data)
			self.__BF.WriteRAW(self.__DATA_HEADER, size=len(self.__DATA_HEADER)) # DATA HEADER
			self.__BF.WriteRAW(self.__DELIMITER, size=len(self.__DELIMITER)) # DELIMITER
			self.__BF.WriteUnsignedLongLongInt(len(d_name)) # DATA NAME SIZE
			self.__BF.WriteUnsignedLongLongInt(len(d_data)) # DATA SIZE
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
	def Decode(self, ice_password:bytes=XDR_UUID.bytes) -> bool:
		if self.__IsEncoded != True:
			return False
		if self.__IsSupport != True:
			return False
		header = self.__BF.ReadRAW(size=len(self.__BIFF_HEADER)) # BIFF HEADER
		if header != self.__BIFF_HEADER:
			return False
		self.__BF.ReadRAW(size=len(self.__DELIMITER)) # DELIMITER
		uuid = self.__BF.ReadRAW(size=16) # XDR_UUID
		biff_version = self.__BF.ReadUnsignedShortInt() # BIFF VERSION
		encoder_version = self.__BF.ReadUnsignedShortInt() # ENCODER VERSION
		encoder_flags = self.__BF.ReadUnsignedShortInt() # ENCODER FLAGS
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
			settings = dict()
			settings['FL_ENCRYPTED_ICE'] = False
			settings['FL_COMPRESSED_ZLIB'] = False
			settings['FL_COMPRESSED_DEFLATE'] = False
			for setting in FlagsBIFF.FlagsToSubSets(encoder_flags):
				if setting == FlagsBIFF.FL_ENCRYPTED_ICE:
					settings['FL_ENCRYPTED_ICE'] = True
				if setting == FlagsBIFF.FL_COMPRESSED_ZLIB:
					settings['FL_COMPRESSED_ZLIB'] = True
				if setting == FlagsBIFF.FL_COMPRESSED_DEFLATE:
					settings['FL_COMPRESSED_DEFLATE'] = True
			if settings['FL_ENCRYPTED_ICE']:
				d_data = IceKey(8, SHA512(ice_password)).Decrypt(d_data)
			if settings['FL_COMPRESSED_DEFLATE']:
				obj = ZLIB_DECOMPRESS_OBJ(-ZLIB_MAX_WBITS)
				c_data = ByteArray(obj.decompress(d_data))
				c_data.extend(obj.flush())
				d_data = c_data.ToBytes()
			if settings['FL_COMPRESSED_ZLIB']:
				d_data = ZLIB_DECOMPRESS(d_data)
			data[d_name] = dict()
			data[d_name]['size'] = d_size
			data[d_name]['sha512'] = d_hash.hex().upper()
			data[d_name]['time'] = TimeFromStamp(d_time)
			data[d_name]['data'] = d_data
			data[d_name]['verified'] = (d_hash == SHA512(d_data))
		return {'BIFF': {'uuid': UUID(bytes=uuid).__str__(), 'verified': (uuid == XDR_UUID.bytes), 'biff_version': biff_version, 'encoder_version': encoder_version, 'encoder_flags': encoder_flags, 'time': TimeFromStamp(time), 'name': name, 'description': description}, 'DATA': data}

