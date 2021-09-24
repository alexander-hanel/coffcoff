"""
Name:       coffcoff.py
Summary:    A python script for exploring COFF string tables. 
Author:     Alexaner Hanel
Date:       20210924
Version:    1.0

"""
import pefile
import ctypes
from enum import IntEnum
from collections import namedtuple

UNKNOWN = 0x3737

DEBUG = True
if DEBUG:
    import hexdump

class COFFSYMBOLTABLE(ctypes.Structure):
    """
    Described in [PE-COFF] 5.4. Coff Symbol Table
    """
    _pack_ = 1
    _fields_ = [
            ("zeroes", ctypes.c_uint), ("offset", ctypes.c_uint), ("value", ctypes.c_uint),
            ("section_number", ctypes.c_short), ("type", ctypes.c_ushort), ("storage_class", ctypes.c_ubyte),
            ("number_aux_symbols", ctypes.c_ubyte)
        ]
    def __new__(cls, buffer):
        return cls.from_buffer_copy(buffer)

    def __init__(self, data):
        pass


class SECNUMVALUES(IntEnum):
    """
    Described in [PE-COFF] 5.4.2. Section Number Values
    """
    IMAGE_SYM_UNDEFINED = 0
    IMAGE_SYM_ABSOLUTE = -1
    IMAGE_SYM_DEBUG = -2


class TYPEREP(IntEnum):
    """
    Described in [PE-COFF] 5.4.3. Type Representation
    """
    IMAGE_SYM_TYPE_NULL = 0  # No type information or unknown base type
    IMAGE_SYM_TYPE_VOID = 1  # No valid type; used with void pointers and functions
    IMAGE_SYM_TYPE_CHAR = 2  # Character (signed byte)
    IMAGE_SYM_TYPE_SHORT = 3  # Two-byte signed integer
    IMAGE_SYM_TYPE_INT = 4  # Natural integer type
    IMAGE_SYM_TYPE_LONG = 5  # Four-byte signed integer
    IMAGE_SYM_TYPE_FLOAT = 6  # Four-byte floating-point number
    IMAGE_SYM_TYPE_DOUBLE = 7  # Eight-byte floating-point number
    IMAGE_SYM_TYPE_STRUCT = 8  # Structure
    IMAGE_SYM_TYPE_UNION = 9  # Union
    IMAGE_SYM_TYPE_ENUM = 10  # Enumerated type
    IMAGE_SYM_TYPE_MOE = 11  # Member of enumeration (a specific value)
    IMAGE_SYM_TYPE_BYTE = 12  # Byte; unsigned one-byte integer
    IMAGE_SYM_TYPE_WORD = 13  # Word; unsigned two-byte integer
    IMAGE_SYM_TYPE_UINT = 14  # Unsigned integer of natural size
    IMAGE_SYM_TYPE_DWORD = 15  # Unsigned four-byte integer

    # not exactly correct, this should be reading the most significant byte
    IMAGE_SYM_DTYPE_POINTER = 16  # Pointer to base type.
    IMAGE_SYM_DTYPE_FUNCTION = 32  # Function returning base type.
    IMAGE_SYM_DTYPE_ARRAY = 48  # Array of base type.
    # Go Lang Specific (??)
    IMAGE_SYM_DTYPE_ARRAY_GO = 776


class SCLASS(IntEnum):
    """
    Described in [PE-COFF] 5.4.4. Storage Class
    """
    IMAGE_SYM_CLASS_END_OF_FUNCTION = 0xFF  # Special symbol representing end of function, for debugging purposes
    IMAGE_SYM_CLASS_NULL = 0  # No storage class assigned.
    IMAGE_SYM_CLASS_AUTOMATIC = 1  # Automatic (stack) variable
    IMAGE_SYM_CLASS_EXTERNAL = 2  # Used by Microsoft tools for external symbols
    IMAGE_SYM_CLASS_STATIC = 3  # The Value field specifies the offset of the symbol within the section
    IMAGE_SYM_CLASS_REGISTER = 4  # Register variable. The Value field specifies register number.
    IMAGE_SYM_CLASS_EXTERNAL_DEF = 5  # Symbol is defined externally
    IMAGE_SYM_CLASS_LABEL = 6  # Code label defined within the module
    IMAGE_SYM_CLASS_UNDEFINED_LABEL = 7  # Reference to a code label not defined.
    IMAGE_SYM_CLASS_MEMBER_OF_STRUCT = 8  # Structure member
    IMAGE_SYM_CLASS_ARGUMENT = 9  # Formal argument (parameter)of a function
    IMAGE_SYM_CLASS_STRUCT_TAG = 10  # Structure tag-name entry
    IMAGE_SYM_CLASS_MEMBER_OF_UNION = 11  # Union member.
    IMAGE_SYM_CLASS_UNION_TAG = 12  # Union tag-name entry
    IMAGE_SYM_CLASS_TYPE_DEFINITION = 13  # Typedef entry.
    IMAGE_SYM_CLASS_UNDEFINED_STATIC = 14  # Static data declaration
    IMAGE_SYM_CLASS_ENUM_TAG = 15  # Enumerated type tagname entry.
    IMAGE_SYM_CLASS_MEMBER_OF_ENUM = 16  # Member of enumeration
    IMAGE_SYM_CLASS_REGISTER_PARAM = 17  # Register parameter
    IMAGE_SYM_CLASS_BIT_FIELD = 18  # Bit-field reference
    IMAGE_SYM_CLASS_BLOCK = 100  # A .bb (beginning of block) or .eb (end of block) record
    IMAGE_SYM_CLASS_FUNCTION = 101  # Used by Microsoft tools for symbol records that define the extent of a function
    IMAGE_SYM_CLASS_END_OF_STRUCT = 102  # End of structure entry
    IMAGE_SYM_CLASS_FILE = 103  # Used by Microsoft tools, for the source-file symbol record.
    IMAGE_SYM_CLASS_SECTION = 104  # Definition of a section
    IMAGE_SYM_CLASS_WEAK_EXTERNAL = 105  # Weak external

    IMAGE_SYM_CLASS_CLR_TOKEN = 107


class AUXSYMBOLFUNCDEF(ctypes.Structure):
    """
    Described in [PE-COFF] 5.5.1 Auxiliary Format 1: Function Definitions
    """
    _pack_ = 1
    _fields_ = [
            ("tag_index", ctypes.c_uint), ("total_size", ctypes.c_uint), ("pointer_to_line_number", ctypes.c_uint),
            ("pointer_to_next_function", ctypes.c_uint), ("unused", ctypes.c_ushort)
        ]
    def __new__(cls, buffer):
        return cls.from_buffer_copy(buffer)

    def __init__(self, data):
        pass


class AUXSYMBOLBFEF(ctypes.Structure):
    """
    Described in [PE-COFF] 5.5.2 Auxiliary Format 2: .bf and .ef Symbols
    """
    _pack_ = 1
    _fields_ = [
            ("unused", ctypes.c_uint), ("line_number", ctypes.c_ushort), ("unused_1", ctypes.c_uint), ("unused_2", ctypes.c_ushort),
            ("pointer_to_next_function", ctypes.c_uint),  ("unused", ctypes.c_ushort)
        ]
    def __new__(cls, buffer):
        return cls.from_buffer_copy(buffer)

    def __init__(self, data):
        pass


class AUXSYMBOLWEAK(ctypes.Structure):
    """
    Described in [PE-COFF] 5.5.3 Auxiliary Format 3: Weak Externals
    """
    _pack_ = 1
    _fields_ = [
            ("tag_index", ctypes.c_uint), ("characteristics", ctypes.c_uint), ("unused", ctypes.c_uint), ("unused_1", ctypes.c_uint),
            ("unused_2", ctypes.c_ushort)
        ]
    def __new__(cls, buffer):
        return cls.from_buffer_copy(buffer)

    def __init__(self, data):
        pass


class AUXSYMBOLSECTIONDEF(ctypes.Structure):
    """
    Described in [PE-COFF] 5.5.5 Auxiliary Format 5: Section Definitions
    """
    _pack_ = 1
    _fields_ = [
            ("length", ctypes.c_uint), ("number_of_relocations", ctypes.c_ushort), ("number_of_line_numbers", ctypes.c_ushort),
            ("checksum", ctypes.c_uint), ("number", ctypes.c_ushort), ("selection", ctypes.c_byte), ("unused", ctypes.c_byte),
            ("unused_1", ctypes.c_ushort)
        ]
    def __new__(cls, buffer):
        return cls.from_buffer_copy(buffer)

    def __init__(self, data):
        pass


class COFFS(object):
    def __init__(self, pe_file):
        self.ENTRYSIZE = 18
        self.file_path = pe_file
        self.error = False
        self.string_table = None
        self.load()
        if self.error:
            if DEBUG:
                print('DEBUG: %s' % self.error)
            return
        self.entries = []
        self.file_tab = []
        self.func_tab = []
        self.func_static_tab = []
        self.section_tab = []
        self.parse_coff()

    def load(self):
        """
        responsible parsing the portable executable file
        """
        try:
            self.pe_data = open(self.file_path, "rb").read()
            self.pe = pefile.PE(data=self.pe_data)
            self.ptr_symbol_table = self.pe.FILE_HEADER.PointerToSymbolTable
            # read ptr to symbol table
            if not self.ptr_symbol_table:
                self.error = "FILE_HEADER.PointerToSymbolTable not present"
                return
            # read the number of symbols
            self.offset_string_table = self.pe.FILE_HEADER.NumberOfSymbols * 18
            if not self.offset_string_table:
                self.error = "NumberOfSymbols not present"
                return
            # at this point the PE has symbols to parse
            # read the start of the symbol table into a buffer
            self.symbol_table = self.pe_data[self.ptr_symbol_table:]
            # read the start of the start of the string symbol names into a buffer
            self.string_table = self.symbol_table[self.offset_string_table:]
        except Exception as e:
            self.error = e

    def parse_coff(self):
        aux_state = False  # TODO: should auxilary be an integer rather than a state?
        # loop through symbol table
        for ci in range(0, self.offset_string_table, self.ENTRYSIZE):
            if aux_state:
                temp_aux = { "type_aux": None}
                # this part might seem redundant but it allows for looping through each entry 18 bytes at a time
                # rather skipping N*18 for each aux
                aux_data = self.symbol_table[ci:ci + self.ENTRYSIZE]
                # 5.5.1. Auxiliary Format 1: Function Definition
                if p_data.storage_class == SCLASS.IMAGE_SYM_CLASS_EXTERNAL and TYPEREP(p_data.type) == TYPEREP.IMAGE_SYM_DTYPE_FUNCTION:
                    aux_temp = AUXSYMBOLFUNCDEF(aux_data)
                    temp_aux["type_aux"] = "AUX_FUNCTION_DEF"
                    temp_aux["tag_index"] = aux_temp.tag_index
                    temp_aux["total_size"] = aux_temp.total_size
                    temp_aux["pointer_to_line_number"] = aux_temp.pointer_to_line_number
                    temp_aux["pointer_to_next_function"] = aux_temp.pointer_to_next_function
                elif p_data.storage_class == SCLASS.IMAGE_SYM_CLASS_FUNCTION:
                    aux_temp = AUXSYMBOLBFEF(aux_data)
                    temp_aux["type_aux"] = "AUX_SYMBOL_DEF"
                    temp_aux["tag_index"] = aux_temp.tag_index
                    temp_aux["total_size"] =  aux_temp.total_size
                    temp_aux["pointer_to_line_number"] = aux_temp.pointer_to_line_number
                    temp_aux["pointer_to_next_function"] =  aux_temp.pointer_to_next_function
                elif p_data.storage_class == SCLASS.IMAGE_SYM_CLASS_STATIC and TYPEREP(
                        p_data.type) == TYPEREP.IMAGE_SYM_TYPE_NULL:
                    if symbol_name.startswith(b"."):
                        temp_aux["type_aux"] = "AUX_SECTION_DEF"
                        aux_temp = AUXSYMBOLSECTIONDEF(aux_data)
                        temp_aux["length"] = aux_temp.length
                        temp_aux["number_of_relocations"] = aux_temp.number_of_relocations
                        temp_aux["number_of_line_numbers"] =  aux_temp.number_of_line_numbers
                # Described in [PE-COFF] 5.5.4. Auxiliary Format 4: Files
                elif symbol_name == b".file" and p_data.storage_class == SCLASS.IMAGE_SYM_CLASS_FILE:
                    file_name = self.symbol_table[ci:ci + self.ENTRYSIZE].rstrip(b"\x00")
                    temp_aux["type_aux"] = "AUX_FILE"
                    if file_name.startswith(b"\x00"):
                        file_name = ""
                    temp_aux["file_name"] = file_name
                    self.file_tab.append(file_name)
                aux_state = False
                self.entries.append(temp_aux)
                continue
            coff_data = self.symbol_table[ci:ci + self.ENTRYSIZE]
            if not coff_data:
                continue
            p_data = COFFSYMBOLTABLE(coff_data)
            # skip null entries
            if p_data.storage_class == SCLASS.IMAGE_SYM_CLASS_NULL:
                continue
            # parse out symbol string
            symbol_name = self.read_symbol_name(p_data, coff_data)
            # Described in [PE-COFF] 5.5.4. Auxiliary Format 4: Files
            if p_data.storage_class == SCLASS.IMAGE_SYM_CLASS_STATIC and TYPEREP(p_data.type) == TYPEREP.IMAGE_SYM_TYPE_NULL:
                # hack but I'm not seeing anything that can be used to identify just the section names
                if symbol_name.startswith(b"."):
                    self.section_tab.append(symbol_name)
                else:
                    self.func_static_tab.append(symbol_name)
            elif p_data.storage_class == SCLASS.IMAGE_SYM_CLASS_EXTERNAL and TYPEREP(p_data.type) == TYPEREP.IMAGE_SYM_DTYPE_FUNCTION:
                self.func_tab.append(symbol_name)
            pp = pretty_symbol_entry(p_data, symbol_name)
            temp_dict = {"name": None, "type": None, "aux": None, "sclass": None, "type_aux": None}
            temp_dict["name"] = pp.name
            temp_dict["type"] = pp.type.name
            temp_dict["aux"] = pp.aux
            temp_dict["sclass"] = pp.storage.name
            self.entries.append(temp_dict)
            if pp.aux:
                aux_state = True

    def read_symbol_name(self, p_data, coff_data):
        """
        """
        temp_string = ""
        if p_data.zeroes:
            # string name is less than 8 bytes
            api_name = coff_data[0:8].rstrip(b"\x00")
            if api_name:
                temp_string = api_name
        else:
            # string is over 8 bytes and contains null byte
            temp_data = self.string_table[p_data.offset:p_data.offset + 256]
            api_name = temp_data.split(b"\x00")[0]
            if api_name:
                temp_string = api_name
        return temp_string


def pretty_symbol_entry(coffentry, symbol_name):
    Symbol = namedtuple("Symbol","name section type storage aux fname")
    Symbol.storage = SCLASS(coffentry.storage_class)
    if Symbol.storage == SCLASS.IMAGE_SYM_CLASS_NULL:
        return Symbol
    Symbol.name = symbol_name
    if coffentry.section_number in SECNUMVALUES.__members__.values():
        Symbol.section = SECNUMVALUES(coffentry.section_number)
    else:
        Symbol.section = coffentry.section_number
    Symbol.type = TYPEREP(coffentry.type)
    Symbol.storage = SCLASS(coffentry.storage_class)
    Symbol.aux = coffentry.number_aux_symbols
    return Symbol

def example():
    import pprint
    CC = COFFS("./test_bin/debug_symbols.exe")
    print("Entries")
    pprint.pprint(CC.entries)
    print("File Tab")
    pprint.pprint(CC.file_tab)
    print("Func Tab")
    pprint.pprint(CC.func_tab)
    print("Func Static Tab")
    pprint.pprint(CC.func_static_tab)
    print("Section Tab")
    pprint.pprint(CC.section_tab)

# example()