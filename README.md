# COFF Portable Executable Symbol Table Parser

coff-coff is a COFF symbol table parser written for Portable Executables (PE). This project was created when I became interested in what attributes could be extracted from PE files compiled with GCC. The set of extracted attributes isn't complete but the findings are still interesting.

### COFF Symbol File Format
To retrieve the offset to the COFF symbol table, we use `pe.FILE_HEADER.PointerToSymbolTable`. The ptr is the raw file offset to the symbol tables. To retrieve the number of symbols, we use `pe.FILE_HEADER.NumberOfSymbols`. If we were using the standard COFF header structure it would look like the following.

IMAGE_FILE_HEADER structure (winnt.h)
```C++
typedef struct _IMAGE_FILE_HEADER {
  WORD  Machine;
  WORD  NumberOfSections;
  DWORD TimeDateStamp;
  DWORD PointerToSymbolTable;
  DWORD NumberOfSymbols;
  WORD  SizeOfOptionalHeader;
  WORD  Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

```
To explore the format, we will be using `pefile` and `hexdump`. The example file below is the `a.exe` from the `bin` directory. Following along at home is encouraged. The Python code below loads a PE file using pefile, extracts a pointer to the symbol table and prints the number of symbols.

```python
>>> import pefile
>>> import hexdump
>>> pe = pefile.PE("./bin/a.exe")
>>> pe.FILE_HEADER
<Structure: [IMAGE_FILE_HEADER] 0x84 0x0 Machine: 0x14C 0x86 0x2 NumberOfSections: 0xE 0x88 0x4 TimeDateStamp: 0x60F466A3 [Sun Jul 18 17:36:35 2021 UTC] 0x8C 0x8 PointerToSymbolTable: 0x6400 0x90 0xC NumberOfSymbols: 0x3F8 0x94 0x10 SizeOfOptionalHeader: 0xE0 0x96 0x12 Characteristics: 0x107>
>>> pe_data = open("./bin/a.exe", "rb").read()
# hexdump of the IMAGE_FILE_HEADER
>>> hexdump.hexdump(pe_data[0x84:0xA0])
00000000: 4C 01 0E 00 A3 66 F4 60  00 64 00 00 F8 03 00 00  L....f.`.d......
00000010: E0 00 07 01 0B 01 02 1E  00 1A 00 00              ............
# retrieve the ptr to the symbol table
>>> ptr_symbol_table = pe.FILE_HEADER.PointerToSymbolTable
>>> print("0x%s" % ptr_symbol_table)
0x25600
# dump 32 bytes at the start of the symbol table
>>> hexdump.hexdump(pe_data[ptr_symbol_table:ptr_symbol_table+0x20])
00000000: 2E 66 69 6C 65 00 00 00  1D 00 00 00 FE FF 00 00  .file...........
00000010: 67 01 63 72 74 65 78 65  2E 63 00 00 00 00 00 00  g.crtexe.c......
```

The last two lines of hexdump is a symbol table entry. Each entry is 18 (0x12) bytes in length. A structure definition from [ReactOS](https://doxygen.reactos.org/da/db6/pecoff_8h_source.html#l00243) looks like the following.  

```C++
typedef struct _IMAGE_SYMBOL {
  union {
    BYTE ShortName[8];
    struct {
      DWORD Short;
      DWORD Long;
    } Name;
    DWORD LongName[2];
  } N;
  DWORD Value;
  SHORT SectionNumber;
  WORD Type;
  BYTE StorageClass;
  BYTE NumberOfAuxSymbols;
} IMAGE_SYMBOL;
```
Overall the structure is pretty easy to understand, except there is a little bit of logic for retrieving the name. If the name is 8 bytes or less (ShortName), it is stored in the symbol entry. If the name is greater than 8 bytes (LongName), than the first four bytes of the short name are `\x00\x00\x00\x00`and the following four bytes are an offset within the string table. We will cover the string table in a little bit.

#### Structure Like Parsing with ctypes
For anyone wondering how to represent the `_IMAGE_SYMBOL` structure in Python, it can be done using ctypes. For example, the following snippet originally appeared in  my `gopepe` project. Go also uses COFF within it's compiled executables. When passed an 18 byte blob of binary data, it creates a ctype instance with each defined structure field being populated.

```python
>>> import ctypes
>>> class COFFSYMBOLTABLE(ctypes.Structure):
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
            # if self.zeroes:print("SHORTNAME!")
            pass
```
To parse the data, we pass it as an argument to the creation of the object. Now each field (which is populated with a tuple of ("name", ctypes type)) is populated with the value.
```python
>>> example = COFFSYMBOLTABLE(pe_data[ptr_symbol_table:ptr_symbol_table+18])
>>> example.zeroes
1818846766
```
There are multiple variations of calling `cls.from_buffer_copy` ([docs](https://docs.python.org/3/library/ctypes.html#ctypes._CData.from_buffer)) but the above format allows for comparing the parsed data within `__init__`.

#### COFF Symbol String Table

The COFF symbol string table resides at the end of the symbol table. Since each entry in the symbol table is 18 bytes, it can be calculated by multiplying the number of symbols by the size of the entry. The number of symbols resides in `pe.FILE_HEADER.NumberOfSymbols`. The following snippet shows calculating the offset to the symbol string table and dumping the first 32 bytes.

```python
# retrieve the number of NumberOfSymbols
>>> number_of_symbols = pe.FILE_HEADER.NumberOfSymbols
>>> print("0x%s" % number_of_symbols)
0x1016
>>> print("0x%x" % (number_of_symbols*18))
0x4770
>>> hexdump.hexdump(pe_data[0x4770:0x4770+0x30])
00000000: 59 00 01 11 58 38 36 5F  54 55 4E 45 5F 53 53 45  Y...X86_TUNE_SSE
00000010: 5F 50 41 52 54 49 41 4C  5F 52 45 47 5F 44 45 50  _PARTIAL_REG_DEP
00000020: 45 4E 44 45 4E 43 59 00  02 11 58 38 36 5F 54 55  ENDENCY...X86_TU
```

The symbol names are stored as strings and are delimited with a null (`\x00`) byte.  It's interesting to note that Window's documentation states that COFF debugging information should not be present.

>This value should be zero for an image because COFF debugging information is deprecated.

Executables compiled with MingW GCC contain symbols and Go binaries contain some fields.

#### Symbol Table Fields
Now that we understand how the symbol table stores strings let's dig into the fields within the symbol table entries. Based off of entry attributes, I have been able to identify five types. There is a file entity, function entity, function static entity, section entity and an auxiliary entity. The auxiliary entity has three types, there is the function definition, symbol definitions and section definitions. The auxiliary entity is used to describe an entity. For example, the file entity is identified because it has a name of `.file` a storage class of `IMAGE_SYM_CLASS_FILE` and an `aux` of 1. Since it has an `aux` of 1, the following 18 bytes after the file entity are the auxiliary entity which contains the file name (e.g. `crtexe.c`).

```
{'name': b'.file', 'type': 'IMAGE_SYM_TYPE_NULL', 'aux': 1, 'sclass': 'IMAGE_SYM_CLASS_FILE', 'type_aux': None},
{'type_aux': 'AUX_FILE', 'file_name': b'crtexe.c'}
```
For anyone curious what this would look like from a hexdump view, the first 18 bytes are the file entity and at offset `0x6A12` is the file auxiliary entity.

```
Offset(h) 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F

00006A00  2E 66 69 6C 65 00 00 00 1D 00 00 00 FE FF 00 00  .file.......þÿ..
00006A10  67 01 63 72 74 65 78 65 2E 63 00 00 00 00 00 00  g.crtexe.c......
00006A20  00 00 00 00                                      ....

```
While this might sound boring, its pretty cool because you can extract the original source code file names. The following snippet loads an executable, parses it and prints all the file names extracted from the file entities.

```python
CC = COFFS("./bin/debug_symbols.exe")
print(CC.file_tab)
```
Output
```
[b'crtexe.c', b'cygming-crtbegin.c', b'xor.c', b'gccmain.c', b'natstart.c', b'wildcard.c', b'charmax.c', b'dllargv.c', b'gs_support.c', b'_newmode.c', b'tlssup.c', b'cinitexe.c', b'merr.c', b'CRT_fp10.c', b'mingw_helpers.c', b'pseudo-reloc.c', b'xtxtmode.c', b'crt_handler.c', b'tlsthrd.c', b'tlsmcrt.c', '', b'pesect.c', b'fake', b'libgcc2.c', b'mingw_matherr.c', b'acrt_iob_func.c', '', b'fake', b'fake', b'fake', b'fake', b'cygming-crtend.c']
```
For anyone curious, the `fake` entities are kind of a placeholder because "The interface doesn't give us access to the name of the input file yet" [[source]](https://chromium.googlesource.com/chromiumos/third_party/binutils/+/refs/heads/stabilize-4920.6.B/libiberty/simple-object-coff.c#614).
