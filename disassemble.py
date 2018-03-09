import cle
from capstone import *

ld = cle.Loader("/bin/ls")
entry = ld.main_object.entry
min_addr = ld.main_object.min_addr
max_addr = ld.main_object.max_addr
CODE = ''.join(ld.memory.read_bytes(ld.main_object.entry, 0x100))
md = Cs(CS_ARCH_X86, CS_MODE_64)
7 for i in md.disasm(CODE, 0x1000):
8     print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
