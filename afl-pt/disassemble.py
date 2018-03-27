#arg_parse.py
#coding:utf-8
import cle
from capstone import *
import argparse

parser = argparse.ArgumentParser(description='Process bin name.')
parser.add_argument('string', type= str, help='bin name')
args = parser.parse_args()

ld = cle.Loader(args.string)

f = open("./raw_bin", "wb")
bin_code = ""

entry = ld.main_object.entry
# 'data', 'header', 'is_null', 'name', 'stream'


for i in ld.main_object.sections:
	if i.name == ".text":
		# print i.vaddr, i.filesize
		min_addr = i.vaddr
		max_addr = i.vaddr + i.filesize
		raw_bytes = ld.memory.read_bytes(i.vaddr, i.filesize)
		for byte in raw_bytes:
			bin_code += byte

# print len(bin_code)
f.write(bin_code)
f.close()


faddr = open("./min_max.txt", "w")
faddr.write(str(min_addr) + "\n" + str(max_addr) + "\n" + str(entry))
faddr.close()



#~ raw_bytes = ld.memory.read_bytes(ld.main_object.entry, max_addr-min_addr)
#~ CODE = ''.join( raw_bytes )
#~ md = Cs(CS_ARCH_X86, CS_MODE_64)
#~ for i in md.disasm(CODE, entry):
    #~ print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

#~ print "len(raw_bytes) = ", len(raw_bytes)
#~ print "entry_point = ", hex(ld.main_object.entry)
#~ print "min_addr = ", hex(min_addr)
#~ print "max_addr = ", hex(max_addr)
#~ print "max_addr - min_addr = ", max_addr - min_addr
#~ print "loader min and max addr: ", ld.min_addr, ld.max_addr
