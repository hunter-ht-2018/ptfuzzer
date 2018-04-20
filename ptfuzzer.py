#arg_parse.py
#coding:utf-8
import cle
from capstone import *
import argparse
import os

raw_bin_file = "./testcase/readelf"
afl_bin = "./build/afl-ptfuzz"
target_args = ""
afl_args = "-t 999999 -i ./testcase/ptest/in -o ./testcase/ptest/out"
target_args = "-a"

raw_bin = raw_bin_file+".text"

# parser = argparse.ArgumentParser(description='Process bin name.')
# parser.add_argument('string', type= str, help='bin name')
# args = parser.parse_args()

# ld = cle.Loader(args.string)

ld = cle.Loader(raw_bin_file)

f = open(raw_bin, "wb")
if not f:
	print "open file " + raw_bin + " for writing failed."

bin_code = ""
base_addr = 0x0
entry = ld.main_object.entry + base_addr
# 'data', 'header', 'is_null', 'name', 'stream'



for i in ld.main_object.sections:
	if i.name == ".text":
		print i.vaddr
		min_addr = i.vaddr + base_addr
		max_addr = i.vaddr + i.filesize + base_addr
		raw_bytes = ld.memory.read_bytes(i.vaddr, i.filesize)
		for byte in raw_bytes:
			bin_code += byte

# print len(bin_code)
f.write(bin_code)
f.close()

cmdline = "sudo %s -r %s -l %d -h %d -e %d %s %s %s @@" % (afl_bin, raw_bin, min_addr, max_addr, entry, afl_args, raw_bin_file, target_args)
print cmdline
os.system(cmdline)



#faddr = open("./min_max.txt", "w")
#faddr.write(str(min_addr) + "\n" + str(max_addr) + "\n" + str(entry))
#faddr.close()



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
