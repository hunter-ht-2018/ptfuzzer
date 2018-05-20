#!/usr/bin/python
#arg_parse.py
#coding:utf-8
import argparse
import cle
from capstone import *
import argparse
import os


parser = argparse.ArgumentParser(description = 'Process arguements and bin name.')
parser.add_argument('app_bin', type = str, help = 'the target application')
parser.add_argument('--app_args', type = str, help = 'application arguments')
args = parser.parse_args()

bin_dir = os.path.dirname(__file__)
afl_bin = os.path.join(bin_dir, "run_pt")
app_bin = args.app_bin
app_args = args.app_args
if app_args == None:
    app_args = ""

raw_bin = "." + os.path.basename(app_bin) + ".text"

ld = cle.Loader(app_bin)

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

cmdline = "sudo %s %s %d %d %d %s %s" % (afl_bin, raw_bin, min_addr, max_addr, entry, app_bin, app_args)
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
