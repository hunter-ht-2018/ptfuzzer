#!/usr/bin/python
#arg_parse.py
#coding:utf-8
import argparse
import cle
from capstone import *
import argparse
import os

def binary_loaded_info(app_bin):
    
    # First, get binary type: executable or shared object(PIE)
    bin_type = "executable"
    app_bin = os.path.realpath(app_bin)
    file_info = os.popen("file " + app_bin)
    if "shared object" in file_info.read():
        bin_type = "shared_object"
    print "binary type is ", bin_type
    
    # Now load binary, calculate program loaded base, entry, text_min and text_max 
    ld = cle.Loader(app_bin)
    bin_code = ""
        
    base_addr = ld.main_object.sections[0].vaddr
    entry = ld.main_object.entry + base_addr
    print "Program base by cle: ", base_addr
    print "Program entry by cle: ", entry
    for i in ld.main_object.sections:
        if i.name == ".text":
            text_min = i.vaddr
            text_max = i.vaddr + i.filesize
            raw_bytes = ld.memory.read_bytes(i.vaddr, i.filesize)
            for byte in raw_bytes:
                bin_code += byte
            break
        
    #Third, write raw binary code to file
    raw_bin = "." + os.path.basename(app_bin) + ".text"
    f = open(raw_bin, "wb")
    if not f:
        print "open file " + raw_bin + " for writing failed."
        sys.exit(-1)
        
    f.write(bin_code)
    f.close()
        
    # Now we have to recalcuate the loaded addresses for Position-independent executables
    if bin_type == "shared_object":
        text_min -= base_addr
        text_max -= base_addr
        entry -= base_addr
        base_addr = 0x0
        
        base_addr = 0x555555554000
        text_min += base_addr
        text_max += base_addr
        entry += base_addr
    
    bin_loaded_info = {
        'base': base_addr,
        'entry': entry,
        'text_min': text_min,
        'text_max': text_max,
        'raw_bin': raw_bin
        }
    return bin_loaded_info 

if __name__ == '__main__':
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
    
    
    info = binary_loaded_info(app_bin)
    
    print "calculated real program base: ", hex(info['base'])
    print "calculated real program entry: ", hex(info['entry'])
    
    cmdline = "sudo %s %s %d %d %d %s %s" % (afl_bin, info['raw_bin'], info['text_min'], info['text_max'], info['entry'], app_bin, app_args)
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
