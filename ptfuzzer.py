#!/usr/bin/python
# coding:utf-8
import argparse
import cle
from capstone import *
import argparse
import os
from run_with_pt import binary_loaded_info


def load_config():
    config_kvs = {}
    config_file = None
    candidates = ['ptfuzzer.conf', '/etc/ptfuzzer.conf']
    for c in candidates:
        if os.path.isfile(c):
            config_file = c
            break;
    if config_file == None:
        return {}
    with open(config_file) as f:
        for line in f.readlines():
            pos = line.find('#')
            #print "pos = ", pos 
            line = line[0:pos]
            #print line
            line.strip()
            if len(line) == 0:
                continue
            words = line.split('=')
            if len(words) != 2:
            	continue
            key = words[0]
            value = words[1]
            config_kvs[key] = value;
    return config_kvs

conf = load_config()
mem_limit = None
if conf.has_key("MEM_LIMIT"):
    mem_limit = int(conf["MEM_LIMIT"])
    print "config MEM_LIMIT to", mem_limit
    
parser = argparse.ArgumentParser(description='Process arguements and bin name.')
parser.add_argument('afl_args', type=str, help='arguements of AFL')
parser.add_argument('target', type=str, help='target bin name and arguements of target bin')
args = parser.parse_args()

# get afl binary and afl arguments
bin_dir = os.path.dirname(__file__)
afl_bin = os.path.join(bin_dir, "afl-ptfuzz")
afl_args = args.afl_args

# get target binary and target arguments
target_words = args.target.split()
raw_bin_file = target_words[0];
target_args = ""
for i in range(1, len(target_words)):
	target_args += (target_words[i] + " ")
	
# get the loaded info of target binary
info = binary_loaded_info(raw_bin_file)
raw_bin = info['raw_bin']
min_addr = info['text_min']
max_addr = info['text_max']
entry = info['entry']

# compose the command line for running AFL
if mem_limit != None:
    cmdline = "sudo %s -r %s -m %d -l %d -h %d -e %d %s %s %s @@" % (afl_bin, raw_bin, mem_limit, min_addr, max_addr, entry, afl_args, raw_bin_file, target_args)
else:
    cmdline = "sudo %s -r %s -l %d -h %d -e %d %s %s %s @@" % (afl_bin, raw_bin, min_addr, max_addr, entry, afl_args, raw_bin_file, target_args)
print cmdline
os.system(cmdline)
