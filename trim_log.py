import sys

file_name = sys.argv[1]

f = open(file_name)

lines = f.readlines()
#filters = ["tip_fup:", "tip:", "tip_pgd:" , "tip_pge:", "tnt8:", "long_tnt:"]
filters = ["tip_fup:", "tip:", "tip_pgd:" , "tip_pge:"]

tnt_cache = None
def print_tnt_cache(tnt):
    print tnt[0], tnt[1], tnt[2]
    
for line in lines:
    for sf in filters:
        if line.startswith(sf):
            if tnt_cache != None:
                print_tnt_cache(tnt_cache)
                tnt_cache = None
            print line,
            break

    if line.startswith("tnt8:") or line.startswith("long_tnt:"):
        tnt = line.strip().split()
        tnt_marker = tnt[0]
        tnt_bits = int(tnt[1])
        tnt_data = tnt[2]
        if tnt_cache == None:
            tnt_cache = ["tnt_cache:", tnt_bits, tnt_data]
        else:
            tnt_cache[1] += tnt_bits
            tnt_cache[2] += tnt_data
    
f.close()



