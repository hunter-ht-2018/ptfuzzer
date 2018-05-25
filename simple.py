import sys

file_name = sys.argv[1]

f = open(file_name)

lines = f.readlines()
#filters = ["tip_fup:", "tip:", "tip_pgd:" , "tip_pge:", "tnt8:", "long_tnt:"]
filters = ["tip_fup:", "tip:", "tip_pgd:" , "tip_pge:"]


for line in lines:
    for sf in filters:
        if line.startswith(sf):
            print line,
            break

f.close()



