import sys

file_name = sys.argv[1]

f = open(file_name)

lines = f.readlines()
filters = ["tip_fup:", "tip:", "tip_pgd:" , "tip_pge:"]

output = []
for line in lines:
    for sf in filters:
        if line.startswith(sf):
            output.append(line)
            break

f.close()

for l in output:
    print l ,


