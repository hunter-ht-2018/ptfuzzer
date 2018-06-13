# ~ import sys

# ~ file_name = sys.argv[1]

# ~ f = open(file_name)

# ~ lines = f.readlines()

# ~ output = []
# ~ i = 0
# ~ while i < len(lines):
    # ~ if lines[i].startswith("tip_fup: "):
        # ~ if lines[i+1] == "tip_pgd: 0\n" and lines[i+2] == "tip_pge: " + lines[i].split()[1] + "\n":
        # ~ if lines[i+1] == "tip_pgd: 0\n" and lines[i+2].startswith("tip_pge: "):
            # ~ i += 3
        # ~ else:
            # ~ i += 1
    # ~ else:
        # ~ output.append(lines[i])
        # ~ i += 1

# ~ f.close()

# ~ for l in output:
    # ~ print l ,

import sys
file1 = sys.argv[1]
file2 = sys.argv[2]
f1 = open(file1, 'r')
f2 = open(file2, 'r')

data1 = f1.readlines()
data2 = f2.readlines()

size = len(data1)

if len(data1) > len(data2):
    size = len(data2)

i = 0
j = 0
out1 = []
out2 = []
while i < size and j < size:
    while data1[i].startswith("tip_fup: "):
        if data1[i + 1] == "tip_pgd: 0\n" and data1[i + 2] == "tip_pge: " + data1[i].split()[1] + "\n":
        # ~ if lines[i+1] == "tip_pgd: 0\n" and lines[i+2].startswith("tip_pge: "):
            i += 3
        else:
            i += 1
    
    while data2[j].startswith("tip_fup: "):
        if data2[j + 1] == "tip_pgd: 0\n" and data2[j + 2] == "tip_pge: " + data2[j].split()[1] + "\n":
        # ~ if lines[i+1] == "tip_pgd: 0\n" and lines[i+2].startswith("tip_pge: "):
            j += 3
        else:
            j += 1
    if data1[i] != data2[j]:
        print i, j
        break
    out1.append(data1[i])
    out2.append(data2[j])
    i += 1
    j += 1

f = open("out1.txt", "w")
for l in out1:
    f.write(l)
f.close()

f = open("out2.txt", "w")
for l in out2:
    f.write(l)
f.close()
