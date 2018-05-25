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
last = None

for i in range(0, size):
    line1 = data1[i].strip()
    line2 = data2[i].strip()
    if line1 != line2:
        print "first diff pos: ", i
        print "file1: %s" % line1
        print "file2: %s" % line2
        print "last equal: ", last
        for j in range(0, 10):
            pos = i + j - 1
            if pos < size:
                line1 = data1[pos].strip()
                line2 = data2[pos].strip()
                print line1 + '\t\t\t\t' + line2
        break
    last = line1

