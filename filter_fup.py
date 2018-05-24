import os
num_round = 10
def is_fup(line):
    return line.startswith("tip_fup:")
def is_tip(line):
    return line.startswith("tip:")
def is_tip_pgd(line):
    return line.startswith("tip_pgd:")
def is_tip_pge(line):
    return line.startswith("top_pge:")

def filter_fup(log_file, out_file):
    fup = None
    fup_pgd = None
    f = open(log_file)
    out_f = open(out_file, 'w')
    lines = f.readlines()
    for line in lines:
        if is_fup(line):
            fup = None
        elif is_tip(line):
            if fup == None:
                out_f.write(line)
            else:
                out_f.write(line)
                fup = None  #clear the state
        elif is_tip_pgd(line):
            if fup != None:
                fup_pgd = line
            else:
                out_f.write(line)
        elif is_tip_pge(line):
            if fup != None:
                fup = None  # clear the state
                fup_pgd = None
            else:
                out_f.write(line)
        else:
            out_f.write(line)
    f.close()
    out_f.close()

for i in range(0, num_round):
    print "run %d..." % i
    cmd = "python build/bin/run_with_pt.py /bin/ls > debug_output.txt"
    print cmd
    os.system(cmd)
    pt_log_file = "pt%d.log" % i
    cmd = "python simple.py debug_output.txt > %s" % pt_log_file
    print cmd
    os.system(cmd)
    pt_filter_file = "fpt%d.log" % i
    filter_fup(pt_log_file, pt_filter_file)
