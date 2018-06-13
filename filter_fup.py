import os
import argparse
num_round = 10
def is_fup(line):
    return line.startswith("tip_fup: ")
def is_tip(line):
    return line.startswith("tip: ")
def is_tip_pgd(line):
    return line.startswith("tip_pgd: 0")
def is_tip_pge(line):
    return line.startswith("tip_pge: ")

def filter_fup(log_file, out_file):
    fup = None
    fup_pgd = None
    f = open(log_file)
    out_f = open(out_file, 'w')
    lines = f.readlines()
    for l in lines:
        line = l.strip()
        words = line.split()
        tip_type = words[0]
        addr = words[1]
        if is_fup(line):
            fup = line
            continue
        elif is_tip_pgd(line):
            if fup != None:
                fup_pgd = line
            else:
                out_f.write(line + "\n")
        elif is_tip_pge(line):
            if fup_pgd != None:
                if line.split()[1] == fup.split()[1]:
                    #print line.split()[1], fup_addr
                    fup = None  # clear the state
                    fup_pgd = None
                else:
                    out_f.write(fup_pgd + '\n')
                    out_f.write(line + '\n')
                    fup = None
                    fup_pgd = None
            else:
                out_f.write(line + "\n")
                fup = None
        else:
            out_f.write(line + "\n")
            fup = None

    f.close()
    out_f.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description = 'Process arguements and bin name.')
    #parser.add_argument('app_bin', type = str, help = 'the target application')
    parser.add_argument('-c', '--cmd-line', dest = "cmd", type = str, help = 'application arguments')
    args = parser.parse_args()
    
    for i in range(0, num_round):
        print "run %d..." % i
        #cmd = "python build/bin/run_with_pt.py ./build/ptest/readelf -a ./build/ptest/readelf > debug_output.txt"
        cmd = "python build/bin/run_with_pt.py %s > debug_output.txt" % args.cmd
        print cmd
        if args.cmd != None:
            os.system(cmd)
        pt_log_file = "pt%d.log" % i
        cmd = "python trim_log.py debug_output.txt > %s" % pt_log_file
        print cmd
        if args.cmd != None:
            os.system(cmd)
        pt_filter_file = "fpt%d.log" % i
        filter_fup(pt_log_file, pt_filter_file)

    print "check file differences:"
    for i in range(1, num_round):
        pt_filter_file = "fpt%d.log" % i
        cmd = "diff %s fpt0.log" % pt_filter_file
        print cmd
        os.system(cmd)
