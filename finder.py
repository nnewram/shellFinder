from pwn import *
import sys
import os

STORE = False

if "store" in sys.argv:
    if not os.path.exists("db"):
        os.mkdir("db")
    STORE = True

filename = sys.argv[1]

os.system("".join(["objdump -d ", filename, " -M intel | grep -a \"call\" | grep -a -E \"rax|rbx|rcx|rdx|eax|ebx|edx\" | grep -v \"\\[\" > calls"]))
os.system("".join(["objdump -d ", filename, " -M intel | grep -a \"jmp\" | grep -a \"rax|rbx|rcx|rdx|eax|ebx|edx\" | grep -v \"\\[\" >> calls"]))

os.system("".join(["objdump -d ", filename, " -M intel | grep -a \"call\" | grep -a \"\\[\" >> calls"]))
os.system("".join(["objdump -d ", filename, " -M intel | grep -a \"jmp\" | grep -a \"\\[\" >> calls"]))

offsets = []

with open("calls", "r") as calls:
    callsRead = calls.readlines()
    [offsets.append(int(x.replace(" ", "").split(":")[0], 16)) for x in callsRead]

elf = ELF(filename) # slowest part of this process... Might be possible to speed up trough readelf

#os.system("".join(["objdump -Dz ", filename, " | grep -a -E \"<[^.@]*>:$\" > functions"]))

'''
>>> os.system("readelf -sW ../../libc-database/db/libc6_2.30-0ubuntu2.1_amd64.so | awk \'$4 == \"FUNC\"\' >> utt")
>>> a = s[1].split(": ")[1].split("@")[0].split(" ")
>>> a[0], a[-1]
'''

addresses = []
functionNames = []

functionsWithCalls = {"unknow": []}

for function in elf.functions:
    addresses.append(elf.functions[function].address)
    functionNames.append(function)

functionNames = [x for _,x in sorted(zip(addresses, functionNames))]
addresses.sort()
offsets.sort()

prevIndex = 0
for offset in offsets:
    for addressIndex in range(prevIndex, len(addresses)-1):
        if offset >= addresses[addressIndex] and offset <= addresses[addressIndex+1]:
            if functionNames[addressIndex] in functionsWithCalls:
                functionsWithCalls[functionNames[addressIndex]].append(offset)
            else:
                functionsWithCalls[functionNames[addressIndex]] = [offset]
            prevIndex = addressIndex # next gadget will start search where hte other one left off as they are sorted. In big programs this might skip a lot of functions, speeding it up
            break
    else:
        if offset >= addresses[-1]:
            if functionNames[-1] in functionsWithCalls:
                functionsWithCalls[functionNames[-1]].append(offset)
            else:
                functionsWithCalls[functionNames[-1]] = [offset]
        else:
            functionsWithCalls["unknow"].append(offset)
if STORE:
    if "/" in filename:
        filename = filename.split("/")[-1]
    if os.path.exists("db/" + filename + ".txt"):
        os.system("rm " + "db/" + filename + ".txt")
    with open("db/" + filename + ".txt", "w+") as outputFile:
        for x in functionsWithCalls:
            outputFile.write(x + ": " + str(functionsWithCalls[x]) + "\n")
else:
    print("done")
    [print(x + ":", functionsWithCalls[x]) for x in functionsWithCalls]

os.system("rm calls")