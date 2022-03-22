def checkDuplicates(line):
    line = bytes.fromhex(line)
    data = [line[i:i+16] for i in range(0, len(line), 16)]
    return (len(data) != len(set(data)))

with open("aes.data") as f:
    lines = f.readlines()
    for line in lines:
        if checkDuplicates(line):
            print(line, '\n')
