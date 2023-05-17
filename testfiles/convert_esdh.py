#!/usr/bin/env python3
import re
import binascii

crvs = ["p256", "p384", "p521"]
encs = ["a128gcm", "a192gcm", "a256gcm"]
kws  = ["a256kw", "a192kw", "a128kw"]

filenames = [f"es_dh_{crv}_{enc}_{kw}.cose" for crv in crvs for enc in encs for kw in kws]
index = 0
#print(filenames)

pat = re.compile(r"^    ([a-f0-9]{2} )+$")

f = open("es-dh_examples.txt", "r")
lines = f.readlines()
t = ""

def write_to_file(hex_string):
    global index
    if len(hex_string) > 0:
        hex_string = hex_string.replace(' ', '')
        hex_string = hex_string.replace('\n', '')
        print(f"==={filenames[index]}===")
        print(hex_string)
        with open(filenames[index], "wb") as f:
            f.write(binascii.unhexlify(hex_string))
        index += 1

for line in lines:
    if pat.match(line):
        t += line
    else:
        write_to_file(t)
        t = ""

write_to_file(t)

