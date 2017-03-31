#!/usr/bin/env python

import re
import sys
import binascii

def file_check(fn):
    try:
        open(fn, 'r')
        return 1
    except IOError:
        print 'Error: File ' + fn + ' does not appear to exist.'
        return 0

def hexstr_clean(a):
    return re.sub('[^0-9a-fA-F]', '', a)

def hexstr_print_format(a):
    return re.sub('(.{2})', r'\g<0>' + ' ', a)

def hexstr_xor(a, b):
    a_bytes = bytearray.fromhex(a)
    b_bytes = bytearray.fromhex(b)
    xor_bytes = bytearray()
    for a_val, b_val in zip(a_bytes, b_bytes):
	xor_bytes.append(a_val ^ b_val)
    return xor_bytes	

if(len(sys.argv) < 4):
    exit('Missing arguments. Need data_folder_path, file1_name, file2_name')

data_path = sys.argv[1] 
f1_name = sys.argv[2]
f2_name = sys.argv[3]
res_name = f1_name + 'XOR' + f2_name
f1_path = data_path + f1_name
f2_path = data_path + f2_name
res_path = data_path + res_name

if not(file_check(f1_path) and file_check(f2_path)):
    exit()

f1_file = open(f1_path, 'r')
f2_file = open(f2_path, 'r')

f1_data = f1_file.read()
f2_data = f2_file.read()

f1_data_cleaned = hexstr_clean(f1_data)
f2_data_cleaned = hexstr_clean(f2_data)

xor_bytes = hexstr_xor(f1_data_cleaned, f2_data_cleaned)
res_data = hexstr_print_format(binascii.hexlify(xor_bytes))

res_file = open(res_path, 'w')
res_file.write(res_data)

print hexstr_print_format(f1_data_cleaned) + ' = ' + f1_name
print hexstr_print_format(f2_data_cleaned) + ' = ' + f2_name 
print res_data 				   + ' = ' + f1_name + ' XOR ' + f2_name
print ''


