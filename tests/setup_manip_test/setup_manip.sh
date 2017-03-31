if [ $# -lt 4 ]
  then
    printf "Not enough arguments supplied, need filepaths of data and manipulated data and crc remainder\n"
    printf "[data_folder] [data] [data_manip] [remainder] [cipherstream]\n"
    exit
fi

data_folder=$1

data=$2
datamanip=$3
dataXORdatamanip="${data}XOR$datamanip"

remainder=$4
CRC_data_="$data.crc"
CRC_datamanip_="$datamanip.crc"
CRC_dataXORdatamanip_="$dataXORdatamanip.crc"
# crc_r(data XOR data_manip) XOR remainder
CRC_dataXORdatamanip_XORremainder="${CRC_dataXORdatamanip_}XOR$remainder"
# crc_r(data XOR data_manip) XOR remainder XOR crc(data)
CRC_dataXORdatamanip_XORremainderXORCRC_data_="${CRC_dataXORdatamanip_XORremainder}XOR$CRC_data_"
# crc_r(data XOR data_manip) XOR remainder XOR crc(data) XOR crc(data_manip)
CRC_dataXORdatamanip_XORremainderXORCRC_data_XORCRC_datamanip_="${CRC_dataXORdatamanip_XORremainderXORCRC_data_}XOR$CRC_datamanip"

CC_remainder_="$remainder.cc"
CC_CRC_data__="$data.cc"
CC_CRC_datamanip__="$datamanip.cc"
# cc(crc_r(data XOR data_manip))
CC_CRC_dataXORdatamanip__="$dataXORdatamanip.cc"
# cc(crc_r(data XOR data_manip)) XOR cc(remainder)
CC_CRC_dataXORdatamanip__XORCC_remainder_="${CC_CRC_dataXORdatamanip__}XOR$CC_remainder_"
# cc(crc_r(data XOR data_manip)) XOR cc(remainder) XOR cc(crc(data))
CC_CRC_dataXORdatamanip__XORCC_remainder_XORCC_CRC_data__="${CC_CRC_dataXORdatamanip__XORCC_remainder_}XOR$CC_CRC_data__"
# cc(crc_r(data XOR data_manip)) XOR cc(remainder) XOR cc(crc(data)) XOR cc(crc(data_manip))
CC_CRC_dataXORdatamanip__XORCC_remainder_XORCC_CRC_data__XORCC_CRC_datamanip__="${CC_CRC_dataXORdatamanip__XORCC_remainder_XORCC_CRC_data__}XOR$CC_CRC_datamanip__"
# cc(crc_r(data XOR data_manip) XOR remainder XOR crc(data))
CC_CRC_dataXORdatamanip_XORremainderXORCRC_data__="${CRC_dataXORdatamanip_XORremainderXORCRC_data_}.cc"
# cc(crc_r(data XOR data_manip) XOR remainder XOR crc(data)) XOR cc(crc(data_manip))
CC_CRC_dataXORdatamanip_XORremainderXORCRC_data__XORCC_CRC_datamanip__="${CC_CRC_dataXORdatamanip_XORremainderXORCRC_data__}XOR$CC_CRC_datamanip"

cipherstream=$5
# ciph(cc(crc(data)))
CIPH_CC_CRC_data___="${CC_CRC_data__}XOR$cipherstream"
# ciph(cc(crc(data_manip)))
CIPH_CC_CRC_datamanip___="${CC_CRC_datamanip__}XOR$cipherstream"
# cc(crc_r(data XOR data_manip)) XOR cc(remainder) XOR ciph(cc(crc(data)))
CC_CRC_dataXORdatamanip__XORCC_remainder_XORCIPH_CC_CRC_data___="${CC_CRC_dataXORdatamanip__XORCC_remainder_}XOR$CIPH_CC_CRC_data___"
# cc(crc_r(data XOR data_manip)) XOR cc(remainder) XOR ciph(cc(crc(data))) XOR ciph(cc(crc(data_manip)))
CC_CRC_dataXORdatamanip__XORCC_remainder_XORCIPH_CC_CRC_data___CIPH_CC_CRC_datamanip___="${CC_CRC_dataXORdatamanip__XORCC_remainder_XORCIPH_CC_CRC_data___}XOR$CIPH_CC_CRC_datamanip___"


# crc_r(data), cc(crc_r(data))
../../src/dummycoder --no-ciphering --data-type plain --encode --data-path "$data_folder$data"
# crc_r(data_manip), cc(crc_r(data_manip))
../../src/dummycoder --no-ciphering --data-type plain --encode --data-path "$data_folder$datamanip"
# data XOR data_manip
../../xor_hexstrings.py $data_folder $data $datamanip

# crc_r(data XOR data_manip), cc(crc_r(data XOR data_manip))
../../src/dummycoder --no-ciphering --data-type plain --encode --data-path "$data_folder$dataXORdatamanip"
# crc_r(data XOR data_manip) XOR remainder
../../xor_hexstrings.py $data_folder $CRC_dataXORdatamanip_ $remainder
# crc_r(data XOR data_manip) XOR remainder XOR crc_r(data)
../../xor_hexstrings.py $data_folder $CRC_dataXORdatamanip_XORremainder $CRC_data_
# crc_r(data XOR data_manip) XOR remainder XOR crc_r(data) XOR crc_(data_manip) === TEST
../../xor_hexstrings.py $data_folder $CRC_dataXORdatamanip_XORremainderXORCRC_data_ $CRC_datamanip_
printf "TEST1 - CHECK == 0!\n\n" 
# cc(remainder)
../../src/dummycoder --no-ciphering --data-type cc --encode --data-path "$data_folder$remainder"
# cc(crc_r(data XOR data_manip) XOR remainder XOR crc_r(data))
../../src/dummycoder --no-ciphering --data-type cc --encode --data-path "$data_folder$CRC_dataXORdatamanip_XORremainderXORCRC_data_"
# cc(crc_r(data XOR data_manip) XOR remainder XOR crc_r(data)) XOR cc(crc_(data_manip)) === TEST
../../xor_hexstrings.py $data_folder $CC_CRC_dataXORdatamanip_XORremainderXORCRC_data__ $CC_CRC_datamanip__
printf "TEST2 - CHECK == 0!\n\n" 

# cc(crc_r(data XOR data_manip)) XOR CC(remainder)
../../xor_hexstrings.py $data_folder $CC_CRC_dataXORdatamanip__ $CC_remainder_
# cc(crc_r(data XOR data_manip)) XOR CC(remainder) XOR cc(crc_r(data))
../../xor_hexstrings.py $data_folder $CC_CRC_dataXORdatamanip__XORCC_remainder_ $CC_CRC_data__
# cc(crc_r(data XOR data_manip)) XOR CC(remainder) XOR cc(crc_r(data)) XOR cc(crc_(data_manip)) === TEST
../../xor_hexstrings.py $data_folder $CC_CRC_dataXORdatamanip__XORCC_remainder_XORCC_CRC_data__ $CC_CRC_datamanip__
printf "TEST3 - CHECK == 0!\n\n" 

# ciph(cc(crc_r(data)))
../../xor_hexstrings.py $data_folder $CC_CRC_data__ $cipherstream
# ciph(cc(crc_r(data_manip)))
../../xor_hexstrings.py $data_folder $CC_CRC_datamanip__ $cipherstream
# cc(crc_r(data XOR data_manip)) XOR cc(remainder) XOR ciph(cc(crc(data)))
../../xor_hexstrings.py $data_folder $CC_CRC_dataXORdatamanip__XORCC_remainder_ $CIPH_CC_CRC_data___
# cc(crc_r(data XOR data_manip)) XOR cc(remainder) XOR ciph(cc(crc(data))) XOR ciph(cc(crc(data_manip)))
../../xor_hexstrings.py $data_folder $CC_CRC_dataXORdatamanip__XORCC_remainder_XORCIPH_CC_CRC_data___ $CIPH_CC_CRC_datamanip___
printf "TEST4 - CHECK == 0!\n\n" 

# cleanup
rm $(find $data_folder -name "*.il")
rm $(find $data_folder -name "*.burstmap") 

