#!/usr/bin/env python
#11/18/2017 rjmendez
import binascii, bitstring, sys, getopt, rflib, time

#Help
help_msg = 'Nothing Yet'

#Radio stuff
frequency = 318000000
baudRate = 1000
keyLen = 0

def ConfigureD(d):
    d.setMdmModulation(rflib.MOD_ASK_OOK)
    d.setFreq(frequency)
    d.makePktFLEN(keyLen)
    d.setMdmDRate(baudRate)
    d.setMaxPower()
    d.lowball()
#Padding the input values.
def PadBytes(byte_length, hex_val):
    #print(str(byte_length-len(hex_val)))
    pad_num = byte_length-len(hex_val)
    if pad_num >= 1:
        pad_str = "0" * pad_num
        #print(pad_str)
        padded_hex_val = str(pad_str + hex_val)
        #print(padded_hex_val)
        return padded_hex_val
    if pad_num == 0:
        #do nothing
        padded_hex_val = hex_val
        return padded_hex_val
    if pad_num < 0:
        print('Invalid length of input, was expecting <= ' + str(byte_length) + ' but we got ' + str(len(hex_val)) + ' instead!')
        print(help_msg)
        quit()

def PacketValues(sysid):
    hex_sysid = PadBytes(6, str(hex(sysid)).lstrip("0x"))
    input_hex = hex_sysid
    return input_hex

def ValidateInputs(sysid):
    if sysid >= 1048576:
        print("Invalid System ID Detected!")
        print(help_msg)
        quit()
    if sysid <= 1048575:
        return sysid

#Bytes to Bits ascii stream.
def byte_to_binary(n):
    return ''.join(str((n & (1 << i)) and 1) for i in reversed(range(8)))
#Hex to Bytes.
def hex_to_binary(h):
    return ''.join(byte_to_binary(ord(b)) for b in binascii.unhexlify(h))

def main(argv):
    data = 1
    rxid = ''
    sysid = ''
    input_hex = ''
    output_hex = ''
    output_bin = ''
    try:
        opts, args = getopt.getopt(argv,"hs:",["systemid"])
    except getopt.GetoptError as error:
        print(error)
        print(help_msg)
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print(help_msg)
            sys.exit()
        elif opt in ("-s", "--systemid"):
            sysid = int(arg)
    if len(sys.argv) == 1:
        print('Invalid input, program accepts the following input format:\n' + help_msg)
        sys.exit(2)


    sysid = ValidateInputs(sysid)
    #Generate packet hex
    input_hex = PacketValues(sysid)
    
    #Convert hex to binary ascii stream
    input_bin = hex_to_binary(input_hex)
    input_bin = input_bin[4:] #Removing extra null byte
    #print(input_bin)
    
    #Convert binary data to format that the radio is expecting. 1 = 00001 0 = 001000
    for bit in input_bin:
        if bit == '0':
            output_bin += '001000'
        elif bit == '1':
            output_bin += '000001'
        else:
            print("lolwut?")
    
#    rf_data = bitstring.BitArray(bin=output_bin+data_spoiler).tobytes()

    '''
Reading the Linear protocol documentation describes a 6ms 25 bit-frame with individual 1ms symbols 

  sync      1      2      3      4      5      6      7      8      9     10     11     12     13     14     15     16     17     18     19     20     21     22     23
000001 000001 001000 000001 001000 000001 001000 000001 001000 001000 001000 000001 001000 000001 001000 000001 001000 001000 000001 000001 001000 001000 000001 001000 000000
000001 000001 001000 000001 001000 000001 001000 000001 001000 001000 001000 000001 001000 000001 001000 000001 001000 001000 000001 000001 001000 001000 000001 001000 000000
000001 000001 001000 000001 001000 000001 001000 000001 001000 001000 001000 000001 001000 000001 001000 000001 001000 001000 000001 000001 001000 001000 000001 001000 000000
000001 000001 001000 000001 001000 000001 001000 000001 001000 001000 001000 000001 001000 000001 001000 000001 001000 001000 000001 000001 001000 001000 000001 001000 000000
000001 000001 001000 000001 001000 000001 001000 000001 001000 001000 001000 000001 001000 000001 001000 000001 001000 001000 000001 000001 001000 001000 000001 001000 000000
000001 000001 001000 000001 001000 000001 001000 000001 001000 001000 001000 000001 001000 000001 001000 000001 001000 001000 000001 000001 001000 001000 000001 001000 000000
000001 000001 001000 000001 001000 000001 001000 000001 001000 001000 001000 000001 001000 000001 001000 000001 001000 001000 000001 000001 001000 001000 000001 001000 000000
000001 000001 001000 000001 001000 000001 001000 000001 001000 001000 001000 000001 001000 000001 001000 000001 001000 001000 000001 000001 001000 001000 000001 001000 000000
000001 000001 001000 000001 001000 000001 001000 000001 001000 001000 001000 000001 001000 000001 001000 000001 001000 001000 000001 000001 001000 001000 000001 001000 000000
000001 000001 001000 000001 001000 000001 001000 000001 001000 001000 001000 000001 001000 000001 001000 000001 001000 001000 000001 000001 001000 001000 000001 001000 000000
     1      1     8       1      8      1      8      1      8      8      8      1      8      1      8      1      8      8      1      1      8      8      1      8    NUL

If 000001 = 1 and 001000 = 0:
110101010001010100110010NUL
D51532

Documentation describes frame 0 as the sync frame, 1-20 as system code, and 21-23 as data bits.

10101010001010100110 010
AA2A6 2
    '''

    sync_frame = "000001"
    data_frame = "001000000001001000" #2
    null_tail  = "000000"
    rf_data = bitstring.BitArray(bin=sync_frame+output_bin+data_frame+null_tail).tobytes()
    keyLen = len(rf_data)
    #Configure Radio here.
    d = rflib.RfCat()
    ConfigureD(d)
    #Transmit here.
    print('Sending packet payload 4*: ' + input_hex + '2')
    d.RFxmit(rf_data, repeat=3)
    time.sleep(1)
    d.setModeIDLE()
    print('Done!')
    quit()


if __name__ == "__main__":
    main(sys.argv[1:])

