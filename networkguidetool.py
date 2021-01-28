import re

def prefixToSubBin(prefix):
    subn = ''
    netBits = prefix
    hostBits = 32-int(prefix)

    for i in range(int(netBits)):
        subn = subn + '1'
    for i in range(int(hostBits)):
        subn = subn + '0'

    return subn

def getBroadcast(prefix, networkAdd):
    hostBit = 32-int(prefix)

    subn = networkAdd[:-hostBit]

    for i in range(hostBit):
        subn = subn +'1'

    return subn

def errorCheck(ip):
    split = ip.split('.')
    nSplit = [int(x) for x in split]

    for x in  nSplit:
        if x >= 256 or x < 0:
            return True

    if len(split) < 4 or len(split) > 4:
        return True
    elif re.search('[a-zA-Z]', ip):
        return True
    else:
        return False

def toBinary(x):
    return format(int(x), '08b')

def subnetCalc():

    subnetCheatSheet = {
        4: 30,
        8: 29,
        16: 28,
        32: 27,
        64: 26,
        128: 25,
        256: 24,
        512: 23,
        1024: 22,
        2048: 21,
        4096: 20,
        8192: 19,
        16384: 18,
        32768: 17,
        65536: 16,
    }


    ip = input("Input IP Address: ")
    if re.search('/', ip):
        pass
    else:
        print('\nError: Invalid IP Address. Missing Prefix Lengths')
        return
    ip = ip.split('/')
    prefix = ip[1]
    ip = ip[0]

    split = ip.split('.')
    nSplit = [int(x) for x in split]
    nSplit = [toBinary(x) for x in split]
    bIP = "".join(map(str, nSplit))

    try:
        numNetworks = int(input("Input number of networks: "))
    except:
        print("Error: Invalid IP Address")
        return

    networkList = [dict() for x in range(numNetworks)]

    tmp = 0
    for network in networkList:
        tmp += 1
        netName = input('Input the name of network ' + str(tmp) + ': ')
        network['netName'] = netName
        ipNeeded = input('Input the number of IP Address needed: ')
        network['ipNeeded'] = int(ipNeeded)
        network['id'] = str(tmp)

    networkList = sorted(networkList, key=lambda x:x['ipNeeded'], reverse=True)

    temp = bIP
    nIP = int(temp,2)
    for network in networkList:
        for val in subnetCheatSheet:
            if network['ipNeeded'] < val:
                network['prefix'] = subnetCheatSheet[val]
                totalIP = val
                break

        subnetMask = int(prefixToSubBin(network['prefix']),2)
        subnetMask = ".".join(map(str, subnetMask.to_bytes(4, "big")))
        network['subnetMask'] = subnetMask

        nIP = nIP
        network['networkAddress'] = ".".join(map(str, nIP.to_bytes(4, "big")))

        firstUsableIp = nIP + int(toBinary(1).replace('0b',''))
        network['firstUsableIP'] = ".".join(map(str, firstUsableIp.to_bytes(4, "big")))

        nIP = nIP + int(toBinary(totalIP).replace("0b",""),2)
        lastUsableIp = nIP  - int(toBinary(2).replace("0b",""),2)
        broadcastAddr = nIP - int(toBinary(1).replace('0b',""),2)

        network['lastUsableIP'] = ".".join(map(str, lastUsableIp.to_bytes(4, "big")))
        network['broadcastAddr'] = ".".join(map(str, broadcastAddr.to_bytes(4, "big")))

        network['usableIP'] = str(totalIP-2)
        network['freeIP'] = str(totalIP-network['ipNeeded']-2)

    networkList = sorted(networkList, key=lambda x:x['id'])

    print("\n\nNetwork Information")
    print("{:<5s} {:<25s} {:<25s} {:<25s} {:<25s}".format('ID', 'Network Name', 'Network Address', 'Subnet Mask', 'Prefix Length'))
    for network in networkList:
        print('{:<5s} {:<25s} {:<25s} {:<25s} {:<25s}'.format(str(network['id']), network['netName'], network['networkAddress'], network['subnetMask'], '/'+str(network['prefix'])))

    print('\nAddress Information')
    print("{:<5s} {:<25s} {:<25s} {:<25s} {:<25s} {:<25s}".format('ID', 'First Usable Addr', 'Last Usable Addr', 'Broadcast Address', 'Usable IPs', 'Free IPs'))
    for network in networkList:
        print("{:<5s} {:<25s} {:<25s} {:<25s} {:<25s} {:<25s}".format(str(network['id']), network['firstUsableIP'], network['lastUsableIP'], network['broadcastAddr'], network['usableIP'], network['freeIP']))
    print("\n\n")

def checkAddressClass():
    ip = input('\nInput IP Address: ')
    if re.search('/', ip):
        return 'Error: Invalid IP Address'
    if errorCheck(ip):
        return 'Error: Invalid IP Address'
    split = ip.split('.')
    nSplit = [int(x) for x in split]
    nSplit = [toBinary(x) for x in nSplit]
    bFirstOct = nSplit[0].replace('0b','')
    bIP =  "".join(map(str, nSplit))


    if re.search("^127\.(([1-9]?\d|[12]\d\d)\.){2}([1-9]?\d|[12]\d\d)$", ip):
        return 'The IP Address ' + ip + ' is a Special Purpose Address. It is a Loopback address with the range of 127.0.0.0'
    elif re.search("^169\.254\.([1-9]?\d|[12]\d\d)\.([1-9]?\d|[12]\d\d)$", ip):
        return 'The IP Address ' + ip + ' is a Special Purpose Address. It is a Link-local address with the range of 169.254.0.0'
    elif re.search("^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])(\.([1-9]?\d|[12]\d\d)){2}$", ip):
        return 'The IP Address ' + ip + ' is a Special Purpose Address. It is a Shared Address Space with the range of 100.64.0.0'
    elif re.search("^(22[4-9]|23\d)(\.([1-9]?\d|[12]\d\d)){3}$", ip):
        return 'The IP Address ' + ip + ' is a Special Purpose Address. It is a Multicast Address with the range of 224.0.0.0'    

    if bFirstOct[0] == '0':
        bSubnetMask = 0b11111111000000000000000000000000

        bitWiseAnd = int(bIP,2) & bSubnetMask
        networkAddress = ".".join(map(str, bitWiseAnd.to_bytes(4, "big")))

        return 'The IP Address ' +  ip + ' is a Class A Address, whose network address is ' + networkAddress + "/8"
    elif bFirstOct[0] == '1' and bFirstOct[1] == '0':
        bSubnetMask = 0b11111111111111110000000000000000

        bitWiseAnd = int(bIP,2) & bSubnetMask
        networkAddress = ".".join(map(str, bitWiseAnd.to_bytes(4, "big")))

        return 'The IP Address ' +  ip + ' is a Class B Address, whose network address is ' + networkAddress + "/16"
    elif bFirstOct[0] == '1' and bFirstOct[1] == '1' and bFirstOct[2] == '0':
        bSubnetMask = 0b11111111111111111111111100000000

        bitWiseAnd = int(bIP,2) & bSubnetMask
        networkAddress = ".".join(map(str, bitWiseAnd.to_bytes(4, "big")))

        return 'The IP Address ' + ip + ' is a Class C Address, whose network address is ' + networkAddress + "/24"
    elif bFirstOct[0] == '1' and bFirstOct[1] == '1' and bFirstOct[2] == '1' and bFirstOct[3] == '0':
        return 'The IP Address ' + ip + ' is a Class D Address, this IP range is used for Multicasting '
    elif bFirstOct[0] == '1' and bFirstOct[1] == '1' and bFirstOct[2] == '1' and bFirstOct[3] == '1':
        return 'The IP Address ' + ip + ' is a Class E Address, this IP range is Experimental Networks'

def checkAddressType():
    ip = input('\nInput IP Address: ')
    if re.search('/', ip):
        pass
    else:
        return '\nError: Invalid IP Address. Missing Prefix Lengths'
    ip = ip.split('/')
    prefix = ip[1]

    if int(prefix) > 32 or int(prefix) < 1:
        return '\nError: Invalid Prefix'

    ip = ip[0]

    if errorCheck(ip):
        return 'Error: Invalid IP Address'

    split = ip.split('.')
    nSplit = [int(x) for x in split]
    nSplit = [toBinary(x) for x in nSplit]
    bIP =  "".join(map(str, nSplit))

    subNetBinary = prefixToSubBin(prefix)
    broadCastSubn = getBroadcast(prefix, bIP)
    bitWiseAnd =  int(bIP,2) &  int(subNetBinary,2)
    networkAddress = ".".join(map(str, bitWiseAnd.to_bytes(4, "big")))

    broadCastAddress = bitWiseAnd | int(broadCastSubn, 2)
    broadCastAddress = ".".join(map(str, broadCastAddress.to_bytes(4,"big")))

    if ip == networkAddress:
        return "The IP Address " + ip + " is a Network Address"
    elif ip == broadCastAddress:
        return 'The IP Address ' + ip + " is a Broadcast Address"
    else:
        return 'The IP Address ' + ip + ' is a Host Address'


while 1:
    print("\nHello there Network Admin!\nIn order to help you, please select any of the following options:\n\n")
    print("[1] Subnet Calculator")
    print("[2] Check Address Class")
    print("[3] Check Address Type")
    print("[4] Exit\n")

    menuItem = input("Input: ")

    if menuItem == '1':
        subnetCalc()
    elif menuItem == '2':
        print(checkAddressClass())
    elif menuItem == '3':
        print(checkAddressType())
    elif menuItem == '4':
        print("\nGood Luck Network Admin!")
        break
    else:
        print("Invalid Input. Please try again...")