from pwn import *
import base64 as b64

IV = ['\x00'] * 16
secret = 'CExgdPSuHeBcqnmdPhHfAM7NzkVbnWYh8pn2VOxBP8E='
secret1 = b64.b64decode(secret)[0:16]
secret2 = b64.b64decode(secret)[16:]
p = remote('127.0.0.1',9000)
middle = []
pt = ''

for x in xrange(0,16):
    for y in xrange(0,256):
        p.recvuntil("IV:\n")
        p.sendline(b64.b64encode(''.join(IV))) #send your IV
        p.recvuntil("Data:\n")
        p.sendline(b64.b64encode(secret1)) #send your Data
        # p.sendline(b64.b64encode(secret2)) #send your Data
        res = p.recvuntil("\n")
        # print res
        if 'bad decrypt' in res:
            IV[15-x] = chr(y)
        elif 'Decrpytion Done' in res:
            print 'Decrpytion Done' 
            print IV
            IV[15-x] = chr(ord(IV[15-x]) ^ (x + 1)) #to get the correct middle, just like ---> IV[0] ^ 0x01 = middle[0]
            middle.append(ord(IV[15-x])) #store the correct middle
            print middle
            pt += chr(ord(IV[15-x]) ^ ord('A')) #first plaint text
            # pt += chr(ord(IV[15-x]) ^ ord(secret1[15-x])) #second plaint text
            for z in xrange(0,x + 1):
                IV[15-z] = chr(middle[z] ^ (x + 2)) #generate the next new IV
            break
        else:
            print res
            exit()
        if y == 255:
            print '[!] Something wrong'
            print x + 1
            exit()
p.send("\n")
p.close()
print '[!] Final IV : '
print IV
print '[!] Get middle : ', middle
print '[!] PlaintText is : ' + pt[::-1]

