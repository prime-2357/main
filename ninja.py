from Crypto.Util.number import *
from Crypto.Cipher import AES
import base64
import os
import sys
from getpass import getpass


def b64e(data):
    e = base64.b64encode(data)
    return e.replace(b'/', b'_').replace(b'+', b'-').replace(b'=', b'$')

def b64d(buf):
    data = buf.replace(b'_', b'/').replace(b'-', b'+').replace(b'$', b'=')
    d = base64.b64decode(data)
    return d

def df_auth(v1, v2, v3):
    n = 158666263322542459443482362561248123622857501450798120624794801826634578101560427431750726306358100611313238302325544575179471973190056165632519361038245205669675460143298663992646560444803891407969154999556025300090872848635962871963645563145818105252922947330825315975660533127134077121762110233414689013764
    B = 109021842291734516764260508265130856086672682679924814230418557897902549421729342368069768744401526572977409683644330081835089521312771673423552477230660454014445493550948356102540630737351304554658688464541557941763623022568983832385310576440609539692887020223090757398519421066964262381427762110232718201665

    c = 25376225495380208779926077044389842532776132803269752236193971019373736739439870814936771150514853503993401492962180193358255493532840364888161310382896522379272369157712928095571695097976575442734082585655689450433806700354795647283394563060943229959683464652917963778011877975681397913995715628741651331289
    iv = long_to_bytes(pow(bytes_to_long(v3), 2) % 249122807602262102664902082843366738827)

    p = (bytes_to_long(v1) * bytes_to_long(v2) * bytes_to_long(v3))
    key = long_to_bytes(p % 334306311472871709307597530923744033186)
    a = pow(p, 7)

    c1 = pow(B, a, n)

    if c1 == c:
        return (key, iv)
    return (None, None)

def e_d_crypt_filename(filename, key, iv, option):
    try:
        if option not in ['e', 'd']:
            return None
        cipher = AES.new(key, AES.MODE_GCM, iv)
        if option == 'e':
            fn = cipher.encrypt(filename.encode())
            b64fn = b64e(fn).decode()
            return b64fn
            
        fn = b64d(filename.encode())
        pt = cipher.decrypt(fn)
        return pt.decode()
    except:
        return None

SCRIPT_FILE_NAME = sys.argv[0].split('\\')[-1]

v1 = getpass('v1: ')
v2 = getpass('v2: ')
v3 = getpass('v3: ')

v1 = v1.encode()
v2 = v2.encode()
v3 = v3.encode()

CHUNK_SIZE = 40960



key, iv = df_auth(v1, v2, v3)

if key is None:
    print('[-] YOU DID NOT PASS THE SECURITY CHECK')
    sys.exit(0)

def encrypt_file(filename):
    encrypted_filename = e_d_crypt_filename(filename, key, iv, 'e')

    try:
        _in = open(filename, 'rb')
        _out = open('./dv/'+encrypted_filename, 'wb')
        cipher = AES.new(key, AES.MODE_GCM, iv)

        n, size = 0, os.path.getsize(filename)
        while n < size:
            buff = _in.read(CHUNK_SIZE)
            ciphertext = cipher.encrypt(buff)
            _out.write(ciphertext)
            n += len(buff)
            print('\r{} %'.format(int(n/size * 100.0)), end='')
            sys.stdout.flush()
        _in.close()
        _out.close()
        return 0
    except Exception as e:
        print(e)
        return -1

def decrypt_file(filename):
    decrypted_filename = e_d_crypt_filename(filename, key, iv, 'd')

    try:
        _in = open('./dv/'+filename, 'rb')
        _out = open('./dv/mirror/'+decrypted_filename, 'wb')
        cipher = AES.new(key, AES.MODE_GCM, iv)

        n, size = 0, os.path.getsize('./dv/'+filename)
        while n < size:
            buff = _in.read(CHUNK_SIZE)
            ciphertext = cipher.decrypt(buff)
            _out.write(ciphertext)
            n += len(buff)
            print('\r{} %'.format(int(n/size * 100.0)), end='')
            sys.stdout.flush()
        _in.close()
        _out.close()
        return 0
    except Exception as e:
        print(e)
        return -1


def decryptor_interface():
    content = os.listdir('./dv')
    menu = []

    idx = 0
    for filename in content:
        if filename == 'mirror':
            continue
        decrypted_filename = e_d_crypt_filename(filename, key, iv, 'd')
        size = os.path.getsize('./dv/'+filename)
        item = [filename, decrypted_filename, size]
        menu.append(item)
        print(f'[{idx}] : {decrypted_filename} - {size} bytes')
        idx+=1


    while True:
        idx = int(input('\n>>> '))
        if idx == -1:
            break
        decrypt_file(menu[idx][0])
        input('\n[PRESS ENTER TO DESTROY THE FILE] ')
        _in = open('./dv/mirror/'+menu[idx][1], 'wb')
        n = 0
        while n < menu[idx][2]:
            _in.write(b'A'*CHUNK_SIZE)
            n += CHUNK_SIZE
        _in.close()


def encryptor_interface():
    content = os.listdir('.')
    menu = []

    idx = 0
    for filename in content:
        if not os.path.isfile(filename) or filename == SCRIPT_FILE_NAME:
            continue
        size = os.path.getsize(filename)
        item = [filename, size]
        menu.append(item)
        print(f'[{idx}]: {filename} - {size} bytes')
        idx+=1

    while True:
        idx = int(input('\n>>> '))
        if idx == -1:
            break
        encrypt_file(menu[idx][0])
        option = input('\n[DESTROY THE ORIGINAL FILE? Y/N] ').lower()
        if option == 'y':
            _in = open(menu[idx][0], 'wb')
            n = 0
            while n < menu[idx][1]:
                _in.write(b'A'*CHUNK_SIZE)
                n += CHUNK_SIZE
            _in.close()


if __name__=='__main__':
    print('\n[****  CRYPTO TOOL BY @1  ****]\n[****  ENTER d FOR DECRYPTION AND e FOR ENCRYPTION  ****]\n')
    option = input('>>> ')
    if option == 'd':
        decryptor_interface()
    elif option == 'e':
        encryptor_interface()
    else:
        print('Invalid option!')
        sys.exit(0)
