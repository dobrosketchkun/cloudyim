try:
    from config import yatoken, my_secret, my_public
except:
    pass
from cryptoutils import encrypt_sealed_box, decrypt_sealed_box
from cryptoutils import decode_and_check_aes, encrypt_aes, check_key
from nacl.public import PrivateKey, Box, PublicKey, SealedBox
from operator import itemgetter
import os
import platform
import yadisk
import requests
import base64
import json
import nacl.encoding
import nacl.hash
import random
import getpass

headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) ' 
					  'AppleWebKit/537.11 (KHTML, like Gecko) '
					  'Chrome/23.0.1271.64 Safari/537.11',
		'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
		'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.3',
		'Accept-Encoding': 'none',
		'Accept-Language': 'en-US,en;q=0.8',
		'Connection': 'keep-alive'}



def clear_screen():
    """
    Clears the terminal screen.
    """

    # Clear command as function of OS
    command = "cls" if platform.system().lower()=="windows" else "clear"
    os.system(command)


def get_ya(token):
    return yadisk.YaDisk(token=token)

def roster(public):
    if not os.path.isfile('roster.data'):
        file = open('roster.data', 'w')
        file.close()
    else:
        with open('roster.data', 'r') as file:
            roster_data = file.read()
        roster = roster_data.split('\n')
        #print(roster)
        if public in roster:
            pass
        else:
            roster.append(public)
            if roster[0] == '':
                roster = roster[1:]
                roster_data = '\n'.join(roster)
            else:
                roster_data = '\n'.join(roster)
            #print(roster_data)
            with open('roster.data', 'w') as file:
                file.write(roster_data)

def read_roster():
    with open('roster.data', 'r') as file:
        roster_data = file.read()
    roster = roster_data.split('\n')
    return roster


def make_message(message, aes_key, addressees, secret, nick_name='Anonymous'):
  secret = check_key(secret)
  secret = bytes.fromhex(secret)
  secret = PrivateKey(private_key=secret)
  public = bytes(secret.public_key).hex()
  message = json.dumps([message, nick_name]).encode('utf-8')
  # print('message', message)
  message = base64.b64encode(message).decode('utf-8')
  encrypted_message, tag, nonce = encrypt_aes(message, aes_key)

  aes_data = json.dumps({'aes':[aes_key, tag, nonce]}).encode('utf-8')
  #print('aes_data', aes_data)
  aes_data = base64.b64encode(aes_data).decode('utf-8')

  encrypted_keys = []
  for public_key in addressees:
    encrypted_keys.append(encrypt_sealed_box(aes_data, public_key))
  encrypted_keys.append(encrypt_sealed_box(aes_data, public))
  #print('encrypted_keys', encrypted_keys)
  encoded_encrypted_keys = base64.b64encode(json.dumps({'encrypted_keys':encrypted_keys}).encode('utf-8')).decode('utf-8')

  content = json.loads('{}')
  content['keys'] = encoded_encrypted_keys
  content['data'] = encrypted_message
  content['public'] = public
  return base64.b64encode(json.dumps(content).encode('utf-8')).decode('utf-8')

def decode_message(encrypted, secret):
  encrypted = base64.b64decode(encrypted).decode('utf-8')
  encrypted = json.loads(encrypted)
  keys = encrypted['keys']
  data = encrypted['data']
  public = encrypted['public']
  roster(public)
  decoded_encrypted_keys = base64.b64decode(keys).decode('utf-8')
  decoded_encrypted_keys= json.loads(decoded_encrypted_keys)['encrypted_keys']
  for decoded in decoded_encrypted_keys:
    try:
      aes_data = decrypt_sealed_box(decoded, secret)
      aes_data = base64.b64decode(aes_data).decode('utf-8')
      aes_key, tag, nonce = json.loads(aes_data)['aes']
      # print(aes_key, tag, nonce)
    except nacl.exceptions.CryptoError:
      pass
  # print(base64.b64decode(aes_key))
  try:
      decoded_data = decode_and_check_aes(aes_key.encode('utf-8'),
                                          data.encode('utf-8'),
                                          tag.encode('utf-8'),
                                          nonce.encode('utf-8'))
      decoded_data = base64.b64decode(decoded_data).decode('utf-8')
      decoded_data = json.loads(decoded_data)
      # print('decoded_data', decoded_data)
      message = decoded_data[0]
      nick_name = decoded_data[1]
  except UnboundLocalError:
    message = ''
    nick_name = ''
  return message, nick_name
  

def post_message(message, aes_key, addressees, secret=None, server='/test_chat/', nick_name='Anonymous'):
  y = get_ya(yatoken)
  encoded = make_message(message, aes_key, addressees, secret, nick_name=nick_name)
  hasher = nacl.hash.sha512
  randomer = encoded + ''.join([str(random.random()) for _ in range(100)])
  file_name = hasher(randomer.encode('utf-8'), encoder=nacl.encoding.HexEncoder).decode('utf-8')
  with open(file_name,'w') as file:
    file.write(encoded)
  y.upload(file_name, server + file_name)
  os.remove(file_name)

def get_history(height, secret, server='/test_chat'):
  y = get_ya(yatoken)
  folder_data = y.get_meta(server)
  link_list = []
  for _ in folder_data['embedded']['items']:
    link_list.append((_['file'], _['created']))
  if len(link_list) <= height:
    height = len(link_list)
  link_list.sort(key=itemgetter(1))

  preview = []
  for url, created in link_list[-height:]:
    r = requests.get(url, allow_redirects=True, headers=headers)
    data = base64.b64decode(r.content)
    try:
        decoded, nick_name = decode_message(r.content, secret)
        # name = find_in_roster(roster, decoded[2])
        preview.append((created.strftime("%d-%b-%y (%H:%M:%S)"), #%Y for full view of an year
              nick_name,
              decoded))
    except KeyError:
        pass
  return preview

def print_history(history):
  full = ''
  for line in history:
    row = line[0] + ' :: ' + line[1] + ' --> ' + line[2] + '\n'
    full += row
  return full

def check_password_input(first, second, error):
    isEqual = False
    while not isEqual:
        pass1 = getpass.getpass(first)
        pass2 = getpass.getpass(second)
        if pass1 != pass2:
            clear_screen()
            print(error)
        else:
            clear_screen()
            isEqual = True
    return pass1