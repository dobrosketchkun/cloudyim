from nacl.public import PrivateKey, Box, PublicKey, SealedBox
from Crypto.Hash import SHA512, SHA256
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import nacl.encoding
import nacl.hash
import base64
import random
import json

def check_key(key):
  '''
  Check if key in base64 or in hex form and return hex
  '''
  try:
    PrivateKey(private_key=bytes.fromhex(key))
    return  key
  except:
    rekey = base64.b64decode(key)
    rekey = bytes(rekey).hex()
    return rekey


def encrypt_aes(data, key):
  key = base64.b64decode(key)
  cipher = AES.new(key, AES.MODE_EAX)
  nonce = cipher.nonce
  ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
  nonce = base64.b64encode(nonce).decode('utf-8')
  ciphertext = base64.b64encode(ciphertext).decode('utf-8')
  tag = base64.b64encode(tag).decode('utf-8')
  return ciphertext, tag, nonce

def decode_and_check_aes(key, ciphertext, tag, nonce):
  key = base64.b64decode(key)
  ciphertext = base64.b64decode(ciphertext)
  tag = base64.b64decode(tag)
  nonce =base64.b64decode(nonce)

  cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
  plaintext = cipher.decrypt(ciphertext).decode('utf-8')
  try:
      cipher.verify(tag)
  except ValueError:
      #print("Key incorrect or message corrupted")
      return 'corrupted'
  return plaintext

def encrypt_sealed_box(message, public_rec):
  message = message.encode('utf-8')
  public_rec = check_key(public_rec)
  public_rec = bytes.fromhex(public_rec)
  public_rec = PublicKey(public_key=public_rec)
  sealed_box = SealedBox(public_rec)
  encrypted = sealed_box.encrypt(message)
  return base64.b64encode(encrypted).decode('utf-8')

def decrypt_sealed_box(encrypted, secret):
  secret = check_key(secret)
  secret = bytes.fromhex(secret)
  secret = PrivateKey(private_key=secret)
  unseal_box = SealedBox(secret)
  encrypted = base64.b64decode(encrypted)
  plaintext = unseal_box.decrypt(encrypted)
  return plaintext.decode('utf-8')


def new_key_pair(etype='base64'):
  secret = PrivateKey.generate()
  public = secret.public_key
  if etype == 'hex':
    return bytes(secret).hex(), bytes(public).hex()
  if etype == 'base64':
    return  base64.b64encode(bytes(secret)).decode('utf-8'), base64.b64encode(bytes(public)).decode('utf-8')



def sha000(password, circles = 1):
	'''
	Some defence from rainbow tables
	'''
	for times in range(circles):
		cond = 1
		counter = 0
		while cond:
			sha256 = str(SHA256.new(password.encode()).hexdigest())
			if sha256[0:4] == '0000':
			#if sha256[0] == '0':
				cond = 0	
				result = sha256 
				
					
			else:
				password = sha256
				counter += 1
		password = result	
	return result

def make_aes_key(password, length):
  password = sha000(password, 5)	
  key =  PBKDF2(password, salt = (str(sha000(password, 2))), dkLen = length, count = 10000)
  return base64.b64encode(key).decode('utf-8')
 

def encrypt_secret_key(password):
    key = make_aes_key(password, 32)
    my_secret, my_public = new_key_pair()
    my_secret_ciphertext, my_secret_tag, my_secret_nonce = encrypt_aes(my_secret, key)
    sec_data = json.dumps([my_secret_ciphertext, my_secret_tag, my_secret_nonce]).encode('utf-8')
    sec_data = base64.b64encode(sec_data).decode('utf-8')
    return sec_data, my_public

def decrypt_secret_key(sec_data, password):
    key = make_aes_key(password, 32)
    sec_data = base64.b64decode(sec_data)
    my_secret_ciphertext, my_secret_tag, my_secret_nonce = json.loads(sec_data)
    my_secret = decode_and_check_aes(key, my_secret_ciphertext, my_secret_tag, my_secret_nonce)
    return my_secret