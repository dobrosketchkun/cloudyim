import json
import yadisk
import os.path
import os
import platform
import datetime
import random
import getpass
import base64

try:
    from config import yatoken, my_secret, my_public
except:
    pass
from utils import clear_screen, get_ya, roster, read_roster, make_message, decode_message
from utils import post_message, get_history, print_history, check_password_input
from cryptoutils import check_key, encrypt_aes, decode_and_check_aes
from cryptoutils import make_aes_key, new_key_pair,  encrypt_secret_key, decrypt_secret_key
from Crypto.Random import get_random_bytes

yes = ['y', 'Y', 'yes', 'Yes']
no = ['n', 'N', 'no', 'No']

if __name__ == '__main__':
    isQuitLoop = False
    while not isQuitLoop:
        clear_screen()
        answer1 = input('Welcome to CloudIM! Do you want to create new config? [y/n] ')

        if answer1 in yes:
            pass1 = check_password_input(first='Please enter a new password:',
                                         second='Please enter the password on more time:',
                                         error='They are different, try again!')
            clear_screen()
            print('Generating new keys, please wait.')
            sec_data, my_public = encrypt_secret_key(pass1)
            clear_screen()
            yatok = check_password_input(first='Please enter your Yandex API token:',
                                         second='Please enter the token on more time:',
                                         error='They are different, try again!')
            clear_screen()
            my_nick_name = input('Please enter your nickname: ')
            data = 'yatoken = "' + yatok + '"\n' + 'my_secret = "' + sec_data +\
                                        '"\n' + 'my_public = "' + my_public + '"\n' +\
                                        'my_nick_name = "' + my_nick_name + '"\n'

            with open('config.py', 'w') as file:
                file.write(data)
            clear_screen()
            print('New config is done!')
            exit()
        elif answer1 in no:
            answer2 = input('Do you want to load existing config? [y/n] ')
            if answer2 in ['y', 'Y', 'yes', 'Yes']:
                isRight = False
                while not isRight:
                    password = getpass.getpass('Please enter your password:')
                    try:
                        from config import my_secret, my_public, yatoken, my_nick_name
                        clear_screen()
                        print('Decrypting data, please wait.')
                        my_secret = decrypt_secret_key(my_secret, password)
                        clear_screen()
                        isRight = True
                        isQuitLoop = True
                    except:
                        clear_screen()
                        print('Wrong password or corrupted config file, try again.')
            elif answer2 in no:
                answer3 = input('Quit? [y/n] ')
                if answer3 in yes:
                    exit()
                else:
                    pass


    isServer = False
    while not isServer:
        clear_screen()
        server = input('Please enter chat room: ')
        y = get_ya(yatoken)
        if not y.exists(server):
            answer4 = input('Chat doesn\'t exist. Create? [y/n] ')
            if answer4 in yes:
                y.mkdir(server)
                isServer = True
            elif answer4 in no:
                pass
        else:
            isServer = True

    clear_screen()
    history = get_history(height=10,
                secret=my_secret,
                server=server)
    history_v = print_history(history)
    print('Chatroom: ' + server + '\n' + history_v + 'Enter: ', end ='')


    isExit = False
    while not isExit:
        key = get_random_bytes(32)
        key = base64.b64encode(key).decode('utf-8')
        current_time = datetime.datetime.now().strftime("%d-%b-%y (%H:%M:%S)") 
        yours = input('')
        if yours == 'exit()':
            isExit = True
        elif yours == 'r':
            history = get_history(height=10,
                        secret=my_secret,
                        server='/'+server)
            history_v = print_history(history)
            clear_screen()
            print('Chatroom: ' + server + '\n' + history_v + 'Enter: ', end ='')
        elif yours == '':
            clear_screen()
            print('Chatroom: ' + server + '\n' + history_v + 'Enter: ', end ='')
        else:
            
            post_message(message=yours,
                         aes_key=key,
                         addressees=read_roster(),
                         secret=my_secret,
                         server='/'+server +'/',
                         nick_name=my_nick_name)
            history = get_history(height=10,
                        secret=my_secret,
                        server='/'+server)
            history_v = print_history(history)
            clear_screen()
            print('Chatroom: ' + server + '\n' + history_v + 'Enter: ', end ='')
