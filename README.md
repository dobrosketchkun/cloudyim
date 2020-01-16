# cloudyim
Rudimentary chat with server on cloud drive (Yandex.Disk, Google Drive, etc)

First of all, [create](https://yandex.ru/dev/disk/rest/) Yandex Disk API token.
Then buckle up and run ```cloudyim.py```.

To exit from program type ```exit()``` and hit Enter.
To refresh chat type ```r```  and hit Enter. (Yeah, I know, pre-alpha)

In order to preserve your credentials, backup ```config.py``` (and ```roster.data``` too, if you want to talk to that people)

## TODO:
* Google Drive, Mega.nz, other
* actual UI (maybe in browser)
* usable roster, not this automatic one
* automatic history refreshing


#### requirements
* yadisk
* pynacl
* pycryptodome
