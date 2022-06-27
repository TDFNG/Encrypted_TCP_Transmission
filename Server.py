from threading import Thread

import MyTCP


def rec(con: MyTCP.Client):
    while 1:
        try:
            print('\r对方>' + con.recv().decode() + '\n\n自己>', end='')
        except:
            break


def sen(con: MyTCP.Client):
    while 1:
        try:
            con.send(input('\n自己>').encode())
        except:
            break


while 1:
    print('Connecting...')
    CON = MyTCP.Server(1, '127.0.0.1')
    print('Connected')
    R = Thread(target=rec, args=(CON,))
    S = Thread(target=sen, args=(CON,))
    R.start()
    S.start()
    R.join()
    CON.close()
    print('\n\nConnection Losted,Press Enter to Reconnect', end='')
    S.join()
