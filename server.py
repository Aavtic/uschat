# importing the file which contains all the functions required for the chat application
import utility
# threading -> a module used for running multiple processes simultaneously
import threading
# module just used for the purpose of identifying the system, in line 9
from platform import system
# python module used for interacting with the os
import os

# the following block of code is used for the identification of the system on which the program is executed
# its used for initialy clearing the screen when the program is executed
# so that we can pass the correct command to the terminal
# checking if the system on which the program is running is Windows
if system() == 'Windows'  :
    # so that we can use the 'cls' command on the command prompt
    os.system('cls')
else : 
    # using the 'clear' command which is mainley used in linux os
    os.system('clear')
# making a list to hold the ip addresses of the clients who establish a connection with the server
clients = []
# making a thread object which when starts runs the 'look_for_clients' function in the utility.py file, whish will run simultaneously , and passing the clients list so that the output will get stored in it
t1 = threading.Thread(target=utility.look_for_clients, args=(clients,))
# starting the thread
t1.start()
# thread which runs the 'supply_logs' function stored in the utility.py file which will supply a list of all user with whome the user who connected had a conversation
t3 = threading.Thread(target=utility.supply_logs, args=())
# setting the thread as a daemon process (daemon process - a process which runs constantly in the background)
t3.daemon = True
# starting the thread
t3.start()
# using a function in utility.py which would start a thread and takes arguments (variables which are passed into a function) which are used to set the thread eg > daemon, args... 
# starting a thread 'recieve_chat_message_S' which listens for connections and the name of the user and add them to a dictionary
utility.start_thread(thread=utility.recieve_chat_message_S, args_=(), daemon_=True)
# starting a thread which would send the chat history to the users who connect and passin the additional informations (more code comments in detail in the function)
utility.start_thread(thread=utility.chat_data_S, args_=(), daemon_=True)
# starting a thread which will give a list of all users who has an account (detailed info in the function)
utility.start_thread(thread=utility.give_user_list_S, args_=(), daemon_=True)
# starting a thread which recieves the direct messages from the users and send it over to the respective recipients
utility.start_thread(thread=utility.get_chat_user,args_=(),daemon_=True)
# starting a thread which recieves the usernames of the connected users and add them to a dictionary (detailed info in the function)
utility.start_thread(thread=utility.get_broadcast_names, args_=(), daemon_=True)
# starting a thread which recieves the broadcasted messages and send it to the respective users with whome the user had conversation
utility.start_thread(thread=utility.recv_broadcast_S, args_=(), daemon_=True)
# starting a thread which which recieves the usernames and passwords of the user who want to be registered to the app and add them to the credentials
utility.start_thread(thread=utility.reg_S, args_=(), daemon_=True)
# thread which sends the list of the users who are currentley connected to the server
t2 = threading.Thread(target = utility.check_for_clients, args=(clients,))
# setting the thread to run in the background 
t2.daemon = True
# starting the thread
t2.start()