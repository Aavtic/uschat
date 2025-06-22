from cryptography.fernet import Fernet
import simplejson
import json
import os
import threading
import ast
import time
from tkinter import *
import socket
from PIL import Image, ImageTk


IP = "0.0.0.0"
P_CLIENT_CONNECT = 7676

IP_CLIENT = "0.0.0.0"
PORT_CLIENT = 7676

SUPPLY_LOGS_P = 7878

REG_P = 5454

BROADCAST_P = 7777
BROADCAST_RECV = 8081

MUTUAL_CHAT_P = 6767
MUTUAL_CHAT_SOCK = None

CHAT_LISTENER_PORT = 6666

client_chat_s = None

recv_msg_s_C = None

broadcast_s = dict()

broadcast_s_S = None

PREV_CHAT = []

broadcast_s_C = None

BROADCAST_WINDOW = False

broadcast_msg_list = list()

CHAT_CLIENTS = dict()

CHAT_S = None

SUPPLY_LOGS_DATA_P = 4444

CURR_CHAT_WIN = ""

global to
to = ""

WINDOW = True

global LOGGED_IN
LOGGED_IN = False

global users
users = None

global connections
connections = dict()

USER_LIST_P = 5656

global curr_users_port

curr_users_port = 5555

CHAT = False

global current_users_client
current_users_client = None

global valid_users
valid_users = None

FRIENDS = []


KEY = b'1jDg1F-EUCbJFx3kRQBxt9KjFGmb6FV3K7o95qsRMjI='

def destroy_splash() :
    # destroy the splash screen
    r2.destroy()


def get_current_users() :
    """A function which connects to the server"""
    global current_users_client
    while WINDOW :
        time.sleep(1)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try :
            s.connect((IP, curr_users_port))
        except :
            continue
        current_users_client = s.recv(1024).decode('utf-8')
        current_users_client = eval(str(current_users_client))
        s.close()
def start_thread(thread,args_, daemon_) :
    t1 = threading.Thread(target=thread,args=args_)
    t1.daemon = daemon_
    t1.start()

def give_current_users() :
    global connections
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((IP, curr_users_port))
    s.listen()
    while True : 
        connection_keys = str(connections.keys())
        connection_keys = connection_keys[10:-1]
        conn,_ = s.accept()
        conn.send(connection_keys.encode('utf-8'))



def Splash_win() :
    global r2
    # making a root window 
    r2 = Tk()
    # setting its background in hex code
    r2['bg'] = '#F1F5AB'
    # setting its geometry 
    r2.geometry("750x450+300+100")
    # disabling the title bar of the window
    r2.overrideredirect(True)
    # MAKING A FRAME TO HOLD WIDGETS
    # in this case we make a frame and place an image inside it
    frame = Frame(r2, width=1000, height=400,bg='#f1f5ab')
    frame.place(anchor='center', relx=0.5, rely=0.5)
    img = ImageTk.PhotoImage(Image.open("sources/uschat.png"))
    label = Label(frame, image = img, borderwidth=0, highlightthickness=0 )
    # packing the image inside the frame
    label.pack()
    # after 1.5 seconds close the splash screen
    r2.after(1500, destroy_splash,)
    mainloop()



def add_creds(username, password) : 
    f = open('Serverfiles/credentials/credentials.txt', 'r+')

    creds = f.readlines()[0]
    creds = eval(creds)
    fernet = Fernet(KEY)
    creds = fernet.decrypt(creds).decode()
    print('creds  :', creds)
    creds = eval(creds)
    creds[username] = password
    print('new creds : ', creds)
    f.seek(0)
    f.truncate()
    creds = fernet.encrypt(str(creds).encode())
    f.write(str(creds))
    f.close()
    print('credentials updated')

def reg_S() : #   
    """Server which recieves the names and password from the client and adds it to the credentials.txt file"""
    global REG_P
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((IP, REG_P))
    s.listen()
    while True : 
        conn,_ = s.accept()
        user_pass = conn.recv(1024).decode()
        print('user, pass recieved', user_pass)
        user_pass = eval(user_pass)
        add_creds(username=user_pass['username'], password=user_pass['password'])


def reg_C(username, password) :
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((IP, REG_P)) 
    # making a dictionary to store the username and password and then send it to the server 
    message = dict()
    message['username'] = username
    message['password'] = password
    # we convert the message to string because the send function only takes string as parameters 
    s.send(str(message).encode())
    s.close()

def client_connect(IP,PORT) :
    """ a function which connects to the server and once connected it breaks the loop 
        this function runs till it connects to the server """
    global s
    while WINDOW :
        try :
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((IP, PORT))
            print('Connected to the server !!!')
            break 
        except ConnectionRefusedError: 
            print('failed to find the server...\nSearching...')

def check_online_func_S() :
    global connections
    connections_ = connections
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect()
def log_chat_file(file_path_, message, ) :
    """function which takes the filename and the message to be logged and then appending to the file if the file already exists 
        or if it dosint exists , makes a file and writes message to it"""
    
    try :
        # checking if the file exists
        if os.path.exists(file_path_) :
            # then open the file in appending mode 'a' because we know that since the file exists it should have some chat inside so we should append the message from now 
            f = open(file_path_, 'a')
            f.write("\n" + message)
            f.close()
            n = open(file_path_, 'r')
            msgs = n.readlines()
            # checking if the no of lines in the file is 101 
            if len(msgs) == 101:
                # if it is then , open the file in read and write mode 'r+' and delete the first line in the file
                f = open(file_path_, 'r+')
                lines = f.readlines()
                lines = lines[1:]
                f.seek(0)
                f.truncate()
                f.writelines(lines)
        else :
            # if the file does not exists then make a file with that filename and write the messages to it
            f = open(file_path_, 'a')
            f.write(message)
            f.close()
    except :
            print("Error creating the log files \nExiting...")
            exit(0)

def broadcast_D(message) : 
    pass
        

def logchat(message) :
    message = eval(message)
    # now we sort the names in the message sent by the client ,  the 'to' and 'by' and make a file based on that so that it wont get confused in the future
    names = [message['to'],message['by']] # storing the names in a list
    message_ = message['message'] # storing the message message in the message sent by the client in a variable message_
    log_msg = {} 
    log_msg['name'] = message['by']
    log_msg['message'] = message_ 
    # sorting the names
    names.sort() 
    file_name = names[0] + "_"  + names[1]
    # making the file
    file_path = f"Serverfiles/logs/{file_name}.txt"
    log_chat_file(file_path_=file_path, message=str(log_msg))

def give_chat_name() :
    # making a socket (used for creating server and also connecting to them)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # connecting to the server using the server ip and the desired port
    s.connect((IP, CHAT_LISTENER_PORT))
    # sending the username of the client which is stored in a variable called CURRENT_USER
    s.send(str(CURRENT_USER).encode())
    # saving the socket in a recv_msg_s_C variable for future use
    global recv_msg_s_C
    recv_msg_s_C = s
    # starting a thread which recieves direct messages sent by the server to us
    start_thread(thread=recieve_chat_C, args_=(), daemon_=True)

def recieve_chat_message_S() :
    """Server which accepts names and  connection from the clients and store them in a dictionary
        therefore when 'a' sends a message to 'b' and 'b' is present in the dictionary the server can transfer the message to 'b' """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((IP, CHAT_LISTENER_PORT))
    s.listen()
    while True :
        conn,_ = s.accept()
        name = conn.recv(1024).decode()
        # adding the name and the connectionto a dictionary called CHAT_CLIENTS
        CHAT_CLIENTS[name] = conn

def get_chat_user():
    """Server which recieves messages from the clients which are dictionary in string form
        and then forward the message to the client if he is connected to the"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    global IP, CHAT_S
    s.bind((IP, MUTUAL_CHAT_P))
    s.listen()
    CHAT_S = s
    print('Chat user server started')
    while True :
        conn, _ = s.accept()
        message = conn.recv(1024).decode()
        print('recieved msg from client :', message)
        # messages sent from the client will be in a dictionary form eg : {'by' : 'karis', 'to' : 'john', 'message' : 'hello there'}
        # so we check if the client sent us a dictionary just by looking at the first element of the message recieved by the server 
        # if the first element is '{' then we can say that the message is a dictionary 
        if message[0] == "{"  and len(CHAT_CLIENTS.keys()) > 1 : # checking if the first element of the message is '{' and if the no of clients connected to the server is greater than one
            message_ = eval(message) # using eval to convert the message from string to dictionary
            print(message_)
            # storing the 'to' in the message to a variable 'to'
            to = message_['to'] 
            if message_['to'] in CHAT_CLIENTS:
                # checking if that client is also in the dictionary CHAT_CLIENTS
                # then getting the connection from the CHAT_CLIENTS which we declared earlier
                client = CHAT_CLIENTS[to]
                message_ = str(message_)
                # finally sending the message to the client
                client.send(message_.encode())

        if message[0] == "{" : 
            logchat(message=message)
def get_chats_C(user1, user2) : 
    """Function takes two names and sends it to the server and recieves the chat history between them"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try : 
        s.connect((IP, SUPPLY_LOGS_DATA_P))
    except : 
        print('ERROR in connecting to logs server !')
    # adding a ',' between the both users
    username_list = user1 + "," + user2
    # sending the usernames
    s.send(username_list.encode())
    print('usenames sent...')
    # recieves the chat history in json form
    chat_history = recv_json(conn=s)
    # closing the socket
    s.close()

    return chat_history

def get_logged_data(file) : 
    print('file :', file)
    # opening the perticular history file in reading mode
    f = open(f'Serverfiles/logs/{file}', 'r')
    # declaring a list to store the history 
    his_list = []

    for line in f :
        # looping through each line in history file and appending it to the list
        his_list.append(line)
    his_list = str(his_list)
    return his_list

def get_chat_data(u1, u2):
    # storing a list of all the chat log files in files variable
    files = os.listdir('Serverfiles/logs/')
    # looping through the files
    for file in files : 
        # checking if the user one is persent in the file
        if u1  in str(file) :
            # if it exists then  check if the second user is in the file
            if u2 in str(file) :
                print('chat in file : ',file)
                # so if both of the names are present in the file then we pass that file name to the get_logged_data function which takes the filename as an
                logs = get_logged_data(file=file)
                return logs

def recv_json(conn): 
        data = ""
        while True :
            try :
                data = data + conn.recv(1024).decode()
                return simplejson.loads(data)
            except  ValueError:
                continue

def sendjson(message, conn):
        data = simplejson.dumps(message)
        conn.send(data.encode())


def chat_data_S()  : 
    """Server which is used to send the chat logs between two people
       This server sends the chat logs to the clients in json format  since the chat history can be huge and the normal socket recv wont be able to handle it
       and using json to send the big files is a better option"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((IP, SUPPLY_LOGS_DATA_P))
    s.listen()
    print('Chat history Server started ...')
    while True : 
        conn, _ = s.accept() 
        # recieving the names of the two people which are sent by the client
        # names are sent in the format -> john,karis so that we can just split the message between ',' so that we can get the both names
        usernames = conn.recv(1024).decode()
        usernames = usernames.split(',')
        username1 = usernames[0]
        username2 = usernames[1]
        # the chat history data will be processed in the 'get_chat_data' funcion and will be stored in data variable
        data = get_chat_data(username1, username2)
        # finally sending the output in json format 
        sendjson(message=data, conn=conn)
        
def get_current_logs(user):
    # os.listdir(directory) -> returns a list of all the files and folders present in the specified directory
    # storing the list of all chat log files in a varialbe 'files'
    files  = os.listdir('Serverfiles/logs')
    # declaring an empty list to store all the names of users who had a conversation 
    names = []
    send_names = [] # a list which will hold the list of all the names of the people with whome the user had a conversation
    for i in files : # search through all the files in the list 'file'    
        file_name = os.path.splitext(i)[0]
        # splitting the filenames with '_' so that we get the names of the users eg : filename -> karis_john.txt , names -> karis, john 
        names.append(file_name.split("_"))
    for j in names :
        # looping through all the names 
        if user in j : # checking if the 'user'(variable passed to the function when its called) is in the files
            print("Yes ", user + " is in the logs") 
            # if it exists then deleting the name(self) and appending the other name to 'send_names' list  # because the other name would be the one with whome the user has conversation
            index = j.index(user)
            j.pop(index)
            send_names.append(j[0])
    return send_names
def supply_logs() :
    """ Function which is used to supply a list of user 
        with whome the user had conversation """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((IP,SUPPLY_LOGS_P))
    print('Supply Server started...')
    s.listen()
    while True :
        # accepting a conversation
        conn, _ = s.accept()
        # recieving the user name of the client
        search = conn.recv(1024).decode()
        # function 'get_current_logs' returns a list of all the users 
        # if there is no users then it returns an empty list -> []
        res = get_current_logs(search)
        if res == [] :
            conn.send("no".encode())
        else :
            conn.send(str(res).encode())
def ask_creds(clients, address) :
    # THREAD WHICH RECIEVES THE USER NAME AND PASSWORDS WHICH THE CLIENT ENTERS WHILE LOGGIN IN
    # AND DO THINGS ACCORDINGLY
    global KEY 
    while True :
        # using the 'clients' variable which stores the connection ('conn' variable which was previously created before calling the function)
        # using the 'clients' variable to recieve messages sent to the server
        message = clients.recv(1024).decode("utf-8")
        # since the messages recieved throught the socket are strings we convert it to a dictionary form using the 'ast' library
        creds = ast.literal_eval(message)
        creds = dict(creds)
        # storing the username in the message to a variable 'username' and password in the variable 'password'
        username = creds["username"]
        password = creds["password"]
        # opening the credentials.txt file which contains the usernames and passwords of the current users 
        # we are opening the file in reading mode ('r')
        credentials = open("Serverfiles/credentials/credentials.txt", "r")
        # 'readlines() sotores the lines of a file in a list'
        credentials = credentials.readlines()
        credentials = credentials[0]
        credentials = eval(credentials)
        # making a Fernet object and passing the KEY variable as an argument 
        # we will use the fernet object to decrypt the credentials
        fernet = Fernet(KEY)
        # decrypting the credentials
        credentials = fernet.decrypt(credentials).decode()
        # the credentials are stored in a dictionary form eg > {'john' : '123456Seven'}
        # the credentials will be in a string form so we use the eval function to convert it to a dictionary
        credentials = eval(credentials)
        # using global to access variables which are declared outside the function
        global users
        # storing the credentials dictionary in the users variable so that we can use it afterwards
        users = credentials
        # checking if the username given by the user is in the dictionary of credentials
        if username in credentials.keys() :
            print(username)
            # if it qexists then checking if the corresponding password to that username is the password given by the user 
            if credentials[username] == password :
                # if it is then sending an ok message to the user 
                clients.send("OK".encode("utf-8"))
                global connections
                # and adding the username and the connection to a dictionary
                connections[username] = [clients,address,credentials[username][1],credentials[username][2]]
                print(connections)
                break
            else : 
                # if its not then then sending a message 'AUTH_DECLINED' to the user
                clients.send("AUTH_DECLINED".encode("utf-8"))
        # if the given username is not in the dictionary then sending 'DECLINED' message to the client
        else : 
            clients.send("DECLINED".encode("utf-8"))


def make_creds_T(client,address) :
    # make a thread object which runs 'ask_creds' function and 
    t1 = threading.Thread(target=ask_creds, args=(client,address))
    # starting the thread
    t1.start()

def look_for_clients(list_name) :
    print('Server is up and running [+]')

    # MAKING A SOCKET for clients to connect
    client_sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    # BINDING THE SOCKET WITH THE SERVER'S IP ADDRESS AND PORT
    client_sock.bind((IP, P_CLIENT_CONNECT))
    # SETTING THE SOCKET TO LISTEN FOR CLIENTS AFTERWARDS
    client_sock.listen()
    # starting an infinete loop
    while True :
        # recieving a connection and saving the connection in the 'conn' variable and the ip address in the 'addr' variable
        conn,  addr = client_sock.accept()
        # appending the address (ip address) of the connected client to the list passed to the function
        list_name.append(addr)
        # starting make_creds_T function (a function created just to start a thread)
        # and passing the 'conn' and 'addr' variables to the 
        make_creds_T(conn, addr)
# [('192.168.100.6', 52724)]
def check_for_clients(clients_list) :
    last_elem = ""
    n = 0
    while True : 
        if len(clients_list) == 0: 
            pass
        elif len(clients_list) == 1:
            if n == 0 : 
                print(clients_list)
                print(clients_list[0][0])
                n += 1
                start_thread(give_current_users,(),True)
        elif len(clients_list)  > 1 :
            if clients_list[-1] != last_elem : 
                print(clients_list[-1][0])
                last_elem = clients_list[-1]
        else : 
            pass

def show_chat(message) :
    global CURR_CHAT_WIN
    # function which displays the message recieved to the chat window
    print('by : ', message['by'])    
    print('curr chat win : ', CURR_CHAT_WIN)
    # CURR_CHAT_WIN is a variable which stores the name of the user in the title bar of the chat window it stores an empty string '' when the  user closes the chat window
    if message['by'] == CURR_CHAT_WIN:
        print('user on chat screen! ')
        insert_chat(message=message['message'], mode="e")
    else : 
        print('user is not on chat screen')


def recieve_chat_C() :
    global recv_msg_s_C
    # using the recv_msg_s_C socket that we saved before to recieve messages from the server
    while WINDOW:
        # recieve the message and show the chat in the chat window
        # if the user is not in the chat window then just do nothing
        message = recv_msg_s_C.recv(2048).decode()
        message = eval(message)
        show_chat(message=message)

def send_chat(message, to, by):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((IP, MUTUAL_CHAT_P))
    data = {}
    data['to'] = to
    data['by'] = by
    data['message'] = message 
    message = json.dumps(data)
    message = str(message)
    print("sending message : ", message)
    s.send(message.encode())

def insert_chat(message, mode):
    # message will be added to the screen as a label 
    message = Label(scrollable_frame, text=message,font=('Helvetica', 20), bg="#87ff54")
    message.pack(anchor=mode,pady=3)
    # setting the y view to the bottom of the screen (when we add a chat the screen should automatically go the the bottom)
    canvas.update_idletasks() 
    canvas.yview_moveto(1)

def get_entry(event=None) :
    message_ = entry.get()
    entry.delete(0,END)
    insert_chat(message=message_, mode='w')
    global users, to, CURRENT_USER, CHAT ,PREV_CHAT
    CHAT = True
#    if to not in PREV_CHAT: 
#       PREV_CHAT.append(to)
#       show_friends(add_friend=to, frame=scrollable_frame3)
    send_chat(message_,to,str(CURRENT_USER))

def process_chats(chats_list) :
    # converting chat_list to a list and looping through every individual messages in it
    chats_list = eval(chats_list)
    for chat in chats_list :
        chat = eval(chat)
        print("chat  : ", chat)
        # we check if the one who sent the perticular chat is us then display it on the left side else display it on the right side
        if chat['name'] == CURRENT_USER : 
            print('current user :',  CURRENT_USER)
            insert_chat(message=chat['message'], mode='w')
        elif chat['name'] != CURRENT_USER : 
            print('other user : ', chat['name'])
            insert_chat(message=chat['message'], mode='e')
        else : 
            print('Unknown chat message in dict!,  ', chat)
def configure_scroll_region(e):
    canvas.configure(scrollregion=canvas.bbox('all'))
def onclosing() :
    global CURR_CHAT_WIN, root_c, CHAT, PREV_CHAT, scrollable_frame3
    print('current chat win :', CURR_CHAT_WIN)
    print('prev chat :', PREV_CHAT)
    if (CHAT == True) and (CURR_CHAT_WIN not in PREV_CHAT):
        show_friends(frame=scrollable_frame3, add_friend = to)
        CHAT = False
    else : 
        print('user did not start a conversation...')
    CURR_CHAT_WIN = ""
    print('curr chat win set empty')
    root_c.destroy()
def resize_frame(e):
    canvas.itemconfig(scrollable_window, width=e.width)
def chat_window(client_name, add_chat=[]) :
    """Function which creates a chat window"""
    # it takes client_name as an argument which will be name of the user logged in
    # add_chat is a list which will contain the chat history which will be placed in the chat window screen
    global to
    to = client_name
    global scrollable_frame, entry,canvas,scrollable_window, root_c, CURR_CHAT_WIN
    root_c = Tk()
    root_c.title("   "  + client_name)
    root_c.geometry("710x690+250+3")    
    root_c.resizable(False,False)
    container = Frame(root_c ,  width=700, height=600)
    # 595656
    # d9d5d4
    container.pack(padx=10, expand=1, fill="both")
    # here we use canvas because we want to add a scrollbar later 
    canvas = Canvas(container, bg="#595656")
    scrollable_frame = Frame(canvas, bg="#595656",padx=5)
    scrollable_window = canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")

    scrollable_frame.bind("<Configure>", configure_scroll_region)
    scrollbar = Scrollbar(container, orient="vertical", command=canvas.yview)
    canvas.configure(yscrollcommand=scrollbar.set)
    canvas.update_idletasks()
    canvas.yview_moveto(1.0)

    scrollbar.pack(side="right", fill="y")
    canvas.bind("<Configure>", resize_frame)
    canvas.pack(fill="both", expand=True)
    send_button = Button(root_c, text="Send", fg="#83eaf7", font="lucida 11 bold", bg="#7d7d7d", padx=10,relief="solid", bd=2, command=get_entry)
    send_button.pack(side="right", padx=(0,30), pady=(3,5))
    entry = Entry(root_c, font=("lucida 10 bold",18), width=45,highlightcolor="blue", highlightthickness=1)
    entry.bind('<Return>', get_entry)
    entry.pack(side="bottom", anchor="sw", padx=(11,3), pady=(3,5))
    entry.focus_set()
    # checking if there is add_chat is an empty list
    if add_chat == [] : 
        pass
    # if its not then process the chats to display them on the screen
    else : 
        process_chats(chats_list=add_chat)

    CURR_CHAT_WIN = client_name

    root_c.protocol("WM_DELETE_WINDOW", onclosing)

    root_c.mainloop()
    
    
def send_and_recv_msg(s):
    print('connecting to chat server')
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((IP_CLIENT,MUTUAL_CHAT_P))
def get_chat_users(user) :
    # function which sends the username to the server and recieves a list of users with whome the user had conversation and a message 'no' if he didint have a conversation
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    global SUPPLY_LOGS_P, IP
    while WINDOW :
        try : 
            s.connect((IP, SUPPLY_LOGS_P))
            s.send(str(user).encode())
            # recieve the list of users from the server
            res = s.recv(1024).decode()
            # if the recieved message is 'no' then that means there are no logs for the user
            if res == "no" :
                print("not in the logs")
                break
            else : 
                print('chat logs with : ', res)
                # setting the value of the list friends to the res
                global FRIENDS
                FRIENDS = res
                break
        except : 
            print('error while connecting to the supply server !')


def list_of_users() : 
    user_list = []
    f = open('Serverfiles/credentials/credentials.txt', 'r')
    users = f.readline()
    users = eval(users)
    fernet = Fernet(KEY)
    users = fernet.decrypt(users).decode()
    users = eval(users)
    for name in users.keys() : 
        user_list.append(name)
    send_list = str(user_list)
    return send_list

def give_user_list_S() :
    """Server which would just send the list of all the users in the credentials file"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((IP, USER_LIST_P))
    s.listen()
    while True : 
        conn,_ = s.accept()
        users_list = list_of_users()
        conn.send(users_list.encode())

def search_client(search) :
    global FRIENDS, PREV_CHAT
    print('search : ', search)
    print('current prev chat : ', PREV_CHAT)
    # connecting to the server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((IP, USER_LIST_P))
    # recieving the list of all users
    user_list = s.recv(1024).decode()
    # checking 
    if search in (user_list and PREV_CHAT): # checking if the searched user is in the list of users and if the current logged in user had talked to the user
        print("USER FOUND !")
        print('waiting for chat logs...')
        # getting the chat history between the both users
        history = get_chats_C(search, CURRENT_USER)
        print('got chat logs !')
        print(history)
        s.close()
        chat_window(client_name=search, add_chat=history)
    elif search in user_list :
        print('nope , user is not in friends') 
        s.close()
        chat_window(client_name=search)
    else : 
        print('USER NOT FOUND !!!')

def send_broadcast_msg_S(message) : 
    message = eval(message)
    print('message passed :', message)
    to_list = message['to']
    print('to list msg :', to_list)
    print('tolist :', to_list)
    print(type(to_list))
    message_ = dict()
    message_['by'] = message['by']
    message_['to'] = message['to']
    message_['message'] = message['message']
    print('broadcasted message :', message)
    print('modified message : ', message_)

    for name in to_list : # looping through the names of usernames with whome the client has talked to  
        print(name)
        # checking if the user is present in the users who are connected to the server and if yes then forward them the modified message and if not do nothing 
        if name in broadcast_s.keys(): 
            broadcast_s[name].send(str(message_).encode())
            print('broadcast message sent')
        else : 
            print(f'{name} os not online')

def recv_broadcast_S() :
    """Server which recieves broadcast messages from the client and then sent it over to
         the other clients who should get the broadcast message """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((IP, BROADCAST_RECV))
    s.listen()
    while True : 
        conn,_ = s.accept()
        message = conn.recv(1024).decode()
        print(message)
        send_broadcast_msg_S(message=message)
def get_broadcast_names() : # SERVER WHICH RECIEVES CLIENT NAMES AND STORES THEM 
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((IP, BROADCAST_P))
    s.listen()
    while True : 
        conn,_ = s.accept()
        # the client will sent his username to the server
        message = conn.recv(1024).decode()
        print('broadcast server client : ', message)
        # the server adds the username to a dictionary with its value set to the connection used to communicate with the client(conn)
        broadcast_s[message] = conn

def send_broadcast_msg_C(message) :
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((IP,BROADCAST_RECV))
    s.send(message.encode())
    s.close()

def make_Broadcast_msg_C(message) :
    message_ = dict()
    message_['by'] = CURRENT_USER
    message_['message'] = message
    message_['to'] = PREV_CHAT
    print('message to using prev chat:',PREV_CHAT)
    message_ = str(message_)
    send_broadcast_msg_C(message=message_)
def recv_broadcast_C(conn) :
    # function which recieves broadcast messages and displays it to the screen if the user is on the broadcast window, if not then the message will be saved 
    while WINDOW : 
        global  broadcast_msg_list
        message = conn.recv(1024).decode()
        message = eval(message)
        print(message)
        # extrating the message content from the message forwarded by the server
        message = message['message']
        print('broadcast msg : ', message)
        if BROADCAST_WINDOW == True:
            # display the message
            print('broadcast_win is True')
            # saving the message  
            broadcast_msg_list.append({'message' : message, 'mode' : 'e'})
            insert_chat2(message=message, mode='e')
        else : 
            # saving the message 
            broadcast_msg_list.append({'message' : message, 'mode' : 'e'})
            print('broadcasted msg  :', broadcast_msg_list)

def broadcast_connect_C() :
    # a function used to recieve broadcasts from the server and display them 
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((IP, BROADCAST_P))
    # sends the name of the user to the server
    s.send(CURRENT_USER.encode())
    recv_broadcast_C(s)


def insert_chat2(message, mode, msglist = None) :
    """Function which inserts chat messages to the chat window"""
    if not msglist : # if no message list is supplied then its a fresh broadcast window and insert message to it
        label = Label(scrollable_frame2, text=message,font=('Helvetica', 20), bg="#87ff54")
        label.pack(anchor=mode,pady=3)
        canvas2.update_idletasks() 
        canvas2.yview_moveto(1)
        print('message_broadcasting :', message)
    if msglist: # if message list is supplied then there already must be messages in the broadcast window so we add them 
        # the messages are stored in the list mesglist
        for name in msglist : 
            if name == 'sender' : # if the message is by the sender(other person) 
                label = Label(scrollable_frame2, text=msglist['sender'] ,font=('Helvetica', 20), bg="#87ff54")
                label.pack(anchor='e',pady=3)
                canvas2.update_idletasks() 
                canvas2.yview_moveto(1)
                print('message_broadcasting :', message)
            else : # if the message is by us
                label = Label(scrollable_frame2, text=msglist['sender'] ,font=('Helvetica', 20), bg="#87ff54")
                label.pack(anchor='w',pady=3)
                canvas2.update_idletasks() 
                canvas2.yview_moveto(1)
                print('message_broadcasting :', message)

    
def show_prev_broadcast(msg_list) : 
    for message in msg_list : 
        message_ = message['message']
        mode = message['mode']
        insert_chat2(message=message_, mode=mode)

def get_entry2(event=None) :
    message_ = entry2.get()
    entry2.delete(0,END)
    global broadcast_msg_list
    broadcast_msg_list.append({'message' : message_, 'mode' : 'w'})
    insert_chat2(message=message_, mode='w')
    make_Broadcast_msg_C(message=message_)
def configure_scroll_region2(e):
    canvas2.configure(scrollregion=canvas2.bbox('all'))
def resize_frame2(e):
    canvas2.itemconfig(scrollable_window2, width=e.width)
def onclosing2() : 
    global BROADCAST_WINDOW, root2
    BROADCAST_WINDOW = False
    root2.destroy()
def broadcast_window(prev_c=[]):
    title =  ''
    global PREV_CHAT
    friends  = PREV_CHAT
    for name in friends: 
        title += name + ","
    title = title[0:-1]
    global canvas2, scrollable_window2 , scrollable_frame2, entry2, root2
    # Creating the broadcast window
    root2 = Tk()
    root2.title(title)
    root2.geometry("710x690+250+3")    
    root2.resizable(False,False)
    container2 = Frame(root2)
    # 595656
    # d9d5d4
    container2.pack(padx=10, expand=1, fill="both")
    canvas2 = Canvas(container2, bg="#595656")
    scrollable_frame2 = Frame(canvas2, bg="#595656",padx=5)

    scrollable_window2 = canvas2.create_window((0, 0), window=scrollable_frame2, anchor="nw")

    scrollable_frame2.bind("<Configure>", configure_scroll_region2)

    scrollbar2 = Scrollbar(container2, orient="vertical", command=canvas2.yview)
    canvas2.configure(yscrollcommand=scrollbar2.set)
    canvas2.update_idletasks()
    canvas2.yview_moveto(1.0)

    scrollbar2.pack(side="right", fill="y")
    canvas2.bind("<Configure>", resize_frame2)
    canvas2.pack(fill="both", expand=True)
    send_button = Button(root2, text="Send", fg="#83eaf7", font="lucida 11 bold", bg="#7d7d7d", padx=10,relief="solid", bd=2, command=get_entry2)
    send_button.pack(side="right", padx=(0,30), pady=(3,5), anchor="se")
    entry2 = Entry(root2, font=("lucida 10 bold",18), width=45,highlightcolor="blue", highlightthickness=1)
    entry2.bind('<Return>', get_entry2)
    entry2.pack(side="bottom", anchor="sw", padx=(11,3), pady=(3,5))
    entry2.focus_set()

    global BROADCAST_WINDOW
    BROADCAST_WINDOW = True
    
    root2.protocol("WM_DELETE_WINDOW", onclosing2)
    if prev_c ==  [] : 
        pass
    else : 
        show_prev_broadcast(prev_c)


    root2.mainloop()

def show_friends(friends_=None, frame=None, add_friend=None)  :
    """Function that displays the list of users that we talked on the screen"""
    try : 
        no_label.destroy()
    except :
        pass
    global PREV_CHAT
    if friends_ : # if there are previous chats for the user
        friends = eval(friends_)
        for friend in friends:
            PREV_CHAT.append(friend) 
            # we make a frame for each label 
            frame3 = Frame(frame, bg="#f1f5ab", highlightbackground='black', highlightthickness=1)
            frame3.pack(side="top", fill="x", padx=(1,), pady=2)
            friend_label = Label(frame3, text=friend, font=('Helvetica', 17), fg="#2DED12", bg="#f1f5ab")
            friend_label.pack(side="left", padx=(30, 0))
            #dm_img = PhotoImage('sources/dm.png')
            image = Image.open('sources/dm.png')
            photo = ImageTk.PhotoImage(image=image)
            send_button = Button(frame3,image = photo, command=lambda k = friend : search_client(search=k), borderwidth=0, highlightthickness=0)
            send_button.image=photo
            send_button.pack(side="right", padx=5)

    elif add_friend : 
        PREV_CHAT.append(add_friend)
        if add_friend : 
            frame3 = Frame(frame, bg="#f1f5ab" , highlightbackground='black', highlightthickness=1)
            frame3.pack(side="top", fill="x", padx=(1,), pady=2)
            friend_label = Label(frame3, text=add_friend, font=('Helvetica', 17), fg="#2DED12", bg="#f1f5ab")
            friend_label.pack(side="left", padx=(30, 0))
            image = Image.open('sources/dm.png')
            photo = ImageTk.PhotoImage(image=image)
            send_button = Button(frame3,image=photo, command=lambda k = add_friend : search_client(search=k), borderwidth=0, highlightthickness=0)
            send_button.image=photo
            send_button.pack(side="right", padx=5)
    else : 
        print('error, wrong call of the function')

def configure_scroll_region3(e):
    canvas3.configure(scrollregion=canvas3.bbox('all'))
def resize_frame3(e):
    canvas3.itemconfig(scrollable_window3, width=e.width)

def get_search(self=None) :
    global search_bar
    # getting the search 
    search = search_bar.get()
    search_client(search)
def user_screen(client_root) :
    global canvas3, scrollable_window3, scrollable_frame3, main_frame, root, no_label
    # destroying the elements from the previous window
    main_frame.destroy()
    main_canvas.destroy() 
    login_button.destroy()
    register_button.destroy()
    global CURRENT_USER 
    # labeling the username in the screen 
    curr_user = CURRENT_USER[0].upper() + CURRENT_USER[1:]
    login_message = Label(client_root, text=f"Logged in as {curr_user}",font=('Times 14',30),background="#f1f5ab")
    login_message.place(x=525,y=15)
    string_var = StringVar
    global search_bar
    search_bar = Entry(client_root,font=('Times 14',15),background="#FFFDD0",textvariable=string_var)
    # if the enter button is perssed then run the get_search command
    search_bar.bind('<Return>' , get_search)
    search_bar.place(x=560, y=80)
    image = Image.open('sources/search.png')
    photo = ImageTk.PhotoImage(image=image)        
    search_button = Button(client_root,image=photo,command = get_search, bg="#f1f5ab", borderwidth=0,highlightthickness=0)
    search_button.image = photo
    search_button.place(x=790,y=75)

    # BROADCAST TO ALL SECTION
    global broadcast_msg_list
    broadcast_button = Button(client_root, text='Broadcast to all', fg="#5fed3b", font="lucida 11 bold", bg="#f2ee7e", padx=10,relief="solid", bd=2, command=lambda k=broadcast_msg_list:broadcast_window(k))
    broadcast_button.place(x=620,y=120)



    container = Frame(client_root, bg="#f1f5ab")
    # 595656
    # d9d5d4
    container.place(x=500, y=200, width=400, height=400)
    canvas3 = Canvas(container, bg="#f1f5ab")
    scrollable_frame3 = Frame(canvas3, bg="#f1f5ab",padx = 1)
    scrollable_window3 = canvas3.create_window((0, 0), window=scrollable_frame3, anchor="nw")

    scrollable_frame3.bind("<Configure>", configure_scroll_region3)

    scrollbar3 = Scrollbar(container, orient="vertical", command=canvas3.yview)
    canvas3.configure(yscrollcommand=scrollbar3.set)
    canvas3.update_idletasks()
    canvas3.yview_moveto(1.0)

    scrollbar3.pack(side="right", fill="y")
    canvas3.bind("<Configure>", resize_frame3)
    canvas3.pack(fill="both", expand=True)

    global FRIENDS
    # if there are previous chats for the user then we pass the list of those usernames to the show_friends function to display them to the screen
    print(FRIENDS)
    if FRIENDS == [] :
        print('there are no logs with this user : ', CURRENT_USER) 
        no_label = Label(scrollable_frame3 , text= 'no chats', font=('Helvetica',18), bg="#f1f5ab")
        no_label.pack(pady=(15))
    else  : 
        show_friends(FRIENDS,scrollable_frame3)


def register() : 
    # this function gets the usernames and passwords and then sends it over to the server
    global usernameEntry_R, password_Entry_R,r3
    username = usernameEntry_R.get()
    password = password_Entry_R.get()
    # destroying the register window
    r3.destroy()
    reg_C(username=username, password=password)
    

def client_register() : 
    global r3
    r3 = Toplevel()
    # set the background colour of GUI window
    r3['bg'] = '#f1f5ab'
    r3.geometry("300x200+1000+65")
    r3.resizable(False, False)
    # set the title of GUI window
    r3.title("Sign Up page")
    # create a Form label

    m_frame = Frame(r3, height=120, width=400, bg='#f1f5ab')
    m_frame.pack(fill='both', side='top')

    image = PhotoImage(file='sources/add-user-2.png')
    # create a Form label
    login = Label(m_frame,image = image, bg='#f1f5ab')
    login.pack()

    usernameLabel = Label(r3, text="User Name",font=('Times 14',10),  bg='#f1f5ab').place(x = 20,y = 70)
    username = StringVar()
    global password_Entry_R,usernameEntry_R
    usernameEntry_R = Entry(r3, textvariable=username)
    usernameEntry_R.place(x = 95, y = 70)  
    pass_label = Label(r3, text="Password",font=('Times 14',10), bg='#f1f5ab').place(x = 20,y = 100)
    password_s = StringVar()
    password_Entry_R = Entry(r3, textvariable=password_s, show="*")
    password_Entry_R.place(x = 95, y = 100)
    button_img = PhotoImage(file='sources/signup.png')
    b1 = Button(r3,image = button_img,  bg='#f1f5ab',borderwidth=0, highlightthickness=0, command = register)
    b1.place(x = 120,y = 130)

    r3.mainloop()
def client_login() :
    # The login window 
 
    global r1
    # we user Toplevel() to create the window because it causes problems when we use Tk() within a window made with Tk()
    r1 = Toplevel()
    # set the background colour of GUI window
    r1['bg'] = '#f1f5ab' 
   
    r1.geometry("300x200+1000+65")
    # setting a non resizable window
    r1.resizable(False, False)
    # set the title of GUI window
    r1.title("login page")

    # set the configuration of GUI window
    # making a frame to hold all the widgets (buttons , entrybox for usename and password entry etc)
    m_frame = Frame(r1, height=120, width=400, bg='#f1f5ab')
    m_frame.pack(fill='both')
    image = PhotoImage(file='sources/avatar.png')
    # create a Form label
    login = Label(m_frame,image = image, bg='#f1f5ab')
    login.pack()
    # using label to display text "User Name" on the screen
    usernameLabel = Label(m_frame, text="User Name",font=('Times 14',10),bg='#f1f5ab').place(x = 20,y = 70)
    username = StringVar()
    global password_Entry,usernameEntry
    # making an entry widget for the entry of the username
    usernameEntry = Entry(m_frame, textvariable=username, fg='#218F07')
    usernameEntry.place(x = 95, y = 70)  
    pass_label = Label(m_frame, text="Password",font=('Times 14',10),bg='#f1f5ab').place(x = 20,y =100)
    password_s = StringVar()
    password_Entry = Entry(m_frame, textvariable=password_s, show="*", fg='#218F07')
    password_Entry.place(x = 95, y = 100)
    # loadin the image for the login button
    button_img = PhotoImage(file='sources/login_button.png')
    b1 = Button(m_frame,image =button_img,borderwidth=0, highlightthickness=0, command=client_get_creds)
    b1.pack(side='bottom', pady=(65,0))
    r1.mainloop()

def close() : 
    global WINDOW
    WINDOW = False
    root.destroy()

def client_ui(IP_, PORT_) :
    """TKINTER is a python module which is used for creating gui programs""" 
    global root,heading, login_button, register_button, main_canvas, main_frame
    # creating a root object which holds the control of the window    
    root = Tk()
    # setting the screen height and width to the maximum length of the screen and maximum length of the screen 
    x,y = root.winfo_screenwidth(),root.winfo_screenheight()
    root.geometry(f'{x}x{y}')
    # setting the background color of the program
    root.iconbitmap("")
    root['bg'] = "#f1f5ab"
    # set the title of GUI window
    root.title("Us Chat")
    # Frame an object used in tkinter to hold a widget or a group of widgets
    # widgets are the elements in the screen eg > Lablel(used to label text or images to the screen), Entry > used to make an entry box to input values
    main_frame = Frame(root)
    # packing the frame to the sreen
    main_frame.pack(fill="both", expand=True)
    # making a canvas to hold images of the buttons 
    main_canvas = Canvas(main_frame, bg='#f1f5ab')
    main_canvas.pack(fill='both', expand=True)
    # loading the required images to be displayed on the button
    login_image = PhotoImage(file="sources/login.png")
    register_img = PhotoImage(file="sources/add-user.png")
    # creating the buttons and adding the images to it
    login_button = Button(main_canvas, image=login_image, borderwidth=0, highlightthickness=0,command=client_login)
    login_button.pack(side="top", anchor='e', pady=5, padx=12)
    # Button > a tkinter widget used to make buttons
    register_button = Button(main_canvas, image=register_img, borderwidth=0, highlightthickness=0, command=client_register)
    register_button.pack(side='top', anchor='e',pady=5, padx=25)

    image = PhotoImage(file='sources/uschat.png')
    main_canvas.create_image(650, 95, image=image,anchor='center')
    
    def create_threads(ip, port) :
        # creating and starting a thread which will connect to the server 
        t1 = threading.Thread(target=client_connect,args=(ip,port))
        t1.daemon = True
        t1.start()
        #t2 = threading.Thread(target=check_logged_in)
        #t2.daemon = True
        #t2.start()
        t3 = threading.Thread(target=get_current_users)
        #t3.daemon = True
        t3.start()

    # calling the function and passing the ip and port as parameters which are supplied while calling the function client_ui
    create_threads(IP_, PORT_)
    # root.mainloop() - > used to run the gui window continously
    root.protocol("WM_DELETE_WINDOW", close)
    root.mainloop()

def send_creds(message) :
    # sending the message using the socket that we created to connect to the server previously
    s.send(message.encode("utf-8"))
    # recieving the state (weather the server accepted the credentials or not)
    state = s.recv(2048).decode('utf-8')
    print(state)
    if state ==  "OK" :
        # withdrawing the login screen  
        r1.withdraw()
        # setting a boolean value LOGGED_IN to Trye
        global LOGGED_IN
        LOGGED_IN = True
        # starting the threads which will give the username again to connect to other servers for chating and broadcasting messages
        start_thread(thread=give_chat_name,args_=(), daemon_=True)
        start_thread(thread=broadcast_connect_C, args_=(), daemon_ = True)
        t1 = threading.Thread(target=get_chat_users, args=(CURRENT_USER,),daemon=True)
        t1.start()
        t1.join()
        user_screen(root)
        print("AUTHENTICATION SUCCESS !!!")
        print("current user logged in :" , CURRENT_USER)
    elif state == "AUTH_DECLINED" :
        print("INVALID PASSWORD !!!")
    elif state == "DECLINED" : 
        print("AUTHENTICATION FAILED")
    else  : 
        print("error not valid response")
global CURRENT_USER
CURRENT_USER = ""
def client_get_creds() :
    # FUNCTION WHICH GETS THE TEXT ENTERED IN THE ENTRY BOXES AND THEN SENDS IT OVER TO THE SERVER
    # getting the entry in the usernameEntry and password_Entry using the get() function
    user_name = usernameEntry.get()
    global CURRENT_USER
    CURRENT_USER = user_name
    password = password_Entry.get()
    # dynamically making a dictionary because we want it to be in a string 
    # there is a simpler way to do this but i just used this method
    user_name = f"'{user_name}'"
    password = f"'{password}'"
    message = "{'username' : " +  user_name + ",'password' : " + password  + "}"
    # sending the creds
    send_creds(message)




def recv_message(connection) : 
    message = connection.recv(1024).decode("utf-8")
    creds_recv = message


def minimum_clients(client_list) :
    if len(client_list) > 0  :
        pass