from platform import system
import os
import utility
from tkinter import *

"""THE IP ADDRESS OF THE SERVER SHOULD BE PASSED HERE"""
IP = "0.0.0.0"

PORT = 7676

global LOGGED_IN
LOGGED_IN = False

if system() == 'Windows'  :
    os.system('cls')
else : 
    os.system('clear')

utility.Splash_win()
# STARTING THE CLIENT UI 
utility.client_ui(IP,PORT)

