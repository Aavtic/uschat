from platform import system
import os
import utility

"""THE IP ADDRESS OF THE SERVER SHOULD BE PASSED HEREWSSSSS"""
IP = "0.0.0.0"

PORT = 7676

global LOGGED_IN
LOGGED_IN = False

if system() == 'Windows'  :
    os.system('cls')
else : 
    os.system('clear')

# starting the splash screen window
utility.Splash_win()
# STARTING THE CLIENT UI 
utility.client_ui(IP,PORT)