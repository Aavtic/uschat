# UsChat

A GUI App to chat with your friends on the same network!

## Features
-   Login/Registration setup
-   Direct Messages
-   Group Chats
-   BroadCast Messages
-   Persistant messages (chat history is preserved)
-   Encrypted Traffic
-   Encrypted Messages stored on the server

## Installlation

### Clone this repository

`sh
git clone https://github.com/aavtic/uschat
`

## Setup

### Setting up the server.
To setup the server open the `utility.py` and update the `IP` Global variable to the desired ip you want to host the server.
By default the server listens on the `0.0.0.0` interface, which means it will listen on all interfaces on your machine. This can be quick for a quick start.

### Settting up the client

To setup the client open the `client.py` and `client.pyw` both are same files but we will only use the `client.pyw` file to run the GUI client.
Update the `IP` Global variable to the IP address of the server.
By default this will try to connect to `0.0.0.0` on any interface where the server is running on the server port.

### PORTS

The default port the serve uses for connection is `7676`
Along with some other ports for other sub-services -

#### For transfer of chat history
```SUPPLY_LOGS_P: 7878```

#### For registration and login
```
REG_P = 5454
```
#### For broadcast chatting
```
BROADCAST_P = 7777
BROADCAST_RECV = 8081
```
### For Direct Messages
```
MUTUAL_CHAT_P = 6767
MUTUAL_CHAT_SOCK = None
```

### Client PORT for listening for incomming messages
CHAT_LISTENER_PORT = 6666

If any of the ports are being used by any other services you can easily change them here!