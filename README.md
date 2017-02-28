Chat Room
=
Simple C implementation of chat room using TCP/IP sockets (IPv4 and IPv6).

For client you can use telnet, netcat or other similar tool.

## Install

```
$ git clone git@github.com:dragonator/chat-room.git
$ cd chat-room
$ make

```
## Start Server

```
$ ./chat_room
```

## Connect Client 

Using telnet: `$ telnet ...`

Using netcat: `$ netcat ...`

## Chat commands

The following commands are available:

| Command                   | Description                           |
|---------------------------|---------------------------------------|
|.name <nikname>            | Pick nickname. Nicknames can contain only letters, numbers and underscope.  |
|.msg <nickname> <message>  | Send message to other user.           |
|.msg_all <message>         | Send message to all users.            |
|.list                      | Show list of users in the room.       |
|.quit                      |Leave the chat room.                   |
