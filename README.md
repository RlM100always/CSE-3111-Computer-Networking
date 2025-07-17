# Group Chatting with File Sharing

## Project Overview
This project implements a network-based communication system that enables multiple clients to exchange real-time text messages and share files through a central server. The system is built using Python, leveraging socket programming and threading concepts to achieve a robust client-server architecture capable of concurrent interactions.

## Features
- **Client-Server Architecture**: A centralized server manages all communications and data transfers.
- **Messaging System**: Clients can send and receive text messages in real time.
- **File Sharing**: Clients can upload and download files between each other through the server.
- **Multi-threading**: The server uses threads to handle multiple clients concurrently, ensuring efficient communication.
- **TCP Flow Control**: Implemented by sending file data in manageable chunks and waiting for acknowledgment or time delay before sending the next set of data.


## Problem Domain and Motivations
This project addresses the critical need for real-time multi-user communication and secure file sharing across a network. Key motivations include:
- **Real-time Collaboration**: Essential for remote working and team productivity.
- **Secure File Sharing**: Critical in modern systems to ensure data integrity and privacy.
- **Practical Application**: Provides a hands-on opportunity to apply Python's networking capabilities in a practical and useful application.

## Objectives
- Implement a server capable of handling multiple clients using threading.
- Enable real-time message exchange between clients.
- Facilitate file sharing functionality over the same connection.

## Tools and Technologies
- **Python**: The primary programming language used for both client and server components. Tkinter is used for the client-side GUI.
- **Socket Programming (`socket` module)**: Utilized to establish network communication between devices.
- **Threading (`threading` module)**: Employed to manage multiple clients simultaneously on the server side.

## Screenshots 
<p align="center">
  <!-- Replace with your actual screenshots -->
  <img width="600" src="https://github.com/RlM100always/Hisab/blob/main/groupchat/Screenshot%202025-07-17%20192640.png?raw=true" />
  <img width="600" src="https://github.com/RlM100always/Hisab/blob/main/groupchat/Screenshot%202025-07-17%20192649.png?raw=true" />
  <img width="600" src="https://github.com/RlM100always/Hisab/blob/main/groupchat/Screenshot%202025-07-17%20193038.png?raw=true" />
</p>


## Acknowledgements
- Dr. Ismat Rahman, Associate Professor, Dept. of CSE, DU
- Mr. Palash Roy, Lecturer, Dept. of CSE, DU
- Mr. Jargis Ahmed, Lecturer, Dept. of CSE, DU

