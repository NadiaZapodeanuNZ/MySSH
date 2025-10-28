## 🔐 MySSH – Secure Local Client-Server Communication in C

<p style="font-size:14px; color:gray;">
MySSH is a project developed as part of the Computer Networks course at the Faculty of Computer Science "Alexandru Ioan Cuza" University of Iasi.  
The system is based on a client-server architecture, where the client is able to transmit Linux commands to the server.  
The server receives these commands, executes them, and returns the results to the client.
</p>

![TCP Client-Server Diagram](https://www.geeksforgeeks.org/c/tcp-server-client-implementation-in-c/)

---

## 🧩 **Overview**

**MySSH** is a **C-based networking project** that implements a **secure client-server communication system** using:
- **TCP sockets**
- **Multithreading**
- **SSL/TLS encryption (via OpenSSL)**

The project demonstrates how to combine **networking**, **security**, and **concurrent programming** concepts to create a **safe, efficient**, and **functional local communication system**.

---

## ⚙️ **Project Architecture**

The project consists of two main components:
- 🖥️ **Server** – handles connections, authentication, commands, and encryption  
- 💻 **Client** – connects to the server, sends commands, and receives responses  

The communication is established via a **TCP connection** secured by **SSL/TLS**, and the server supports **multiple clients simultaneously** using **threads**.

---

## 🧠 **Authentication System**

User data is stored in a simple text-based database (`users.txt`) with the following structure:

