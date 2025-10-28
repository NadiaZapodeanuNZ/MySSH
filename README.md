## 🔐 MySSH – Secure Local Client-Server Communication in C

<p style="font-size:14px; color:gray;">
MySSH is a project developed as part of the Computer Networks course at the Faculty of Computer Science "Alexandru Ioan Cuza" University of Iasi.  
The system is based on a client-server architecture, where the client is able to transmit Linux commands to the server.  
The server receives these commands, executes them, and returns the results to the client.
</p>


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


Where:
- `username` → the user's login name  
- `encrypted_password` → stored as a **SHA256 hash**  
- `status` → `0` if the user is logged out, `1` if logged in  

This lightweight system mimics basic database behavior for user authentication.

---

## 🔒 **SSL/TLS Configuration**

To ensure secure communication, an **SSL context** is configured using **OpenSSL**.  
The server loads a **certificate** and a **private key**, while the client establishes a **secure encrypted session**.

**Main steps:**
1. Initialize SSL context → `SSL_CTX_new()`
2. Load certificates → `SSL_CTX_use_certificate_file()` and `SSL_CTX_use_PrivateKey_file()`
3. Accept or connect with encryption → `SSL_accept()` and `SSL_connect()`

All transmitted data — such as **user credentials**, **commands**, and **results** — is encrypted end-to-end.

---

## 🧵 **Sockets and Multithreading**

The server uses **two types of sockets**:

| Socket Type | Purpose |
|--------------|----------|
| Listening Socket | Waits for new incoming client connections |
| Client Socket | Created per accepted client connection for dedicated communication |

Each client connection is handled in a **separate thread**, ensuring **parallel execution** and **non-blocking communication**.

---

## 🧰 **Implemented Commands**

| Command | Description |
|----------|-------------|
| `register` | Registers a new user |
| `login` | Authenticates an existing user |
| `logout` | Logs out the current user |
| `cd <folder>` | Changes the current directory (if allowed) |
| `pwd` | Displays the current working directory |
| `quit` | Ends the current session |
| Any Linux command | Executed on the server via `popen()`; output is sent back to the client |

---

## 🧮 **Core Technologies**

- 🧠 **C Programming Language**
- 🌐 **TCP/IP Networking**
- 🧵 **Multithreading (pthread)**
- 🔐 **SSL/TLS (OpenSSL)**
- 🧾 **File-based User Storage**
- ⚙️ **System Command Execution (`popen`)**
- 🔁 **SHA256 Hashing**

---

## 🛠️ **Compilation and Execution**

### 🖥️ Compile and run the **Server**
```bash
gcc server.c -o server -lssl -lcrypto -lpthread
./server


### 💻 Compile and run the **Client**
```bash
gcc client.c -o client -lssl -lcrypto
./client
