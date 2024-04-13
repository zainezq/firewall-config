# Firewall Configuration Program

This project consists of a multi-threaded server and a client program written in C to manage firewall configurations. 
The server listens on a specified port and processes requests from clients to add, delete, or check firewall rules. 
The client program allows users to interact with the server and manage firewall rules remotely.

## Features

- **Adding Rules**: Clients can add firewall rules to the server by specifying a valid firewall rule string.
- **Checking Rules**: Users can check whether a given IP address and port are allowed according to the existing rules.
- **Deleting Rules**: Clients can delete valid firewall rules from the server.
- **Listing Rules**: The server can provide a list of all current firewall rules along with the IP addresses and ports associated with each rule.

## Usage

### Server Program

To start the server, run the following command:

```
./server <port>
```

Replace `<port>` with the port number on which you want the server to listen for incoming connections (for example `8080`).

### Client Program

To interact with the server, use the following commands:

- **Adding a Rule**:
  ```
  ./client <serverHost> <serverPort> A <rule>
  ```

- **Checking a Rule**:
  ```
  ./client <serverHost> <serverPort> C <IPAddress> <port>
  ```

- **Deleting a Rule**:
  ```
  ./client <serverHost> <serverPort> D <rule>
  ```

- **Listing Rules**:
  ```
  ./client <serverHost> <serverPort> L
  ```

Replace `<serverHost>` with the hostname of the server and `<serverPort>` with the port number on which the server is listening.

### Rule Specification

A firewall rule has the following format:

```
<IPAddresses> <ports>
```

- `<IPAddresses>` can be a single IP address (e.g., `147.188.192.41`) or a range of IP addresses (e.g., `147.188.193.0-147.188.194.255`).
- `<ports>` can be a single port number (e.g., `443`) or a range of ports (e.g., `21-22`).

## Credits

