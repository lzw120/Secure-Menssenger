Secure-Menssenger
=================

Proposed an architecture for a secure instant messaging system and implemented with Java from Network Security.
This is basically a P2P chat messenger with a client and server.
Basically server takes the responsibility of authorization and veryfication, and client is able to chat through different clients securely encrypted with session key, which is generated from client's private key. The good thing for this mechanism is that server can not decrypt the message and doesn't know what the client is transmitting, it only does the authorization and verfication.
