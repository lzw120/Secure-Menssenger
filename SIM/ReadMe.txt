MANUAL for Team6 Secure IM


Installation Instructions:

Preconfiguration: 
2 pairs of RSA keys are needed, one for server and the other for client (we've created them with OpenSSL). Client's private key is encrypted by W'-- a password derived key and store in the file.

2 password derived keys are also needed, we  have written code to generate them:
One of them is W, the other is W'. W is stored in file and W' is used to encrypt client't private key, and the result Y is stored in file.

The real world istuation is that client creats his publice key stored in file and private key, and use password to derive 2 secret key, one stored in file as W, the other used to encrypt private key and store the encrypted private key to file. Then the client gives all these files to server. And server gives its public key to all users.

Here we provided these files we used to test our program, you can generate them by yourself as well using PBEKeyGenerator.class we provided and OpenSSL.

client_public_key.der, client_y.txt, client_w.txt, server_private_key.der	(store in server side)

server_public_key.der 	(store in client side)

client_y.txt contains encrypted private key of client with password 123
client_w.txt files contains password based key created with password 123

We use a CSV file to simulate database which stores all public infomation of clients. We have 2 users in simulation: "aaa" and "bbb". They have same password as 123(not ideal in real world).

Put server folder, recordtable folder, Messages folder and Keys folder in server side.

Put client folder, recordtable folder, Messages folder and Keys folder in client side.



To compile:

We use a third party pludin to help read CSV file. So put opencsv_2.3.jar under recordtable directory

Under each folder directory:
> javac *.java

We also handin our eclipse .project file with the code. You may compile the project with eclipse.



To run the server:

Under server folder directory:
> java Server.class [port]


To run the client:
Under client folder directory:
> java ClientApp.class [server ip] [server port]



Command Instructions:

To Login:
	 Run the client software, and type in your username and passpowrd (case sensitive)


To get the list of user online:
	 Type "list" to get a list of everyone who is online, then press enter


To send message to another user:
	 To send message to another user, the format is: "send [username] [message]"

Note: you must run the "list" command before send or receive any message


To Logout:
	Type "Logout" to logoff and exit the client software

