package client;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Timestamp;
import java.util.*;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import Keys.DHKeyGenerator;
import Keys.PBEKeyGenerator;
import Messages.LoginReplyMsg;
import Messages.LoginReqMsg;
import Messages.LoginRequest;
import Messages.TalkingMessage;
import Messages.TalkingReplyFromServer;
import Messages.TalkingRequestOrReplyToClient;
import Messages.TalkingRequestToServer;
import Messages.Verification;
import recordtable.*;

public class ClientApp {
	String user_name;
	String pwd;
	RSAPrivateKey client_private_key;
	RSAPublicKey client_public_key;
	RecordTable record_table;
	InetAddress server_ip;
	int server_port;
	DatagramSocket client_socket;
	private static ServerSocket listen_Socket;
	private static Socket request_socket;
	private static int local_port;

	public ClientApp() {
		try {
			// TODO Auto-generated constructor stub
			// DatagramSocket client_socket = new DatagramSocket(9000);
			record_table = new RecordTable();
			user_name = "aaa";
			pwd = "123";
			// get_user_input();
			server_ip = InetAddress.getByName("localhost");
			server_port = 9999;

			// login("server_public_key.der");

			listen_Socket = new ServerSocket(0);
			local_port = listen_Socket.getLocalPort();

		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private static void invoke(final Socket client) throws IOException {
		new Thread(new Runnable() {
			public void run() {
				// process authenticate request from client
				// communication message
			}

		}).start();
	}

	
	static public void listen_quest() {
		new Thread(new Runnable() {
			public void run() {
				Socket thread_socket = null;
				while (true) {
					try {
						thread_socket = listen_Socket.accept();
						invoke(thread_socket);
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
			}
		}).start();
	}

	
	static public void main(String[] args) {
		ClientApp testclient = new ClientApp();
		testclient.login("server_public_key.der");
	}

	public void get_user_input() {
		System.out.println("Please input your username and password");
		System.out.println("Username:");
		Scanner scanner = new Scanner(System.in);
		user_name = scanner.next();
		System.out.println("password:");
		pwd = scanner.next();
	}

	public int login(String public_key_file) {
		try {

			client_public_key = (RSAPublicKey) read_in_public_keys(record_table
					.get_public_key_path(user_name));

			DatagramSocket client_socket = new DatagramSocket(9000);

			ByteArrayOutputStream byte_output = new ByteArrayOutputStream();
			ObjectOutputStream out = new ObjectOutputStream(byte_output);

			// // 1.
			LoginRequest request = new LoginRequest(user_name);
			// // send login request to server
			out.writeObject(request);
			send_UDP_packet(byte_output.toByteArray(), client_socket,
					server_ip, server_port);
			out.flush();
			// byte_output.reset();
			//
			// // 2.
			// // receive cookie from server
			byte[] receiveDataBuff = new byte[1024];
			DatagramPacket receivedPacket = new DatagramPacket(receiveDataBuff,
					receiveDataBuff.length);
			client_socket.receive(receivedPacket);
			byte[] cookie = new byte[receivedPacket.getLength()];
			for (int i = 0; i < cookie.length; i++) {
				cookie[i] = receiveDataBuff[i];
			}

			// 3.
			// get public key of destination from .KEY file and instantiate
			// public key
			RSAPublicKey server_public_key = (RSAPublicKey) read_in_public_keys(public_key_file);
			// instantiate LoginReqMsg
			LoginReqMsg login = new LoginReqMsg();
			login.setCookie(cookie);
			login.setEncrypted_message(request, server_public_key);
			DHKeyGenerator dh_key_gen = new DHKeyGenerator("DH_p_g");
			// generate g^a mod p
			login.setEncrypted_partial_dh_key(dh_key_gen, pwd);
			// send LoginReqMsg class with Cookie
			byte_output = new ByteArrayOutputStream();
			out = new ObjectOutputStream(byte_output);
			out.writeObject(login);
			send_UDP_packet(byte_output.toByteArray(), client_socket,
					server_ip, server_port);
			out.flush();

			// 4.
			// receive LoginReplyMsg class
			client_socket.receive(receivedPacket);
			byte[] serialized_msg = receivedPacket.getData();
			ByteArrayInputStream byte_input = new ByteArrayInputStream(
					serialized_msg);
			ObjectInputStream in = new ObjectInputStream(byte_input);
			Object msg = in.readObject();
			LoginReplyMsg login_reply = (LoginReplyMsg) msg;
			byte[] gb_mod_p = login_reply.get_partial_DHkey(pwd, "calculateW");
			SecretKey dH_key = dh_key_gen.generate_secret_key(gb_mod_p);
			record_table.add_online_entry("server", server_ip.toString(),
					server_port, dH_key);
			client_private_key = (RSAPrivateKey) login_reply.get_RSA_priv_key(
					pwd, "password", dH_key);
			int challenge = login_reply.get_challenge();

			// 5.
			// send challenge back to server, finish login.
			Verification verification = new Verification();
			verification.set_encrypted_message(client_private_key, dH_key,
					challenge);
			out.flush();
			out.writeObject(verification);
			send_UDP_packet(byte_output.toByteArray(), client_socket,
					server_ip, server_port);

			client_socket.close();

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (GeneralSecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return 0;

	}

	// request to server for to_username's public key
	public TalkingReplyFromServer request_pub_from_server(String to_username,
			SecretKey session_key, DatagramSocket client_socket) {
		try {
			// DatagramSocket client_socket = new DatagramSocket(9000);

			ByteArrayOutputStream byte_output = new ByteArrayOutputStream();
			ObjectOutputStream out = new ObjectOutputStream(byte_output);

			TalkingRequestToServer talk_to_server = new TalkingRequestToServer(
					user_name, to_username);
			TalkingMessage talk = new TalkingMessage();
			talk.setEncrypted_message_session_key(talk_to_server, session_key);

			// send talk to server
			out.flush();
			out.writeObject(talk);
			send_UDP_packet(byte_output.toByteArray(), client_socket,
					server_ip, server_port);

			// receive reply from server and verify HMAC
			byte[] receiveDataBuff = new byte[1024];
			DatagramPacket receivedPacket = new DatagramPacket(receiveDataBuff,
					receiveDataBuff.length);
			client_socket.receive(receivedPacket);
			byte[] serialized_msg = receivedPacket.getData();
			ByteArrayInputStream byte_input = new ByteArrayInputStream(
					serialized_msg);
			ObjectInputStream in = new ObjectInputStream(byte_input);
			Object msg = in.readObject();
			TalkingMessage reply_message = (TalkingMessage) msg;

			// client_socket.close();

			// verify hmac first
			if (!reply_message.verify_HMAC_session_key(session_key)) {
				System.out
						.println("HMAC is not correct, message integrity is corrupted");
				return null;
			}
			// analyze reply
			TalkingReplyFromServer reply = (TalkingReplyFromServer) reply_message
					.get_talking_request_object(session_key);
			return reply;

		} catch (Exception e) {
			// TODO: handle exception
			e.printStackTrace();
		}
		return null;

	}

	public void talking_authenticate(String to_username, SecretKey session_key,
			Timestamp t) {
		try {
			DatagramSocket client_socket = new DatagramSocket(9000);
			ByteArrayOutputStream byte_output = new ByteArrayOutputStream();
			ObjectOutputStream out = new ObjectOutputStream(byte_output);

			TalkingReplyFromServer reply = request_pub_from_server(to_username,
					session_key, client_socket);
			InetAddress dst_addr = InetAddress.getByName(reply.getIpaddress());
			int dst_port = reply.getPort();
			RSAPublicKey dst_public_key = reply.getDest_publickey();

			// go for dst
			DHKeyGenerator dh_key_gen = new DHKeyGenerator("DH_p_g");
			TalkingMessage talk = new TalkingMessage();
			TalkingRequestOrReplyToClient authenticate_to_client = new TalkingRequestOrReplyToClient(
					user_name, to_username, talk.get_partial_DHkey(dh_key_gen),
					client_private_key, t);
			talk.setEncrypted_message_rsa_key(authenticate_to_client,
					dst_public_key);

			// send talk to dst
			out.flush();
			out.writeObject(talk);
			send_UDP_packet(byte_output.toByteArray(), client_socket, dst_addr,
					dst_port);

			// receive reply from client
			byte[] receiveDataBuff = new byte[1024];
			DatagramPacket receivedPacket = new DatagramPacket(receiveDataBuff,
					receiveDataBuff.length);
			client_socket.receive(receivedPacket);
			byte[] serialized_msg = receivedPacket.getData();
			ByteArrayInputStream byte_input = new ByteArrayInputStream(
					serialized_msg);
			ObjectInputStream in = new ObjectInputStream(byte_input);
			Object msg = in.readObject();
			TalkingMessage reply_message = (TalkingMessage) msg;

			// verify hmac
			if (!reply_message.verify_HMAC_rsa_key(client_public_key,
					client_private_key)) {
				System.out.println("Hmac false");
				return;
			}

			TalkingRequestOrReplyToClient client_reply = reply_message
					.get_talking_request_or_reply_object(client_private_key);

			// analyze client_reply

			// to be finished
			// check from, check to, check timestamp = t + 1

			// create session key
			SecretKey client_session_key = dh_key_gen
					.generate_secret_key(client_reply.getPartial_DH());

			// add entry
			record_table.add_online_entry(to_username, dst_addr.toString(),
					dst_port, client_session_key);

			client_socket.close();

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return;
	}

	public int talk_to_client() {

		return 0;
	}

	SecretKey calculate_W_from_pwd() {
		try {
			// issue: duplicate calculation
			// generate W from password and salt
			String salt = "calculateW";
			SecretKey w = PBEKeyGenerator.derive_W(pwd, salt);
			return w;
		} catch (GeneralSecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	SecretKey calculate_W2_from_pwd() {
		try {
			// generate W2 from password and salt
			String salt = "calculateW2";
			SecretKey w = PBEKeyGenerator.derive_W(pwd, salt);
			return w;
		} catch (GeneralSecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	public void receive_request_from_client() {
		try {
			DatagramSocket client_socket = new DatagramSocket(9000);

			// receive reply from client
			byte[] receiveDataBuff = new byte[1024];
			DatagramPacket receivedPacket = new DatagramPacket(receiveDataBuff,
					receiveDataBuff.length);
			client_socket.receive(receivedPacket);
			byte[] serialized_msg = receivedPacket.getData();
			ByteArrayInputStream byte_input = new ByteArrayInputStream(
					serialized_msg);
			ObjectInputStream in = new ObjectInputStream(byte_input);
			Object msg = in.readObject();
			TalkingMessage reply_message = (TalkingMessage) msg;

			// verify hmac
			if (!reply_message.verify_HMAC_rsa_key(client_public_key,
					client_private_key)) {
				System.out.println("Hmac false");
				return;
			}
			TalkingRequestOrReplyToClient client_request = reply_message
					.get_talking_request_or_reply_object(client_private_key);
			String from = client_request.getSource();
			String to = client_request.getDest();
			byte[] ga_mod_p = client_request.getPartial_DH();
			Timestamp timestamp = new Timestamp(client_request.getTimestamp()
					.getTime() + 1);

			DHKeyGenerator dh_key_gen = new DHKeyGenerator("DH_p_g");
			byte[] gb_mod_p = dh_key_gen.generate_gx_modp();
			SecretKey client_client_key = dh_key_gen
					.generate_secret_key(ga_mod_p);

			SecretKey client_server = record_table.get_session_key(server_ip
					.toString());
			TalkingReplyFromServer reply_from_server = request_pub_from_server(
					from, client_server, client_socket);

			// verify some information, like from, to, ip, port
			// ...
			InetAddress from_address = InetAddress.getByName(reply_from_server
					.getIpaddress());
			int from_port = reply_from_server.getPort();

			RSAPublicKey from_public_key = reply_from_server
					.getDest_publickey();

			// send back to client
			TalkingRequestOrReplyToClient client_reply = new TalkingRequestOrReplyToClient(
					to, from, gb_mod_p, client_private_key, timestamp);
			TalkingMessage talk = new TalkingMessage();
			talk.setEncrypted_message_rsa_key(client_reply, from_public_key);

			// add to online entry
			record_table.add_online_entry(from, from_address.toString(),
					from_port, client_client_key);

			ByteArrayOutputStream byte_output = new ByteArrayOutputStream();
			ObjectOutputStream out = new ObjectOutputStream(byte_output);
			out.flush();
			out.writeObject(talk);
			send_UDP_packet(byte_output.toByteArray(), client_socket,
					from_address, from_port);

			client_socket.close();

		} catch (Exception e) {
			// TODO: handle exception
		}
	}

	public void add_chatting_item(String username, InetAddress ip, int port,
			SecretKey session_key) {
		record_table.add_online_entry(username, ip.toString(), port,
				session_key);
	}

	public void remove_chatting_item(InetAddress ip) {
		record_table.delete_user(ip.toString());
	}

	void send_UDP_packet(byte[] sent_bytes, DatagramSocket serverSocket,
			InetAddress ipAddr, int port) throws IOException {
		byte[] sendDataBuff = sent_bytes;
		DatagramPacket sendPacket = new DatagramPacket(sendDataBuff,
				sendDataBuff.length);

		sendPacket.setAddress(ipAddr);
		sendPacket.setPort(port);

		serverSocket.send(sendPacket);
	}

	// read public key from file
	public static Object read_in_public_keys(String keyFile) {
		try {
			File file = new File(keyFile);
			if (!file.exists()) {
				System.out.println(keyFile + " not exists!");
				System.exit(0);
				return null;
			}

			int fileLength = (int) file.length();
			byte[] keyData = new byte[fileLength];
			FileInputStream inFileStream = new FileInputStream(keyFile);
			ByteArrayOutputStream bout = new ByteArrayOutputStream();
			inFileStream.read(keyData);
			bout.write(keyData);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
					bout.toByteArray());
			RSAPublicKey objKey = (RSAPublicKey) keyFactory
					.generatePublic(publicKeySpec);
			return objKey;

		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("Error in read Key" + keyFile);
		return 0;
	}
}