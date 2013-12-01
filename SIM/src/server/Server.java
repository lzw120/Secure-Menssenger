package server;

import java.io.*;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.SecretKey;

import client.ClientApp;

import Keys.DHKeyGenerator;
import Keys.PBEKeyGenerator;
import Messages.LoginReplyMsg;
import Messages.LoginReqMsg;
import Messages.LoginRequest;
import Messages.LogoutACK;
import Messages.LogoutRequest;
import Messages.TalkingContent;
import Messages.TalkingMessage;
import Messages.TalkingReplyFromServer;
import Messages.TalkingRequestToServer;
import Messages.Verification;
import Messages.message_type;

import recordtable.RecordTable;

public class Server {
	static String public_key_path;
	static String private_key_path;
	static RSAPublicKey server_public_key;
	static RSAPrivateKey server_private_key;
	// List<OnlineClientItem> online_clients;
	static String hash_algorithm = "SHA1";
	static RecordTable record_table;
	static int challenge = 0;
	private static ServerSocket serverSocket;

	// initialize server, public key and private key, and record table
	public Server(int port) throws IOException {

		serverSocket = new ServerSocket(port, 20);
		// initialize record table
		record_table = new RecordTable();

		// initialize public key and private key of server
		server_private_key = (RSAPrivateKey) read_in_private_keys(record_table
				.get_private_key_path("server"));
		server_public_key = (RSAPublicKey) read_in_public_keys(record_table
				.get_public_key_path("server"));
	}

	public static void main(String[] args) {
		try {
			int serverport = Integer.parseInt(args[0]);
			Server server = new Server(serverport);
			System.out.println("Server Start...");
			// service();
			while (true) {
				Socket socket = null;
				try {
					System.out.println("listeining on port " + args[0]);
					socket = serverSocket.accept();
					System.out.println("a request from " + socket.getInetAddress().toString() + " comes");
					invoke(socket);
				} catch (IOException e) {
					e.printStackTrace();
				} finally {
					// try {
					// if (socket != null)
					// socket.close();
					// } catch (IOException e) {
					// e.printStackTrace();
					// }
				}
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private static void invoke(final Socket socket) throws IOException {
		new Thread(new Runnable() {
			public void run() {

				Object msg_recv = null;
				try {
					ObjectInputStream in = new ObjectInputStream(socket
							.getInputStream());
					msg_recv = in.readObject();

				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (ClassNotFoundException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

				Class<? extends Object> class_type = msg_recv.getClass();
				String class_name = class_type.getCanonicalName();
				System.out.println(class_name);

				try {
					if (class_name.equals("java.lang.String")) {
							String string = (String) msg_recv;
							System.out.println(string);
							return;
					}
					else if (class_name.equals("Messages.LoginRequest")) {
						login(socket);
					} 
					else if (class_name.equals("Messages.TalkingMessage")) {
						InetAddress ipAddr = socket.getInetAddress();
						TalkingMessage t = (TalkingMessage) msg_recv;
						SecretKey session_key = record_table
								.get_session_key(record_table.get_user_name(socket.getInetAddress().toString(), t.local_port));
						// verify first, if not correct just skip
						if (!t.verify_HMAC_session_key(session_key)) {
							System.out.println("Verification hmac failed");
							OutputStream out = socket.getOutputStream();
							out.write("hmac failed".getBytes());
							return;
						}
						
						if (t.getType() == message_type.Talk_REQ_Server) {
							recv_talking_req_to_server(socket, t);
						}
						else if (t.getType() == message_type.Logout_Server) {
							logout_client(socket,
									t.get_logout_request(session_key),
									session_key);
						} else if (t.getType() == message_type.Talk_Content) {
							// might be list command
							TalkingContent content_obj = t
									.get_talking_content_object(session_key);
							String text = content_obj.getContent();
							if (text.equals("list"))
								send_list(socket, content_obj, session_key, t.local_port);

						}
					}
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (GeneralSecurityException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (ClassNotFoundException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} finally {
					try {
						socket.close();
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}

			}

		}).start();
	}

	// read public key from file
	public static Object read_in_public_keys(String keyFile) {
		try {
			File file = new File(keyFile);
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
//			e.printStackTrace();
			return null;
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

	// read private key from file
	public static Object read_in_private_keys(String keyFile) {
		try {
			File file = new File(keyFile);
			int fileLength = (int) file.length();
			byte[] keyData = new byte[fileLength];
			FileInputStream inFileStream = new FileInputStream(keyFile);
			ByteArrayOutputStream bout = new ByteArrayOutputStream();
			inFileStream.read(keyData);
			bout.write(keyData);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			KeySpec privateKeySpec = new PKCS8EncodedKeySpec(bout.toByteArray());
			RSAPrivateKey objKey = (RSAPrivateKey) keyFactory
					.generatePrivate(privateKeySpec);
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

	static void login(Socket socket) throws IOException,
			GeneralSecurityException {
		InetAddress ipAddr = socket.getInetAddress();
		// int port=receivedPacket.getPort();

		try {
			// 1. create a cookie and send it back to client
			byte[] cookie = create_cookie(ipAddr.getHostAddress(),
					server_private_key);
			OutputStream output = socket.getOutputStream();
			output.write(cookie);
			output.flush();

			// 2. receive LoginReqMsg
			System.out.println("Receive LoginReqMsg");
			ObjectInputStream in = new ObjectInputStream(
					socket.getInputStream());
			
			Object object = in.readObject();
			if (object.getClass().getCanonicalName().equals("java.lang.String")) {
				String string = (String) object;
				System.out.println(string);
				System.exit(0);
			}
			
			LoginReqMsg login_req_msg = (LoginReqMsg) object;
			
			LoginRequest deserialized_request = login_req_msg
					.getLogin_request_object(server_private_key);

			String user_name = deserialized_request.user_name;

			byte[] returned_cookie = login_req_msg.getCookie();
			if (!Arrays.equals(returned_cookie, cookie)) {
				System.out.println("get unexpected cookie back");
				return;
			}

			// generate the other part of DH key
			System.out.println("Generate g b mod p");
			DHKeyGenerator dh_key_gen = new DHKeyGenerator("DH_p_g");
			byte[] gb_mod_p = dh_key_gen.generate_gx_modp();

			SecretKey w = getW_by_name(user_name);
			// generate DH secret key
			byte[] ga_mod_p = login_req_msg.getPartial_dh_key(w);
			SecretKey dh_key = dh_key_gen.generate_secret_key(ga_mod_p);

			byte[] y = getY_by_name(user_name);

			// 3. create LoginReplyMsg and sent it back to client
			LoginReplyMsg login_reply = new LoginReplyMsg();
			login_reply.set_encryptedY(y, dh_key);
			login_reply.set_encrypted_partial_key(gb_mod_p, w);

			// set challenge using secure random generator
			SecureRandom srg = SecureRandom.getInstance("SHA1PRNG");
			challenge = srg.nextInt();
			login_reply.set_challenge(challenge);

			// deserialize LoginReplyMsg and sent out
			ObjectOutputStream out = new ObjectOutputStream(
					socket.getOutputStream());
			System.out.println("Send LoginReplyMsg");
			out.writeObject(login_reply);
			out.flush();

			// 4. receive Verification
			in = new ObjectInputStream(socket.getInputStream());
			System.out.println("Receive Verification");
			Verification verification_obj = (Verification) in.readObject();
			// get client's public key and verify the signature
			RSAPublicKey public_key = (RSAPublicKey) read_in_public_keys(record_table
					.get_public_key_path(user_name));
			if (!verification_obj.Verify(public_key, dh_key, challenge))
				return;
			int port = verification_obj.get_verified_port(dh_key);

			// 5. store online client item in memory
			if (record_table.online_table.containsKey(user_name)) {
				record_table.online_table.remove(user_name);
			}
			record_table.add_online_entry(user_name, ipAddr.toString(), port,
					dh_key);
			System.out.println("user " + user_name + " get verified");

		}
		catch (BadPaddingException e) {
			// TODO: handle exception
			ObjectOutputStream outstream = new ObjectOutputStream(socket.getOutputStream());
			outstream.writeObject("password incorrect");
		}
		catch (Exception e) {
			e.printStackTrace();
		}

	}

	static void recv_talking_req_to_server(Socket socket, Object msg_recv)
			throws GeneralSecurityException, IOException,
			ClassNotFoundException {
		System.out.println("Messages.TalkingRequestToServer");
		InetAddress ipAddr = socket.getInetAddress();
		TalkingMessage t = (TalkingMessage) msg_recv;
		String user_name = record_table.get_user_name(ipAddr.toString(), t.local_port);

		SecretKey session_key = record_table.get_session_key(user_name);

		// verify HMAC first, if not correct just skip
		if (!t.verify_HMAC_session_key(session_key)) {
			System.out.println("Verification hmac failed");
			ObjectOutputStream outstream = new ObjectOutputStream(socket.getOutputStream());
			outstream.writeObject("hmac failed");
			outstream.flush();
			return;

		}

		TalkingRequestToServer talk_to_server = (TalkingRequestToServer) t
				.get_talking_request_to_server(session_key);
		String deString = talk_to_server.getDest();
		boolean online_state = record_table.online_table.containsKey(deString);
		if (!online_state) {
			System.out.println("user not exist");
			ObjectOutputStream objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
			objectOutputStream.writeObject("user not exist");	
		}
		String filepathString = record_table.get_public_key_path(deString);
		
		RSAPublicKey target_public_key = (RSAPublicKey) read_in_public_keys(filepathString);
		String dest_ip = record_table.get_ip_from_user(talk_to_server.getDest());
		int dest_port = record_table.get_port_from_user(talk_to_server.getDest());

		// create TalkingReplyFromServer
		TalkingReplyFromServer reply = new TalkingReplyFromServer(
				talk_to_server.getDest(), dest_ip, dest_port, target_public_key);

		// create TalkingMessage and set HMAC
		TalkingMessage talking_msg = new TalkingMessage();
		talking_msg.setType(message_type.Talk_REP_Server);
		
		talking_msg.setEncrypted_message_session_key(reply, session_key);

		ByteArrayOutputStream output = new ByteArrayOutputStream();
		ObjectOutputStream out = new ObjectOutputStream(output);
		out.writeObject(talking_msg);
		talking_msg.generate_HMAC_session_key(output.toByteArray(), session_key);
		
		// send TalkingReplyFromServer to client
		ObjectOutputStream out2 = new ObjectOutputStream(
				socket.getOutputStream());
		out2.writeObject(talking_msg);
		out2.flush();
		System.out.println("send out talking reply message");
	}

	static long get_appropriate_timestamp(String usr)
	{
		long recorded_timestamp = record_table.get_last_update(usr);
		
		long timestamp;
		if(recorded_timestamp != -1)
		{
			timestamp = recorded_timestamp + 1;
		}
		else
		{
			timestamp = new Date().getTime();
		}
		return timestamp;
	}
	
	static void logout_client(Socket socket, LogoutRequest logout_req,
			SecretKey session_key) throws IOException {
		String usr_name = logout_req.getIniciator();
		long timestamp = logout_req.getTimestamp();
		long last_timestamp = record_table.get_last_update(usr_name);
		if (last_timestamp != -1) {
			if (last_timestamp + 1 != timestamp) {
				System.out.println("Get out of order LogoutRequest");
				return;
			}
		}

		timestamp++;

		LogoutACK logout_ack = new LogoutACK(usr_name, "server");
		logout_ack.setTimestamp(timestamp);

		TalkingMessage logout_msg = new TalkingMessage();
		logout_msg.setType(message_type.ACK_Server);
		logout_msg.setEncrypted_message_session_key(logout_ack, session_key);
		ByteArrayOutputStream output = new ByteArrayOutputStream();
		ObjectOutputStream out = new ObjectOutputStream(output);
		out.writeObject(logout_msg);
		logout_msg.generate_HMAC_session_key(output.toByteArray(), session_key);

		ObjectOutputStream obj_out = new ObjectOutputStream(
				socket.getOutputStream());
		System.out.println("Send Logout ACK");
		obj_out.writeObject(logout_msg);

		System.out.println("Delete from online clients.");
		record_table.delete_user(usr_name);

	}

	static void send_list(Socket socket, TalkingContent content_obj,
			SecretKey session_key, int local_port) throws IOException {
		long timestamp = content_obj.getTimestamp();
		InetAddress ip = socket.getInetAddress();
		String user = record_table.get_user_name(ip.toString(), local_port);

		// verify timestamp
		long last_timestamp = record_table.get_last_update(user);
		if (last_timestamp != -1) {
			if (last_timestamp + 1 != timestamp) {
				System.out.println("Get out of order TalkingMessage");
				return;
			}
		}
		record_table.online_table.get(user).setLast_update(
				new Timestamp(++timestamp));

		// Concatenate user names
		ArrayList<String> online_users = record_table.get_online_users();
		
		TalkingContent content = new TalkingContent(
				concatenate_online_user_names(online_users), timestamp);
		TalkingMessage message = new TalkingMessage();
		message.setEncrypted_message_session_key(content, session_key);
		message.setType(message_type.Talk_Content);

		// compute Hmac
		ByteArrayOutputStream output = new ByteArrayOutputStream();
		ObjectOutputStream out = new ObjectOutputStream(output);
		out.writeObject(message);
		message.generate_HMAC_session_key(output.toByteArray(), session_key);

		// send TalkingMessage
		ObjectOutputStream obj_out = new ObjectOutputStream(
				socket.getOutputStream());
		System.out.println("Send out on line list");
		obj_out.writeObject(message);
	}

	static String concatenate_online_user_names(ArrayList<String> users) {
		String online_names = "";
		for (String user : users) {
			online_names = online_names + " " + user;
		}
		return online_names;
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

	// public RSAPublicKey get_public_key()
	// {
	//
	// }
	//
	// public RSAPrivateKey get_private_key()
	// {
	//
	// }

	public void add_online_user() {

	}

	public void get_online_users() {
		ArrayList<String> online_listArrayList = record_table
				.get_online_users();
		for (int i = 0; i < online_listArrayList.size(); i++) {
			System.out.println(online_listArrayList.get(i));
		}
	}

	public void remove_online_user() {

	}

	// generate a cookie made from Hash(ip, Server's private key)
	static byte[] create_cookie(String ip_address, PrivateKey server_priv_key) {
		try {
			MessageDigest message_digest = MessageDigest
					.getInstance(hash_algorithm);
			message_digest.update(ip_address.getBytes());

			message_digest.update(server_priv_key.getEncoded());
			byte[] md = message_digest.digest();
			return md;
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
	}

	static private byte[] readBytesFromFile(String fileName) throws IOException {
		File f = new File(fileName);
		FileInputStream infile = new FileInputStream(f);
		byte[] bytes = new byte[(int) f.length()];
		try {
			infile.read(bytes);
			return bytes;
		} finally {
			infile.close();
		}
	}

	//
	static SecretKey getW_by_name(String usr_name) {
		String file_name = record_table.get_password_path(usr_name);
		SecretKey w = null;
		try {
			w = PBEKeyGenerator.read_W_from_file(file_name);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return w;

	}

	static byte[] getY_by_name(String usr_name) {
		return record_table.get_private_key(usr_name);
	}
}