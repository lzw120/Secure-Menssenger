package client;

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Timestamp;
import java.util.*;

import javax.crypto.*;

import Keys.DHKeyGenerator;
import Keys.PBEKeyGenerator;
import Messages.*;
import recordtable.*;

public class ClientApp {
	static String user_name;
	String pwd;
	static RSAPrivateKey client_private_key;
	static RSAPublicKey client_public_key;
	static RSAPublicKey server_public_key;
	static RecordTable record_table;
	static InetAddress server_ip;
	static int server_port;
	// public DatagramSocket client_socket;
	private static ServerSocket listen_Socket;
	public static Socket request_socket;
	public static int local_port;
	Timer timer;

	public ClientApp() throws SocketException {
		try {
			// TODO Auto-generated constructor stub
			// DatagramSocket client_socket = new DatagramSocket(9000);
			listen_Socket = new ServerSocket(0, 4);
			local_port = listen_Socket.getLocalPort();
			record_table = new RecordTable();
			user_name = "aaa";
			pwd = "123";
			get_user_input();
			server_ip = InetAddress.getByName("localhost");
			server_port = 9999;
			client_public_key = (RSAPublicKey) read_in_public_keys(record_table
					.get_public_key_path(user_name));
			server_public_key = (RSAPublicKey) read_in_public_keys(record_table
					.get_public_key_path("server"));

			// set up timer to delete old entry in record_table
			Timer timer = new Timer(true);
			timer.schedule(new OnlineItemTask(record_table, 10), (long) 10,
					(long) 10000);

		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private void invoke(final Socket client) throws IOException {
		new Thread(new Runnable() {
			public void run() {
				ObjectInputStream inputStream;
				try {
					inputStream = new ObjectInputStream(client.getInputStream());
					Object msg_recv = inputStream.readObject();
					Class<? extends Object> class_type = msg_recv.getClass();
					String class_name = class_type.getCanonicalName();
					System.out.println(class_name);
					if (class_name.equals("java.lang.String")) {
						String errorString = (String) msg_recv;
						System.out.println(errorString);
					} else if (class_name.equals("Messages.TalkingMessage")) {
						String dest_ip = client.getInetAddress().toString()
								.replace("/", "");
						TalkingMessage talkingMessage = (TalkingMessage) msg_recv;
						String dest_name = record_table.get_user_name(dest_ip,
								talkingMessage.local_port);

						if (dest_name.equals("")) {
							System.out
									.println("Received unexisting user's message");

							if (talkingMessage.getType() == message_type.Talk_REQ_Client) {
								if (!talkingMessage.verify_HMAC_rsa_key(
										client_public_key, client_private_key)) {
									ObjectOutputStream outstream = new ObjectOutputStream(
											client.getOutputStream());
									outstream.writeObject("hmac failed");
									client.close();
									return;
								}
							} else {
								client.close();
								return;
							}
						}

						else if (!talkingMessage
								.verify_HMAC_session_key(record_table
										.get_session_key(dest_name))) {
							System.out.println("error Hmac for message");
							ObjectOutputStream outstream = new ObjectOutputStream(
									client.getOutputStream());
							outstream.writeObject("hmac failed");
							outstream.flush();
							return;
						}

						// process authenticate request from client
						if (talkingMessage.getType() == message_type.Talk_REQ_Client) {
							receive_request_from_client(talkingMessage, client);
						}
						// communication message
						else if (talkingMessage.getType() == message_type.Talk_Content) {
							// print user name and message
							TalkingContent talkingContent = get_chatting_content(
									talkingMessage, dest_name);

							// verify timestamp here ...
							// if talkingContent.getTimestamp2() ==
							// record_table.online_table.get(dest_name).getLast_update()
							// + 1
							long update_time = talkingContent.getTimestamp();
							if (update_time != record_table.online_table
									.get(dest_name).getLast_update().getTime() + 1) {
								System.out
										.println("received out of ordered message!");
							}
							record_table.online_table.get(dest_name)
									.setLast_update(new Timestamp(update_time));

							System.out.println("User " + dest_name
									+ " sends a message: "
									+ talkingContent.getContent());

						} else if (talkingMessage.getType() == message_type.Logout_Client) {
							// logout_client
							dest_ip = client.getInetAddress().toString()
									.replace("/", "");
							dest_name = record_table.get_user_name(dest_ip,
									talkingMessage.local_port);
							SecretKey key = record_table
									.get_session_key(dest_name);
							if (!talkingMessage.verify_HMAC_session_key(key)) {
								System.out
										.println("Hmac for log out information is not correct!");
								ObjectOutputStream outstream = new ObjectOutputStream(
										client.getOutputStream());
								outstream.writeObject("hmac failed");
							}
							LogoutACK ack = new LogoutACK(dest_name, user_name);
							TalkingMessage tm = new TalkingMessage();
							tm.setEncrypted_message_session_key(ack, key);
							tm.setType(message_type.ACK_Client);
							ObjectOutputStream ops = new ObjectOutputStream(
									client.getOutputStream());
							ops.writeObject(tm);
							remove_chatting_item(dest_name);

						}
						client.close();
					}

				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (ClassNotFoundException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (GeneralSecurityException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

			}

		}).start();
	}

	public void listen_quest() {
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

	static public void main(String[] args) throws Exception {

		ClientApp testclient = new ClientApp();
		testclient.login("localhost");
		// start interactive
		Thread t = new Thread(new InteractiveController(testclient));
		t.start();

		// start listen request
		testclient.listen_quest();
		// testclient.get_user_input();

	}

	public void get_user_input() {
		System.out.println("Please input your username and password");
		System.out.println("Username:");
		Scanner scanner = new Scanner(System.in);
		user_name = scanner.next();
		System.out.println("password:");
		pwd = scanner.next();
	}

	public int login(String serverip) {
		try {
			server_ip = InetAddress.getByName(serverip.replace("/", ""));
			// tcp connect to server
			request_socket = new Socket(server_ip, server_port);

			// ByteArrayOutputStream byte_output = new ByteArrayOutputStream();
			ObjectOutputStream out = new ObjectOutputStream(
					request_socket.getOutputStream());
			// 1.
			LoginRequest request = new LoginRequest();
			// send login request to server
			out.writeObject(request);
			out.flush();
			// send_TCP_packet(byte_output.toByteArray(), request_socket);

			// 2.
			// receive cookie from server
			byte[] receiveDataBuff = new byte[20];
			read_from_TCP_packet(request_socket, receiveDataBuff);
			// DatagramPacket receivedPacket = new
			// DatagramPacket(receiveDataBuff, receiveDataBuff.length);
			// socket.receive(receivedPacket);
			byte[] cookie = new byte[receiveDataBuff.length];
			for (int i = 0; i < cookie.length; i++) {
				cookie[i] = receiveDataBuff[i];
			}

			// 3.
			// instantiate LoginReqMsg
			request.setUser_name(user_name);
			LoginReqMsg login = new LoginReqMsg();
			login.setCookie(cookie);
			login.setEncrypted_message(request, server_public_key);
			DHKeyGenerator dh_key_gen = new DHKeyGenerator("DH_p_g");
			// generate g^a mod p
			login.setEncrypted_partial_dh_key(dh_key_gen, pwd);
			// send LoginReqMsg class with Cookie
			// byte_output = new ByteArrayOutputStream();
			// out = new ObjectOutputStream(byte_output);
			out = new ObjectOutputStream(request_socket.getOutputStream());
			out.writeObject(login);
			out.flush();

			// send_TCP_packet(byte_output.toByteArray(), request_socket);
			// send_UDP_packet(byte_output.toByteArray(), client_socket,
			// server_ip, server_port);
			// out.flush();

			// 4.
			// receive LoginReplyMsg class
			// client_socket.receive(receivedPacket);
			// byte[] serialized_msg = receivedPacket.getData();
			// read_from_TCP_packet(request_socket, receiveDataBuff);

			// byte[] serialized_msg = receiveDataBuff;
			// ByteArrayInputStream byte_input = new ByteArrayInputStream(
			// serialized_msg);
			ObjectInputStream in = new ObjectInputStream(
					request_socket.getInputStream());
			Object msg = in.readObject();

			if (msg.getClass().getCanonicalName().equals("java.lang.String")) {
				String errorString = (String) msg;
				System.out.println(errorString);
				System.exit(0);
			}

			LoginReplyMsg login_reply = (LoginReplyMsg) msg;
			byte[] gb_mod_p = login_reply.get_partial_DHkey(pwd, "calculateW");
			SecretKey dH_key = dh_key_gen.generate_secret_key(gb_mod_p);
			record_table.add_online_entry("server", server_ip.toString(),
					server_port, dH_key);
			client_private_key = (RSAPrivateKey) login_reply.get_RSA_priv_key(
					pwd, "calculateW2", dH_key);
			int challenge = login_reply.get_challenge();

			// 5.
			// send challenge back to server, finish login.
			Verification verification = new Verification();
			verification.set_encrypted_message(client_private_key, dH_key,
					challenge, local_port, user_name);
			// byte_output = new ByteArrayOutputStream();
			// out = new ObjectOutputStream(byte_output);
			out = new ObjectOutputStream(request_socket.getOutputStream());
			out.writeObject(verification);
			out.flush();
			// send_TCP_packet(byte_output.toByteArray(), request_socket);
			// send_UDP_packet(byte_output.toByteArray(), client_socket,
			// server_ip, server_port);
			System.out.println("Login success!");
			request_socket.close();
			// client_socket.close();

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

	static long get_appropriate_timestamp(String usr) {
		long recorded_timestamp = ClientApp.record_table.get_last_update(usr);

		long timestamp;
		if (recorded_timestamp != -1) {
			timestamp = recorded_timestamp + 1;
		} else {
			timestamp = new Date().getTime();
		}
		return timestamp;
	}

	// request to server for to_username's public key
	public static TalkingReplyFromServer request_pub_from_server(
			String to_username, SecretKey session_key, Socket client_socket) {
		try {

			ByteArrayOutputStream byte_output = new ByteArrayOutputStream();
			ObjectOutputStream out = new ObjectOutputStream(byte_output);

			TalkingRequestToServer talk_to_server = new TalkingRequestToServer(
					user_name, to_username);
			TalkingMessage talk = new TalkingMessage();
			talk.local_port = local_port;
			talk.setType(message_type.Talk_REQ_Server);
			talk.setEncrypted_message_session_key(talk_to_server, session_key);

			// send talk to server
			out.writeObject(talk);
			// send_UDP_packet(byte_output.toByteArray(), client_socket,
			// server_ip, server_port);
			send_TCP_packet(byte_output.toByteArray(), client_socket);

			// receive reply from server and verify HMAC
			// byte[] receiveDataBuff = new byte[1024];
			// DatagramPacket receivedPacket = new
			// DatagramPacket(receiveDataBuff,
			// receiveDataBuff.length);
			// client_socket.receive(receivedPacket);
			// byte[] serialized_msg = receivedPacket.getData();
			// ByteArrayInputStream byte_input = new ByteArrayInputStream(
			// serialized_msg);
			// ObjectInputStream in = new ObjectInputStream(byte_input);
			ObjectInputStream in = new ObjectInputStream(
					client_socket.getInputStream());
			Object msg = in.readObject();

			if (msg.getClass().getCanonicalName().equals("java.lang.String")) {
				String errorString = (String) msg;
				System.out.println(errorString);
				return null;
			}

			TalkingMessage reply_message = (TalkingMessage) msg;

			// client_socket.close();

			// verify hmac first
			if (!reply_message.verify_HMAC_session_key(session_key)) {
				ObjectOutputStream outstream = new ObjectOutputStream(
						client_socket.getOutputStream());
				outstream.writeObject("hmac failed");
				outstream.flush();
			}
			// analyze reply
			TalkingReplyFromServer reply = (TalkingReplyFromServer) reply_message
					.get_talking_request_to_server(session_key);
			return reply;

		} catch (Exception e) {
			// TODO: handle exception
			e.printStackTrace();
		}
		return null;

	}

	public int talking_authenticate(String to_username,
			SecretKey server_session_key) {
		try {
			// DatagramSocket client_socket = new DatagramSocket(9000);
			request_socket = new Socket(server_ip, server_port);

			ByteArrayOutputStream byte_output = new ByteArrayOutputStream();
			ObjectOutputStream out = new ObjectOutputStream(byte_output);

			TalkingReplyFromServer reply = request_pub_from_server(to_username,
					server_session_key, request_socket);
			if (reply == null) {
				System.out.println("User not exists!");
				return -1;
			}
			InetAddress dst_addr = InetAddress.getByName(reply.getIpaddress()
					.replace("/", ""));
			int dst_port = reply.getPort();
			RSAPublicKey dst_public_key = reply.getDest_publickey();
			request_socket.close();
			// go for dst
			DHKeyGenerator dh_key_gen = new DHKeyGenerator("DH_p_g");
			TalkingMessage talk = new TalkingMessage();
			talk.setType(message_type.Talk_REQ_Client);
			talk.local_port = local_port;
			long mytimestamp = get_appropriate_timestamp(to_username);
			TalkingRequestOrReplyToClient authenticate_to_client = new TalkingRequestOrReplyToClient(
					user_name, to_username, talk.get_partial_DHkey(dh_key_gen),
					client_private_key, mytimestamp, 0);
			talk.setEncrypted_message_rsa_key(authenticate_to_client,
					dst_public_key);

			request_socket = new Socket(dst_addr, dst_port);
			// send talk to dst
			out = new ObjectOutputStream(request_socket.getOutputStream());
			out.writeObject(talk);
			// send_TCP_packet(byte_output.toByteArray(), request_socket);
			// send_UDP_packet(byte_output.toByteArray(), client_socket,
			// dst_addr, dst_port);

			// receive reply from client
			// byte[] receiveDataBuff = new byte[1024];
			// DatagramPacket receivedPacket = new
			// DatagramPacket(receiveDataBuff,
			// receiveDataBuff.length);
			// client_socket.receive(receivedPacket);
			// byte[] serialized_msg = receivedPacket.getData();
			// ByteArrayInputStream byte_input = new ByteArrayInputStream(
			// serialized_msg);
			// ObjectInputStream in = new ObjectInputStream(byte_input);
			ObjectInputStream in = new ObjectInputStream(
					request_socket.getInputStream());
			Object msg = in.readObject();
			TalkingMessage reply_message = (TalkingMessage) msg;

			// verify hmac
			if (!reply_message.verify_HMAC_rsa_key(client_public_key,
					client_private_key)) {
				System.out.println("Hmac false");
				return -1;
			}

			TalkingRequestOrReplyToClient client_reply = reply_message
					.get_talking_request_or_reply_object(client_private_key);

			// analyze client_reply

			// check from, check to, check timestamp = t + 1
			if (client_reply.getTimestamp2() != mytimestamp + 1) {
				System.out.println("received out of ordered message");
			}

			// create session key
			SecretKey client_session_key = dh_key_gen
					.generate_secret_key(client_reply.getPartial_DH());

			// add entry
			record_table.add_online_entry(to_username, dst_addr.toString(),
					dst_port, client_session_key);
			record_table.online_table.get(to_username).setLast_update(
					new Timestamp(client_reply.getTimestamp2()));
			record_table.online_table.get(to_username).setCreate_date(
					new Timestamp(client_reply.getTimestamp1()));

			request_socket.close();

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return 1;
	}

	/**
	 * @param content_obj
	 * @return ByteArrayOutputStream to be sent contains talking content
	 * @throws IOException
	 */
	// public ByteArrayOutputStream talk_to_client(TalkingContent content_obj,
	// String dest_ip) throws IOException {
	// SecretKey session_key = record_table.get_session_key(dest_ip);
	//
	// TalkingMessage talking_msg = new TalkingMessage();
	// talking_msg.setEncrypted_message_session_key(content_obj, session_key);
	//
	// ByteArrayOutputStream byte_output = new ByteArrayOutputStream();
	// ObjectOutputStream out = new ObjectOutputStream(byte_output);
	// out.writeObject(talking_msg);
	// return byte_output;
	// }

	public TalkingContent get_chatting_content(TalkingMessage talking_msg_obj,
			String user) throws GeneralSecurityException, IOException,
			ClassNotFoundException {
		SecretKey session_key = record_table.get_session_key(user);

		TalkingContent content = talking_msg_obj
				.get_talking_content_object(session_key);
		return content;
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

	public static void receive_request_from_client(
			TalkingMessage msg_from_client, Socket client_socket) {
		try {
			// ObjectInputStream in = new
			// ObjectInputStream(client_socket.getInputStream());
			// TalkingMessage msg = (TalkingMessage) in.readObject();

			TalkingRequestOrReplyToClient client_request = msg_from_client
					.get_talking_request_or_reply_object(client_private_key);
			String from = client_request.getSource();
			String to = client_request.getDest();
			byte[] ga_mod_p = client_request.getPartial_DH();

			// ask for public key from server
			SecretKey client_server = record_table.get_session_key("server");
			request_socket = new Socket(server_ip, server_port);
			TalkingReplyFromServer reply_from_server = request_pub_from_server(
					from, client_server, request_socket);
			request_socket.close();

			InetAddress from_address = InetAddress.getByName(reply_from_server
					.getIpaddress().replace("/", ""));
			int from_port = reply_from_server.getPort();

			RSAPublicKey from_public_key = reply_from_server
					.getDest_publickey();

			// verify signature
			if (!client_request.verify_signature(from_public_key)) {
				System.out.println("Signature in Talking request is invalid");
				return;
			}

			// verify timestamp here
			// ...

			// gennerate g b mod p
			DHKeyGenerator dh_key_gen = new DHKeyGenerator("DH_p_g");
			byte[] gb_mod_p = dh_key_gen.generate_gx_modp();
			SecretKey client_client_key = dh_key_gen
					.generate_secret_key(ga_mod_p);

			// send back to client
			long update_time = get_appropriate_timestamp(from);
			long create_time = client_request.getTimestamp1() + 1;
			// sender fills t1, receiver fills t2
			TalkingRequestOrReplyToClient client_reply = new TalkingRequestOrReplyToClient(
					to, from, gb_mod_p, client_private_key, update_time,
					create_time);
			TalkingMessage talk = new TalkingMessage();

			talk.setEncrypted_message_rsa_key(client_reply, from_public_key);
			talk.setType(message_type.Talk_REP_Client);
			talk.local_port = local_port;
			// long time_stamp = get_appropriate_timestamp(user_name);

			// fill in Hmac
			ByteArrayOutputStream output = new ByteArrayOutputStream();
			ObjectOutputStream out = new ObjectOutputStream(output);
			out.writeObject(talk);
			talk.generate_HMAC_rsa_key(output.toByteArray(), from_public_key);

			// ByteArrayOutputStream byte_output = new ByteArrayOutputStream();
			// ObjectOutputStream out = new ObjectOutputStream(byte_output);
			// out.writeObject(talk);
			// send_UDP_packet(byte_output.toByteArray(), client_socket,
			// from_address, from_port);
			ObjectOutputStream ops = new ObjectOutputStream(
					client_socket.getOutputStream());
			ops.writeObject(talk);

			// add to online entry
			record_table.add_online_entry(from, from_address.toString(),
					from_port, client_client_key);
			record_table.online_table.get(user_name).setLast_update(
					new Timestamp(update_time));
			record_table.online_table.get(user_name).setCreate_date(
					new Timestamp(create_time));
		} catch (Exception e) {
			// TODO: handle exception
		}
	}

	public void add_chatting_item(String username, InetAddress ip, int port,
			SecretKey session_key) {
		record_table.add_online_entry(username, ip.toString(), port,
				session_key);
	}

	public void remove_chatting_item(String usr_name) {
		record_table.delete_user(usr_name);
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

	public static void send_TCP_packet(byte[] sent_bytes, Socket socket)
			throws IOException {
		OutputStream socketOutputStream = socket.getOutputStream();
		socketOutputStream.write(sent_bytes);
	}

	void read_from_TCP_packet(Socket socket, byte[] receive_buffer) {
		try {
			InputStream socketInputStream = socket.getInputStream();
			socketInputStream.read(receive_buffer);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
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