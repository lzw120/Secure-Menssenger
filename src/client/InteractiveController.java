package client;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.sql.Timestamp;
import java.util.Date;

import javax.crypto.SecretKey;

import Messages.LogoutACK;
import Messages.LogoutRequest;
import Messages.TalkingContent;
import Messages.TalkingMessage;
import Messages.message_type;

class InteractiveController implements Runnable
{
	ClientApp client;
	boolean stop;
	
	public InteractiveController(ClientApp client)
	{
		this.client =  client;
		this.stop = false;
	}
	
	public void run() {
		try {

			while (!stop) {
				BufferedReader input = new BufferedReader(
						new InputStreamReader(System.in));
				String sendMsg = input.readLine();
				sendMsg = sendMsg.trim();

				if (sendMsg.equals("list")) {
					// set list message
					SecretKey server_session = client.record_table.get_session_key("server");
					
					long timestamp = get_appropriate_timestamp("server");
					
					ClientApp.record_table.online_table.get("server").setLast_update(new Timestamp(timestamp));
					
					TalkingContent content_obj = new TalkingContent("list", timestamp);
					TalkingMessage talking_msg = new TalkingMessage();
					talking_msg.local_port = client.local_port;
					talking_msg.setType(message_type.Talk_Content);
					talking_msg.setEncrypted_message_session_key(content_obj,
							server_session);

					ByteArrayOutputStream output = new ByteArrayOutputStream();
					ObjectOutputStream out = new ObjectOutputStream(output);
					out.writeObject(talking_msg);
					talking_msg.generate_HMAC_session_key(output.toByteArray(), server_session);
					
					
					// serialize and send out
					ByteArrayOutputStream byte_output = new ByteArrayOutputStream();
					ObjectOutputStream out2;
					out2 = new ObjectOutputStream(byte_output);
					out2.writeObject(talking_msg);
					ClientApp.request_socket = new Socket(client.server_ip, client.server_port);
					ClientApp.send_TCP_packet(byte_output.toByteArray(), client.request_socket);
					out2.flush();
					
					ObjectInputStream ins = new ObjectInputStream(client.request_socket.getInputStream());
					Object msg = ins.readObject();
					if (msg.getClass().getCanonicalName().equals("java.lang.String")) {
						String errorString = (String) msg;
						System.out.println(errorString);
						ClientApp.request_socket.close();
						continue;
					}
					
					TalkingMessage t = (TalkingMessage) msg;
					
					if (!t.verify_HMAC_session_key(client.record_table.get_session_key("server"))) {
						System.out.println("error Hmac for message");
						ObjectOutputStream outstream = new ObjectOutputStream(client.request_socket.getOutputStream());
						outstream.writeObject("hmac failed");
						outstream.flush();
						ClientApp.request_socket.close();
						continue;
					}
					
					TalkingContent content = (TalkingContent) t.deserializeMsg(t.decryptMsg_session_key(server_session));
					
					if (content.getTimestamp() != timestamp + 1) {
						System.out.println("out of order");
						continue;
					}
					
					client.record_table.online_table.get("server").setLast_update(new Timestamp(content.getTimestamp()));
					
					System.out.println(content.getContent());
					
					ClientApp.request_socket.close();
				}
				else if (sendMsg.startsWith("send")) {

					String[] msg = sendMsg.split(" ", 3);
					if (msg.length != 3) {
						System.out.println("send command should contain 2 arguments.");
						continue;
					}
					String dest_usr = msg[1];
					String text = msg[2];

					if(dest_usr.equals(client.user_name))
					{
						System.out.println("sent message to " + dest_usr);
						System.out.println(text);
						continue;
					}
					// if first time talking to B
					if (!client.record_table.online_table.containsKey(dest_usr)) {
						SecretKey session_server = client.record_table.get_session_key("server");
//						long time_server = get_appropriate_timestamp("server");
						int state = client.talking_authenticate(dest_usr, session_server);
						if (state == -1) {
							continue;
						}
//						ClientApp.record_table.online_table.get("server").setLast_update(new Timestamp(time_server));
								
						
					}
					// send content
					String dest_ip = client.record_table.get_ip_from_user(dest_usr);
					int dest_port = client.record_table.get_port_from_user(dest_usr);
					SecretKey session_key = client.record_table.get_session_key(dest_usr);
					
					long create_time = client.record_table.online_table.get(dest_usr).getCreate_date().getTime() + 1;
//					ClientApp.record_table.online_table.get(dest_usr).setLast_update(new Timestamp(timestamp1));
					client.record_table.online_table.get(dest_usr).setCreate_date(new Timestamp(create_time));
					
					TalkingContent content_obj = new TalkingContent(text, create_time);
					TalkingMessage talking_msg = new TalkingMessage();
					talking_msg.setType(message_type.Talk_Content);
					talking_msg.local_port = client.local_port;
					talking_msg.setEncrypted_message_session_key(content_obj,
							session_key);

					ByteArrayOutputStream output = new ByteArrayOutputStream();
					ObjectOutputStream out = new ObjectOutputStream(output);
					out.writeObject(talking_msg);
					talking_msg.generate_HMAC_session_key(output.toByteArray(), session_key);
					
					
					// serialize and send out
					ByteArrayOutputStream byte_output = new ByteArrayOutputStream();
					ObjectOutputStream out2;
					out2 = new ObjectOutputStream(byte_output);
					out2.writeObject(talking_msg);

					ClientApp.request_socket = new Socket(InetAddress.getByName(dest_ip.replace("/","")),
							dest_port);
					ClientApp.send_TCP_packet(byte_output.toByteArray(),
							ClientApp.request_socket);
					System.out.println("Sent message to " + dest_usr);
					ClientApp.request_socket.close();

				} else if (sendMsg.equals("Logout")) {
					// logout from server
					SecretKey server_session = ClientApp.record_table.get_session_key("server");
					
					long timestamp = get_appropriate_timestamp("server");
					ClientApp.record_table.online_table.get("server").setLast_update(new Timestamp(timestamp));
					
					LogoutRequest logout_req = new LogoutRequest(ClientApp.user_name);
					logout_req.setTimestamp(timestamp);
					TalkingMessage talking_msg = new TalkingMessage();
					talking_msg.setType(message_type.Logout_Server);
					talking_msg.local_port = client.local_port;
					talking_msg.setEncrypted_message_session_key(logout_req, server_session);					

					ByteArrayOutputStream output = new ByteArrayOutputStream();
					ObjectOutputStream out = new ObjectOutputStream(output);
					out.writeObject(talking_msg);
					talking_msg.generate_HMAC_session_key(output.toByteArray(), server_session);
					
					// serialize and send out
					ByteArrayOutputStream byte_output = new ByteArrayOutputStream();
					ObjectOutputStream out2;
					out2 = new ObjectOutputStream(byte_output);
					out2.writeObject(talking_msg);
					client.request_socket = new Socket(client.server_ip, client.server_port);
					client.request_socket.setSoTimeout(10000);
					client.send_TCP_packet(byte_output.toByteArray(), client.request_socket);
					
					// wait for ACK					
					InputStream input_s = client.request_socket.getInputStream();
					ObjectInputStream in = new ObjectInputStream(input_s);
					try
					{
						Object msg = in.readObject();
						
						if (msg.getClass().getCanonicalName().equals("java.lang.String")) {
							String errorString = (String) msg;
							System.out.println(errorString);
						}
						
						TalkingMessage logout_msg = (TalkingMessage) msg;
						byte[] logout_text = logout_msg.decryptMsg_session_key(client.record_table.get_session_key("server"));
						
						if (!logout_msg.verify_HMAC_session_key(client.record_table.get_session_key("server"))) {
							System.out.println("error Hmac for message");
							ObjectOutputStream outstream = new ObjectOutputStream(client.request_socket.getOutputStream());
							outstream.writeObject("hmac failed");
							outstream.flush();
						}
						
						LogoutACK logout_ack = (LogoutACK) logout_msg.deserializeMsg(logout_text);
						long ack_timestamp = logout_ack.getTimestamp();
						long last_timestamp = client.record_table.get_last_update("server");

						if (!(logout_ack.getIniciator().equals(client.user_name)
								&& logout_ack.getReplyer().equals("server"))) {
							System.out.println("Received unexpected ack");
						}
						
						if (last_timestamp != -1) {
							if (last_timestamp + 1 != ack_timestamp) {
								System.out.println("Get out of order ack");
							}
						}
						client.record_table.delete_user("server");
					}
					catch(SocketTimeoutException  soe)
					{
						client.record_table.delete_user("server");
						System.out.println("Can't recevie LogoutACK");
					}
					
					// logout all clients
					for(String user : ClientApp.record_table.get_online_users())
					{
						String ip = ClientApp.record_table.get_ip_from_user(user).replace("/", "");
						SecretKey session_key = ClientApp.record_table.get_session_key(user);
						timestamp = get_appropriate_timestamp(user);
						ClientApp.record_table.online_table.get(user).setLast_update(new Timestamp(timestamp));
						talking_msg.setType(message_type.Logout_Client);
						talking_msg.local_port = client.local_port;
						talking_msg.setEncrypted_message_session_key(logout_req, session_key);	
						
						output = new ByteArrayOutputStream();
						out = new ObjectOutputStream(output);
						out.writeObject(talking_msg);
						talking_msg.generate_HMAC_session_key(output.toByteArray(), session_key);
						
						// serialize and send out
						byte_output = new ByteArrayOutputStream();
						out2 = new ObjectOutputStream(byte_output);
						out2.writeObject(talking_msg);
						client.request_socket = new Socket(ip, ClientApp.record_table.get_port_from_user(user));
						client.request_socket.setSoTimeout(10000);
						client.send_TCP_packet(byte_output.toByteArray(), client.request_socket);
						System.out.println("Send LogoutRequest to " + user);		
						
						// wait for ACK						
						input_s = client.request_socket.getInputStream();
						in = new ObjectInputStream(input_s);
						try
						{
							Object msg = in.readObject();
							
							if (msg.getClass().getCanonicalName().equals("java.lang.String")) {
								String errorString = (String) msg;
								System.out.println(errorString);
								client.request_socket.close();
							}
							
							TalkingMessage logout_msg = (TalkingMessage) msg;
							byte[] logout_text = logout_msg.decryptMsg_session_key(client.record_table.get_session_key(user));

							if (!logout_msg.verify_HMAC_session_key(client.record_table.get_session_key(user))) {
								System.out.println("error Hmac for message");
								ObjectOutputStream outstream = new ObjectOutputStream(client.request_socket.getOutputStream());
								outstream.writeObject("hmac failed");
								outstream.flush();
							}
							
							LogoutACK logout_ack = (LogoutACK) logout_msg.deserializeMsg(logout_text);
							long ack_timestamp = logout_ack.getTimestamp();
							long last_timestamp = client.record_table.get_last_update(user);

							if (!(logout_ack.getIniciator().equals(client.user_name)
									&& logout_ack.getReplyer().equals(user))) {
								System.out.println("Received unexpected ack");
							}
							
							if (last_timestamp != -1) {
								if (last_timestamp + 1 != ack_timestamp) {
									System.out.println("Get out of order ack");
								}
							}
							client.record_table.delete_user(user);
						}
						catch(SocketTimeoutException  soe)
						{
							System.out.println("Can't recevie LogoutACK");
						}
						
					}
					
					client.request_socket.close();
//					client.timer.cancel();
					System.exit(0);
					
				}
				else
				{
					System.out.println("No this command");
					continue;
				}
			}
		} catch (Exception e) {
			// TODO: handle exception
			e.printStackTrace();
		}
	}
	
	long get_appropriate_timestamp(String usr)
	{
		long recorded_timestamp = ClientApp.record_table.get_last_update(usr);
		
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
	
	
}