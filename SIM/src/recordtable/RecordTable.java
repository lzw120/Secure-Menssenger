package recordtable;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;

import javax.crypto.SecretKey;

public class RecordTable {
	public HashMap<String, onlineitem> online_table;
	public offlineitem offline_table;
	
	public RecordTable() {
		// TODO Auto-generated constructor stub
		online_table = new HashMap<String, onlineitem>();
		offline_table = new offlineitem();
	}
	
	// return public key by given user name
	synchronized public byte[] get_public_key(String username) {
		return offline_table.get_public_key_from_user(username);
	}
	
	synchronized public byte[] get_private_key(String username) {
		return offline_table.get_private_key_from_user(username);
	}
	
	synchronized public byte[] get_password(String username) {
		return offline_table.get_password_from_user(username);
	}
	
	synchronized public String get_public_key_path(String username) {
		return offline_table.get_public_key_path(username);
	}
	
	synchronized public String get_private_key_path(String username) {
		return offline_table.get_private_key_path(username);
	}
	
	synchronized public String get_password_path(String username) {
		return offline_table.get_password_path(username);
	}
	
	synchronized public String get_ip_from_user(String username) {		
		if (online_table.containsKey(username)) {
			String ip = online_table.get(username).getIpaddr();
			return ip.substring(ip.indexOf("/")+1);
		}
		else {
			System.out.println("No such user: " + username);
			return null;			
		}
		
	}
	
	synchronized public int get_port_from_user(String username) {
		if (online_table.containsKey(username)) {
			return online_table.get(username).getPort();
		}
		else {
			System.out.println("No such user: " + username);
			return 0;			
		}
	}
	
	synchronized public ArrayList<String> get_online_users() {
		ArrayList<String> online_list = new ArrayList<String>();
		Set set = online_table.keySet();
		Iterator iterator = set.iterator();
		while (iterator.hasNext()) {
			String username =  (String)iterator.next();
			online_list.add(username);
		}
		return online_list;
	}
	
	//String username, String ip, int port, BigInteger sessionKey
	synchronized public int add_online_entry(String username, String ip, int port, SecretKey sessionKey ) {
		if (ip.indexOf("/") != -1) {
			ip = ip.substring(ip.indexOf("/")+1);
		}
		onlineitem item = new onlineitem(username, ip, port, sessionKey);
		if (online_table.containsKey(username)) {
			System.out.println(username + " already added\n");
			return 0;
		}
		else {
			online_table.put(username, item);			
			return 1;
		}		
	}
	
	synchronized public String get_user_name(String ip, int port) {
		if (ip.indexOf("/") != -1) {
			ip = ip.substring(ip.indexOf("/")+1);
		}
		Set set = online_table.keySet();
		Iterator iterator = set.iterator();
		while (iterator.hasNext()) {
			onlineitem item = online_table.get(iterator.next());
			if (item.getIpaddr().equals(ip) && item.getPort() == port) {
				return item.getUser_name();
			}
		}
		return "";
	}
	
	synchronized public long get_last_update(String user_name)
	{
		if(online_table.containsKey(user_name))
			return online_table.get(user_name).getLast_update().getTime();
		else 
			return -1;
	}
	
	// return the session key by user name
	synchronized public SecretKey get_session_key(String usr) {
		if (online_table.containsKey(usr)) {
			return online_table.get(usr).getSession_key();
		}
		else {
			System.out.println("No such user: ");
			return null;
		}
	}
	
	// remove user entry to corresponding to user name
	synchronized public int delete_user(String user) {
		if (online_table.containsKey(user)) {
			online_table.remove(user);
			return 1;
		}
		else {
			return 0;
		}
	}
	
}
