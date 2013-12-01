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
	public byte[] get_public_key(String username) {
		return offline_table.get_public_key_from_user(username);
	}
	
	public byte[] get_private_key(String username) {
		return offline_table.get_private_key_from_user(username);
	}
	
	public byte[] get_password(String username) {
		return offline_table.get_password_from_user(username);
	}
	
	public String get_public_key_path(String username) {
		return offline_table.get_public_key_path(username);
	}
	
	public String get_private_key_path(String username) {
		return offline_table.get_private_key_path(username);
	}
	
	public String get_password_path(String username) {
		return offline_table.get_password_path(username);
	}
	
	public String get_ip_from_user(String username) {
		Set set = online_table.keySet();
		Iterator iterator = set.iterator();
		while (iterator.hasNext()) {
			onlineitem item = online_table.get(iterator.next());
			if (item.getUser_name().equals(username)) {
				return item.getIpaddr();
			}
		}
		return "";
	}
	
	public int get_port_from_user(String username) {
		Set set = online_table.keySet();
		Iterator iterator = set.iterator();
		while (iterator.hasNext()) {
			onlineitem item = online_table.get(iterator.next());
			if (item.getUser_name().equals(username)) {
				return item.getPort();
			}
		}
		return 0;
	}
	
	public ArrayList<String> get_online_users() {
		ArrayList<String> online_list = new ArrayList<String>();
		Set set = online_table.keySet();
		Iterator iterator = set.iterator();
		while (iterator.hasNext()) {
			String username = online_table.get(iterator.next()).getUser_name();
			online_list.add(username);
		}
		return online_list;
	}
	
	//String username, String ip, int port, BigInteger sessionKey
	public int add_online_entry(String username, String ip, int port, SecretKey sessionKey ) {
		onlineitem item = new onlineitem(username, ip, port, sessionKey);
		if (online_table.containsKey(ip)) {
			System.out.println(ip + " already added\n");
			return 0;
		}
		else {
			online_table.put(ip, item);			
			return 1;
		}		
	}
	
	public String get_user_name(String ip) {
		if (online_table.containsKey(ip)) {
			return online_table.get(ip).getUser_name();
		}
		else {
			System.out.println("No such user to corresponding ip " + ip);
			return null;			
		}
	}
	
	// return the session key from an ip address
	public SecretKey get_session_key(String ip) {
		if (online_table.containsKey(ip)) {
			return online_table.get(ip).getSession_key();
		}
		else {
			System.out.println("No such session key to corresponding ip " + ip);
			return null;
		}
	}
	
	// remove user entry to corresponding ip address
	public int delete_user(String ip) {
		if (online_table.containsKey(ip)) {
			online_table.remove(ip);
			return 1;
		}
		else {
			return 0;
		}
	}
	
}
