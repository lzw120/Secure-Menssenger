package recordtable;

import java.awt.List;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.sql.Timestamp;
import java.util.Iterator;

import au.com.bytecode.opencsv.CSVReader;
import au.com.bytecode.opencsv.CSVWriter;

public class offlineitem {
	String username;
	
	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	// return path of public key from a given username
	public String get_public_key_path(String username) {
		try {
			CSVReader reader = new CSVReader(new FileReader("clientsDB.csv"));
			String[] next_lineStrings;
			// search for user key
			while((next_lineStrings = reader.readNext()) != null)
			{
				if (next_lineStrings[0].equals(username)) {
					String key_file = next_lineStrings[1];
					return key_file;
				}
			}
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("No entry record of " + username);
		return "";
	}
	
	// return public key from a given user name
	public byte[] get_public_key_from_user(String username) {
		try {
			CSVReader reader = new CSVReader(new FileReader("clientsDB.csv"));
			String[] next_lineStrings;
			// search for user key
			while((next_lineStrings = reader.readNext()) != null)
			{
				if (next_lineStrings[0].equals(username)) {
					String key_file = next_lineStrings[1];
					File file = new File(key_file);
					FileInputStream inputStream = new FileInputStream(file);
					byte[] temp_buff = new byte[(int) file.length()];
					inputStream.read(temp_buff);
					inputStream.close();
					return temp_buff;
				}
			}
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("No entry record of " + username);
		return null;
	}

	// return the private key Y's path from a given user name
	public String get_private_key_path(String username) {
		try {
			CSVReader reader = new CSVReader(new FileReader("clientsDB.csv"));
			String[] next_lineStrings;
			// search for user key from directory
			// need for test
			while((next_lineStrings = reader.readNext()) != null)
			{
				if (next_lineStrings[0].equals(username)) {
					String key_file = next_lineStrings[2];
					return key_file;
				}
			}			
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("No entry record of " + username);
		return "";
	}
	// return the private key Y from a given user name
	public byte[] get_private_key_from_user(String username) {
		try {
			CSVReader reader = new CSVReader(new FileReader("clientsDB.csv"));
			String[] next_lineStrings;
			// search for user key from directory
			// need for test
			while((next_lineStrings = reader.readNext()) != null)
			{
				if (next_lineStrings[0].equals(username)) {
					String key_file = next_lineStrings[2];
					File file = new File(key_file);
					FileInputStream inputStream = new FileInputStream(file);
					ByteArrayOutputStream byte_output_stream = new ByteArrayOutputStream();
					byte[] temp_buff = new byte[(int) file.length()];
					int count = 0;
					while ((count = inputStream.read(temp_buff)) != -1) {
						byte_output_stream.write(temp_buff, 0, count);
//						temp_buff = new byte[1024];
						}
						inputStream.close();
						return temp_buff;
				}
			}			
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("No entry record of " + username);
		return null;
	}
	
	// return the password W's path from a given username
	public String get_password_path(String username) {
		try {
			CSVReader reader = new CSVReader(new FileReader("clientsDB.csv"));
			String[] next_lineStrings;
			// search for user key
			while((next_lineStrings = reader.readNext()) != null)
			{
				if (next_lineStrings[0].equals(username)) {
					String key_file = next_lineStrings[3];
					return key_file;
				}
			}		
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("No entry record of " + username);
		return "";
	}
	// return the password W from a given user name
	public byte[] get_password_from_user(String username) {
		try {
			CSVReader reader = new CSVReader(new FileReader("clientsDB.csv"));
			String[] next_lineStrings;
			// search for user key
			while((next_lineStrings = reader.readNext()) != null)
			{
				if (next_lineStrings[0].equals(username)) {
					String key_file = next_lineStrings[3];
					File file = new File(key_file);
					FileInputStream inputStream = new FileInputStream(file);
					ByteArrayOutputStream byte_output_stream = new ByteArrayOutputStream();
					byte[] temp_buff = new byte[1024];
					int count = 0;
					while ((count = inputStream.read(temp_buff)) != -1) {
						byte_output_stream.write(temp_buff, 0, count);
						temp_buff = new byte[1024];
						}
						inputStream.close();
						return temp_buff;
				}
			}		
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("No entry record of " + username);
		return null;
	}
	
	
	public String get_timestamp_from_user(String username) {
		try {
			CSVReader reader = new CSVReader(new FileReader("clientsDB.csv"));
			String[] next_lineStrings;
			// search for user key
			while((next_lineStrings = reader.readNext()) != null)
			{
				if (next_lineStrings[0].equals(username)) {
					return next_lineStrings[4];
				}
			}		
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("No entry record of " + username);
		return "";
	}
	
	
	public String get_expiretime_from_user(String username) {
		try {
			CSVReader reader = new CSVReader(new FileReader("clientsDB.csv"));
			String[] next_lineStrings;
			// search for user key
			while((next_lineStrings = reader.readNext()) != null)
			{
				if (next_lineStrings[0].equals(username)) {
					return next_lineStrings[5];
				}
			}		
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("No entry record of " + username);
		return "";
	}
}
