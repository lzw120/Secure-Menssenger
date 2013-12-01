package Messages;

import java.io.Serializable;
import java.security.Timestamp;

public class LogoutACK  implements Serializable
{
	String logout_id;
	String ackentity_id;	
	Timestamp timestamp;
	
}