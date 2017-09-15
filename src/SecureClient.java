import java.io.*;
import java.net.*;
import java.security.KeyPair;


public class SecureClient {
	public static void main(String args[])
    {
		try {
			
			DiffieHellman dfconn = new DiffieHellman();
			
			dfconn.generateKeys();
			
			int port = 7777;
		    String s; 
		    BufferedReader cin = new BufferedReader(new InputStreamReader(System.in));
		    new DatagramSocket();
		    InetAddress host = InetAddress.getByName("localhost");
		             
		    
		    while(true)
		            {
		                System.out.println("Enter message to send : ");
		                s = (String)cin.readLine();
		                byte[] b = s.getBytes();
		
		                new DatagramPacket(b , b.length , host , port);
		            }
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
    }
  }	



