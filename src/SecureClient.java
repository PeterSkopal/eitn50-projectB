import java.io.*;
import java.net.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;

public class SecureClient {
	public static void main(String args[])
    {
		try {
			
			DiffieHellman dfconn = new DiffieHellman();
			
			KeyPair clientKeys = dfconn.generateKeys();
			
			DatagramSocket sock = null;
		    int port = 7777;
		    String s; 
		    BufferedReader cin = new BufferedReader(new InputStreamReader(System.in));
		    sock = new DatagramSocket();
		    InetAddress host = InetAddress.getByName("localhost");
		             
		    
		    while(true)
		            {
		                System.out.println("Enter message to send : ");
		                s = (String)cin.readLine();
		                byte[] b = s.getBytes();
		
		                DatagramPacket  dp = new DatagramPacket(b , b.length , host , port);
		             //   sock.send(dp);
		            }
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
    }
  }	



