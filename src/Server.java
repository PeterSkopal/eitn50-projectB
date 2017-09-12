
import java.io.*;
import java.net.*;
import java.security.KeyPair;

public class Server {
			
	public static void main(String args[]) {
        DatagramSocket sock = null;
        int port = 7777;
        
        String serverPublicKey;
		DiffieHellman difHel = new DiffieHellman();
        
		KeyPair keyPair = difHel.generateKeys();
		System.out.println(keyPair.getPrivate());
		System.out.println(keyPair.getPublic());
		
        try {
        	sock = new DatagramSocket(port);
        	byte[] buffer = new byte[65536];
            DatagramPacket incoming = new DatagramPacket(buffer, buffer.length);
            System.out.println("Server socket created. Waiting for incoming data...");
            
            sock = new DatagramSocket();
			InetAddress host = InetAddress.getByName("localhost");
      
            while(true) {
                sock.receive(incoming);
                byte[] data = incoming.getData();
                String s = new String(data, 0, incoming.getLength());
                System.out.println(incoming.getAddress().getHostAddress() + " : " + incoming.getPort() + " - " + s);
                
                if (s.equals("Hello Server Handshake")) {
                	byte[] handshake = "Client Handshake".getBytes();
        			sock.send(new DatagramPacket(handshake, handshake.length, host, port));
                } else if (s.startsWith("Client Public Key")) {
                	byte[] publicKey = (byte[]) keyPair.getPublic().toString().getBytes();
                	sock.send(new DatagramPacket(publicKey, publicKey.length, host, port));
                }
                
            }
        
        } catch(IOException e) {
            System.err.println("IOException " + e);
        }
    }
}
