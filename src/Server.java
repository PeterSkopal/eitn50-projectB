
import java.io.*;
import java.net.*;
import java.security.KeyPair;

public class Server {

	public static void main(String args[]) {
		DatagramSocket sendSock = null;
		DatagramSocket recSock = null;
		int recPort = 7777;
		int runPort = 7778;
		String clientPublicKey;

		DiffieHellman difHel = new DiffieHellman();
		
		KeyPair keyPair = difHel.generateKeys();
		
		try {
			sendSock = new DatagramSocket();
			InetAddress host = InetAddress.getByName("localhost");
			recSock = new DatagramSocket(recPort);
			byte[] buffer = new byte[65536];
			byte[] helloCl = "Hello Client Handshake".getBytes();
			byte[] publicKey = (byte[]) ("Server Public Key" + keyPair.getPublic().toString()).getBytes();
			DatagramPacket incoming = new DatagramPacket(buffer, buffer.length);
			DatagramPacket helloClient = new DatagramPacket(helloCl, helloCl.length, host, runPort);
			DatagramPacket serverPublicKey = new DatagramPacket(publicKey, publicKey.length, host, runPort);
			
			System.out.println("Server listening on: " + host.toString() + ":" + recPort);
			System.out.println("Server running on: " + host.toString() + ":" + runPort);
			System.out.println("Server socket created. Waiting for incoming data...");

			while (true) {
				recSock.receive(incoming);
				byte[] data = incoming.getData();
				
				String s = new String(data, 0, incoming.getLength());
				if (s.equals("Hello Server Handshake")) {
					System.out.println(incoming.getAddress().getHostAddress() + " : " + incoming.getPort() + " - " + s + "\tSUCCESS");
					
					sendSock.send(helloClient);
				} else if (s.startsWith("Client Public Key")) {
					clientPublicKey = s.substring("Client Public Key".length(), s.length());
					
					System.out.println("Recieving Public Key from Client.");
					System.out.println("Sending Public Key to Client.");
					
					sendSock.send(serverPublicKey);
				} else {			
					System.out.println(incoming.getAddress().getHostAddress() + " : " + incoming.getPort() + " - " + s);
				}
			}

		} catch (IOException e) {
			System.err.println("IOException " + e);
		}
	}
}
