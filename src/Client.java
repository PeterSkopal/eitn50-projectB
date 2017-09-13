import java.io.*;
import java.net.*;
import java.security.Key;
import java.security.KeyPair;

public class Client {

	public static void main(String args[]) throws InterruptedException {
		DatagramSocket recSock = null;
		DatagramSocket sendSock = null;
		int recPort = 7778;
		int runPort = 7777;
		String s;
		String serverPublicKey;
		DiffieHellman difHel = new DiffieHellman();
		
		KeyPair keyPair = difHel.generateKeys();
//		System.out.println(keyPair.getPrivate());
//		System.out.println(keyPair.getPublic());
		
		// client incoming messages
		BufferedReader cin = new BufferedReader(new InputStreamReader(System.in));

		// server incoming messages
		byte[] buffer = new byte[65536];
		DatagramPacket incoming = new DatagramPacket(buffer, buffer.length);

		try {
			sendSock = new DatagramSocket();
			recSock = new DatagramSocket(recPort);
			InetAddress host = InetAddress.getByName("localhost");
			System.out.println("Client running on: " + host + ":" + runPort);
			System.out.println("Client listening on: " + host + ":" + recPort);
			System.out.println("Sending Handshake to Server");

			byte[] handshake = ("Hello Server Handshake").getBytes();
			sendSock.send(new DatagramPacket(handshake, handshake.length, host, runPort));

			while (true) {
				recSock.receive(incoming);
				byte[] data = incoming.getData();
				String str = new String(data, 0, incoming.getLength());
				if (str.equals("Hello Client Handshake")) {
					System.out.println("Server says: " + str);
					System.out.println("Sending Public Key to Server.");
					
					byte[] publicKey = (byte[]) ("Client Public Key" + keyPair.getPublic().toString()).getBytes();
					sendSock.send(new DatagramPacket(publicKey, publicKey.length, host, runPort));
					break;
				}
			}
	
			while (true) {
				recSock.receive(incoming);
				byte[] data = incoming.getData();
				String str = new String(data, 0, incoming.getLength());
				if (str.startsWith("Server Public Key")) {
					serverPublicKey = str.substring("Server Public Key".length(), str.length());
					
					System.out.println("Recieving Public Key from Server: " + serverPublicKey);
					break;
				}
			}

			while (true) {
				// take input and send the packet
				System.out.println("Enter message to send : ");
				s = (String) cin.readLine();
				byte[] b = s.getBytes();

				DatagramPacket dp = new DatagramPacket(b, b.length, host, runPort);
				sendSock.send(dp);
			}
		} catch (IOException e) {
			System.err.println("IOException " + e);
		}
	}
}
