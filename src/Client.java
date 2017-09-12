import java.io.*;
import java.net.*;
import java.security.Key;
import java.security.KeyPair;

public class Client {

	public static void main(String args[]) {
		DatagramSocket sock = null;
		int port = 7777;
		String s;
		String serverPublicKey;
		DiffieHellman difHel = new DiffieHellman();
		
		KeyPair keyPair = difHel.generateKeys();
		System.out.println(keyPair.getPrivate());
		System.out.println(keyPair.getPublic());
		
		// client incoming messages
		BufferedReader cin = new BufferedReader(new InputStreamReader(System.in));

		// server incoming messages
		byte[] buffer = new byte[65536];
		DatagramPacket incoming = new DatagramPacket(buffer, buffer.length);

		try {
			sock = new DatagramSocket();
			InetAddress host = InetAddress.getByName("localhost");

			byte[] handshake = "Hello Server Handshake".getBytes();
			System.out.println("Making Handshake with message: '" + handshake.toString() + "'");
			sock.send(new DatagramPacket(handshake, handshake.length, host, port));

			while (true) {
				sock.receive(incoming);
				byte[] data = incoming.getData();
				String str = new String(data, 0, incoming.getLength());
				if (str.equals("Client Handshake")) {
					System.out.println("Server says: 'Client Handshake'");
					byte[] publicKey = (byte[]) keyPair.getPublic().toString().getBytes();
					System.out.println("Sending Public Key to Server: " + publicKey);
					sock.send(new DatagramPacket(publicKey, publicKey.length, host, port));
					break;
				}
			}
			
			while (true) {
				sock.receive(incoming);
				byte[] data = incoming.getData();
				String str = new String(data, 0, incoming.getLength());
				if (str.startsWith("Server Public Key")) {
					serverPublicKey = str.substring("Server Public Key".length(), str.length());
					System.out.println("Recieving Public Key from Server: " + serverPublicKey);
					System.out.println(serverPublicKey);
					break;
				}
			}

			while (true) {
				// take input and send the packet
				System.out.println("Enter message to send : ");
				s = (String) cin.readLine();
				byte[] b = s.getBytes();

				DatagramPacket dp = new DatagramPacket(b, b.length, host, port);
				sock.send(dp);
			}
		} catch (IOException e) {
			System.err.println("IOException " + e);
		}
	}
}
