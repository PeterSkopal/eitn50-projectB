import java.io.*;
import java.net.*;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.SecretKey;

import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

public class Client {

	public static void main(String args[]) throws InterruptedException {
		DatagramSocket recSock = null;
		DatagramSocket sendSock = null;
		int recPort = 7778;
		int runPort = 7777;
		String s;
		String serverPublicKey;
		DiffieHellman difHel = new DiffieHellman();
		PublicKey serverPublic;
		SecretKey commonSecret = null;

		KeyPair keyPair = difHel.generateKeys();

		// client incoming messages
		BufferedReader cin = new BufferedReader(new InputStreamReader(System.in));

		try {
			recSock = new DatagramSocket(recPort);
			sendSock = new DatagramSocket();
			InetAddress host = InetAddress.getByName("localhost");

			System.out.println("Client running on: " + host + ":" + runPort);
			System.out.println("Client listening on: " + host + ":" + recPort);
			System.out.println("Sending Handshake to Server");

			sendHello(sendSock, host, runPort);

			while (true) {
				if (reciveHello(recSock)) {
					break;
				}
				sendHello(sendSock, host, runPort);
			}

			sendPublicKey(sendSock, keyPair.getPublic(), host, runPort);

			while (true) {
				if ((serverPublic = recieveServerKey(recSock, difHel)) != null) {
					break;
				}
				sendPublicKey(sendSock, keyPair.getPublic(), host, runPort);
			}
			commonSecret = DiffieHellman.generateSharedSecret(keyPair.getPrivate(), serverPublic);

			while (true) {
				try {
					// take input and send the packet
					System.out.println("Enter message to send : ");

					s = (String) cin.readLine();
					String b = DiffieHellman.encryptString(commonSecret, s);
					String send = new String("data-" + b + ":iv-");
					byte[] sendByte = send.getBytes("UTF-8");
					byte[] iv = difHel.getIv();
					// Adding sendByte and iv together to one byte array
					byte[] destination = new byte[sendByte.length + iv.length];
					System.arraycopy(sendByte, 0, destination, 0, sendByte.length);
					System.arraycopy(iv, 0, destination, sendByte.length, iv.length);
					
					MessageDigest digest = MessageDigest.getInstance("SHA-256");
					System.out.println(destination);
					
					byte[] hash = digest.digest(destination);
					byte[] hashMessage = ":hash-".getBytes("UTF-8");			
					System.out.println("Hashing the following:\t" + new String(destination, "UTF-8"));
					// Making and hash byte array
					byte[] hashPack = new byte[hashMessage.length + hash.length];
					System.arraycopy(hashMessage, 0, hashPack, 0, hashMessage.length);
					System.arraycopy(hash, 0, hashPack, hashMessage.length, hash.length);
					
					// Making complete package by adding destination and hash 
					byte[] pack = new byte[destination.length + hashPack.length];
					System.arraycopy(destination, 0, pack, 0, destination.length);
					System.arraycopy(hashPack, 0, pack, destination.length, hashPack.length);
					System.out.println("Complete Transmit:\t" + new String(pack, "UTF-8"));
					DatagramPacket dp = new DatagramPacket(pack, pack.length, host, runPort);
					sendSock.send(dp);
				} catch (Exception e) {
					e.printStackTrace();
				}

			}
		} catch (IOException e) {
			System.err.println("IOException " + e);
		}
	}

	public static void sendHello(DatagramSocket sendSock, InetAddress host, int runPort) {
		byte[] handshake = ("Hello Server Handshake").getBytes();
		try {
			sendSock.send(new DatagramPacket(handshake, handshake.length, host, runPort));
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public static boolean reciveHello(DatagramSocket recSock) {
		byte[] buffer = new byte[65536];
		DatagramPacket incoming = new DatagramPacket(buffer, buffer.length);

		try {
			recSock.receive(incoming);
		} catch (IOException e) {
			e.printStackTrace();
		}

		byte[] data = incoming.getData();
		String str = new String(data, 0, incoming.getLength());

		if (str.equals("Hello Client Handshake")) {
			System.out.println("Server says: " + str);
			System.out.println("Sending Public Key to Server.");
			return true;
		} else {
			return false;
		}
	}

	public static void sendPublicKey(DatagramSocket sendSock, PublicKey pubKey, InetAddress host, int runPort) {
		byte[] publicKey = (byte[]) pubKey.getEncoded();

		try {
			sendSock.send(new DatagramPacket(publicKey, publicKey.length, host, runPort));
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public static PublicKey recieveServerKey(DatagramSocket recSock, DiffieHellman difHel) {

		byte[] buffer = new byte[65536];
		DatagramPacket incoming = new DatagramPacket(buffer, buffer.length);

		try {
			recSock.receive(incoming);
		} catch (IOException e) {
			e.printStackTrace();
		}
		byte[] data = incoming.getData();
		byte[] serverKeyByte = new byte[incoming.getLength()];

		System.arraycopy(data, 0, serverKeyByte, 0, incoming.getLength());

		PublicKey serverPublicKey = DiffieHellman.PublicKeyFromByte(serverKeyByte);

		if (serverPublicKey != null) {
			return serverPublicKey;
		} else {
			return null;
		}
	}
}
