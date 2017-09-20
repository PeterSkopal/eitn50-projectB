
import java.io.*;
import java.net.*;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;

import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

public class Server {

	public static void main(String args[]) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		DatagramSocket sendSock = null;
		DatagramSocket recSock = null;
		int recPort = 7777;
		int runPort = 7778;
		PublicKey clientPublicKey;
		SecretKey commonSecret = null;
		ArrayList<Integer> seqNbrs = new ArrayList<Integer>();

		DiffieHellman difHel = new DiffieHellman();

		KeyPair keyPair = difHel.generateKeys();

		try {
			sendSock = new DatagramSocket();
			recSock = new DatagramSocket(recPort);
			InetAddress host = InetAddress.getByName("localhost");

			byte[] buffer = new byte[65536];

			byte[] publicKey = (byte[]) keyPair.getPublic().getEncoded();
			DatagramPacket incoming = new DatagramPacket(buffer, buffer.length);

			DatagramPacket serverPublicKey = new DatagramPacket(publicKey, publicKey.length, host, runPort);

			System.out.println("Server listening on: " + host.toString() + ":" + recPort);
			System.out.println("Server running on: " + host.toString() + ":" + runPort);
			System.out.println("Server socket created. Waiting for incoming data...");

			while (true) {
				if (reciveHello(recSock)) {
					break;
				}
			}

			sendHello(sendSock, host, runPort);

			while (true) {
				if ((clientPublicKey = recieveClientKey(recSock, difHel)) != null) {
					break;
				}
			}

			sendPublicKey(sendSock, keyPair.getPublic(), host, runPort);
			commonSecret = DiffieHellman.generateSharedSecret(keyPair.getPrivate(), clientPublicKey);
		} catch (IOException e) {
			System.err.println("IOException " + e);
		}

		byte[] buffer = new byte[65536];
		DatagramPacket incoming = new DatagramPacket(buffer, buffer.length);
		while (true) {
			try {
				recSock.receive(incoming);
			} catch (IOException e) {
				e.printStackTrace();
			}
			byte[] data = incoming.getData();
			String s = new String(data, 0, incoming.getLength());
			String[] arr = s.split(":::iv-");
			String clientIv = arr[1];
			String deData = DiffieHellman.decryptString(commonSecret, arr[0], clientIv.getBytes());
			String delims = ":::+";
			String[] tokens = deData.split(delims);
			
			System.out.println("Recieved Package:\t" + s);
			
			String clientData = null;
			String clientSeq = null;
			String clientHash = null;
			String completePackage = "";

			for (String parameter : tokens) {
				System.out.println("parameter:\t" + parameter);
				if (parameter.startsWith("seq-")) {
					clientSeq = parameter.substring("seq-".length());
					if (seqNbrs.contains(Integer.parseInt(clientSeq))) {
						System.out.println("This sequence number as already been used. Disconnecting Client");
						throw new Exception();
					}
					System.out.println(Integer.parseInt(clientSeq));
					seqNbrs.add(Integer.parseInt(clientSeq));
					completePackage += parameter;
				} else if (parameter.startsWith("data-")) {
					clientData = parameter.substring("data-".length());
					completePackage += parameter + ":::";
				
				} else if (parameter.startsWith("hash-")) {
					clientHash = parameter.substring("hash-".length());
					try {
						MessageDigest digest = MessageDigest.getInstance("SHA-256");
						
						System.out.println("Hashing the following:\t" + completePackage);
						byte[] hashbyte = completePackage.getBytes(); 
						byte[] hash = digest.digest(hashbyte);

						String hashString = new String(hash, "UTF-8");
						System.out.println("Servers Hash:\t" + hashString);
						System.out.println("Clients Hash:\t" + clientHash);
						
						if (hashString.equals(clientHash)) {
							System.out.println("Integrity check positive");
						} else {
							System.out.println("Integrity check negative. Disconnecting Client.");
							throw new Exception();
						}
					} catch (Exception e) {
						e.printStackTrace();
					}
				}
			}
			System.out.println("Client Says:\t" + clientData);
		}
	}

	public static boolean reciveHello(DatagramSocket recSock) {
		byte[] buffer = new byte[65536];
		DatagramPacket incoming = new DatagramPacket(buffer, buffer.length);
		try {
			recSock.receive(incoming);
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		}
		byte[] data = incoming.getData();
		String s = new String(data, 0, incoming.getLength());

		if (s.equals("Hello Server Handshake")) {
			System.out.println(
					incoming.getAddress().getHostAddress() + " : " + incoming.getPort() + " - " + s + "\tSUCCESS");
			return true;
		}
		return false;
	}

	public static void sendHello(DatagramSocket sendSock, InetAddress host, int runPort) {
		try {
			byte[] helloCl = "Hello Client Handshake".getBytes("UTF-8");			
			DatagramPacket helloClient = new DatagramPacket(helloCl, helloCl.length, host, runPort);
			sendSock.send(helloClient);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static PublicKey recieveClientKey(DatagramSocket recSock, DiffieHellman difHel) {
		System.out.println("Recieving Public Key from Client.");
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

	public static void sendPublicKey(DatagramSocket sendSock, PublicKey pubKey, InetAddress host, int runPort) {
		byte[] publicKey = (byte[]) pubKey.getEncoded();

		try {
			sendSock.send(new DatagramPacket(publicKey, publicKey.length, host, runPort));
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
