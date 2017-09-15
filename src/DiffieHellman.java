import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;


public class DiffieHellman {
	
	public static byte[] iv = new SecureRandom().generateSeed(8);
	 
public static KeyPair generateKeys(){
	Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime192v1");
	KeyPairGenerator g;
	
	try{
	g = KeyPairGenerator.getInstance("ECDSA", "BC");
	g.initialize(ecSpec, new SecureRandom());
	KeyPair pair = g.generateKeyPair();
	return pair;
	
	}catch(Exception e){
		return null;
	}
}
	
	 public static SecretKey generateSharedSecret(PrivateKey privateKey,
	         		PublicKey publicKey) {
	        try {
	            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", "BC");
	            keyAgreement.init(privateKey);
	            keyAgreement.doPhase(publicKey, true);

	            SecretKey key = keyAgreement.generateSecret("DES");
	     
	            return key;
	        } catch (Exception e) {
	            // TODO Auto-generated catch block
	            ((Throwable) e).printStackTrace();
	            return null;
	        }
	} 
	public static PublicKey PublicKeyFromByte(byte[] publicKey){ 
	 try {
			KeyFactory kf = KeyFactory.getInstance("ECDSA");
			PublicKey Key2 = kf.generatePublic(new X509EncodedKeySpec(publicKey));
			return Key2;		
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
	return null;  
	}
	
	 public static String encryptString(SecretKey key, String plainText) {
	        try {
	            IvParameterSpec ivSpec = new IvParameterSpec(iv);
	            Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding", "BC");
	            byte[] plainTextBytes = plainText.getBytes("UTF-8");
	            byte[] cipherText;

	            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
	            cipherText = new byte[cipher.getOutputSize(plainTextBytes.length)];
	            int encryptLength = cipher.update(plainTextBytes, 0,
	                    plainTextBytes.length, cipherText, 0);
	            encryptLength += cipher.doFinal(cipherText, encryptLength);

	            return bytesToHex(cipherText);
	        } catch (Exception e) {
	            e.printStackTrace();
	            return null;
	        }
	    }

	    public static String decryptString(SecretKey key, String cipherText, byte[] iv2) {
	        try {
	            Key decryptionKey = new SecretKeySpec(key.getEncoded(),
	                    key.getAlgorithm());
	            IvParameterSpec ivSpec = new IvParameterSpec(iv2);
	            Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding", "BC");
	            byte[] cipherTextBytes = hexToBytes(cipherText);
	            byte[] plainText;
	            cipher.init(Cipher.DECRYPT_MODE, decryptionKey, ivSpec);
	            plainText = new byte[cipher.getOutputSize(cipherTextBytes.length)];
	            int decryptLength = cipher.update(cipherTextBytes, 0,
	                    cipherTextBytes.length, plainText, 0);
	            decryptLength += cipher.doFinal(plainText, decryptLength);

	            return new String(plainText, "UTF-8");
	        } catch (Exception e) {
	            e.printStackTrace();
	            return null;
	        }
	    }

	    public static String bytesToHex(byte[] data, int length) {
	        String digits = "0123456789ABCDEF";
	        StringBuffer buffer = new StringBuffer();

	        for (int i = 0; i != length; i++) {
	            int v = data[i] & 0xff;

	            buffer.append(digits.charAt(v >> 4));
	            buffer.append(digits.charAt(v & 0xf));
	        }

	        return buffer.toString();
	    }

	    public static String bytesToHex(byte[] data) {
	        return bytesToHex(data, data.length);
	    }

	    public static byte[] hexToBytes(String string) {
	        int length = string.length();
	        byte[] data = new byte[length / 2];
	        for (int i = 0; i < length; i += 2) {
	            data[i / 2] = (byte) ((Character.digit(string.charAt(i), 16) << 4) + Character
	                    .digit(string.charAt(i + 1), 16));
	        }
	        return data;
	}
	    
	    public byte[] getIv(){
	    	return iv;
	    }
}
