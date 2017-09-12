import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;


public class DiffieHellman {
	
	
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
}
