import java.io.*;
import java.net.*;

public class Client {
	
	public static void main(String args[])
    {
        DatagramSocket sock = null;
        int port = 7777;
        String s;
         
        BufferedReader cin = new BufferedReader(new InputStreamReader(System.in));
         
        try
        {
            sock = new DatagramSocket();
            InetAddress host = InetAddress.getByName("localhost");
             
            while(true)
            {
                //take input and send the packet
                System.out.println("Enter message to send : ");
                s = (String)cin.readLine();
                byte[] b = s.getBytes();
                 
                DatagramPacket  dp = new DatagramPacket(b , b.length , host , port);
                sock.send(dp);
                 
            }
        }
         
        catch(IOException e)
        {
            System.err.println("IOException " + e);
        }
    }	
}
	
