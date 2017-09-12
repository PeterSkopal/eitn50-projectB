
import java.io.*;
import java.net.*;

public class Server {
			
	public static void main(String args[])
    {
        DatagramSocket sock = null;
        
        try{
        	sock = new DatagramSocket(7777);
        	byte[] buffer = new byte[65536];
            DatagramPacket incoming = new DatagramPacket(buffer, buffer.length);
            System.out.println("Server socket created. Waiting for incoming data...");
            
            while(true)
            {
                sock.receive(incoming);
                byte[] data = incoming.getData();
                
                String s = new String(data, 0, incoming.getLength());
                System.out.println(incoming.getAddress().getHostAddress() + " : " + incoming.getPort() + " - " + s);
            }
        
        }catch(IOException e)
        {
            System.err.println("IOException " + e);
        }
        
    }
}
