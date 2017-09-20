
public class Utility {
	
	public static byte[] concatArray(byte[] one, byte[] two) {
		byte[] concatArray = new byte[one.length + two.length];
		System.arraycopy(one, 0, concatArray, 0, one.length);
		System.arraycopy(two, 0, concatArray, one.length, two.length);
		return concatArray;
	}
}
