import java.util.Scanner;
import java.io.*;
import java.math.BigInteger;

//This class implements the data encryption standard (DES) encyption
public class DataEncryptionStandard {
	public static void main(String[] args) throws IOException{
		//get input file and declare scanner for reading
		//File input = new File("C:\\Users\\Landon W\\Documents\\Eclipse Workspace\\Small Projects\\CyberSecurity\\src\\alice.txt");	//for debug, not optimal
		BufferedReader input = new BufferedReader(new FileReader("C:\\Users\\Landon W\\Documents\\Eclipse Workspace\\Small Projects\\CyberSecurity\\src\\alice.txt"));
		Scanner inputReader = new Scanner(input);

		//make a file to store the binary version of input and declare a FileWriter to write to the created file
		File binary = File.createTempFile("binary", ".txt", new File("C:\\Users\\Landon W\\Documents\\Eclipse Workspace\\Small Projects\\CyberSecurity\\src"));
		FileWriter binaryWriter = new FileWriter(binary);

		//make a file to store the encrypted version of input and declare a FileWriter to write to the created file
//		File encrypt = File.createTempFile("encrypt", ".txt", new File("C:\\Users\\Landon W\\Documents\\Eclipse Workspace\\Small Projects\\CyberSecurity\\src"));
//		FileWriter encryptWriter = new FileWriter(encrypt);
		
		//make a file to store the decrypted version of input and declare a FileWriter to write to the created file
		File decrypt = File.createTempFile("decrypt", ".txt", new File("C:\\Users\\Landon W\\Documents\\Eclipse Workspace\\Small Projects\\CyberSecurity\\src"));
		FileWriter decryptWriter = new FileWriter(decrypt);
//		
		//bits is used to store binary of each word; word is to store the next word in input file
		String bits, word;
		
		//set RWE permissions for the input file and input file converted to binary
//		input.setReadable(true);
//		input.setWritable(false);		//only available if using File objects
//		input.setExecutable(false);
		binary.setReadable(true);
		binary.setWritable(true);
		binary.setExecutable(false);
		
		//convert the alice.txt file into binary
		while (inputReader.hasNext()) {
			word = inputReader.next();
			bits = new BigInteger(word.getBytes()).toString(2);		//.toString(2) means binary output; 8 for oct; 16 for hex
			if(bits.length()%8 != 0) {								//this will drop leading 0s, which is corrected with this if statement
				binaryWriter.write("0" + bits);
			} else {
				binaryWriter.write(bits);
			}
//			System.out.println(word);		//for console debug
//			System.out.println(bits);
		}
		inputReader.close();
		binaryWriter.close();		//close scanner and FileWriter

		InputStream inputStream = new FileInputStream(binary.getAbsolutePath());		//read in the binary file
		int data = inputStream.read();	//data variable for storing binary digit from file
		int ASCIICode; 					//ASCIICode for storing ASCII value
		String bytes = "", str;			//bytes for storing the next byte in the file, str to store the ASCII character from the ASCIICode value
		char c;							//to store as ASCII format, without this, it will read either 48 or 49 (0s and 1s in ASCII value)
		while(data != -1) {
			for (int i = 0; i <8; i++) {
				c = (char) data;				//for each 8 binary digits, get its ASCII value (read in a ASCII decimal), attach the value to
				bytes += c;						//the byte string, and move on
//				System.out.println(c);
				data = inputStream.read();
			}
			ASCIICode = Integer.parseInt(bytes, 2);					//convert from bytes to base 10 int
			str = new Character((char)ASCIICode).toString();		//find the ASCII character from given ASCII value
			System.out.println(str);
			decryptWriter.write(str);
			//data = inputStream.read();
			str = "";
			bytes = "";		//reset str and bytes for next round
		}
		
//		read.close();
				
//		encryptWriter.close();
		decryptWriter.close();
		//binary.deleteOnExit();	//delete binary file on completion of program
		//encrypt.deleteOnExit();	//delete encryption file on completion of program
		//decrypt.deleteOnExit();	//delete decryption file on completion of program
	}
}