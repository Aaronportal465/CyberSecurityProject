import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;
import java.io.*;		//for BufferedReader, File, FileInputStream, FileReader, FileWriter, IOException, and InputStream
import java.math.BigInteger;

//This class implements the data encryption standard (DES) encyption
public class DataEncryptionStandard {
	//constant array tables used for encryption and decryption permutations
	private static int[] IP = {58, 50, 42, 34, 26, 18, 10,  2, 60, 52, 44, 36, 28, 20, 12,  4, 		//Initial Permutation Table
							   62, 54, 46, 38, 30, 22, 14,  6, 64, 56, 48, 40, 32, 24, 16,  8,		//(4 x 16) table
							   57, 49, 41, 33, 25, 17,  9,  1, 59, 51, 43, 35, 27, 19, 11,  3, 
							   61, 53, 45, 37, 29, 21, 13,  5, 63, 55, 47, 39, 31, 23, 15,  7};

	private static int[] PD = {57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18, 10,  2, 		//Parity Drop Permutation Table
							   59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36, 63, 55, 47, 39, 		//(3 x 16) + 8 table
							   31, 23, 15,  7, 62, 54, 46, 38, 30, 22, 14,  6, 61, 53, 45, 37, 
							   29, 21, 13,  5, 28, 20, 12,  4};
	
	private static int[] CP = {14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10, 23, 19, 12,  4, 		//Compression Permutation Table
							   26,  8, 16,  7, 27, 20, 13,  2, 41, 52, 31, 37, 47, 55, 30, 40,		//(3 x 16) table
							   51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32};
	
	private static int[] pBox = {16,  7, 20, 21, 29, 12, 28, 17,  1, 15, 23, 26,  5, 18, 31, 10, 	//P-Box Permutation Table (2 x 16)
								  2,  8, 24, 14, 32, 27,  3,  9, 19, 13, 30,  6, 22, 11,  4, 25};
	
	private static int[] FP = {40,  8, 48, 16, 56, 24, 64, 32, 39,  7, 47, 15, 55, 23, 63, 31, 		//Final Permutation Table
							   38,  6, 46, 14, 54, 22, 62, 30, 37,  5, 45, 13, 53, 21, 61, 29, 		//(4 x 16) table
							   36,  4, 44, 12, 52, 20, 60, 28, 35,  3, 43, 11, 51, 19, 59, 27, 
							   34,  2, 42, 10, 50, 18, 58, 26, 33,  1, 41,  9, 49, 17, 57, 25 };
	
	private static int[][][] sBox = {													//S-Box (8 x 4 x 16) table
	        { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
	          { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },					//S-Box for 1st 6 bit block
	          { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },			
	          { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } },
	
	        { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
	          { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },					//S-Box for 2nd 6 bit block
	          { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
	          { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } },
	        
	        { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
	          { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },					//S-Box for 3rd 6 bit block
	          { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
	          { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } },
	        
	        { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
	          { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },					//S-Box for 4th 6 bit block
	          { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
	          { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } },
	        
	        { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
	          { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },					//S-Box for 5th 6 bit block
	          { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
	          { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } },
	        
	        { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
	          { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },					//S-Box for 6th 6 bit block
	          { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
	          { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } },
	        
	        { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
	          { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },					//S-Box for 7th 6 bit block
	          { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
	          { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } },
	        
	        { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
	          { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },					//S-Box for 8th 6 bit block
	          { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
	          { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } }};
	
	public static void main(String[]args) throws IOException{
//		File input = new File("C:\\Users\\Landon W\\Documents\\Eclipse Workspace\\Small Projects\\CyberSecurity\\src\\alice.txt");	//for debug, unoptimal to reading
		//get input file and declare scanner for reading
		//debug.text is a short txt document with "Hello World" text inside it that is easily used to debug encryption and decryption
		BufferedReader input = new BufferedReader(new FileReader("C:\\Users\\Landon W\\Documents\\Eclipse Workspace\\Small Projects\\CyberSecurity\\src\\alice.txt"));
		Scanner inputReader = new Scanner(input);

		//make a file to store the binary version of input and declare a FileWriter to write to the created file
		File binary = File.createTempFile("binary", ".txt", new File("C:\\Users\\Landon W\\Documents\\Eclipse Workspace\\Small Projects\\CyberSecurity\\src"));
		FileWriter binaryWriter = new FileWriter(binary);
		
		//make a file to store the encrypted version of input and declare a FileWriter to write to the created file
		File encrypt = File.createTempFile("encrypt", ".txt", new File("C:\\Users\\Landon W\\Documents\\Eclipse Workspace\\Small Projects\\CyberSecurity\\src"));
		FileWriter encryptWriter = new FileWriter(encrypt);
		
		//make a file to store the decrypted version of encrypted text and declare a FileWriter to write to the created file
		File decrypt = File.createTempFile("decrypt", ".txt", new File("C:\\Users\\Landon W\\Documents\\Eclipse Workspace\\Small Projects\\CyberSecurity\\src"));
		FileWriter decryptWriter = new FileWriter(decrypt);
		
		File result = File.createTempFile("result", ".txt", new File("C:\\Users\\Landon W\\Documents\\Eclipse Workspace\\Small Projects\\CyberSecurity\\src"));
		FileWriter resultWriter = new FileWriter(result);
		
		//set RWE permissions for the input file and input file converted to binary
		binary.setReadable(true);
		binary.setWritable(true);
		binary.setExecutable(false);
		encrypt.setReadable(true);
		encrypt.setWritable(true);
		encrypt.setExecutable(false);
		decrypt.setReadable(true);
		decrypt.setWritable(true);
		decrypt.setExecutable(false);
		result.setReadable(true);
		result.setWritable(true);
		result.setExecutable(false);
		
		/*------------------------------------------------------------------------NOTE------------------------------------------------------------------------*
		 *There are two built in debuggings, one for advanced debugging and the other for simple and quick debugging. For advanced debugging, use the         *
		 *	debug.txt file as BufferedReader input. Simple change the "alice.txt" to "debug.txt". Then, uncomment the hardcoded key array for debugging,      *
		 *	and comment out key generater in the "array and variable" section in the encryptionmethods. Scan through the comments next to each variable to see*
		 *	what else needs to be commented out. Codes that needed to be comments out will have a comment tag saying to comment it out for debugging followed *
		 *	by 5 '*'. Advanced mode of debugging will check if the padding of 0s for uneven 64-bit texts is working properly. For simple debugging, uncomment *
		 *  the key array and the text array in the encryption/decryption methods. The while loop, along with the first section inside the while loop will    *
		 *	also need to be commented out. Scan the comments next to each variable to see what else needs to be commented out. Codes needed to be commented   *
		 *	out will have a comment tag saying to comment it out followed by 5 '*'. This mode of debugging only makes sure that a simple 64-bit block of plain*
		 *	text will be encrypted properly. Remember to reset the commments to make sure that the normal DES encryption and decryption will run properly.	  *																					  *
		//----------------------------------------------------------------------------------------------------------------------------------------------------*/

		convertToBinary(input, binary, inputReader, binaryWriter);		//convert the input file to binary for encryption
		
		long begin1 = System.currentTimeMillis();
		int[] key = desEncrypt(binary, encrypt, encryptWriter);			//encrypt the binary file (comment out if debugging decryption)******
		long end1 = System.currentTimeMillis();
		
		long begin2 = System.currentTimeMillis();
		desDecrypt(key, encrypt, decrypt, decryptWriter);				//decrypt the binary file (comment out if debugging de/encryption)******
		long end2 = System.currentTimeMillis();
		
//		desDecrypt(decrypt, decryptWriter);								//***using this to debug decryption (no key input as parameter)***
		convertToText(decrypt, result, resultWriter);					//convert the decrypted file back into readable text
		
		System.out.println("ENCRYPTION TIME: " + (end1 - begin1) + " milliseconds");
		System.out.println("DECRYPTION TIME: " + (end2 - begin2) + " milliseconds");
		
//		binary.deleteOnExit();		//delete binary file on completion of program
//		encrypt.deleteOnExit();		//delete encryption file on completion of program
//		decrypt.deleteOnExit();		//delete decryption file on completion of program
//		result.deleteOnExit();		//delete decryption file on completion of program
	}

	private static void convertToBinary(BufferedReader in, File out, Scanner inputReader, FileWriter outputWriter) throws IOException {
		inputReader = new Scanner(in);
		outputWriter = new FileWriter(out);

		String bits;			//bits is used to store binary of each word
		String recov = "";		//recov is to stored the number of dropped leading 0s
		String word;			//word is to store the next word in input file

		while (inputReader.hasNext()) {									//convert the alice.txt file into binary
			word = inputReader.next();
			bits = new BigInteger(word.getBytes()).toString(2);			//.toString(2) means binary output; 8 for oct; 16 for hex
			if(bits.length() % 8 != 0) {								//this will drop leading 0s, which is corrected with this if statement
				for(int i = 0; i < (8 - (bits.length() % 8)); i++) {
					recov += "0";										//Find how many leading binary 0s were dropped by cnvertting to BigIntergery
				}
//				System.out.println(word + ": " + recov + bits);			//for binary conversion debugging
				if(inputReader.hasNext()) {
					outputWriter.write(recov + bits + "00100000");		//00100000 is the binary for a space
				} else {
					outputWriter.write(recov + bits);					//end of file, dont add space
				}
				recov = "";												//resetting recov for next round
			} else {
//				System.out.println(word + ":" + bits);					//for binary conversion debugging
				if(inputReader.hasNext()) {
					outputWriter.write(bits + "00100000");
				} else {
					outputWriter.write(bits);
				}
			}
		}
		
		inputReader.close();
		outputWriter.close();
	}
	
	private static void convertToText(File in, File out, FileWriter outputWriter) throws IOException {
		outputWriter = new FileWriter(out);
		
		InputStream inputStream = new FileInputStream(in.getAbsolutePath());		//read in the binary file
		int data = inputStream.read();			//data variable for storing binary digit from file
		int ASCIICode; 							//ASCIICode for storing ASCII value
		String bytes = "", str;					//bytes for storing the next byte in the file, str to store the ASCII character from the ASCIICode value
		char c;									//to store as ASCII format, without this, it will read either 48 or 49 (0s and 1s in ASCII value)
		
		while(data != -1) {
			for (int i = 0; i <8; i++) {
				c = (char) data;				//for each 8 binary digits, get its ASCII value (read in a ASCII decimal), attach the value to
				bytes += c;						//the byte string, and move on
//				System.out.println(c);			//for console debugging
				data = inputStream.read();
			}
			ASCIICode = Integer.parseInt(bytes, 2);					//convert from bytes to base 10 int
			str = new Character((char)ASCIICode).toString();		//find the ASCII character from given ASCII value
//			System.out.println(str);			//for console debugging
			outputWriter.write(str);
			str = "";
			bytes = "";							//reset str and bytes for next round
		}
		outputWriter.close();
	}

	/*DES Steps:
	 * 	1) 64 bit plain text block permutated with initial permutation function and split into left and right halves
	 *  2) 64 bit key goes through parity drop function and then has the rest of the key permutated by table to
	 *     create a 56 bit key
	 * 	3) 16 rounds of encryption process is preformed on the 2 halfs of the plain text with 56-bit key
	 * 		i)	56-bit key split into halfs and changes each round using the circular left shift method. Each round
	 * 			has a shift of 2 except for rounds 1, 2, 9, and 16, which has a shift one 1. Then the keys are
	 * 			combined back together and reordered according to the compression permutation table. In compression
	 * 			permutation, the 9th, 18th, 22nd, 25th, 35th, 38th, 43rd, and 54th bits are left out.
	 * 		ii)	The plain text goes through expansion permutation and then is XOR with key. Only the right half of
	 * 			the plain text goes through this. This half is divided into 8 blocks of 4 bits. Then each of the 4
	 * 			is expended into 6 bits to produce a 48 bit output. This is done by having the first bit of a block
	 * 			to be attached to the end of the previous block (end of last block if working with the very fist 
	 * 			block) and the last bit of the block to be attached to the beginning of the next block (beginning to 
	 * 			very fist block if working with very last block). The 48-bit key is now XOR with this output.
	 * 		iii)The plain text then goes through a S-box substitution. This will shrink the right half text back
	 * 			down to 32 bits. The 48 bits will be divided into 8 6-bit blocks. The fist and last bit of the 6 bit
	 * 			block will determine the row of the S-box while the middle 4 bits will determine the column of the
	 * 			s-box. There are 8 s-boxes, each for the respective block.
	 * 		iv)	The plain text then goes through a P-box permutation using the straight permutation table
	 * 	4) The right plain text now becomes the left plain text for the next round and is also XOR with left plain 
	 * 	   text to create the right plain text for next round
	 *  5) 2 halfs of the plain text are recombined and a final permutation is preformed on it
	*/
	private static int[] desEncrypt(File in, File out, FileWriter outputWriter) throws IOException {
		System.out.println("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<START OF ENCRPTION>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
		InputStream inputStream = new FileInputStream(in.getAbsolutePath());		//read in the binary file (comment this out if using simple debugging)*****
		outputWriter = new FileWriter(out);	//to write the encrypted text to a encrypted text file (comment this out if using simple debugging)*****
		
		//arrays and variables
		int[] key = generateKey();			//to store 64 bit key matrix (comment this out if using advanced and simple debugging key)**********
		int[] permutatedKey = new int[56];	//to store 56 bit parity dropped permutation key
		int[] roundKey = new int[48];		//to store 48 bit individual round keys
		int[] plainText = new int[64];		//to store 64 bit plain text (comment this out if using simple debugging)*****
		int[] encryptedText = new int[64];	//to store the final combined text for final permutation
		int[] lpt = new int[32];			//to hold the left half of the plain text
		int[] rpt = new int[32];			//to hold the right half of the plain text
		int[] eRPT = new int[48];			//to hold the expansion permutation of right plain text
		int[] rRPT = new int[32];			//to hold the reduced right plain text through s-box reduction
		int[] lKey = new int[28];			//to hold the left half of the generated key
		int[] rKey = new int[28];			//to hold the right half of the generated key
		int[] temp = new int[32];			//used for XOR with rpt

		int data = inputStream.read();		//to take the the file binaries bit by bit (comment this out if using simple debugging)*****
		int paddingPointer = 0;				//to point to where the end of the padding is (comment this out if using simple debugging)*****
		long fileLength = in.length();		//take in the file length so program can know if padding is needed (comment this out if using simple debugging)*****
		long filePointer = 0;				//to keep track where in the file the program is at (comment this out if using simple debugging)*****
		StringBuilder s = new StringBuilder();
		
//		int[] key = new int[] {1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 				//this is the key used for debugging
//							   0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 				//comment this out when done degugging
//							   0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 
//							   0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1};
//		int[] plainText = new int[] {0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 		//this is the plain text for debugging
//									 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 		//comment this out when doen debugging
//									 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 
//									 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1};
					
		lengthPermutation(key, permutatedKey, PD);			//Permutate the key with Parity Drop Table (dropping every 8th bit), new length of 56
		System.out.print("Permutated Key: \t\t");
		printArray(permutatedKey);
		
		while(filePointer < fileLength) {		//comment this out if using simple debugging*****
			//***************************************************COMMENT THESE OUT IF USING SIMPLE DEBUGGING************************************************************
			//obtaining 64 bit plain text
			if((filePointer + 64) > fileLength) {									//the last few bits are not enough to make 64 bits, therefore padding is needed
				paddingPointer = (int)(64 - (fileLength - filePointer));			//find how many padding of 0s are needed
				for(int i = (64 - paddingPointer); i < 64; i++) {					//attach the paddings to end to make 64 bits
					plainText[i] = 0;
				}
				for(int i = 0; i < (64 - paddingPointer); i++) {					//fill in the rest of the 64 bit block with binary plain text
					plainText[i] = Integer.parseInt(String.valueOf((char)data));	//char cast int (ASCII dec value) to get 1s and 0s, change to String, then parse
					data = inputStream.read();										//	to int (1s and 0s as values)
				}
			} else {
				for(int i = 0; i < 64; i++) {										//there are enough bits to make a 64 bit block
					plainText[i] = Integer.parseInt(String.valueOf((char)data));
					data = inputStream.read();
				}
			}		
			filePointer += 64;												//advance pointer to the start of the next 64 bit block
			//**********************************************************************************************************************************************************
//			System.out.print("The Current 64-Bit Plain Text: \t");
//			printArray(plainText);

			permutation(plainText, IP);										//initial permutation and splitting of plain text	
//			System.out.print("Permutated 64-Bit Plain Text: \t");
//			printArray(plainText);

			lpt = Arrays.copyOfRange(plainText, 0, 32);						//obtaining the left half of the plain text
//			System.out.print("The Left 64-Bit Plain Text: \t");
//			printArray(lpt);

			rpt = Arrays.copyOfRange(plainText, 32, 64);					//obtaining the right half of the plain text
//			System.out.print("The Right 64-Bit Plain Text: \t");
//			printArray(rpt);
			
			//16 rounds of encryption
			for(int i = 1; i <= 16; i++) {
//				System.out.println("\t\t----------------------------------------ROUND " + i + "----------------------------------------");
//				System.out.print("Start Left Half Text: \t\t");
//				printArray(lpt);												//***For these print statements and printArray(), uncomment
//																				//	 specific ones to see the output after its step. This
//				System.out.print("Start Right Half Text: \t\t");				//	 is mainly used to see if a spefic output is achieved
//				printArray(rpt);												//	 after executing a specific step. However, the more
																				//	 uncommented, the longer the executiion time is***
				lKey = Arrays.copyOfRange(permutatedKey, 0, 28);
//				System.out.print("Left Half Secret Key: \t\t");
//				printArray(lKey);
				
				circularLeftKeyShift(lKey, i);								//creating 28 bit left half key
//				System.out.print("Circulated Left Half Key: \t");
//				printArray(lKey);
				
				rKey = Arrays.copyOfRange(permutatedKey, 28, 56);
//				System.out.print("Right Half Secret Key: \t\t");			
//				printArray(rKey);											
				
				circularLeftKeyShift(rKey, i);								//creating 28 bit right half key
//				System.out.print("Circulated Right Half Key: \t");
//				printArray(rKey);
				
				merge(lKey, rKey, permutatedKey);
//				System.out.print("New Permutated Key: \t\t");
//				printArray(permutatedKey);
				
				lengthPermutation(permutatedKey, roundKey, CP);				//permutated key now length of 48 bits
//				System.out.print("Individual Round Key: \t\t");
//				printArray(roundKey);
				
				expansionPermutation(rpt, eRPT);							//right plain text now length of 48 bits
//				System.out.print("Expanded Right Plain Text: \t");
//				printArray(eRPT);
				
				XOR(eRPT, roundKey);										//XOR the expanded right half of text with round key
//				System.out.print("eRPT XOR With Round Key: \t");
//				printArray(eRPT);
				
				sBox(eRPT, sBox, rRPT);										//right plain text now length of 32 bits
//				System.out.print("Reduced eRPT With S-Box: \t");
//				printArray(rRPT);
				
				permutation(rRPT, pBox);									//permutate the right plain text with P-box
//				System.out.print("Permutated rRPT With P-Box: \t");
//				printArray(rRPT);
				
				deepCopy(lpt, temp);										//swap left plain text and right plain text while XOR lpt with rpt for new rpt
//				System.out.println("\t\t********************Swapping Right-Left Plain Texts:********************");
//				System.out.print("Left Half Plain Text: \t\t");
//				printArray(lpt);
//				System.out.print("Right Half Plain Text: \t\t");
//				printArray(rRPT);
//				System.out.print("*Temporary Text Holder*: \t");
//				printArray(temp);
//				System.out.println("\t\t************************************************************************");
				
				deepCopy(rpt, lpt);
//				System.out.print("*Left Half Plain Text*: \t\t");
//				printArray(lpt);
//				System.out.print("Right Half Plain Text: \t\t");
//				printArray(rRPT);
//				System.out.print("Temporary Text Holder: \t");
//				printArray(temp);
//				System.out.println("\t\t************************************************************************");
				
				XOR(rRPT, temp);						
//				System.out.print("Reduced RPT XOR LPT: \t\t");
//				printArray(rRPT);
				
				deepCopy(rRPT, rpt);										//end of encryption round
//				System.out.print("Left Half Plain Text: \t\t");
//				printArray(lpt);
//				System.out.print("*Right Half Plain Text*: \t");
//				printArray(rRPT);
//				System.out.print("Temporary Text Holder: \t");
//				printArray(temp);
//				System.out.println("\t\t************************************************************************");
				
//				System.out.print("New Left Half Text: \t\t");
//				printArray(lpt);
//				
//				System.out.print("New Right Half Text: \t\t");
//				printArray(rpt);
			}
			merge(rpt, lpt, encryptedText);					//at the end of the 16th round, combine rpt and lpt to form encrypted text
//			System.out.print("Encrypted Text: \t\t");		//the two halves are swapping again at the end
//			printArray(encryptedText);
			
			permutation(encryptedText, FP);					//final permutation of th encrypted text
//			System.out.print("Permutated Encrypted Text: \t");
//			printArray(encryptedText);
					
			for(int bit : encryptedText) {					//change the encryted binary text array into string binary text
				s.append(bit);								
			}
			outputWriter.write(s.toString());				//write the encrypted string into the linked encrypt file
			s.delete(0, s.length());						//reset the string builder for the next 6 bit block
			
//			if(filePointer < fileLength) {
//				System.out.println("=============================================Next 64-Bit Plain Text Set=============================================");
//			}
		}		//Closing bracket for while loop (comment this out if using simple debugging)*****
		
		System.out.println("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<END OF ENCRPTION>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
			
		outputWriter.close();
		return key;
	}
	
	//Decryption is almost same as encryption		***remove key and in parameter variables if debugging, because hardcoded key and text is set******
	private static void desDecrypt(int[] key, File in, File out, FileWriter outputWriter) throws IOException {
		System.out.println("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<START OF DECRPTION>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");

		InputStream inputStream = new FileInputStream(in.getAbsolutePath());		//read in the binary file	(comment out if simple debugging)*****
		outputWriter = new FileWriter(out);	//to write the encrypted text to a decrypted text file (comment out if using simple debugging)*****
		
		//arrays and variables used in DES decryption
		int[] permutatedKey = new int[56];	//to store 56 bit parity dropped permutation key
		int[] roundKey = new int[48];		//to store 48 bit individual round keys
		int[] encryptedText = new int[64];	//to store 64 bit encrypted text (comment this out if using simple debugging)*****
		int[] decryptedText = new int[64];	//to store the final combined text for final permutation
		int[] let = new int[32];			//to hold the left half of the encrypted text
		int[] ret = new int[32];			//to hold the right half of the encrypted text
		int[] eRPT = new int[48];			//to hold the expansion permutation of right plain text
		int[] rRPT = new int[32];			//to hold the reduced right encrypted text through s-box reduction
		int[] lKey = new int[28];			//to hold the left half of the generated key
		int[] rKey = new int[28];			//to hold the right half of the generated key
		int[] temp = new int[32];			//used for XOR with rpt
		List<int[]> roundKeySet = new ArrayList<int[]>();

		int data = inputStream.read();		//to take in the file of binaries bit by bit (comment this out if using simple debugging)*****
		int paddingPointer = 0;				//to point to where the end of the padding is (comment this out if using simple debugging)*****
		long fileLength = in.length();		//take in the file length so program can know if padding is needed (comment this out if using simple debugging)*****
		long filePointer = 0;				//to keep track where in the file the program is at
		StringBuilder s = new StringBuilder();
		
//		int[] key = new int[] {1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 				//this is the key used for debugging; comment out when done degugging
//							   0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1,
//							   0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 
//							   0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1};
//		int[] encryptedText = new int[] {1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 	//this is encrypted text for debugging; comment out when done debugging
//										 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1,
//										 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 
//										 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1};
					
		lengthPermutation(key, permutatedKey, PD);			//Permutate the key with Parity Drop Table (dropping every 8th bit), new length of 56
		System.out.print("Permutated Key: \t\t\t");
		printArray(permutatedKey);
		
		for(int i = 1; i <= 16; i++) {						//difference between encryption and decryption is that we start backwards for key shifting order and
			int[] tempKey = new int[48];					//because of this, I decided to get the individual round keys beforehand to make implementation easier
			lKey = Arrays.copyOfRange(permutatedKey, 0, 28);	
//			System.out.print("Left Half Secret Key: \t\t");
//			printArray(lKey);
			
			circularLeftKeyShift(lKey, i);					//creating 28 bit left half of secret key
//			System.out.print("Circulated Left Half Key: \t");
//			printArray(lKey);
			
			rKey = Arrays.copyOfRange(permutatedKey, 28, 56);
//			System.out.print("Right Half Secret Key: \t\t");
//			printArray(rKey);
			
			circularLeftKeyShift(rKey, i);					//creating 28 bit right half of secret key
//			System.out.print("Circulated Right Half Key: \t");
//			printArray(rKey);
			
			merge(lKey, rKey, permutatedKey);
//			System.out.print("New Permutated Key: \t\t");
//			printArray(permutatedKey);
			
			lengthPermutation(permutatedKey, tempKey, CP);	//permutated key now length of 48 bits
//			System.out.print("Individual Round Key: \t\t");
//			printArray(tempKey);
			
			roundKeySet.add(tempKey);
		}
		
		while(filePointer < fileLength) {		//comment this out if using simple debugging*****
			//***************************************************COMMENT THESE OUT IF USING SIMPLE DEBUGGING************************************************************
			//obtaining 64 bit plain text
			if((filePointer + 64) > fileLength) {									//the last few bits are not enough to make 64 bits, therefore padding is needed
				paddingPointer = (int)(64 - (fileLength - filePointer));			//find how many padding of 0s are needed
				for(int i = (64 - paddingPointer); i < 64; i++) {					//attach the paddings to end to make 64 bits
					encryptedText[i] = 0;
				}
				for(int i = 0; i < (64 - paddingPointer); i++) {					//fill in the rest of the 64 bit block with binary encrypted text
					encryptedText[i] = Integer.parseInt(String.valueOf((char)data));//char cast int (ASCII dec value) to get 1s and 0s, change to String, then parse
					data = inputStream.read();										//	to int (1s and 0s as values)
				}
			} else {
				for(int i = 0; i < 64; i++) {										//there are enough bits to make a 64 bit block
					encryptedText[i] = Integer.parseInt(String.valueOf((char)data));
					data = inputStream.read();
				}
			}		
			filePointer += 64;													//advance pointer to the start of the next 64 bit block of encrypted text
			//**********************************************************************************************************************************************************
//			System.out.print("The Current 64-Bit Encrypted Text: \t");
//			printArray(encryptedText);

			permutation(encryptedText, IP);										//initial permutation and splitting of encrypted text	
//			System.out.print("Permutated 64-Bit Encrypted Text: \t");
//			printArray(encryptedText);

			let = Arrays.copyOfRange(encryptedText, 0, 32);						//obtaining the left half of the encrypted text
//			System.out.print("The Left 64-Bit Encrypted Text: \t");
//			printArray(let);

			ret = Arrays.copyOfRange(encryptedText, 32, 64);					//obtaining the right half of the encrypted text
//			System.out.print("The Right 64-Bit Encrypted Text: \t");
//			printArray(ret);
			
			for(int i = 1; i <= 16; i++) {						//16 rounds of encryption
//				System.out.println("\t\t----------------------------------------ROUND " + i + "----------------------------------------");
				roundKey = roundKeySet.get(16 - (i -1) - 1);	//source from the set of the round keys, but backwards
//				System.out.print("Individual Round Key: \t\t");
//				printArray(roundKey);
//				
//				System.out.print("Start Left Half Text: \t\t");
//				printArray(let);
//				
//				System.out.print("Start Right Half Text: \t\t");
//				printArray(ret);
				
				expansionPermutation(ret, eRPT);				//right encrypted text now length of 48 bits
//				System.out.print("Expanded Right Plain Text: \t");
//				printArray(eRPT);
				
				XOR(eRPT, roundKey);							//XOR the expanded right half of encrypted text with round key
//				System.out.print("eRPT XOR With Round Key: \t");
//				printArray(eRPT);
				
				sBox(eRPT, sBox, rRPT);							//right encrypted text now length of 32 bits
//				System.out.print("Reduced eRPT With S-Box: \t");
//				printArray(rRPT);
				
				permutation(rRPT, pBox);						//permutate the right encrypted text with P-box
//				System.out.print("Permutated rRPT With P-Box: \t");
//				printArray(rRPT);
//				
				deepCopy(let, temp);							//swap left plain text and right encrypted text while XOR lpt with rpt for new rpt
//				System.out.println("\t\t********************Swapping Right-Left Plain Texts:********************");
//				System.out.print("Left Half Encrypted Text: \t");
//				printArray(lpt);
//				System.out.print("Right Half Encrypted Text: \t");
//				printArray(rRPT);
//				System.out.print("*Temporary Text Holder*: \t");
//				printArray(temp);
//				System.out.println("\t\t************************************************************************");
				
				deepCopy(ret, let);
//				System.out.print("*Left Half Encrypted Text*: \t");
//				printArray(lpt);
//				System.out.print("Right Half Encrypted Text: \t");
//				printArray(rRPT);
//				System.out.print("Temporary Text Holder: \t");
//				printArray(temp);
//				System.out.println("\t\t************************************************************************");
				
				XOR(rRPT, temp);						
//				System.out.print("Reduced RPT XOR LPT: \t\t");
//				printArray(rRPT);
				
				deepCopy(rRPT, ret);							//end of decryption round
//				System.out.print("Left Half Encrypted Text: \t");
//				printArray(lpt);
//				System.out.print("*Right Half Encrypted Text*: \t");
//				printArray(rRPT);
//				System.out.print("Temporary Text Holder: \t");
//				printArray(temp);
//				System.out.println("\t\t************************************************************************");
				
//				System.out.print("New Left Half Text: \t\t");
//				printArray(let);
//				
//				System.out.print("New Right Half Text: \t\t");
//				printArray(ret);
			}
			merge(ret, let, decryptedText);						//at the end of the 16th round, combine rpt and lpt to form decrypted text
//			System.out.print("Decrypted Text: \t\t");			//the two halves are swapping again at the end
//			printArray(decryptedText);
			
			permutation(decryptedText, FP);						//final permutation of th decrypted text
//			System.out.print("Permutated Decrypted Text: \t");
//			printArray(decryptedText);
					
			for(int bit : decryptedText) {						//change the decryted binary text array into string binary text
				s.append(bit);								
			}
			outputWriter.write(s.toString());					//write the decrypted string into the linked encrypt file
			s.delete(0, s.length());							//reset the string builder for the next 6 bit block
			
//			if(filePointer < fileLength) {						//comment this out if using simple debugging*****
//				System.out.println("============================================Next 64-Bit Plain Text Set=============================================");
//			}
		}		//Closing bracket for while loop (comment this out if using simple debugging)******
		
		System.out.println("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<END OF DECRPTION>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");

		outputWriter.close();
	}
	
	private static int[] generateKey() {
		int[] key = new int[64];
		String hexKey = "";

		for(int i = 0; i < 16; i++) {			//get a string of 16 character HEX digits
			hexKey += String.format("%x",(int)(Math.random()*(15-0+1) + 0));
		}
		System.out.println("The Hexadecimal Key: \t\t" + hexKey);
		
		long val = 0;
        String digits = "0123456789ABCDEF";
        String recov = "";						//these blocks will convert HEX to binary by converting it to decimal first
        String binaryKey;
		hexKey = hexKey.toUpperCase();
		for (int i = 0; i < hexKey.length(); i++)
        {
            char c = hexKey.charAt(i);
            int d = digits.indexOf(c);
            val = 16*val + d;
        }
		binaryKey = Long.toBinaryString(val);
		if(binaryKey.length() % 8 != 0) {		//this will drop leading 0s, which is corrected with this if statement
			for(int i = 0; i < (8 - (binaryKey.length() % 8)); i++) {
				recov += "0";					//Find how many leading binary 0s were dropped by cnvertting to BigIntergery
			}
		}
		binaryKey = recov + binaryKey;
		
		int keyPointer = 0;
		for(int i = 0; i < 64; i++) {			//place key into array matrix
				key[i] = Integer.parseInt(String.valueOf(binaryKey.charAt(keyPointer)));
				keyPointer++;

		}
		
		System.out.print("The Binary Key: \t\t");
		printArray(key);
		
		return key;
	}
	
	private static void permutation(int[] input, int[] per) {				
		int[] permutated = new int[input.length];
		
		for(int i = 0; i < input.length; i++) {
			permutated[i] = input[per[i] - 1];
		}			//go through the initial permuation table and change the bit sequences
		
		deepCopy(permutated, input);
	}
	
	private static void lengthPermutation(int[] input, int[] output, int[] per) {
		for(int i = 0; i < output.length; i++) {
			output[i] = input[per[i] - 1];
		}			//go through the initial permuation table and change the bit sequences
	}
	
	private static void circularLeftKeyShift(int[] key, int round) {
		int temp;
		if(round == 1 || round == 2 || round == 9 || round == 16) {	//rounds 1, 2, 9, and 16 only shifts 1 place
			temp = key[0];					//hold on to the first element
			for(int i = 0; i < key.length - 1; i++) {
				key[i] = key[i+1];			//shift everything left one index
			}
			key[key.length - 1] = temp;		//insert first element into last index
		} else {
			for(int i = 0; i < 2; i++) {							//other rounds shift 2 index, so 2 iteration
				temp = key[0];
				for(int j = 0; j < key.length - 1; j++) {
					key[j] = key[j+1];
				}
				key[key.length - 1] = temp;
			}
		}
	}
	
	private static void merge(int[] a, int[] b, int[] result) {		
		int length = a.length;
		for (int i = 0; i < length; i = i + 1) {
			result[i] = a[i];
			result[length + i] = b[i];
		}
	}
	
	private static void expansionPermutation(int[] in, int[] out) {
		int eRPTPointer = 1, rptPointer = 0, limit = 0;
		
		out[0] = in[31];				//in expansion permutation, first bit is last bit of right plain text
		out[47] = in[0];				//in expension permutation, last bit is first bit of right plain text
		
		while(eRPTPointer < 47) {		//since first and last bit is set, work on the inner ones
			limit = rptPointer;			//limit variable is used to keep constant track of next 4 bit in right plain text
			for(int j = rptPointer; j < (limit + 4); j++) {	//(limit + 4) used to set the 4 bit blocks
				out[eRPTPointer] = in[rptPointer];		//copy the next 4 bit into expanded permutation text
				eRPTPointer++;			//move the pointers to keep track of bit locations
				rptPointer++;
			}
			if(eRPTPointer == 47) {		//if at the end of the expanded text, break and stop executing the following
				break;
			}
			out[eRPTPointer] = in[rptPointer];		//copy the start of the next rpt 4 bit block to be the end of
			eRPTPointer++;							//current 6 bit block and advance expanded text pointer
			out[eRPTPointer] = in[rptPointer - 1];	//copy the end of the last 4 bit block to be the start of
			eRPTPointer++;							//current 6 bit block and advance expanded text pointer
		}
	}
	
	private static void XOR(int[] arr, int[] with) {
		for(int i = 0; i < arr.length; i++) {
			if(arr[i] == 0 && with[i] == 0) {
				arr[i] = 0;
			} else if(arr[i] == 0 && with[i] == 1) {
				arr[i] = 1;
			} else if(arr[i] == 1 && with[i] == 0) {
				arr[i] = 1;
			} else if(arr[i] == 1 && with[i] == 1) {
				arr[i] = 0;
			}
		}
	}
	
	private static void sBox(int[] in, int[][][] sbox, int[] out) {
		int start = 0, end = 6;					//pointers to creak "blocks"
		int sBoxInt;							//to hold the number obtained from s box
		int rRPTPointer = 0;					//to keep track of the rRPT index
		String newBlock ;						//to store new 4 bit of rRPT block
		String outterBit, innerBits;			//to store outer 2 bits and inner 4 bits
		String recov = "";
		StringBuilder s = new StringBuilder();	//to store 6 bit of eRPT blocks
		
		for(int i = 0; i < 8; i++) {
			for(int j = start; j < end; j++) {
				s.append(String.valueOf(in[j]));			//get the 6 bit blocks
			}
			start = end;
			end += 6;
			outterBit = String.valueOf(s.charAt(0)) + String.valueOf(s.charAt(5));		//get the outer two binary
			innerBits = s.substring(1, 5);												//get the inner 4 binary
			sBoxInt = sbox[i][Integer.parseInt(outterBit, 2)][Integer.parseInt(innerBits, 2)];	//use outter and inner binary as row and col indexes
			newBlock = Integer.toBinaryString(sBoxInt);						//convert the integer into binary string, but may not be 4 bit
			
			if(newBlock.length() % 4 != 0) {								//same idea as in convertToBinary() method, but used 4 bits instead of 8
				for(int j = 0; j < (4 - (newBlock.length() % 4)); j++) {
					recov += "0";			
				}
			}
			newBlock = recov + newBlock;
			recov = "";
			
			for(int j = 0; j < 4; j++) {															//input new 4 bit binary digits into reduced right plain text
				out[rRPTPointer] = Integer.parseInt(String.valueOf((char)newBlock.charAt(j)));		//same idea as getting 64 bit plain text 48s for 0s and 49s for 1s)
				rRPTPointer++;
			}
			
			s.delete(0, s.length());		//reset the string builder for the next 6 bit block
		}
	}
	
	private static void deepCopy(int[] from, int[] to) {
		for(int i = 0; i < from.length; i++) {
			to[i] = from[i];
		}
	}

	private static void printArray(int[] arr) {
		for(int i : arr) {
			System.out.print(i);
		}
		System.out.println();
		System.out.println();
	}
}