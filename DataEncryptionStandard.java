import java.util.Arrays;
import java.util.Scanner;
import java.io.*;		//for BufferedReader, File, FileInputStream, FileReader, FileWriter, IOException, and InputStream
import java.math.BigInteger;

//This class implements the data encryption standard (DES) encyption
public class DataEncryptionStandard {
	public static void main(String[]args) throws IOException{
		//get input file and declare scanner for reading
//		File input = new File("C:\\Users\\Landon W\\Documents\\Eclipse Workspace\\Small Projects\\CyberSecurity\\src\\alice.txt");	//for debug, unoptimal to reading
		BufferedReader input = new BufferedReader(new FileReader("C:\\Users\\Landon W\\Documents\\Eclipse Workspace\\Small Projects\\CyberSecurity\\src\\alice.txt"));
		Scanner inputReader = new Scanner(input);

		//make a file to store the binary version of input and declare a FileWriter to write to the created file
		File binary = File.createTempFile("binary", ".txt", new File("C:\\Users\\Landon W\\Documents\\Eclipse Workspace\\Small Projects\\CyberSecurity\\src"));
		FileWriter binaryWriter = new FileWriter(binary);
		
		//make a file to store the encrypted version of input and declare a FileWriter to write to the created file
//		File encrypt = File.createTempFile("encrypt", ".txt", new File("C:\\Users\\Landon W\\Documents\\Eclipse Workspace\\Small Projects\\CyberSecurity\\src"));
//		FileWriter encryptWriter = new FileWriter(encrypt);
		
		//make a file to store the decrypted version of input and declare a FileWriter to write to the created file
//		File decrypt = File.createTempFile("decrypt", ".txt", new File("C:\\Users\\Landon W\\Documents\\Eclipse Workspace\\Small Projects\\CyberSecurity\\src"));
//		FileWriter decryptWriter = new FileWriter(decrypt);
		
		//set RWE permissions for the input file and input file converted to binary
//		input.setReadable(true);
//		input.setWritable(false);		//only available if using File objects
//		input.setExecutable(false);
		binary.setReadable(true);
		binary.setWritable(true);
		binary.setExecutable(false);
		
		convertToBinary(input, binary, inputReader, binaryWriter);		//convert the input file to binary for encryption
		desEncrypt(binary);												//encrypt the binary file
//		convertToText(binary, decrypt, decryptWriter);					//convert the decrypted file back into readable text
		System.out.println("DONE");
		
//		encryptWriter.close();
//		binary.deleteOnExit();		//delete binary file on completion of program
//		encrypt.deleteOnExit();		//delete encryption file on completion of program
//		decrypt.deleteOnExit();		//delete decryption file on completion of program
	}

	private static void convertToBinary(BufferedReader in, File out, Scanner inputReader, FileWriter binaryWriter) throws IOException {
		inputReader = new Scanner(in);
		binaryWriter = new FileWriter(out);

		String bits;			//bits is used to store binary of each word
		String recov = "";		//recov is to stored the number of dropped leading 0s
		String word;			//word is to store the next word in input file

		while (inputReader.hasNext()) {		//convert the alice.txt file into binary
			word = inputReader.next();
			bits = new BigInteger(word.getBytes()).toString(2);			//.toString(2) means binary output; 8 for oct; 16 for hex
			if(bits.length() % 8 != 0) {								//this will drop leading 0s, which is corrected with this if statement
				for(int i = 0; i < (8 - (bits.length() % 8)); i++) {
					recov += "0";			//Find how many leading binary 0s were dropped by cnvertting to BigIntergery
				}
//				System.out.println(word + ": " + recov + bits);			//for binary conversion debugging
				binaryWriter.write(recov + bits + "00100000");			//00100000 is the binary for a space
				recov = "";					//resetting recov for next round
			} else {
//				System.out.println(word + ":" + bits);					//for binary conversion debugging
				binaryWriter.write(bits + "00100000");
			}
		}
		
		inputReader.close();
		binaryWriter.close();
	}
	
	private static void convertToText(File in, File out, FileWriter decryptWriter) throws IOException {
		decryptWriter = new FileWriter(out);
		
		InputStream inputStream = new FileInputStream(in.getAbsolutePath());		//read in the binary file
		int data = inputStream.read();			//data variable for storing binary digit from file
		int ASCIICode; 							//ASCIICode for storing ASCII value
		String bytes = "", str;					//bytes for storing the next byte in the file, str to store the ASCII character from the ASCIICode value
		char c;									//to store as ASCII format, without this, it will read either 48 or 49 (0s and 1s in ASCII value)
		
		while(data != -1) {
			for (int i = 0; i <8; i++) {
				c = (char) data;			//for each 8 binary digits, get its ASCII value (read in a ASCII decimal), attach the value to
				bytes += c;					//the byte string, and move on
//				System.out.println(c);		//for console debugging
				data = inputStream.read();
			}
			ASCIICode = Integer.parseInt(bytes, 2);					//convert from bytes to base 10 int
			str = new Character((char)ASCIICode).toString();		//find the ASCII character from given ASCII value
//			System.out.println(str);		//for console debugging
			decryptWriter.write(str);
			str = "";
			bytes = "";						//reset str and bytes for next round
		}
		decryptWriter.close();
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
	private static void desEncrypt(File binary) throws IOException {
		InputStream inputStream = new FileInputStream(binary.getAbsolutePath());		//read in the binary file
		
		//arrays and variables
		int[] key = generateKey();			//to store 64 bit key matrix
		int[] permutatedKey;				//to store 56 bit parity dropped permutation key
		int[] roundKey = null;				//to store 48 bit individual round keys
		int[] plainText = new int[64];		//to store 64 bit plain text
		int[] encryptedText = new int[64];	//to store the final combined text for final permutation
		int[] lpt = new int[32];			//to hold the left half of the plain text
		int[] rpt = new int[32];			//to hold the right half of the plain text
		int[] eRPT = new int[48];			//to hold the expansion permutation of right plain text
		int[] rRPT = new int[32];			//to hold the reduced right plain text through s-box reduction
		int[] lKey = new int[28];			//to hold the left half of the generated key
		int[] rKey = new int[28];			//to hold the right half of the generated key
		
		int data = inputStream.read();		//to take the the file binaries bit by bit
		
		//Constants
		int[] IP = {58, 50, 42, 34, 26, 18, 10,  2, 60, 52, 44, 36, 28, 20, 12,  4, 		//Initial Permutation Table
					62, 54, 46, 38, 30, 22, 14,  6, 64, 56, 48, 40, 32, 24, 16,  8,			//(4 x 16) table
					57, 49, 41, 33, 25, 17,  9,  1, 59, 51, 43, 35, 27, 19, 11,  3, 
					61, 53, 45, 37, 29, 21, 13,  5, 63, 55, 47, 39, 31, 23, 15,  7};
		int[] PD = {57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18, 10,  2, 		//Parity Drop Permutation Table
					59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36, 63, 55, 47, 39, 		//(3 x 16) + 8 table
					31, 23, 15,  7, 62, 54, 46, 38, 30, 22, 14,  6, 61, 53, 45, 37, 
					29, 21, 13,  5, 28, 20, 12,  4};
		int[] CP = {14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10, 23, 19, 12,  4, 		//Compression Permutation Table
					26,  8, 16,  7, 27, 20, 13,  2, 41, 52, 31, 37, 47, 55, 30, 40,			//(3 x 16) table
					51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32};
		 int[] pBox = {16,  7, 20, 21, 29, 12, 28, 17,  1, 15, 23, 26,  5, 18, 31, 10, 		//P-Box Permutation Table (2 x 16)
				 	 2,  8, 24, 14, 32, 27,  3,  9, 19, 13, 30,  6, 22, 11,  4, 25};
		int[] FP = {40,  8, 48, 16, 56, 24, 64, 32, 39,  7, 47, 15, 55, 23, 63, 31, 		//Final Permutation Table
					38,  6, 46, 14, 54, 22, 62, 30, 37,  5, 45, 13, 53, 21, 61, 29, 		//(4 x 16) table
					36,  4, 44, 12, 52, 20, 60, 28, 35,  3, 43, 11, 51, 19, 59, 27, 
					34,  2, 42, 10, 50, 18, 58, 26, 33,  1, 41,  9, 49, 17, 57, 25 };
		int[][][] sBox = {																	//S-Box (8 x 4 x 16) table
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
	              { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } }
	        };
		
		while(data != -1) {
			//obtaining 64 bit plain text
			for(int i = 0; i < 64; i++) {
				plainText[i] = data;
				data = inputStream.read();
			}

			//initial permutation and splitting of plain text
			plainText = permutation(plainText, IP);
			lpt = Arrays.copyOfRange(plainText, 0, 33);
			rpt = Arrays.copyOfRange(plainText, 33, 64);
			int[] temp = new int[32];		//used for XOR with rpt
			
			//Drop every 8th bit of the key, and permute it with parity drop permutation table
			permutatedKey = permutation(key, PD);		//now length of 56
			
			//16 rounds of encryption
			for(int i = 1; i <= 16; i++) {
				lKey = circularLeftKeyShift(Arrays.copyOfRange(permutatedKey, 0, 29), i);		//creating 28 bit left half key
				rKey = circularLeftKeyShift(Arrays.copyOfRange(permutatedKey, 29, 56), i);		//creating 28 bit right half key
				roundKey = roundKeyGenerator(roundKey, lKey, rKey, CP);		//now length of 48 bits
				eRPT = expansionPermutation(rpt, eRPT);						//now length of 48 bits
				eRPT = XOR(eRPT, roundKey);						//XOR the expanded right half of text with round key
				rRPT = sBox(eRPT, sBox, rRPT);					//now length of 32 bits
				rRPT = permutation(rRPT, pBox);					
				temp = deepCopy(lpt, temp);			//swap left plain text and right plain text while XOR lpt with rpt for new rpt
				lpt = deepCopy(rRPT, lpt);
				rpt = XOR(rRPT, temp);				//end of encryption round
			}
			merge(lpt, rpt, encryptedText);			//Final permutation of combined left and right half texts
			permutation(encryptedText, FP);
		}	
	}

	private static int[] generateKey() {
		int[] key = new int[64];
		String hex = "";

		//get a string of 16 character HEX digits
		for(int i = 0; i < 16; i++) {
			hex += String.format("%x",(int)(Math.random()*(15-0+1) + 0));
		}
		
		//converting HEX to binary by converting it to decimal first
		long val = 0;
        String digits = "0123456789ABCDEF";
        String recov = "";
        String binaryKey;
		hex = hex.toUpperCase();
		for (int i = 0; i < hex.length(); i++)
        {
            char c = hex.charAt(i);
            int d = digits.indexOf(c);
            val = 16*val + d;
        }
		binaryKey = Long.toBinaryString(val);
		if(binaryKey.length() % 8 != 0) {								//this will drop leading 0s, which is corrected with this if statement
			for(int i = 0; i < (8 - (binaryKey.length() % 8)); i++) {
				recov += "0";			//Find how many leading binary 0s were dropped by cnvertting to BigIntergery
			}
		}
		binaryKey = recov + binaryKey;
		
		//place key into array matrix
		int keyPointer = 0;
		for(int i = 0; i < 64; i++) {
				key[i] = binaryKey.charAt(keyPointer);
				keyPointer++;

		}
		return key;
	}
	
	private static int[] permutation(int[] input, int[] per) {
		int[] pText = input;
		int[] initPer = per;
		int[] output = new int[input.length];
				
		//go through the initial permuation table and change the bit sequences
		for(int i = 0; i < input.length; i++) {
			output[i] = pText[initPer[i] - 1];
		}
		
		return output;
	}

	private static int[] circularLeftKeyShift(int[] key, int round) {
		int temp;
		if(round == 1 || round == 2 || round == 9 || round == 16) {	//rounds 1, 2, 9, and 16 only shifts 1 place
			temp = key[0];					//hold on to the first element
			for(int i = 0; i < key.length; i++) {
				key[i] = key[i+1];			//shift everything left one index
			}
			key[key.length - 1] = temp;		//insert first element into last index
		} else {
			for(int i = 0; i < 2; i++) {							//other rounds shift 2 index, so 2 iteration
				temp = key[0];
				for(int j = 0; j < key.length; j++) {
					key[j] = key[j+1];
				}
				key[key.length - 1] = temp;
			}
		}
		
		return key;
	}

	private static int[] roundKeyGenerator(int[] roundKey, int[] lKey, int[] rKey, int[] CP) {
		roundKey = merge(lKey, rKey, roundKey);		
		roundKey = permutation(roundKey, CP);
		return roundKey;
	}

	private static int[] merge(int[] a, int[] b, int[] result) {		
		if(result != null) {
			result = new int[a.length + b.length];		//if there is a array that we can merge to, use that array
			for (int i = 0; i < a.length; i = i + 1) {		//to save memory space, because this program is working with
	            result[i] = a[i];							//large arrays.
	        }
	        for (int i = 0; i < b.length; i = i + 1) {
	            result[a.length + i] = b[i];
	        }
	        
	        return result;
		} else {
			int[] merged = new int[a.length + b.length];	//if there is no array to merge to, create one,  resule 
			for (int i = 0; i < a.length; i = i + 1) {		//parameter will have a null value
	            merged[i] = a[i];
	        }
	        for (int i = 0; i < b.length; i = i + 1) {
	            merged[a.length + i] = b[i];
	        }
	        
	        return merged;
		}
	}

	private static int[] expansionPermutation(int[] rpt, int[] eRPT) {
		int eRPTPointer = 1, rptPointer = 0, limit = 0;
		
		eRPT[0] = rpt[31];			//in expansion permutation, first bit is last bit of right plain text
		eRPT[47] = rpt[0];			//in expension permutation, last bit is first bit of right plain text
		
		while(eRPTPointer < 47) {	//since first and last bit is set, work on the inner ones
			limit = rptPointer;		//limit variable is used to keep constant track of next 4 bit in right plain text
			for(int j = rptPointer; j < (limit + 4); j++) {	//(limit + 4) used to set the 4 bit blocks
				eRPT[eRPTPointer] = rpt[rptPointer];		//copy the next 4 bit into expanded permutation text
				eRPTPointer++;			//move the pointers to keep track of bit locations
				rptPointer++;
			}
			if(eRPTPointer == 47) {		//if at the end of the expanded text, break and stop executing the following
				break;
			}
			eRPT[eRPTPointer] = rpt[rptPointer];		//copy the start of the next rpt 4 bit block to be the end of
			eRPTPointer++;								//current 6 bit block and advance expanded text pointer
			eRPT[eRPTPointer] = rpt[rptPointer - 1];	//copy the end of the last 4 bit block to be the start of
			eRPTPointer++;								//current 6 bit block and advance expanded text pointer
		}
		
		return eRPT;
	}

	private static int[] XOR(int[] eRPT, int[] roundKey) {
		for(int i = 0; i < eRPT.length; i++) {
			if(eRPT[i] == 0 && roundKey[i] == 0) {
				eRPT[i] = 0;
			} else if(eRPT[i] == 0 && roundKey[i] == 1) {
				eRPT[i] = 1;
			} else if(eRPT[i] == 1 && roundKey[i] == 0) {
				eRPT[i] = 1;
			} else if(eRPT[i] == 1 && roundKey[i] == 1) {
				eRPT[i] = 0;
			}
		}
		return eRPT;
	}

	private static int[] sBox(int[] eRPT, int[][][] sbox, int[] rRPT) {
		int start = 0, end = 6;					//pointers to creak "blocks"
		int sBoxInt;							//to hold the number obtained from s box
		int rRPTPointer = 0;					//to keep track of the rRPT index
		String newBlock ;						//to store new 4 bit of rRPT block
		String outterBit, innerBits;			//to store outer 2 bits and inner 4 bits
		String recov = "";
		StringBuilder s = new StringBuilder();	//to store 6 bit of eRPT blocks
		
		for(int i = 0; i < 8; i++) {
			s.append(Arrays.copyOfRange(eRPT, start, end));		//get the block of 6 bit binaries
			start = end;
			end += end;
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
			
			for(int j = 0; j < 4; j++) {							//input the new 4 bit binary digits into the reduced right plain text
				rRPT[rRPTPointer] = (char)newBlock.charAt(j);		//needed character casting to convert from integer to ASCII (1s and 0s instead of
			}														//48s for 0s and 49s for 1s)
			
			s.delete(0, s.length());		//reset the string builder for the next 6 bit block
		}
		return rRPT;
	}

	private static int[] deepCopy(int[] from, int[] to) {
		for(int i = 0; i < from.length; i++) {
			to[i] = from[i];
		}
		return to;
	}
}