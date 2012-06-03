/*
Copyright 2012, Jernej Kovacic

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/ 

import java.util.*;

import com.jkovacic.cryptoutil.*;
import com.jkovacic.cryptoutil.container.*;


/*
 * A class with some basic tests, intended to provide
 * a brief demonstration of the library.
 * 
 * CFB mode relevant test vectors for AES-256 are available at:
 * http://csrc.nist.gov/groups/STM/cavp/documents/aes/KAT_AES.zip 
 * 
 * @author Jernej Kovacic
 *
 */
public class CryptoContainerTest 
{
	/*
	 * Prepares some AES test vector as specified at:
	 * http://csrc.nist.gov/groups/STM/cavp/documents/aes/KAT_AES.zip 
	 */
	private static List<CryptoContainerTestItem> prepareTestVectors()
	{
		List<CryptoContainerTestItem> retVal = new LinkedList<CryptoContainerTestItem>();
		CryptoContainerTestItem item;
		
		item = new CryptoContainerTestItem();
		item.desc = "CFB128VarTxt256.rsp (14 rounds)";
		item.key = ByteHex.toBytes("00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00".toCharArray());
		item.iv = ByteHex.toBytes("ff:fe:00:00:00:00:00:00:00:00:00:00:00:00:00:00".toCharArray());
		item.plainText = ByteHex.toBytes("00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00".toCharArray());
		item.expected = ByteHex.toBytes("15:69:85:9e:a6:b7:20:6c:30:bf:4f:d0:cb:fa:c3:3c".toCharArray());
		retVal.add(item);
		
		item = new CryptoContainerTestItem();
		item.desc = "CFB128KeySbox256.rsp (14 rounds)";
		item.key = ByteHex.toBytes("b7:a5:79:4d:52:73:74:75:d5:3d:5a:37:72:00:84:9b:e0:26:0a:67:a2:b2:2c:ed:8b:be:f1:28:82:27:0d:07".toCharArray());
		item.iv = ByteHex.toBytes("00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00".toCharArray());
		item.plainText = ByteHex.toBytes("00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00".toCharArray());
		item.expected = ByteHex.toBytes("63:7c:31:dc:25:91:a0:76:36:f6:46:b7:2d:aa:bb:e7".toCharArray());
		retVal.add(item);
		
		return retVal;
	}
	
	public static void main(String[] args)
	{
		// a "random" salt for AesContainer 
		byte[] salt = ByteHex.toBytes("01:23:45:67:89:ab:cd:ef".toCharArray());
		
		List<CryptoContainerTestItem> testVector = prepareTestVectors();
		
		try
		{
			int tests = 0;		// number of tests performed
			int passed = 0;		// number of tests passed
			
			byte[] derText = null;			// DER structure of the AES container
			byte[] cipherText = null;		// Encrypted text
			byte[] decryptedText = null;	// Decrypted text (should equal to plain text)
			
			AesContainer cont = null;
			AesContainerDecoder dec = null;	// needed to extract the cipher text
			
			// First check if container is handled properly
			// (in other words, is it possible to extract the same text as was stored beforehand)
			byte[] key = null;
			byte[] iv = null;
			byte[] plainText = null;
			
			System.out.println("= = = = = AES container test = = = = =");
			
			// Prepare key material (symmetric key, IV, HMAC salt)
			byte[] pass = "passphrase".getBytes();
			Pbkdf2 pb = new Pbkdf2();
			byte[] keyv = pb.getKey(pass, AesContainer.KEY_SIZE + AesContainer.CIPHER_BLOCK_SIZE + AesContainer.RECOMMENDED_SALT_SIZE);
			
			key = new byte[AesContainer.KEY_SIZE];
			System.arraycopy(keyv, 0, key, 0, key.length);
	
			iv = new byte[AesContainer.CIPHER_BLOCK_SIZE];
			System.arraycopy(keyv, AesContainer.KEY_SIZE, iv, 0, AesContainer.CIPHER_BLOCK_SIZE);
			salt = new byte[AesContainer.RECOMMENDED_SALT_SIZE];
			System.arraycopy(keyv, AesContainer.KEY_SIZE + AesContainer.CIPHER_BLOCK_SIZE, salt, 0, AesContainer.RECOMMENDED_SALT_SIZE);
			
			// Text to be stored encrypted into the container
			plainText = "All human beings are born free and equal in dignity and rights. They are endowed with reason and conscience and should act towards one another in a spirit of brotherhood.".getBytes();
			
			// Instantiate a container
			cont = new AesContainer(key, iv, salt);
			
			// Encrypt the test text into the container
			derText = cont.encode(plainText);
			
			// Decrypt it from the container
			decryptedText = cont.decode(derText);
			
			// And compare the decrypted plain text to the original one:
			System.out.println("Original text:  " + new String(plainText));
			System.out.println("Decrypted text: " + new String(decryptedText));
			tests++;
			if ( Arrays.equals(plainText, decryptedText) )
			{
				System.out.println("Texts MATCH\n");
				passed++;
			}
			else
			{
				System.out.println("Texts DO NOT MATCH\n");
			}
						
			// And some tests of the AES engine itself			
			for ( CryptoContainerTestItem item : testVector )
			{
				System.out.println("= = = = = " + item.desc + " = = = = =");
				
				// Instantiate a container class
				cont = new AesContainer(item.key, item.iv, salt);
				
				// Get the DER encoded contents of the container
				derText = cont.encode(item.plainText);
				
				// Extract the cipher text from the container
				dec = new AesContainerDecoder(derText);
				dec.parse();
				cipherText = dec.getText();
				
				System.out.println("Plain text:  " + new String(ByteHex.toHex(item.plainText)));
				System.out.println("Cipher text: " + new String(ByteHex.toHex(cipherText)));
				System.out.println("Expected:    " + new String(ByteHex.toHex(item.expected)));
				
				// Compare cipher text with the expected one
				tests++;
				if ( Arrays.equals(cipherText, item.expected) )
				{
					System.out.println("Cipher texts MATCH");
					passed++;
				}
				else
				{
					System.out.println("Cipher texts DO NOT MATCH");
				}
				
				// Decrypt the cipher text in the container
				decryptedText = cont.decode(derText);
				
				System.out.println("Decrypted text: " + new String(ByteHex.toHex(decryptedText)));
				
				// And compare it to the original plain text
				tests++;
				if ( Arrays.equals(item.plainText, decryptedText) )
				{
					System.out.println("Plain texts MATCH\n");
					passed++;
				}
				else
				{
					System.out.println("Plain texts DO NOT MATCH\n");
				}
			}  // for item
			
		
			System.out.println( tests + " tests performed, " + passed + " tests passed");
		}
		catch ( CryptoContainerException ex )
		{
			ex.printStackTrace();
		}
	}
}



/*
 * A utility class to hold test vector elements
 * 
 * @author Jernej Kovacic
 */
class CryptoContainerTestItem
{
	// Description of the test vector (will be displayed during the testing procedure)
	public String desc = null;
	
	// Encryption key
	public byte[] key = null;
	
	// Encryption initialization vector
	public byte[] iv = null;
	
	// Plain text to be encrypted
	public byte[] plainText = null;
	
	// Expected cipher text
	public byte[] expected = null;
}
