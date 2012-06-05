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

package com.jkovacic.cryptoutil.container;

/**
 * Implementation of Cipher Feedback (CFB) mode of encryption operation.
 * The class can use any symmetric block cipher implementing ICryptoEngine.
 * 
 * The CFB mode is explained at:
 * http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Cipher_feedback_.28CFB.29
 * 
 * @author Jernej Kovacic
 */
public class CfbMode implements ICipherMode
{
	// engine's algorithm's block size
	private final int CIPHER_BLOCK_SIZE;
	
	private ICryptoEngine engine = null;
	private byte[] iv = null;
	private byte[] key = null;
	private boolean initialized = false;
	
	/**
	 * Constructor
	 *  
	 * @param cryptoEngine - a class that performs symmetric encryption/decryption
	 * @param symKey - symmetric algorithm key
	 * @param initVector - initialization vector
	 * 
	 * @throws CryptoContainerException
	 */
	CfbMode(ICryptoEngine cryptoEngine, byte[] symKey, byte[] initVector) throws CryptoContainerException
	{
		this.initialized = false;
		
		// sanity check
		if ( null==cryptoEngine || null==symKey || null==initVector )
		{
			throw new CryptoContainerException("Illegal input parameters");
		}
		
		if ( cryptoEngine.getBlockSize()<=0 )
		{
			throw new CryptoContainerException("Invalid crypto block size");
		}
		
		if ( cryptoEngine.getBlockSize()!=initVector.length )
		{
			throw new CryptoContainerException("Invalid initialization vector size");
		}
		
		this.engine = cryptoEngine;
		this.key = symKey;
		this.iv = initVector;
		this.CIPHER_BLOCK_SIZE = cryptoEngine.getBlockSize();
		this.initialized = true;
	}
	
	/**
	 * Performs the encryption in CFB mode
	 * 
	 * @param plainText - data to be encrypted
	 * 
	 * @return - encrypted data
	 * 
	 * @throws CryptoContainerException if encryption failed (e.g. invalid input, crypto engine not initialized, etc.)
	 */
	public byte[] encrypt(byte[] plainText) throws CryptoContainerException
	{
		// sanity check
		if ( false==initialized )
		{
			throw new CryptoContainerException("Engine not initialized");
		}
		
		if ( null==plainText || 0==plainText.length )
		{
			throw new CryptoContainerException("No input given");
		}
		
		// initialize the crypto engine
		try
		{
			engine.init(true, key);
			engine.reset();
		}
		catch ( IllegalStateException ex )
		{
			throw new CryptoContainerException("Initialization of crypto engine failed: '" + ex.getMessage() + "'");
		}
		
		// In CFB mode, the output length always equals input's length
		byte[] retVal = new byte[plainText.length];
		
		try
		{
			final int r = plainText.length % CIPHER_BLOCK_SIZE;
			final int n = plainText.length / CIPHER_BLOCK_SIZE;
			int len;
			
			// input to engine's processBlock
			byte[] input = new byte[CIPHER_BLOCK_SIZE];
			// output of engine's processBlock (must be preallocated)
			byte[] output = new byte[CIPHER_BLOCK_SIZE];
			
			// In CFB mode, the initial input to the crypto engine is the initialization vector
			System.arraycopy(iv, 0, input, 0, CIPHER_BLOCK_SIZE);
			
			for ( int i=0; i<=n; i++ )
			{
				// number of relevant bytes (important in the last block)
				len = ( i<n ? CIPHER_BLOCK_SIZE : r );
				if ( i==n && 0==r )
				{
					// no more plain text data to be encrypted
					break;  // out of for i
				}
				
				engine.processBlock(input, 0, output, 0);
				
				final int START_BLOCK = i * CIPHER_BLOCK_SIZE;
				
				// CFB cipher text equals to engine's output, xor'ed by the plain text
				System.arraycopy(output, 0, retVal, START_BLOCK, len);
				for ( int j=START_BLOCK; j<START_BLOCK+len; j++ )
				{
					retVal[j] ^= plainText[j];
				}
				
				// The cipher text is input to the crypto engine in the next iteration:
				System.arraycopy(retVal, START_BLOCK, input, 0, len);
				
			}
		}
		catch ( IllegalStateException ex )
		{
			throw new CryptoContainerException("Encryption failed");
		}
		
		return retVal;
	}
	
	/**
	 * Performs the decryption in CFB mode
	 * 
	 * @param cipherText - cipher text to be decrypted
	 * 
	 * @return encrypted plain text
	 * 
	 * @throws CryptoContainerException if decryption failed (e.g. invalid input, crypto engine not initialized, etc.)
	 */
	public byte[] decrypt(byte[] cipherText) throws CryptoContainerException
	{
		// sanity check
		if ( false==initialized )
		{
			throw new CryptoContainerException("Engine not initialized");
		}
		
		if ( null==cipherText || 0==cipherText.length )
		{
			throw new CryptoContainerException("No input given");
		}
		
		// initialize the crypto engine
		try
		{
			/*
			 * This is not a typo!!!
			 * In CFB mode, AES encryption is used for both directions: 
			 * encryption and decryption of the message
			 */
			engine.init(true, key);
			engine.reset();
		}
		catch ( IllegalStateException ex )
		{
			throw new CryptoContainerException("Initialization of crypto engine failed: '" + ex.getMessage() + "'");
		}
		
		// In CFB mode, the output length always equals input's length
		byte[] retVal = new byte[cipherText.length];
		
		try
		{
			final int n = cipherText.length / CIPHER_BLOCK_SIZE;
			final int r = cipherText.length % CIPHER_BLOCK_SIZE;
			int len;
			
			// input to engine's processBlock
			byte[] input = new byte[CIPHER_BLOCK_SIZE];
			// output of engine's processBlock (must be preallocated)
			byte[] output = new byte[CIPHER_BLOCK_SIZE];
			
			// In CFB mode, the initial input to the crypto engine is the initialization vector
			System.arraycopy(iv, 0, input, 0, CIPHER_BLOCK_SIZE);
			
			for ( int i=0; i<=n; i++ )
			{
				// number of relevant bytes (important in the last block)
				len = ( i<n ? CIPHER_BLOCK_SIZE : r );
				if ( i==n && 0==r )
				{
					// no more plain text data to be encrypted
					break;  // out of for i
				}
				
				engine.processBlock(input, 0, output, 0);
				
				final int START_BLOCK = i * CIPHER_BLOCK_SIZE;
				
				// In CFB, the decrypted plain text is engine's output, xor'ed by the cipher text
				System.arraycopy(output, 0, retVal, START_BLOCK, len);
				for ( int j=START_BLOCK; j<START_BLOCK+len; j++ )
				{
					retVal[j] ^= cipherText[j];
				}
				
				// The cipher text is input to the crypto engine in the next iteration:
				System.arraycopy(cipherText, START_BLOCK, input, 0, len);
			}
		}
		catch ( IllegalStateException ex )
		{
			throw new CryptoContainerException("Decryption failed");
		}
		
		return retVal;
	}
}
