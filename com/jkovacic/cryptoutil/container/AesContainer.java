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

import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

import com.jkovacic.cryptoutil.*;


/**
 * A class that manipulates a container for storing encrypted data.
 * The data are encrypted using AES-256 in Cipher Feedback (CFB) mode.
 * 
 * To ensure integrity of encrypted data, HMAC-SHA-1 value of
 * plain text data is calculated and appended to the container.
 * This HMAC is always verified when the data are decrypted.
 * 
 * The container is implemented as 
 * the following DER encoded ASN.1 structure
 * 
 *  Container ::= SEQUENCE {
 *         version      INTEGER,
 *         cipher_text  OCTET STRING,
 *         hmac         OCTET STRING }
 *         
 *         
 * @author Jernej Kovacic
 */
public class AesContainer 
{
	/** AES-256 block size in bytes (determines the size of an initialization vector) */
	public static final int CIPHER_BLOCK_SIZE = 16;
	
	/** AES-256 key size in bytes */
	public static final int KEY_SIZE = 32;
	
	/**
	 * Recommended HMAC-SHA1 secret size.
	 * In practice, any salt with positive size will be accepted.
	 */
	public static final int RECOMMENDED_SALT_SIZE = 24;
	
	// Interfaces are used to simplify introduction of other algorithms (if ever necessary)
	private ICryptoEngine cipher = null;
	private ICipherMode mode = null;
	private Mac hmac = null;

	// cipher symmetric key
	byte[] key = null;
	// cipher initialization vector
	byte[] iv = null;
	// HMAC secret ('salt')
	SecretKeySpec salt = null;
	
	// have all crypto engines been initialized?
	private boolean initialized = false;
		
	
	/**
	 * Constructor.
	 * The input parameters are copied internally, so the given ones can be erased immediately. 
	 * 
	 * @param keyVector - symmetric key (if too long, only the first KEY_SIZE bytes will be taken)
	 * @param initVector - initialization vector (if too long, only the first CIPHER_BLOCK_SIZE bytes wil be taken)
	 * @param hmacSalt - salt of the HMAC function (must be at least one byte long)
	 * 
	 * @throws CryptoContainerException if any input parameter is invalid
	 */
	public AesContainer(byte[] keyVector, byte[] initVector, byte[] hmacSalt) throws CryptoContainerException
	{
		setup(keyVector, initVector, hmacSalt);
	}
	
	/**
	 * Constructor, accepting key material in a single array.
	 * KEY_SIZE bytes are taken for the symmetric key,
	 * CIPHER_BLOCK_SIZE bytes are taken for the initialization vector, and
	 * the rest (must be at least one byte) is taken for the HMAC salt.
	 * 
	 * Hence, the minimum length of keyMaterial must be at least KEY_SIZE + CIPHER_BLOCK_SIZE + 1.
	 * 
	 * @param keyMaterial - byte array with the key material
	 * 
	 * @throws CryptoContainerException if keyMaterial is invalid
	 */
	public AesContainer(byte[] keyMaterial) throws CryptoContainerException
	{
		final int currTotal = KEY_SIZE + CIPHER_BLOCK_SIZE;
		
		// sanity check
		if ( null==keyMaterial || keyMaterial.length<=currTotal )
		{
			throw new CryptoContainerException("Invalid input parameters");
		}
		
		// The first KEY_SIZE bytes are taken from the symmetric key:
		final byte[] keyVector = new byte[KEY_SIZE];
		System.arraycopy(keyMaterial, 0, keyVector, 0, KEY_SIZE);
		
		// The following CIPHER_BLOCK_SIZE bytes are taken for the initialization vector:
		final byte[] initVector = new byte[CIPHER_BLOCK_SIZE];
		System.arraycopy(keyMaterial, KEY_SIZE, initVector, 0, CIPHER_BLOCK_SIZE);
		
		// The rest is taken for the HMAC salt:
		final byte[] hmacSalt = new byte[keyMaterial.length - currTotal];
		System.arraycopy(keyMaterial, KEY_SIZE+CIPHER_BLOCK_SIZE, hmacSalt, 0, keyMaterial.length-currTotal);
		
		CryptoContainerException caughtException = null;
		
		try
		{
			setup(keyVector, initVector, hmacSalt);
		}
		catch ( CryptoContainerException ex )
		{
			// before throwing an exception, clean up the sensitive data!
			caughtException = ex;
		}
		finally
		{
			// zero out the temporary arrays with sensitive data:
			Arrays.fill(keyVector, (byte) 0);
			Arrays.fill(initVector, (byte) 0);
			Arrays.fill(hmacSalt, (byte) 0);
			destroy();
		}
		
		// if an exception was intercepted, rethtrow it:
		if ( null!=caughtException )
		{
			throw caughtException;
		}
	}
	
	/*
	 * Prepares arrays with secrets, initializes crypto engines etc.
	 * 
	 * @param keyVector - symmetric encryption key
	 * @param initVector - initialization vector
	 * @param hmacSalt - salt for HMAC
	 * 
	 * @throws CryptoContainerException if initialization failed for any reason
	 */
	private void setup(byte[] keyVector, byte[] initVector, byte[] hmacSalt) throws CryptoContainerException
	{
		this.initialized = false;
		
		// sanity check
		if ( null==keyVector || null==initVector || null==hmacSalt ||
			 keyVector.length<CIPHER_BLOCK_SIZE || initVector.length<CIPHER_BLOCK_SIZE ||
			 hmacSalt.length<=0 )
		{
			throw new CryptoContainerException("Invalid input parameters");
		}
		
		// copy the key and IV into internal arrays
		this.key = new byte[KEY_SIZE];
		this.iv = new byte[CIPHER_BLOCK_SIZE];
		System.arraycopy(keyVector, 0, this.key, 0, KEY_SIZE);
		System.arraycopy(initVector, 0, this.iv, 0, CIPHER_BLOCK_SIZE);
		
		// and attempt to initialize the crypto engine
		try
		{
			this.cipher = new AesEngine();
			this.mode = new CfbMode(this.cipher, this.key, this.iv);
			this.hmac = Mac.getInstance("Hmac" + DigestAlgorithm.SHA1.getCompact());
		}
		catch ( GeneralSecurityException ex )
		{
			throw new CryptoContainerException("Initialization of crypto engine failed");
		}
		
		// copy the HMAC salt into an internal array
		this.salt = new SecretKeySpec(hmacSalt, this.hmac.getAlgorithm());
		
		// and attempt to initialize the HMAC engine
		try
		{
			hmac.init(this.salt);
		}
		catch ( InvalidKeyException ex )
		{
			throw new CryptoContainerException("Initialization of HMAC failed");
		}
		
		// so far, consider everything as initialized 
		this.initialized = true;
	}
	
	/**
	 * Encrypts plain text and encodes it into a container
	 * 
	 * @param text - plain text data
	 * 
	 * @return DER encoded contents of the container
	 * 
	 * @throws CryptoContainerException if encryption or encoding process failed
	 */
	public byte[] encode(byte[] text) throws CryptoContainerException
	{
		// sanity check
		if ( false==initialized )
		{
			throw new CryptoContainerException("Container engine not initialized");
		}
		
		if ( null==text || 0==text.length )
		{
			throw new CryptoContainerException("No input given");
		}
		
		// reset the HMAC engine
		hmac.reset();
		
		byte[] secretText = null;
		byte[] hmacDigest = null;
		
		// encrypt the plain text
		secretText = mode.encrypt(text);
		// and get its HMAC
		hmacDigest = hmac.doFinal(text);

		// and pack the data into the container
		DerEncoder enc = new DerEncoder();
		
		// container version (currently only 0 is supported)
		enc.appendInt(0);
		// cipher text
		enc.appendOctetStream(secretText);
		// HMAC value
		enc.appendOctetStream(hmacDigest);

		// and finally produce the container contents 
		byte[] retVal = enc.encode();
		
		return retVal;
	}
	
	/**
	 * Extracts the encrypted blob from the container, decrypts it
	 * and verifies the plain text.
	 * 
	 * @param secret - container structure
	 * 
	 * @return plain text
	 * 
	 * @throws CryptoContainerException if decoding, decryption or verification fails
	 */
	public byte[] decode(byte[] secret) throws CryptoContainerException
	{
		// sanity check
		if ( false==initialized )
		{
			throw new CryptoContainerException("Container engine not initialized");
		}
		
		if ( null==secret || 0==secret.length )
		{
			throw new CryptoContainerException("No input given");
		}
		
		// first parse the cipher text and the HMAC value from the container:
		final AesContainerDecoder dec = new AesContainerDecoder(secret);
		if ( false==dec.parse() )
		{
			throw new CryptoContainerException("Parsing of the container failed");
		}
		
		// extract the cipher text from the container
		final byte[] cipherText = dec.getText();
		
		// reset the HMAC engine
		hmac.reset();
		
		
		byte[] text = null;
		byte[] digest = null;
		
		// decrypt the cipher text into plain text
		text = mode.decrypt(cipherText);
		// calculate HMAC of the plain text
		digest = hmac.doFinal(text);
	
		// and compare the HMAC to the one from the container
		if ( false==Arrays.equals(digest, dec.getHmac()) )
		{
			throw new CryptoContainerException("HMAC verification failed");
		}
		
		return text;
	}
	
	/**
	 * Overwrites all sensitive data with zeros.
	 * Recommended to call as soon as the class is not needed anymore. 
	 */
	protected void destroy()
	{
		Arrays.fill(this.key, (byte) 0);
		Arrays.fill(this.iv, (byte) 0);
	}
	
	/*
	 * Destructor.
	 *
	 * When an object is to be destructed, it will make sure,
	 * that sensitive data (e.g. keys, initialization vectors) are
	 * overridden with zeros and as such not available to other
	 * objects that are allocated this object's memory
	 *
	 * @throws Throwable
	 */
	protected void finalize() throws Throwable 
	{
	    try 
	    {
	    	destroy();
	    } 
	    finally 
	    {
	        super.finalize();
	    }
	}
}
