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
 * An interface that defines required methods for classes that
 * implement symmetric encryption. The interface is used by AesContainer.
 * The main reason to introduce is the fact, that due to US export 
 * regulations, strong AES encryption (192 and 256 bit keys) may not be enabled
 * in JVM engines by default. To overcome this restriction and to ensure portability,
 * an AES class implementing this interface was introduced.
 * 
 * If a non-restricted encryption algorithm is ever required it can be implemented 
 * inside a wrapper class implementing this interface.
 * 
 * @author Jernej Kovacic
 * 
 * @see AesEngine
 */
public interface ICryptoEngine 
{
	/**
	 * Initialize the 
	 * 
	 * @param forEncryption should the engine be initialized for encryption (true) or decryption (false)
	 * @param key - symmetric encryption key
	 * 
	 * @throws IllegalStateException - if any initialization parameters are invalid
	 */
	public void init(boolean forEncryption, byte[] key) throws IllegalStateException;
	
	/**
	 * @return name of the encryption algorithm
	 */
	public String getAlgorithmName();
	
	/**
	 * @return block size of the encryption algorithm
	 */
	public int getBlockSize();
	
	/**
	 * Performs an encryption or decryption of a block.
	 * The amount of processed data depends on the actual algorithm's block size 
	 * 
	 * @param in - buffer with the data to be processed
	 * @param inOff - starting position of the data at 'in'
	 * @param out - preallocated buffer to store the processed data
	 * @param outOff - starting position at 'out'
	 * 
	 * @return size of processed data (typically algorithm's block size)
	 * 
	 * @throws IllegalStateException if engine was not initialized or buffers are invalid
	 */
	public int processBlock(byte[] in, int inOff, byte[] out, int outOff) throws IllegalStateException;
	
	/**
	 * Resets the encryption engine (if required by the implementation)
	 */
	public void reset();
}
