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
 * An interface for classes implementing symmetric cipher modes of operation
 * 
 * @author Jernej Kovacic
 * 
 * @see CfbMode
 */
public interface ICipherMode 
{
	/**
	 * Performs the encryption as defined by the implemented mode of operation
	 * 
	 * @param plainText - data to be encrypted
	 * 
	 * @return - encrypted data
	 * 
	 * @throws CryptoContainerException if encryption failed (e.g. invalid input, crypto engine not initialized, etc.)
	 */
	public byte[] encrypt(byte[] plainText) throws CryptoContainerException;
	
	/**
	 * Performs the decryption as defined by the implemented mode of operation
	 * 
	 * @param cipherText - cipher text to be decrypted
	 * 
	 * @return encrypted plain text
	 * 
	 * @throws CryptoContainerException if decryption failed (e.g. invalid input, crypto engine not initialized, etc.)
	 */
	public byte[] decrypt(byte[] cipherText) throws CryptoContainerException;
}
