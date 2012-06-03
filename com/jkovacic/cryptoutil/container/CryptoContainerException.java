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
 * An exception thrown at unexpected events during packing or unpacking of data
 * into crypto containers.  
 * 
 * @author Jernej Kovacic
 */
public class CryptoContainerException extends Exception
{
	static final long serialVersionUID = 7451287L;
	
	/**
	 * Constructor with a description
	 * 
	 * @param desc - description of the exception, later may be retrieved by getMessage 
	 */
	public CryptoContainerException(String desc)
    {
        super(desc);
    }
}
