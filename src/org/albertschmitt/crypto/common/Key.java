/**
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 Albert C Schmitt
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package org.albertschmitt.crypto.common;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/**
 *
 * Base class for strongly typed public and private rsa keys. This class was
 * created to eliminate bouncycastle imports in classes that utilize the
 * RSAService class.
 *
 * @author Albert Schmitt [acschmit] [at] [gmail] [dot] [com]
 */
public abstract class Key
{

	private AsymmetricKeyParameter key;

	/**
	 * @return the key
	 */
	public final AsymmetricKeyParameter getKey()
	{
		return key;
	}

	/**
	 * @param key the key to set
	 */
	public final void setKey(AsymmetricKeyParameter key)
	{
		this.key = key;
	}
}
