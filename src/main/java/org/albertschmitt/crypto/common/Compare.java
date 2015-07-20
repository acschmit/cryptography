/*
 * The MIT License
 *
 * Copyright 2015 acschmit.
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
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.albertschmitt.crypto.common;

/**
 * Cryptographically safe comparison functions that take the same time to
 * complete regardless if they evaluate to true or false. That way, attackers
 * can gain no additional information when hacking.
 */
public class Compare
{

	private Compare()
	{
	}

	/**
	 * Make sure any compare takes the same amount of time. Prevents timing
	 * based attacks.
	 *
	 * @param a byte array 1.
	 * @param b byte array 2.
	 * @return true if byte arrays are equal, false if not.
	 */
	public static boolean safeEquals(byte[] a, byte[] b)
	{
		int diff = a.length ^ b.length;
		for (int i = 0; i < a.length && i < b.length; i++)
		{
			diff |= a[i] ^ b[i];
		}
		return diff == 0;
	}
}
