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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 *
 * @author Albert Schmitt [acschmit] [at] [gmail] [dot] [com]
 */
public class ByteUtil
{

	private final static int BUFFERSIZE = 1024 * 8;

	private ByteUtil()
	{
	}

	/**
	 * Concatenate two byte arrays together.
	 *
	 * @param a First byte array.
	 * @param b Second byte array.
	 * @return Byte array containing First + Second byte array.
	 */
	public static byte[] concatenate(byte[] a, byte[] b)
	{
		byte[] dest = new byte[a.length + b.length];
		System.arraycopy(a, 0, dest, 0, a.length);
		System.arraycopy(b, 0, dest, a.length, b.length);

		return dest;
	}

	/**
	 *
	 * @param instream
	 * @return
	 * @throws IOException
	 */
	public static byte[] readFileBytes(InputStream instream) throws IOException
	{
		byte[] data;

		try (ByteArrayOutputStream outstream = new ByteArrayOutputStream())
		{
			byte[] buffer = new byte[BUFFERSIZE];
			int read;
			while ((read = instream.read(buffer, 0, BUFFERSIZE)) >= 0)
			{
				outstream.write(buffer, 0, read);
			}
			outstream.flush();
			data = outstream.toByteArray();
		}
		return data;
	}

	/**
	 *
	 * @param chars
	 */
	public static void overwrite(char[] chars)
	{
		/**
		 * Erase password to prevent memory hacking.
		 */
		for (int i = 0; i < chars.length; i++)
		{
			chars[i] = ' ';
		}

	}

	/**
	 *
	 * @param bytes
	 */
	public static void overwrite(byte[] bytes)
	{
		/**
		 * Erase password to prevent memory hacking.
		 */
		for (int i = 0; i < bytes.length; i++)
		{
			bytes[i] = ' ';
		}

	}
}
