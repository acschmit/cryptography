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

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * This class wraps the Digest functions for compactness.
 */
public final class DigestSHA
{

	// InputStream buffer size.
	private static final int BUFFER_SIZE = 8192;

	private enum DigestType
	{

		MD5("MD5"), SHA1("SHA1"), SHA256("SHA-256"), SHA384("SHA-384"), SHA512("SHA-512");

		private final String value;

		private DigestType(String value)
		{
			this.value = value;
		}

		public String getValue()
		{
			return value;
		}
	}

	/**
	 * Prevent instantiation. All methods are static.
	 */
	private DigestSHA()
	{
	}

	private static String digest(byte[] data, DigestType digestType) throws NoSuchAlgorithmException
	{
		MessageDigest digest = MessageDigest.getInstance(digestType.getValue());
		digest.update(data, 0, data.length);
		String hash = Hex.encode(digest.digest());
		return hash;
	}

	private static String digest(InputStream is, DigestType digestType) throws NoSuchAlgorithmException, IOException
	{
		MessageDigest digest = MessageDigest.getInstance(digestType.getValue());
		byte[] buffer = new byte[BUFFER_SIZE];
		int read;
		while ((read = is.read(buffer, 0, BUFFER_SIZE)) >= 0)
		{
			digest.update(buffer, 0, read);
		}

		String hash = Hex.encode(digest.digest());
		return hash;
	}

	public static String md5(byte[] data) throws NoSuchAlgorithmException
	{
		return digest(data, DigestType.MD5);
	}

	public static String md5(InputStream is) throws NoSuchAlgorithmException, IOException
	{
		return digest(is, DigestType.MD5);
	}

	public static String sha1(byte[] data) throws NoSuchAlgorithmException
	{
		return digest(data, DigestType.SHA1);
	}

	public static String sha1(InputStream is) throws NoSuchAlgorithmException, IOException
	{
		return digest(is, DigestType.SHA1);
	}

	public static String sha256(byte[] data) throws NoSuchAlgorithmException
	{
		return digest(data, DigestType.SHA256);
	}

	public static String sha256(InputStream is) throws NoSuchAlgorithmException, IOException
	{
		return digest(is, DigestType.SHA256);
	}

	public static String sha384(byte[] data) throws NoSuchAlgorithmException
	{
		return digest(data, DigestType.SHA384);
	}

	public static String sha384(InputStream is) throws NoSuchAlgorithmException, IOException
	{
		return digest(is, DigestType.SHA384);
	}

	public static String sha512(byte[] data) throws NoSuchAlgorithmException
	{
		return digest(data, DigestType.SHA512);
	}

	public static String sha512(InputStream is) throws NoSuchAlgorithmException, IOException
	{
		return digest(is, DigestType.SHA512);
	}
}
