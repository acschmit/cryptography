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

import java.io.UnsupportedEncodingException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * Keyed-Hash Message Authentication Code class. Use this class to verify the
 * data integrity and authenticity of a message.
 *
 */
public final class HMAC
{

	private HMAC()
	{
	}

	public static String hmacDigest(byte[] msg, byte[] keyBytes, Digest digest)
	{
		HMac mac = new HMac(digest);
		mac.init(new KeyParameter(keyBytes));

		mac.update(msg, 0, msg.length);
		byte[] data = new byte[mac.getMacSize()];
		mac.doFinal(data, 0);

		return Hex.encode(data);
	}

	public static String md5(byte[] msg, byte[] keyBytes) throws UnsupportedEncodingException
	{
		MD5Digest digest = new MD5Digest();
		return hmacDigest(msg, keyBytes, digest);
	}

	public static String sha1(byte[] msg, byte[] keyBytes) throws UnsupportedEncodingException
	{
		SHA1Digest digest = new SHA1Digest();
		return hmacDigest(msg, keyBytes, digest);
	}

	public static String sha256(byte[] msg, byte[] keyBytes) throws UnsupportedEncodingException
	{
		SHA256Digest digest = new SHA256Digest();
		return hmacDigest(msg, keyBytes, digest);
	}

	public static String sha512(byte[] msg, byte[] keyBytes) throws UnsupportedEncodingException
	{
		SHA512Digest digest = new SHA512Digest();
		return hmacDigest(msg, keyBytes, digest);
	}

	public static String md5(String msg, byte[] keyBytes) throws UnsupportedEncodingException
	{
		MD5Digest digest = new MD5Digest();
		return hmacDigest(msg.getBytes("UTF-8"), keyBytes, digest);
	}

	public static String sha1(String msg, byte[] keyBytes) throws UnsupportedEncodingException
	{
		SHA1Digest digest = new SHA1Digest();
		return hmacDigest(msg.getBytes("UTF-8"), keyBytes, digest);
	}

	public static String sha256(String msg, byte[] keyBytes) throws UnsupportedEncodingException
	{
		SHA256Digest digest = new SHA256Digest();
		return hmacDigest(msg.getBytes("UTF-8"), keyBytes, digest);
	}

	public static String sha512(String msg, byte[] keyBytes) throws UnsupportedEncodingException
	{
		SHA512Digest digest = new SHA512Digest();
		return hmacDigest(msg.getBytes("UTF-8"), keyBytes, digest);
	}
}
