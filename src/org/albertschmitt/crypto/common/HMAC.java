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

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 *
 * @author Albert Schmitt [acschmit] [at] [gmail] [dot] [com]
 */
public final class HMAC
{

	private HMAC()
	{
	}

	public static String hmacDigest(byte[] msg, byte[] keyBytes, Digest algorithm)
	{
		HMac mac = new HMac(algorithm);
		mac.init(new KeyParameter(keyBytes));

		mac.update(msg, 0, msg.length);
		byte[] data = new byte[mac.getMacSize()];
		mac.doFinal(data, 0);

		return Hex.encode(data);
	}

	public static String md5(String msg, String keyString) throws Exception
	{
		MD5Digest digest = new MD5Digest();
		return hmacDigest(msg.getBytes("ASCII"), keyString.getBytes("UTF-8"), digest);
	}

	public static String sha1(String msg, String keyString) throws Exception
	{
		SHA1Digest digest = new SHA1Digest();
		return hmacDigest(msg.getBytes("ASCII"), keyString.getBytes("UTF-8"), digest);
	}

	public static String sha256(String msg, String keyString) throws Exception
	{
		SHA256Digest digest = new SHA256Digest();
		return hmacDigest(msg.getBytes("ASCII"), keyString.getBytes("UTF-8"), digest);
	}

	public static String sha512(String msg, String keyString) throws Exception
	{
		SHA512Digest digest = new SHA512Digest();
		return hmacDigest(msg.getBytes("ASCII"), keyString.getBytes("UTF-8"), digest);
	}

	public static String md5(String msg, byte[] keyBytes) throws Exception
	{
		MD5Digest digest = new MD5Digest();
		return hmacDigest(msg.getBytes("ASCII"), keyBytes, digest);
	}

	public static String sha1(String msg, byte[] keyBytes) throws Exception
	{
		SHA1Digest digest = new SHA1Digest();
		return hmacDigest(msg.getBytes("ASCII"), keyBytes, digest);
	}

	public static String sha256(String msg, byte[] keyBytes) throws Exception
	{
		SHA256Digest digest = new SHA256Digest();
		return hmacDigest(msg.getBytes("ASCII"), keyBytes, digest);
	}

	public static String sha512(String msg, byte[] keyBytes) throws Exception
	{
		SHA512Digest digest = new SHA512Digest();
		return hmacDigest(msg.getBytes("ASCII"), keyBytes, digest);
	}
}
