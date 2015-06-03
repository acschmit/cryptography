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
package org.albertschmitt.crypto;

import org.albertschmitt.crypto.common.DigestSHA;
import org.albertschmitt.crypto.common.Hex;
import org.albertschmitt.crypto.common.HMAC;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.io.CipherOutputStream;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * This class implements AES 256-bit encryption using the Bouncy Castle API
 * which gets around the 128-bit limitation imposed by the java runtime. Clients
 * can use this class to easily incorporate encryption into their applications.
 * Note when converting between strings and byte arrays clients should be sure
 * to convert using the UTF-8 character set.
 *
 * <p>
 * External Dependencies:
 * <a target="top" href="http://www.bouncycastle.org/">Bouncy Castle Release
 * 1.52</a></p>
 * <ul>
 * <li>bcpkix-jdk15on.jar</li>
 * <li>bcprov-jdk15on.jar</li>
 * </ul>
 *
 * @version 1.0.0
 * @author Albert Schmitt [acschmit] [at] [gmail] [dot] [com]
 */
public class AESService
{

	/**
	 * The size in bytes of the salt.
	 */
	public final static int SALT_SIZE = 64;

	private final static int IV_LENGTH = 16;
	protected final static int AES_128 = 128;
	protected final static int AES_256 = 256;

	private static int key_size;
	private KeyParameter aes_key = null;
	private KeyParameter mac_key = null;

	/**
	 * Create an instance of the AESService.
	 */
	public AESService()
	{
		key_size = AES_256;
	}

	/**
	 * Returns the AES key size. This is a protected function so the programmer
	 * can changed the default key size to 128 bits by sub-classing this
	 * AESService and using #setAESKeySize(int key_size) in the constructor to
	 * change it.
	 *
	 * @return The key size.
	 */
	protected static int getAESKeySize()
	{
		return key_size;
	}

	/**
	 * Inherit from this class and call this function in the constructor to set
	 * the key size if you want it to be 128 bits instead of the default.
	 *
	 * @param key_size The desired AES key size. Only 128 and 256 are valid
	 * values.
	 * @throws Exception Thrown if the key size is not 128 or 256.
	 */
	protected static void setAESKeySize(int key_size) throws Exception
	{
		if (key_size == AES_128 || key_size == AES_256)
		{
			AESService.key_size = key_size;
		}
		else
		{
			throw new Exception("Illegal AES key size.  Must be 128 or 256");
		}
	}

	/**
	 * Concatenate two byte arrays together.
	 *
	 * @param a First byte array.
	 * @param b Second byte array.
	 * @return Byte array containing First + Second byte array.
	 */
	private byte[] concatenate(byte[] a, byte[] b)
	{
		byte[] dest = new byte[a.length + b.length];
		System.arraycopy(a, 0, dest, 0, a.length);
		System.arraycopy(b, 0, dest, a.length, b.length);

		return dest;
	}

	/**
	 * Return a PaddedBufferedBlockCipher for encryption or decryption.
	 *
	 * @param iv The initialization vector.
	 * @param forEncryption True to encrypt, false to decrypt.
	 * @return PaddedBufferedBlockCipher configured to encrypt or decrypt.
	 */
	private PaddedBufferedBlockCipher getCipher(byte[] iv, Boolean forEncryption)
	{
		ParametersWithIV ivKeyParam = new ParametersWithIV(aes_key, iv);
		BlockCipherPadding padding = new PKCS7Padding();
		PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()), padding);
		cipher.reset();
		cipher.init(forEncryption, ivKeyParam);

		return cipher;
	}

	/**
	 * Generates a keyed-hash message authentication code (HMAC) for the given
	 * message bytes.
	 *
	 * @param msgBytes The data for which the HMAC 256 Digest will be generated.
	 * @return The HMAC 256 Digest value for the input data.
	 */
	public String getHmac256Digest(byte[] msgBytes)
	{
		SHA256Digest digest = new SHA256Digest();
		HMac mac = new HMac(digest);
		mac.init(mac_key);
		byte[] data = new byte[mac.getMacSize()];
		mac.reset();

		mac.update(msgBytes, 0, msgBytes.length);
		mac.doFinal(data, 0);
		String hexString = Hex.encode(data);
		return hexString;
	}

	/**
	 * Encode the byte data to AES256 and return it in byte array.
	 *
	 * @param data Byte array to be encoded.
	 * @return AES256 encoded byte array of input data.
	 * @see #decode(byte[] data)
	 */
	public byte[] encode(byte[] data)
	{
		try
		{
			byte[] iv = new byte[IV_LENGTH];
			SecureRandom secure = new SecureRandom();
			secure.nextBytes(iv);
			PaddedBufferedBlockCipher cipher = getCipher(iv, true);

			int outSize = cipher.getOutputSize(data.length);
			byte[] enc = new byte[outSize];

			int length1 = cipher.processBytes(data, 0, data.length, enc, 0);
			cipher.doFinal(enc, length1);

			byte[] encrypted = concatenate(iv, enc);
			return encrypted;
		}
		catch (DataLengthException | IllegalStateException | InvalidCipherTextException ex)
		{
			throw new RuntimeException();
		}
	}

	/**
	 * Decode the AES256 encoded byte data and return it in an byte array.
	 *
	 * @param data AES256 encoded byte array.
	 * @return Decoded byte array of AES256 encoded input data.
	 * @see #encode(byte[] data)
	 */
	public byte[] decode(byte[] data)
	{
		try
		{
			byte[] iv = new byte[IV_LENGTH];
			System.arraycopy(data, 0, iv, 0, IV_LENGTH);
			PaddedBufferedBlockCipher cipher = getCipher(iv, false);

			int outSize = cipher.getOutputSize(data.length - IV_LENGTH);
			byte[] dec = new byte[outSize];

			int count = cipher.processBytes(data, iv.length, data.length - IV_LENGTH, dec, 0);
			count += cipher.doFinal(dec, count);

			// Remove padding
			byte[] out = new byte[count];
			System.arraycopy(dec, 0, out, 0, count);

			return out;
		}
		catch (DataLengthException | IllegalStateException | InvalidCipherTextException ex)
		{
			throw new RuntimeException();
		}
	}

	/**
	 * Encrypt or decrypt a stream and send the result to an output stream.
	 *
	 * @param instream The input stream to be encrypted.
	 * @param outstream The encrypted stream.
	 * @param cipher A PaddedBufferedBlockCipher configured to encrypt or
	 * decrypt.
	 */
	private void doCipher(InputStream instream, OutputStream outstream, PaddedBufferedBlockCipher cipher)
	{
		byte[] buffer = new byte[1024];
		int blocksize = buffer.length;

		try (CipherOutputStream cos = new CipherOutputStream(outstream, cipher))
		{
			while ((blocksize = instream.read(buffer, 0, blocksize)) != -1)
			{
				cos.write(buffer, 0, blocksize);
			}
			cos.flush();
		}
		catch (IOException ex)
		{
			throw new RuntimeException();
		}
	}

	/**
	 * Encode the input stream to AES256 and return it in an output stream.
	 *
	 * @param instream Stream to be encoded.
	 * @param outstream AES256 encoded output stream of input stream.
	 */
	public void encode(InputStream instream, OutputStream outstream)
	{
		try
		{
			byte[] iv = new byte[IV_LENGTH];
			SecureRandom secure = new SecureRandom();
			secure.nextBytes(iv);
			PaddedBufferedBlockCipher cipher = getCipher(iv, true);
			outstream.write(iv, 0, iv.length);

			doCipher(instream, outstream, cipher);
		}
		catch (IOException ex)
		{
			throw new RuntimeException();
		}
	}

	/**
	 * Decode the AES256 encoded input stream and return it in an output stream.
	 *
	 * @param instream AES256 encoded input stream to be decoded.
	 * @param outstream Decoded output stream of input stream.
	 */
	public void decode(InputStream instream, OutputStream outstream)
	{
		try
		{
			byte[] iv = new byte[IV_LENGTH];
			instream.read(iv, 0, IV_LENGTH);
			PaddedBufferedBlockCipher cipher = getCipher(iv, false);

			doCipher(instream, outstream, cipher);
		}
		catch (IOException ex)
		{
			throw new RuntimeException();
		}
	}

	/**
	 * Generate an AES key. A key generated by this method would typically be
	 * encrypted using RSA and sent to the recipient along with data that was
	 * encrypted with the key. The recipient would then decrypt the key using
	 * RSA then use the key to decrypt the data.
	 *
	 * <p>
	 * This method also creates an HMAC key for use by the
	 * {@link #getHmac256Digest(byte[] msgBytes) getHmac256Digest(byte[] msgBytes)}
	 * method.</p>
	 *
	 * @see #getAesKey()
	 * @see #getHmac256Digest(byte[] msgBytes)
	 */
	public void generateKey()
	{
		try
		{
			PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator();

			SecureRandom random = new SecureRandom();
			byte[] password = new byte[64];
			random.nextBytes(password);

			generator.init(password, generateSalt(), 20000);
			aes_key = (KeyParameter) generator.generateDerivedMacParameters(getAESKeySize());

			createHMacKey(aes_key);
		}
		catch (Exception ex)
		{
			throw new RuntimeException();
		}
	}

	/**
	 * Generate an AES key using a given password and salt.
	 *
	 * @param password The password to be used to create the key.
	 * @param salt The 64 byte long array to be used to create the key.
	 * @see #generateSalt()
	 * @see #getAesKey()
	 */
	public void generateKey(String password, byte[] salt)
	{
		try
		{
			PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator();

			byte[] passwordBytes = PKCS5S2ParametersGenerator.PKCS5PasswordToUTF8Bytes(password.toCharArray());
			generator.init(passwordBytes, salt, 20000);
			aes_key = (KeyParameter) generator.generateDerivedMacParameters(getAESKeySize());

			createHMacKey(aes_key);
		}
		catch (Exception ex)
		{
			throw new RuntimeException();
		}
	}

	/**
	 * Creates an HMAC key for use with the
	 * {@link #getHmac256Digest(byte[] msgBytes) getHmac256Digest(byte[] msgBytes)}
	 * method. This method is called whenever an AES key is created or set.
	 *
	 * @param aes_key The AES key for which to generate the HMAC key.
	 * @see #getHmac256Digest(byte[] msgBytes)
	 * @see #setAesKey(byte[] data)
	 * @see #generateKey()
	 * @see #generateKey(String password, byte[] salt)
	 */
	private void createHMacKey(KeyParameter aes_key)
	{
		try
		{
			String keyString = DigestSHA.sha256(aes_key.getKey());
			String hmacdigest = HMAC.sha256("HMAC-KEY" + (char) 1, keyString);
			byte[] keyBytes = Hex.decode(hmacdigest);
			mac_key = new KeyParameter(keyBytes);
		}
		catch (NoSuchAlgorithmException ex)
		{
			throw new RuntimeException();
		}
		catch (Exception ex)
		{
			throw new RuntimeException();
		}
	}

	/**
	 * Generate a salt value using SecureRandom() that can be used to generate
	 * an AES256 key. The salt is 64 bytes in length.
	 *
	 * @return Byte array containing the salt.
	 */
	public byte[] generateSalt()
	{
		SecureRandom random = new SecureRandom();
		byte[] salt = new byte[SALT_SIZE];
		random.nextBytes(salt);
		return salt;
	}

	/**
	 * Get the AES key that was created by {@link #generateKey() generateKey()}
	 * or
	 * {@link #generateKey(String password, byte[] salt) generateKey(String password, byte[] salt)}
	 *
	 * @return Byte array containing the AES key.
	 * @see #setAesKey(byte[] data)
	 */
	public byte[] getAesKey()
	{
		return aes_key.getKey();
	}

	/**
	 * Sets the AES key that was retrieved by the
	 * {@link #getAesKey() getAesKey()} method.
	 *
	 * @param data Byte array containing the AES key.
	 * @see #getAesKey()
	 */
	public void setAesKey(byte[] data)
	{
		aes_key = new KeyParameter(data);
		createHMacKey(aes_key);
	}
}