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

import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.security.SecureRandom;
import org.albertschmitt.crypto.common.Key;
import org.albertschmitt.crypto.common.RSAPrivateKey;
import org.albertschmitt.crypto.common.RSAPublicKey;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

/**
 * This class implements RSA private/public key encryption with a 2048 bit key
 * using the Bouncy Castle API. Clients can use this class to easily incorporate
 * encryption into their applications. Note when converting between strings and
 * byte arrays clients should be sure to convert using the UTF-8 character set.
 * <p>
 * External Dependencies:
 * <a target="top" href="http://www.bouncycastle.org/">Bouncy Castle Release
 * 1.52</a></p>
 * <ul>
 * <li>bcpkix-jdk15on.jar</li>
 * <li>bcprov-jdk15on.jar</li>
 * </ul>
 *
 * @version 1.0.1
 * @author Albert Schmitt [acschmit] [at] [gmail] [dot] [com]
 */
public class RSAService
{

	private static final int RSA_STRENGTH = 1024 * 2;		// size of the RSA Key.
	private static final int ENC_LENGTH = RSA_STRENGTH / 8; // max len of the encrypted byte array.
	private static final int PADDING_PKCS1 = 11;

	/**
	 * Create an instance of the RSAService using a 2048 bit key.
	 */
	public RSAService()
	{
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
	 * Return an AsymmetricBlockCipher for encryption or decryption.
	 *
	 * @param key The RSA key.
	 * @param forEncryption True if encrypting, false if decrypting.
	 * @return AsymmetricBlockCipher configured to encrypt or decrypt
	 */
	private AsymmetricBlockCipher getCipher(Key key, Boolean forEncryption)
	{
		AsymmetricBlockCipher cipher = new RSAEngine();
		cipher = new org.bouncycastle.crypto.encodings.PKCS1Encoding(cipher);
		cipher.init(forEncryption, key.getKey());
		return cipher;
	}

	/**
	 * Encrypt or decrypt a stream and send the result to an output stream. TBD
	 * explain data size limit and why we're using a loop to get around it.
	 *
	 * @param data The data to be encrypted.
	 * @param key The key to be used.
	 * @param forEncryption True to encrypt, false to decrypt.
	 * @return The encrypted data.
	 */
	private byte[] doCipher(byte[] data, Key key, Boolean forEncryption)
	{
		AsymmetricBlockCipher cipher = getCipher(key, forEncryption);

		int enc_length = (forEncryption) ? ENC_LENGTH - PADDING_PKCS1 : ENC_LENGTH;
		int blocksize = enc_length;
		int offset = 0;
		byte[] bytes = new byte[0];

		while (blocksize == enc_length)
		{
			int remainder = data.length - offset;
			blocksize = (remainder > enc_length) ? enc_length : remainder;
			if (blocksize != 0)
			{
				try
				{
					byte[] enc = cipher.processBlock(data, offset, blocksize);
					bytes = concatenate(bytes, enc);
				}
				catch (InvalidCipherTextException ex)
				{
					throw new RuntimeException();
				}
			}
			offset += enc_length;
		}
		if (bytes.length == 0)
		{
			bytes = null;
		}
		return bytes;
	}

	/**
	 * Encrypt or decrypt a stream and send the result to an output stream.
	 *
	 * @param instream The input stream to be encrypted.
	 * @param outstream The encrypted stream.
	 * @param key The key to be used.
	 * @param forEncryption True to encrypt, false to decrypt.
	 */
	private void doCipher(InputStream instream, OutputStream outstream, Key key, Boolean forEncryption)
	{
		try
		{
			AsymmetricBlockCipher cipher = getCipher(key, forEncryption);

			int enc_length = (forEncryption) ? ENC_LENGTH - PADDING_PKCS1 : ENC_LENGTH;
			byte[] inbuf = new byte[enc_length];
			int blocksize = enc_length;

			while ((blocksize = instream.read(inbuf, 0, blocksize)) != -1)
			{
				byte[] enc = cipher.processBlock(inbuf, 0, blocksize);
				outstream.write(enc, 0, enc.length);
			}
			outstream.flush();
		}
		catch (IOException | InvalidCipherTextException ex)
		{
			throw new RuntimeException();
		}
	}

	/**
	 * Decode the RSA encoded byte data and return it in an byte array.
	 *
	 * @param data RSA encoded byte array.
	 * @param key The key to be used.
	 * @return The RSA encoded data.
	 * @see #decode(byte[] data, Key key)
	 */
	public byte[] encode(byte[] data, Key key)
	{
		return doCipher(data, key, true);
	}

	/**
	 * Decode the RSA encoded byte data and return it in an byte array.
	 *
	 * @param data RSA encoded byte array.
	 * @param key The key to be used.
	 * @return Decoded byte array of RSA encoded input data.
	 * @see #encode(byte[] data, Key key)
	 */
	public byte[] decode(byte[] data, Key key)
	{
		return doCipher(data, key, false);
	}

	/**
	 * Encode the input stream to RSA and return it in an output stream.
	 *
	 * @param instream Stream to be encoded.
	 * @param outstream RSA encoded output stream of input stream.
	 * @param key The key to be used.
	 */
	public void encode(InputStream instream, OutputStream outstream, Key key)
	{
		doCipher(instream, outstream, key, true);
	}

	/**
	 * Decode the RSA encoded input stream and return it in an output stream.
	 *
	 * @param instream RSA encoded input stream to be decoded.
	 * @param outstream Decoded output stream of input stream.
	 * @param key The key to be used.
	 */
	public void decode(InputStream instream, OutputStream outstream, Key key)
	{
		doCipher(instream, outstream, key, false);
	}

	/**
	 * Read the RSA Private Key from the specified filename.
	 *
	 * @param filename The file that contains the RSA Private Key.
	 * @return The RSAPrivateKey.
	 */
	public RSAPrivateKey readPrivateKey(String filename)
	{
		FileInputStream in = null;
		RSAPrivateKey key = null;
		try
		{
			in = new FileInputStream(filename);
			key = readPrivateKey(in);
		}
		catch (FileNotFoundException ex)
		{
			throw new RuntimeException();
		}
		finally
		{
			closeStream(in);
		}
		return key;
	}

	/**
	 * Read the RSA Private Key from the specified input stream.
	 *
	 * @param in The input stream that contains the RSA Private Key.
	 * @return The RSAPrivateKey.
	 */
	public RSAPrivateKey readPrivateKey(InputStream in)
	{
		RSAPrivateKey key = null;
		try
		{
			InputStreamReader reader = new InputStreamReader(in);
			PEMKeyPair pkp;
			try (PEMParser pem = new PEMParser(reader))
			{
				pkp = (PEMKeyPair) pem.readObject();
			}

			PrivateKeyInfo pki = pkp.getPrivateKeyInfo();
			key = new RSAPrivateKey();
			key.setPki(pki);
		}
		catch (IOException ex)
		{
			throw new RuntimeException();
		}
		catch (Exception ex)
		{
			throw new RuntimeException();
		}
		return key;
	}

	/**
	 * Read the RSA Public Key from the specified filename.
	 *
	 * @param filename The file that contains the RSA Public Key.
	 * @return The RSAPublicKey.
	 */
	public RSAPublicKey readPublicKey(String filename)
	{
		FileInputStream in = null;
		RSAPublicKey key = null;
		try
		{
			in = new FileInputStream(filename);
			key = readPublicKey(in);
		}
		catch (FileNotFoundException ex)
		{
			throw new RuntimeException();
		}
		finally
		{
			closeStream(in);
		}
		return key;
	}

	/**
	 * Read the RSA Public Key from the specified input stream.
	 *
	 * @param in The input stream that contains the RSA Public Key.
	 * @return The RSAPublicKey.
	 */
	public RSAPublicKey readPublicKey(InputStream in)
	{
		RSAPublicKey key = null;
		try
		{
			InputStreamReader reader = new InputStreamReader(in);
			SubjectPublicKeyInfo pki;
			try (PEMParser pem = new PEMParser(reader))
			{
				pki = (SubjectPublicKeyInfo) pem.readObject();
			}

			byte[] data = pki.getEncoded();
			key = new RSAPublicKey();
			key.setKey(PublicKeyFactory.createKey(data));

		}
		catch (IOException ex)
		{
			throw new RuntimeException();
		}
		return key;
	}

	/**
	 * Extract the Public Key from the RSA Private Key from the file and return
	 * it to the client.
	 *
	 * @param filename The file that contains the RSA Public Key.
	 * @return The RSAPublicKey.
	 */
	public RSAPublicKey readPublicKeyFromPrivate(String filename)
	{
		FileInputStream in = null;
		RSAPublicKey key = null;
		try
		{
			in = new FileInputStream(filename);
			key = readPublicKeyFromPrivate(in);
		}
		catch (FileNotFoundException ex)
		{
			throw new RuntimeException();
		}
		finally
		{
			closeStream(in);
		}
		return key;
	}

	/**
	 * Extract the Public Key from the RSA Private Key from the input stream and
	 * return it to the client.
	 *
	 * @param in The input stream that contains the RSA Public Key.
	 * @return The RSAPublicKey.
	 */
	public RSAPublicKey readPublicKeyFromPrivate(InputStream in)
	{
		RSAPublicKey key = null;
		try
		{
			InputStreamReader reader = new InputStreamReader(in);
			org.bouncycastle.openssl.PEMKeyPair pkp;
			try (PEMParser pem = new PEMParser(reader))
			{
				pkp = (org.bouncycastle.openssl.PEMKeyPair) pem.readObject();
			}

			SubjectPublicKeyInfo pki = pkp.getPublicKeyInfo();
			byte[] data = pki.getEncoded();
			key = new RSAPublicKey();
			key.setKey(PublicKeyFactory.createKey(data));

		}
		catch (IOException ex)
		{
			throw new RuntimeException();
		}
		return key;
	}

	/**
	 * Utility function that writes an RSA Public or Private key to an output
	 * stream.
	 *
	 * @param out The stream to write the RSA key to.
	 * @param pki The Key to be written to the stream.
	 */
	private void writeKey(OutputStream out, Object pki)
	{
		try
		{
			OutputStreamWriter writer = new OutputStreamWriter(out);

//			try (PEMWriter pem = new PEMWriter(writer))
			try (JcaPEMWriter pem = new JcaPEMWriter(writer))
			{
				pem.writeObject(pki);
			}
		}
		catch (IOException ex)
		{
			throw new RuntimeException();
		}
	}

	/**
	 * Construct a Private Key from an AsymmetricCipherKeyPair and write it to
	 * the Output Stream.
	 *
	 * @param keyPair The Private Key.
	 * @param out The stream the Private Key is to be written to.
	 */
	private void writePrivateKey(AsymmetricCipherKeyPair keyPair, OutputStream out)
	{
		try
		{
			PrivateKeyInfo pki = PrivateKeyInfoFactory.createPrivateKeyInfo(keyPair.getPrivate());
			writeKey(out, pki);
		}
		catch (IOException ex)
		{
			throw new RuntimeException();
		}
		catch (Exception ex)
		{
			throw new RuntimeException();
		}
	}

	/**
	 * Construct a Public Key from an AsymmetricCipherKeyPair and write it to
	 * the Output Stream.
	 *
	 * @param keyPair The Public Key.
	 * @param out The stream the Public Key is to be written to.
	 */
	private void writePublicKey(AsymmetricCipherKeyPair keyPair, OutputStream out)
	{
		try
		{
			SubjectPublicKeyInfo pki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(keyPair.getPublic());
			writeKey(out, pki);
		}
		catch (IOException ex)
		{
			throw new RuntimeException();
		}
		catch (Exception ex)
		{
			throw new RuntimeException();
		}
	}

	/**
	 * Generate a Public / Private RSA key pair and write them to the designated
	 * file names.
	 *
	 * @param private_filename The file name to which the RSA Private Key will
	 * be written.
	 * @param public_filename The file name to which the RSA Public Key will be
	 * written.
	 */
	public void generateKey(String private_filename, String public_filename)
	{
		FileOutputStream fos_public = null;
		try
		{
			FileOutputStream fos_private = new FileOutputStream(private_filename);
			fos_public = new FileOutputStream(public_filename);
			generateKey(fos_private, fos_public);
		}
		catch (FileNotFoundException ex)
		{
			throw new RuntimeException();
		}
		finally
		{
			closeStream(fos_public);
		}
	}

	/**
	 * Generate a Public / Private RSA key pair and write them to the designated
	 * Output Streams.
	 *
	 * @param os_private The stream to which the RSA Private Key will be
	 * written.
	 * @param os_public The stream to which the RSA Public Key will be written.
	 */
	public void generateKey(OutputStream os_private, OutputStream os_public)
	{
		try
		{
			BigInteger publicExponent = new BigInteger("10001", 16);
			SecureRandom secure = new SecureRandom();
			RSAKeyGenerationParameters kparams = new RSAKeyGenerationParameters(publicExponent, secure, RSA_STRENGTH, 80);

			RSAKeyPairGenerator kpg = new RSAKeyPairGenerator();
			kpg.init(kparams);
			AsymmetricCipherKeyPair keyPair = kpg.generateKeyPair();

			writePrivateKey(keyPair, os_private);
			writePublicKey(keyPair, os_public);
		}
		catch (Exception ex)
		{
			throw new RuntimeException();
		}
	}

	/**
	 * Checks for the existence of the RSA Private and Public Key and returns
	 * true if they exist or false if they don't.
	 *
	 * @param private_filename The file containing the RSA Private Key.
	 * @param public_filename The file containing the RSA Public Key.
	 * @return True if the key pair exist false if they do not.
	 */
	public boolean areKeysPresent(String private_filename, String public_filename)
	{
		boolean bOK = false;
		File privateKey = new File(private_filename);
		File publicKey = new File(public_filename);

		if (privateKey.exists() && publicKey.exists())
		{
			bOK = true;
		}
		return bOK;
	}

	/**
	 * General purpose function to close a Stream.
	 *
	 * @param stream The stream to be closed.
	 */
	private void closeStream(Closeable stream)
	{
		try
		{
			if (stream != null)
			{
				stream.close();
			}
		}
		catch (IOException ex)
		{
			throw new RuntimeException();
		}
	}
}
