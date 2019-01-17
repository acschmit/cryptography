/**
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 Albert C Schmitt
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
 * documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
 * WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package org.albertschmitt.crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.albertschmitt.crypto.common.ByteUtil;
import org.albertschmitt.crypto.common.Hex;
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
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.util.io.pem.PemGenerationException;
import org.bouncycastle.util.io.pem.PemObject;

/**
 * This class implements RSA private/public key encryption with a 2048 bit key
 * using the Bouncy Castle API. Clients can use this class to easily incorporate
 * encryption into their applications. Note when converting between strings and
 * byte arrays clients should be sure to convert using the UTF-8 character set.
 * <p>
 * External Dependencies:
 * <a target="top" href="http://www.bouncycastle.org/">Bouncy Castle Release
 * 1.52</a>
 * </p>
 * <ul>
 * <li>bcpkix-jdk15on.jar</li>
 * <li>bcprov-jdk15on.jar</li>
 * </ul>
 *
 * @author Albert Schmitt [acschmit] [at] [gmail] [dot] [com]
 */
public class RSAService
{

	/**
	 * The allowable RSA key sizes.
	 */
	public enum KEYSIZE
	{

		RSA_2K(2048), RSA_3K(3072), RSA_4K(4096);

		int value;

		private KEYSIZE(int value)
		{
			this.value = value;
		}

		public int getKeySize()
		{
			return value;
		}

		public int getEncLength()
		{
			return value / 8;
		}
	}

	private final KEYSIZE keysize;
	private static final int PADDING_PKCS1 = 11;

	/**
	 * Create an instance of the RSAService using a 2048 bit key.
	 */
	public RSAService()
	{
		this.keysize = KEYSIZE.RSA_2K;
	}

	/**
	 * Create an instance of the RSAService class using the specified key size.
	 *
	 * @param keysize The key size to create.
	 */
	public RSAService(KEYSIZE keysize)
	{
		this.keysize = keysize;
	}

	/**
	 * Return an AsymmetricBlockCipher for encryption or decryption.
	 *
	 * @param key The RSA key.
	 * @param forEncryption True if encrypting, false if decrypting.
	 * @return AsymmetricBlockCipher configured to encrypt or decrypt.
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
	private byte[] doCipher(byte[] data, Key key, Boolean forEncryption) throws InvalidCipherTextException
	{
		AsymmetricBlockCipher cipher = getCipher(key, forEncryption);

		int max_length = (forEncryption) ? keysize.getEncLength() - PADDING_PKCS1 : keysize.getEncLength();
		int blocksize = max_length;
		int offset = 0;
		byte[] bytes = new byte[0];

		while (blocksize == max_length)
		{
			int remainder = data.length - offset;
			blocksize = (remainder > max_length) ? max_length : remainder;
			if (blocksize != 0)
			{
				byte[] enc = cipher.processBlock(data, offset, blocksize);
				bytes = ByteUtil.concatenate(bytes, enc);
			}
			offset += max_length;
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
			throws IOException, InvalidCipherTextException
	{
		AsymmetricBlockCipher cipher = getCipher(key, forEncryption);

		int max_length = (forEncryption) ? keysize.getEncLength() - PADDING_PKCS1 : keysize.getEncLength();
		byte[] inbuf = new byte[max_length];
		int blocksize = max_length;

		while ((blocksize = instream.read(inbuf, 0, blocksize)) != -1)
		{
			byte[] enc = cipher.processBlock(inbuf, 0, blocksize);
			outstream.write(enc, 0, enc.length);
		}
		outstream.flush();
	}

	/**
	 * Encode the byte data and return it in an byte array.
	 *
	 * @param data The byte array to be encoded.
	 * @param key The key to be used.
	 * @return The RSA encoded data.
	 * @throws org.bouncycastle.crypto.InvalidCipherTextException
	 * @see #decode(byte[] data, Key key)
	 */
	public byte[] encode(byte[] data, Key key) throws InvalidCipherTextException
	{
		return doCipher(data, key, true);
	}

	/**
	 * Encode the String and return it in an byte array.
	 *
	 * @param data The String to be encoded.
	 * @param key The key to be used.
	 * @return The RSA encoded data.
	 * @throws org.bouncycastle.crypto.InvalidCipherTextException
	 * @throws java.io.UnsupportedEncodingException
	 * @see #decode(byte[] data, Key key)
	 */
	public byte[] encode(String data, Key key) throws InvalidCipherTextException, UnsupportedEncodingException
	{
		byte[] bytes = data.getBytes(StandardCharsets.UTF_8);
		return doCipher(bytes, key, true);
	}

	/**
	 * Decode the RSA encoded byte data and return it in an byte array.
	 *
	 * @param data RSA encoded byte array.
	 * @param key The key to be used.
	 * @return Decoded byte array of RSA encoded input data.
	 * @throws org.bouncycastle.crypto.InvalidCipherTextException
	 * @see #encode(byte[] data, Key key)
	 */
	public byte[] decode(byte[] data, Key key) throws InvalidCipherTextException
	{
		return doCipher(data, key, false);
	}

	/**
	 * Decode the RSA encoded String and return it in an byte array.
	 *
	 * @param data RSA encoded String.
	 * @param key The key to be used.
	 * @return Decoded byte array of RSA encoded input data.
	 * @throws org.bouncycastle.crypto.InvalidCipherTextException
	 * @see #encode(byte[] data, Key key)
	 */
	public byte[] decode(String data, Key key) throws InvalidCipherTextException
	{
		byte[] bytes = Hex.decode(data);
		return doCipher(bytes, key, false);
	}

	/**
	 * Encode the input stream to RSA and return it in an output stream.
	 *
	 * @param instream Stream to be encoded.
	 * @param outstream RSA encoded output stream of input stream.
	 * @param key The key to be used.
	 * @throws java.io.IOException
	 * @throws org.bouncycastle.crypto.InvalidCipherTextException
	 */
	public void encode(InputStream instream, OutputStream outstream, Key key)
			throws IOException, InvalidCipherTextException
	{
		doCipher(instream, outstream, key, true);
	}

	/**
	 * Decode the RSA encoded input stream and return it in an output stream.
	 *
	 * @param instream RSA encoded input stream to be decoded.
	 * @param outstream Decoded output stream of input stream.
	 * @param key The key to be used.
	 * @throws java.io.IOException
	 * @throws org.bouncycastle.crypto.InvalidCipherTextException
	 */
	public void decode(InputStream instream, OutputStream outstream, Key key)
			throws IOException, InvalidCipherTextException
	{
		doCipher(instream, outstream, key, false);
	}

	/**
	 * Read the RSA Private Key from the specified filename.
	 *
	 * @param filename The file that contains the RSA Private Key.
	 * @return The RSAPrivateKey.
	 * @throws java.io.FileNotFoundException
	 */
	public RSAPrivateKey readPrivateKey(String filename) throws FileNotFoundException, IOException
	{
		RSAPrivateKey key;
		try (FileInputStream in = new FileInputStream(filename))
		{
			key = readPrivateKey(in);
		}
		return key;
	}

	/**
	 * Read the RSA Private Key from the specified input stream.
	 *
	 * @param instream The input stream that contains the RSA Private Key.
	 * @return The RSAPrivateKey or null if the key is invalid.
	 * @throws java.io.IOException
	 */
	public RSAPrivateKey readPrivateKey(InputStream instream) throws IOException
	{
		RSAPrivateKey key = null;
		try (InputStreamReader reader = new InputStreamReader(instream))
		{
			try (PEMParser pem = new PEMParser(reader))
			{
				Object obj = pem.readObject();
				if (obj instanceof PEMKeyPair)
				{
					PEMKeyPair pkp = (PEMKeyPair) obj;
					PrivateKeyInfo pki = pkp.getPrivateKeyInfo();
					key = new RSAPrivateKey();
					key.setKey(pki);
				}
			}
		}

		return key;
	}

	/**
	 * Read the RSA Private Key from the specified filename using the given
	 * password.
	 *
	 * @param filename The file that contains the RSA Private Key.
	 * @param password The password the private key was encrypted with.
	 * @return The RSAPrivateKey.
	 * @throws FileNotFoundException
	 * @throws IOException
	 * @throws OperatorCreationException
	 * @throws PKCSException
	 */
	public RSAPrivateKey readPrivateKey(String filename, char[] password)
			throws FileNotFoundException, IOException, OperatorCreationException, PKCSException
	{
		RSAPrivateKey key;
		try (FileInputStream instream = new FileInputStream(filename))
		{
			key = readPrivateKey(instream, password);
		}
		return key;
	}

	/**
	 * Read the RSA Private Key from the specified input stream using the given
	 * password.
	 *
	 * @param instream The input stream that contains the RSA Private Key.
	 * @param password The password the private key was encrypted with.
	 * @return The RSAPrivateKey.
	 * @throws IOException
	 * @throws OperatorCreationException
	 * @throws PKCSException
	 */
	public RSAPrivateKey readPrivateKey(InputStream instream, char[] password)
			throws IOException, OperatorCreationException, PKCSException
	{
		RSAPrivateKey key;
		try (InputStreamReader reader = new InputStreamReader(instream))
		{
			try (PEMParser pem = new PEMParser(reader))
			{
				PKCS8EncryptedPrivateKeyInfo pair = (PKCS8EncryptedPrivateKeyInfo) pem.readObject();
				JceOpenSSLPKCS8DecryptorProviderBuilder jce = new JceOpenSSLPKCS8DecryptorProviderBuilder();
				InputDecryptorProvider decProv = jce.build(password);
				PrivateKeyInfo pki = pair.decryptPrivateKeyInfo(decProv);

				key = new RSAPrivateKey();
				key.setKey(pki);
			}
		}

		return key;
	}

	/**
	 * Read the PKCS8 Private Key DER from the specified filename.
	 *
	 * @param filename The file that contains the RSA Private Key.
	 * @return The RSAPrivateKey.
	 * @throws FileNotFoundException
	 * @throws IOException
	 */
	public RSAPrivateKey readPrivateKeyDER(String filename) throws FileNotFoundException, IOException
	{
		RSAPrivateKey key;
		try (FileInputStream instream = new FileInputStream(filename))
		{
			key = readPrivateKeyDER(instream);
		}
		return key;
	}

	/**
	 * Read the PKCS8 Private Key DER from the specified input stream.
	 *
	 * @param instream The input stream that contains the RSA Private Key.
	 * @return The RSAPrivateKey.
	 * @throws IOException
	 */
	public RSAPrivateKey readPrivateKeyDER(InputStream instream) throws IOException
	{

		AsymmetricKeyParameter keyParam = PrivateKeyFactory.createKey(instream);
		RSAPrivateKey key = new RSAPrivateKey();
		key.setKey(keyParam);

		return key;
	}

	public RSAPrivateKey readPrivateKeyDER(String filename, char[] password)
			throws FileNotFoundException, IOException, OperatorCreationException, PKCSException
	{
		RSAPrivateKey key;
		try (FileInputStream instream = new FileInputStream(filename))
		{
			key = readPrivateKeyDER(instream, password);
		}
		return key;
	}

	public RSAPrivateKey readPrivateKeyDER(InputStream instream, char[] password)
			throws IOException, OperatorCreationException, PKCSException
	{
		RSAPrivateKey key;

		byte[] data = ByteUtil.readFileBytes(instream);

		PKCS8EncryptedPrivateKeyInfo pair = new PKCS8EncryptedPrivateKeyInfo(data);
		JceOpenSSLPKCS8DecryptorProviderBuilder jce = new JceOpenSSLPKCS8DecryptorProviderBuilder();
		InputDecryptorProvider decProv = jce.build(password);
		PrivateKeyInfo pki = pair.decryptPrivateKeyInfo(decProv);

		key = new RSAPrivateKey();
		key.setKey(pki);

		return key;
	}

	/**
	 * Read the RSA Public Key from the specified filename.
	 *
	 * @param filename The file that contains the RSA Public Key.
	 * @return The RSAPublicKey.
	 * @throws java.io.FileNotFoundException
	 */
	public RSAPublicKey readPublicKey(String filename) throws FileNotFoundException, IOException
	{
		RSAPublicKey key;
		try (FileInputStream in = new FileInputStream(filename))
		{
			key = readPublicKey(in);
		}
		return key;
	}

	/**
	 * Read the RSA Public Key from the specified input stream.
	 *
	 * @param instream The input stream that contains the RSA Public Key.
	 * @return The RSAPublicKey.
	 * @throws java.io.IOException
	 */
	public RSAPublicKey readPublicKey(InputStream instream) throws IOException
	{
		SubjectPublicKeyInfo pki;
		try (InputStreamReader reader = new InputStreamReader(instream))
		{
			try (PEMParser pem = new PEMParser(reader))
			{
				pki = (SubjectPublicKeyInfo) pem.readObject();
			}
		}

		byte[] data = pki.getEncoded();
		RSAPublicKey key = new RSAPublicKey();
		key.setKey(PublicKeyFactory.createKey(data));

		return key;
	}

	/**
	 * Read the DER Public Key from the specified filename.
	 *
	 * @param filename The file that contains the DER key.
	 * @return RSAPublicKey.
	 * @throws FileNotFoundException
	 * @throws IOException
	 */
	public RSAPublicKey readPublicKeyDER(String filename) throws FileNotFoundException, IOException
	{
		RSAPublicKey key;
		try (FileInputStream instream = new FileInputStream(filename))
		{
			key = readPublicKeyDER(instream);
		}
		return key;
	}

	/**
	 * Read the DER Public Key from the specified input stream.
	 *
	 * @param instream The stream that contains the DER key.
	 * @return RSAPublicKey.
	 * @throws IOException
	 */
	public RSAPublicKey readPublicKeyDER(InputStream instream) throws IOException
	{
		AsymmetricKeyParameter keyParam = PublicKeyFactory.createKey(instream);
		RSAPublicKey key = new RSAPublicKey();
		key.setKey(keyParam);

		return key;
	}

	/**
	 * Extract the Public Key from the RSA Private Key from the file and return
	 * it to the client.
	 *
	 * @param filename The file that contains the RSA Private Key.
	 * @return The RSAPublicKey.
	 * @throws java.io.FileNotFoundException
	 */
	public RSAPublicKey readPublicKeyFromPrivate(String filename) throws FileNotFoundException, IOException
	{
		RSAPublicKey key;
		try (FileInputStream in = new FileInputStream(filename))
		{
			key = readPublicKeyFromPrivate(in);
		}
		return key;
	}

	/**
	 * Extract the Public Key from the RSA Private Key from the input stream and
	 * return it to the client.
	 *
	 * @param instream The input stream that contains the RSA Private Key.
	 * @return The RSAPublicKey.
	 * @throws java.io.IOException
	 */
	public RSAPublicKey readPublicKeyFromPrivate(InputStream instream) throws IOException
	{
		org.bouncycastle.openssl.PEMKeyPair pkp;
		try (InputStreamReader reader = new InputStreamReader(instream))
		{
			try (PEMParser pem = new PEMParser(reader))
			{
				pkp = (PEMKeyPair) pem.readObject();
			}
		}
		SubjectPublicKeyInfo pki = pkp.getPublicKeyInfo();
		byte[] data = pki.getEncoded();
		RSAPublicKey key = new RSAPublicKey();
		key.setKey(PublicKeyFactory.createKey(data));

		return key;
	}

	/**
	 * Utility function that writes an RSA Public or Private key to an output
	 * stream in PEM format.
	 *
	 * @param outstream The stream to write the RSA key to.
	 * @param pki The Key to be written to the stream.
	 */
	private <T> void writePEMKey(OutputStream outstream, T pki) throws IOException
	{
		OutputStreamWriter writer = new OutputStreamWriter(outstream, StandardCharsets.UTF_8);
		try (JcaPEMWriter pem = new JcaPEMWriter(writer))
		{
			pem.writeObject(pki);
		}
	}

	/**
	 * Write the RSAPrivateKey to a stream in DER format.
	 *
	 * @param outstream The stream the DER key is to be written to.
	 * @param key The RSAPrivatKey.
	 * @throws IOException
	 */
	public void writeDERKey(OutputStream outstream, RSAPrivateKey key) throws IOException
	{
		AsymmetricKeyParameter keyParam = key.getKey();
		PrivateKeyInfo pki = PrivateKeyInfoFactory.createPrivateKeyInfo(keyParam);
		byte[] keybytes = pki.getEncoded();
		outstream.write(keybytes);
		outstream.close();
	}

	/**
	 * Write the RSAPublicKey to a stream in DER format.
	 *
	 * @param outstream the stream the DER key is to be written to.
	 * @param key the RSAPublicKey.
	 * @throws IOException
	 */
	public void writeDERKey(OutputStream outstream, RSAPublicKey key) throws IOException
	{
		AsymmetricKeyParameter keyParam = key.getKey();
		SubjectPublicKeyInfo pki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(keyParam);
		byte[] keybytes = pki.getEncoded();

		outstream.write(keybytes);
		outstream.close();
	}

	/**
	 * Generate a Public / Private RSA key pair and write them to the designated
	 * file names.
	 *
	 * @param private_filename The file name to which the RSA Private Key will
	 * be written.
	 * @param public_filename The file name to which the RSA Public Key will be
	 * written.
	 * @throws java.io.FileNotFoundException
	 */
	public void generateKey(String private_filename, String public_filename) throws FileNotFoundException, IOException
	{
		try (FileOutputStream fos_private = new FileOutputStream(private_filename);
			 FileOutputStream fos_public = new FileOutputStream(public_filename))
		{
			generateKey(fos_private, fos_public);
		}
	}

	/**
	 * Generate a Public / Private RSA key pair and write them to the designated
	 * Output Streams.
	 *
	 * @param os_private The stream to which the RSA Private Key will be
	 * written.
	 * @param os_public The stream to which the RSA Public Key will be written.
	 * @throws java.io.IOException
	 */
	public void generateKey(OutputStream os_private, OutputStream os_public) throws IOException
	{
		BigInteger publicExponent = new BigInteger("10001", 16);
		SecureRandom secure = new SecureRandom();
		RSAKeyGenerationParameters kparams = new RSAKeyGenerationParameters(publicExponent, secure,
																			keysize.getKeySize(), 80);

		RSAKeyPairGenerator kpg = new RSAKeyPairGenerator();
		kpg.init(kparams);
		AsymmetricCipherKeyPair keyPair = kpg.generateKeyPair();

		// Write private key.
		PrivateKeyInfo pkiPrivate = PrivateKeyInfoFactory.createPrivateKeyInfo(keyPair.getPrivate());
		writePEMKey(os_private, pkiPrivate);

		// Write public key.
		SubjectPublicKeyInfo pkiPublic = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(keyPair.getPublic());
		writePEMKey(os_public, pkiPublic);
	}

	/**
	 * Generate a Public / Private RSA key pair and write them to the designated
	 * file names.
	 *
	 * @param private_filename The file name to which the RSA Private Key will
	 * be written.
	 * @param public_filename The file name to which the RSA Public Key will be
	 * written.
	 * @param password The RSA Private Key will be encrypted with this password.
	 * @throws java.io.FileNotFoundException
	 * @throws java.security.NoSuchAlgorithmException
	 * @throws org.bouncycastle.operator.OperatorCreationException
	 * @throws java.io.UnsupportedEncodingException
	 */
	public void generateKey(String private_filename, String public_filename, char[] password)
			throws FileNotFoundException, NoSuchAlgorithmException, OperatorCreationException,
				   UnsupportedEncodingException, IOException
	{
		try (FileOutputStream fos_private = new FileOutputStream(private_filename);
			 FileOutputStream fos_public = new FileOutputStream(public_filename))
		{
			generateKey(fos_private, fos_public, password);
		}
	}

	/**
	 * Generate a Public / Private RSA key pair and write them to the designated
	 * Output Streams.
	 *
	 * @param os_private The stream to which the RSA Private Key will be
	 * written.
	 * @param os_public The stream to which the RSA Public Key will be written.
	 * @param password The RSA Private Key will be encrypted with this password.
	 * @throws java.security.NoSuchAlgorithmException
	 * @throws org.bouncycastle.operator.OperatorCreationException
	 * @throws org.bouncycastle.util.io.pem.PemGenerationException
	 * @throws java.io.UnsupportedEncodingException
	 * @throws java.io.IOException
	 */
	public void generateKey(OutputStream os_private, OutputStream os_public, char[] password)
			throws NoSuchAlgorithmException, OperatorCreationException, PemGenerationException,
				   UnsupportedEncodingException, IOException
	{
		final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		final SecureRandom secure = new SecureRandom();
		kpg.initialize(keysize.getKeySize(), secure);
		KeyPair keyPair = kpg.generateKeyPair();

		final PemObject pem = encryptKey(keyPair, password);
		try (JcaPEMWriter writer = new JcaPEMWriter(new OutputStreamWriter(os_private, StandardCharsets.UTF_8)))
		{
			writer.writeObject(pem);
		}

		try (JcaPEMWriter writer = new JcaPEMWriter(new OutputStreamWriter(os_public, StandardCharsets.UTF_8)))
		{
			writer.writeObject(keyPair.getPublic());
		}
	}

	/**
	 * Encrypt the KeyPair with the password and return it as a PEM object.
	 *
	 * @param keyPair The RSA Private / Public Key Pair.
	 * @param password The RSA Private Key will be encrypted with this password.
	 * @return A PEM object with the encrypted KeyPair..
	 * @throws OperatorCreationException
	 * @throws PemGenerationException
	 */
	private PemObject encryptKey(KeyPair keyPair, char[] password)
			throws OperatorCreationException, PemGenerationException
	{
		final JceOpenSSLPKCS8EncryptorBuilder encryptorBuilder = new JceOpenSSLPKCS8EncryptorBuilder(
				PKCS8Generator.PBE_SHA1_3DES);
		encryptorBuilder.setRandom(new SecureRandom());
		encryptorBuilder.setPasssword(password);
		encryptorBuilder.setIterationCount(10000);
		OutputEncryptor oe = encryptorBuilder.build();
		final JcaPKCS8Generator gen = new JcaPKCS8Generator(keyPair.getPrivate(), oe);
		final PemObject pem = gen.generate();
		return pem;
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
}
