# cryptography

An easy to use AES and RSA cryptography library written in java, built on the Bouncy Castle API.  With this library you can quickly and easily incorporate AES-256 and RSA encryption into your project.

If you develop in both Java and C# then this project and the <a href="https://github.com/acschmit/cryptography.Net" target="_blank">C# project</a> are worth taking a look at.  They share the same API.  The Unit Tests and Examples are the same between them as well to illustrate their similarity.

## Version 1.0.8-SNAPSHOT Updates
### Project
*TBD.
 
### AESService
* Changed password in generateKey function to char[] to prevent memory attacks on immutable string password.

### RSAService
* Added functions to read and write DER files.  DER private key must be in PKCS8 format if it is generated by openssl.
 
## Key Structure
Bouncy Castle saves PEM keys in PKCS#1 format but it can read PEM keys in PKCS#8 format as well.

## License
The [license](LICENSE.txt), including licenses for dependent software, can be read [here](LICENSE.txt).

##External Dependencies
This library is dependent on the following jar files in <a href="http://www.bouncycastle.org" target="_blank">Bouncy Castle Version 1.52</a>.

* bcpkix-jdk15on.jar
* bcprov-jdk15on.jar

## Installation instructions
Be sure you have Maven installed in your IDE.

Either download the zip file or clone the repository to obtain the full project source. Compile the project and it will install all jar files in your local repository.

Create a new Maven project and search the repository for **org.albertschmitt**.  Add cryptography version 1.0.7.  Once this is done your project should have the following dependencies.

* cryptography-1.0.7.jar
* bcpkix-jdk15on.jar
* bcprov-jdk15on.jar

## Examples

For comprehensive examples see my other project [cryptography-examples](https://github.com/acschmit/cryptography-examples).

#### Example 1

Adding AES256 encryption to your project can be as simple as this:
```java

import java.security.SecureRandom;
import org.albertschmitt.crypto.AESService;
import static org.albertschmitt.crypto.AESService.SALT_SIZE;

public class Example_060
{
	public static void main(String[] args) throws Exception
	{
		// Create the AES Service
		AESService aes = new AESService();

		String password = "password";
		SecureRandom random = new SecureRandom();
		byte[] salt = new byte[SALT_SIZE];
		random.nextBytes(salt);

		// Create the AES Key using password and salt.
		aes.generateKey(password, salt);

		// Encode and Decode a string then compare to verify they are the same.
		String clear_text = "This is a test";
		byte[] enc_bytes = aes.encode(clear_text.getBytes("UTF-8"));
		byte[] dec_bytes = aes.decode(enc_bytes);
		String dec_text = new String(dec_bytes, "UTF-8");

		if (clear_text.equals(dec_text))
		{
			System.out.println("Original and Decrypted are the same!");
		}
		else
		{
			System.out.println("Original and Decrypted are NOT the same!");
		}
	}
}
```
