import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.print.DocFlavor.URL;


public class ECIES
{

  private static byte[] loadPEM (String resource) throws IOException
  {
    File file = new File (resource);
    FileInputStream in = new FileInputStream (file);

    String pem = new String (in.readAllBytes (), StandardCharsets.ISO_8859_1);
    Pattern parse =
      Pattern.compile ("(?m)(?s)^---*BEGIN.*---*$(.*)^---*END.*---*$.*");
    String encoded = parse.matcher (pem).replaceFirst ("$1");
      return Base64.getMimeDecoder ().decode (encoded);
  }

  public static void main (String[]args) throws Exception, IOException
  {

    String name = "secp256k1";	// type of elliptic curve, choose any other type supported both by our TLCS system AND the JCA/bouncycastle
    String plainText = "Ciao";
    KeyFactory kf = KeyFactory.getInstance ("ECDH");
    Cipher iesCipher = Cipher.getInstance ("ECIES");

      try
    {
      PublicKey pub = kf.generatePublic (new X509EncodedKeySpec (loadPEM ("pk.pem")));	// load the TLCS public key from file


        iesCipher.init (Cipher.ENCRYPT_MODE, pub);

      byte cipherText[] =
	new byte[iesCipher.getOutputSize (plainText.getBytes ().length)];

      // encrypt
      int ctlength =
	iesCipher.update (plainText.getBytes (), 0,
			  plainText.getBytes ().length, cipherText, 0);
        ctlength += iesCipher.doFinal (cipherText, ctlength);

// decrypt                  
      PrivateKey sk = kf.generatePrivate (new PKCS8EncodedKeySpec (loadPEM ("sk.pkcs8")));	// load the TLCS sk from file

      Cipher iesCipher2 = Cipher.getInstance ("ECIES");
        iesCipher2.init (Cipher.DECRYPT_MODE, sk);
        byte[] plainText2 =
	new byte[iesCipher2.getOutputSize (cipherText.length)];
      int ctlength2 =
	iesCipher2.update (cipherText, 0, ctlength, plainText2, 0);
        ctlength2 += iesCipher2.doFinal (plainText2, ctlength2);
        System.out.println ("decrypted plaintext: " +
			    Utils.toString (plainText2));
    } catch (InvalidKeySpecException | IOException e)
    {
      e.printStackTrace ();
    }

  }
}