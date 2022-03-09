#!/usr/bin/env dotnet-script
/*
This script requires OpenSSL to be installed and the 
libcrypto.dylib and libssl.dylib to be accessable vai
the PATH environment variable.
Example: 
sudo ln -Fs /usr/local/opt/openssl/lib/libcrypto.dylib /usr/local/lib
*/

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

// This is the actual key exchange and message passing code.

var client = new Client();
var server = new Server(client.PublicKey);
client.DeriveKeyMaterial(server.PublicKey);
client.Send("Hello World", out var encryptedMessage, out var iv);
server.Receive(encryptedMessage, iv);

// End of script.

public class Client
{
  readonly ECDiffieHellman ECDH = null;

  byte[] clientKey = null;

  public ECDiffieHellmanPublicKey PublicKey => ECDH?.PublicKey;

  /// <summary>
  /// This throws Operation Not Supported Exception: 
  /// I need to figure out how to serialize the public key
  /// </summary>
  public byte[] PublicKeyBlob => PublicKey.ToByteArray();

  public Client()
  {
    ECDH = ECDiffieHellman.Create();
  }

  public Client(byte[] keyBlob) : this()
  {
    DeriveKeyMaterial(keyBlob);
  }

  public Client(ECDiffieHellmanPublicKey publicKey) : this()
  {
    DeriveKeyMaterial(publicKey);
  }

  public void DeriveKeyMaterial(byte[] keyBytes)
  {
    clientKey = ECDH.DeriveKeyMaterial(ECDiffieHellmanOpenSslPublicKey.Create(keyBytes));
  }

  public void DeriveKeyMaterial(ECDiffieHellmanPublicKey publicKey)
  {
    clientKey = ECDH.DeriveKeyMaterial(publicKey);
  }

  public void Send(string message, out byte[] encryptedMessage, out byte[] iv)
  {
    using (var aes = Aes.Create())
    {
      aes.Key = clientKey;
      iv = aes.IV;

      using (var cipherText = new MemoryStream())
      using (CryptoStream cs = new CryptoStream(cipherText, aes.CreateEncryptor(), CryptoStreamMode.Write))
      {
        byte[] plaintextMessage = Encoding.UTF8.GetBytes(message);
        cs.Write(plaintextMessage, 0, plaintextMessage.Length);
        cs.Close();
        encryptedMessage = cipherText.ToArray();
      }
    }
  }
}

public class Server
{
  readonly ECDiffieHellman ECDH = null;

  byte[] serverKey = null;

  public ECDiffieHellmanPublicKey PublicKey => ECDH?.PublicKey;

  /// <summary>
  /// This throws Operation Not Supported Exception: 
  /// I need to figure out how to serialize the public key
  /// </summary>
  public byte[] PublicKeyBlob => PublicKey.ToByteArray();

  public Server()
  {
    ECDH = ECDiffieHellman.Create();
  }

  public Server(byte[] clientPublicKey) : this()
  {
    DeriveKeyMaterial(clientPublicKey);
  }

  public Server(ECDiffieHellmanPublicKey clientPublicKey) : this()
  {
    DeriveKeyMaterial(clientPublicKey);
  }

  public void DeriveKeyMaterial(byte[] keyBytes)
  {
    serverKey = ECDH.DeriveKeyMaterial(ECDiffieHellmanOpenSslPublicKey.Create(keyBytes));
  }

  public void DeriveKeyMaterial(ECDiffieHellmanPublicKey publicKey)
  {
    serverKey = ECDH.DeriveKeyMaterial(publicKey);
  }

  public void Receive(byte[] encryptedMessage, byte[] iv)
  {
    using (var aes = Aes.Create())
    {
      aes.Key = serverKey;
      aes.IV = iv;
      using (var plainText = new MemoryStream())
      using (var cs = new CryptoStream(plainText, aes.CreateDecryptor(), CryptoStreamMode.Write))
      {
        cs.Write(encryptedMessage, 0, encryptedMessage.Length);
        cs.Close();
        string message = Encoding.UTF8.GetString(plainText.ToArray());
        Console.WriteLine(message);
      }
    }
  }
}

public class ECDiffieHellmanOpenSslPublicKey : ECDiffieHellmanPublicKey
{
  public static ECDiffieHellmanPublicKey Create(byte[] keyBlob) => new ECDiffieHellmanOpenSslPublicKey(keyBlob);
  public ECDiffieHellmanOpenSslPublicKey(byte[] keyBlob) : base(keyBlob) { }
}