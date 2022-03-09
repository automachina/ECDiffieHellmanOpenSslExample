# .NET Elliptic Curve Diffie Helman via OpenSSL 
An example of exchanging ECDH keys and encrypted messages on using ECDiffieHelman api on MacOS.

This script requires OpenSSL to be installed on the system.

MacOS: 
- brew install openssl
- libcrypto.dylib and libssl.dylib need to be accessable vai the PATH environment variable.

   - Example: `sudo ln -Fs /usr/local/opt/openssl/lib/libcrypto dylib /usr/local/lib`