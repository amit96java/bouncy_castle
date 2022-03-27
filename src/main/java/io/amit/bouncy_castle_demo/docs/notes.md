https://www.youtube.com/watch?v=1925zmDP_BY

CBC: cipher block chaining

PBKDF2: password based key derivation function

signature contains the message.

certificate contains the public key.

https://github.com/MichelSchudel/crypto-demo

command to generate keystore:

    keytool -genkey -alias amit -keyalg RSA -keystore "D:\local.keystore"

Check data inside keystore file:

    keytool -v -list -keystore "D:\local.keystore"

REad certificate:

    https://docs.hidglobal.com/auth-service/docs/buildingapps/java/read-different-certificate-key-file-formats-with-java.htm

generate private public key :

    https://help.interfaceware.com/v6/how-to-create-self-certified-ssl-certificate-and-publicprivate-key-files

install open ssl on windows:

    https://www.youtube.com/watch?v=jSkQ27sTto0
    install openssl
    add bin path in environment variables
    verify with this command: openssl version

Bouncy Castle Example:

    https://www.bouncycastle.org/fips-java/BCFipsIn100.pdf
Example 58 – Basic CertPath Validation


Bouncy Castle with Scala:

    https://index.scala-lang.org/karasiq/cryptoutils/cryptoutils/1.4.3?binaryVersion=_2.12
