# The FIDO2 extension for TLS 1.3
This repository provides an implementation of the FIDO2 extension for 
TLS 1.3. The extension enables the use of strong cryptographic user
authentication according to FIDO2 specifications during the handshake.  
This repository is forked from the tlslite-ng project in version
0.8.0-alpha26. For more information on tlslite-ng see the
[README-tlslite-ng.md](README_tlslite-ng.md) file or the
[original repository][1].


# Table of Contents
[1. How it works](#basics)  
[2. License](#license)  
[3. Installation](#installation)  
[4. Registration](#registration)  
[5. Authentication](#authentication)


<a name="basics"></a>
# How it works
There are two different modes for the TLS 1.3 with FIDO2 (TFE)
handshake. The FIDO2 with ID (FI) and the FIDO2 with name (FN) mode.  
In the FI mode the user is identified through an ID and does not need to
provide a user name. The ID is returned by the [authenticator][3]
together with an [assertion][4] during the authentication process. It is
bound to the [public key credential source (PKCS)][5] used to generate
the assertion. Only [resident PKCS][6] support authentication without a
user name, as only they allow to store a user ID. Resident PKCSs store
private key shares thus allowing to generate an assertion given only the
identifier of the relying party ([RP-ID][7]). A relying party server
therefore may generate all challenge parameters user-independent. As the
user ID is stored on the authenticator and the user does not need to
remember it, it may be chosen independently for every relying party,
thus reducing the correlatability between them.  
In the FN mode the user is identified through its user name, which he
provides before any FIDO2 operation is initialized. Based on the user
name the server is able to look up the IDs of PKCSs registered to the
user and submit them together with the challenge. That enables the use
of non-resident PKCSs on the authenticator and the compatibility to U2F.  
As the information exchange in the FI and FN mode differ, so does the
design of the two handshake modes.

### The FI mode
In the FI mode the client signals the usage of FIDO2 in the
FIDO2ClientHello extension, also providing the mode of the handshake.
Together with its ServerHello message the server submits a
FIDO2AssertionRequest containing user-independent authentication
parameters including a challenge. The client response in a
FIDO2AssertionResponse message just before the Finished message. It
contains all information the server needs to at the same time identify
and authenticate the user, especially its the ID.  
U2F authenticators do not support this handshake, as the IDs of
previously registered PKCSs are not submitted and therefore no key
handle may be presented to the authenticator, plus they are unable to
store the ID of the user a PKCS is bound to.

 
### The FN mode
In the FN mode a double handshake is performed. The first handshake is
used to confidentially exchange the user name between the client and the
server, establish an ephemeral user name mapping to that user name and
store the tuple on the server. For that purpose the client sends a
FIDO2ClientHelloExtension indicating the use and the mode of the FIDO2
authentication. The server together with its ServerHello sends a
FIDO2NameRequest, asking the client to submit its user name. The client
responds with its name in the FIDO2NameResponse just before the Finished
message. A SHA256 hash over the concatenation of random bytes included
in the FIDO2NameRequest and FIDO2NameResponse is used as the ephemeral
user name.  
In the second handshake the user authentication takes place, much like
in the FI mode. In the FIDO2ClientHelloExtension the user submits the
ephemeral user name agreed upon in the first handshake. The server looks
up the associated user name and generates request parameters based on
the information stored for that particular user, such as the IDs of
registered PKCSs. Together with the ServerHello the server submits a
FIDO2AssertionRequest containing a challenge and all other generated
request parameters. The response of the client is again sent right
before the Finished message. The FIDO2AssertionResponse contains all
information the server needs to authenticate the user.  
The single TFE-FN handshake performs the user authentication within one
handshake, if client and server have communicated in the past. To allow
for the single handshake server and client must establish the ephemeral
user name in a previous connection. Random bytes for generating the
ephemeral user name can therefore be transmitted in the
FIDO2AssertionRequest and FIDO2AssertionResponse messages of a previous
handshake. When establishing the next connection, client and server can
start with the second handshake right away.  
The FN mode is compatible to U2F. The server queries the user name first
and then includes the IDs of already registered PKCSs in the request
parameters. They may be used to present as a key handle to the
authenticator. Also there is not need for the authenticator to store a
user ID, as the server is provided with a user name.

<a name="license"></a>
# License
This project was developed by Tom Breitkopf. It is a fork of the
tlslite-ng project, which is currently maintained and developed by
Hubert Kario and which is in turn a fork of TLS Lite. TLS Lite was
written (mostly) by Trevor Perrin. It includes code from Bram Cohen,
Google, Kees Bos, Sam Rushing, Dimitris Moraitis, Marcelo Fernandez,
Martin von Loewis, Dave Baggett, Yngve N. Pettersen (ported by Paul
Sokolovsky), Mirko Dziadzka, David Benjamin, and Hubert Kario. Original
code in TLS Lite has either been dedicated to the public domain by its
authors, or placed under a BSD-style license
([tlslite-ng/README.md](https://github.com/tomato42/tlslite-ng/blob/v0.8.0-alpha26/README.md)).  
tlslite-ng is currently distributed under Gnu LGPLv2 license.  

This project uses the [python-fido2][2] project. A copyright notice was
therefore added to the license.

This project is distributed under the **GNU GPLv3**. See the
[LICENSE](LICENSE) file for details.


<a name="installation"></a>
# Installation
Requirements:
* The FIDO2 extension for TLS 1.3 has only been tested for Python3
* [python-fido2][2] in version 0.5.0
* [precis-i18n](https://pypi.org/project/precis-i18n/) in version 1.0.1
* Requirements listed in the [tlslite-ng][1]

Optional:
* If pysqlcipher3 is installed, the user database may be encrypted
* If OpenSSL tools are installed, the user certificate may be generated
  automatically during the registration process
* Options listed in [tlslite-ng][1]

### Running setup
To install, run:
```bash
python3 setup.py install
```

To test the installation,run from the projects directory:
```bash
make test
```
If the script prompts "Tests succeeded" in the end, the installation of
the basic tlslite-ng components was successful.

To test that the FIDO2 extension works properly, connect a FIDO2
authenticator, run the following commands from the projects directory
and follow the instructions displayed to you:
```bash
fido2_server.py setup --db-path tests/fido2.db
fido2_server.py register --db-path tests/fido2.db --rp-id localhost --cert tests/user_cert_with_name.pem
fido2_server.py register --db-path tests/fido2.db --rp-id localhost --cert tests/user_cert_with_id.pem
make test
```
If the script prompts "Tests succeeded" in the end, the installation of
all the components went well.  
For everything to work fine the default python version might has to be
set to python3 and pip3 used instead of pip to install required
packages.

<a name="registration"></a>
# Registration
The registration of users may not be performed through the FIDO2
extension at this point. The `fido2_server.py` script, which will be set
up during the installation, however, helps to register users locally and
store the user information in a database. For the examples to work
properly navigate into the "tests" folder of the repository. To
initially set up the user database run:
```bash
fido2_server.py setup --db-path fido2.db
```
Inside the "tests" folder of the repository are files to help you run
example code.

* "server_cert.pem": A certificate for a localhost server.
* "server_key.pem": The corresponding private key of the server.
* "user_cert_with_id.pem": A client certificate for a FIDO2 user without
  a user name.
* "user_cert_with_name.pem": A client certificate for the FIDO2 user
  "test.user".

To register a new user, connect the authenticator you wish to use for
the authentication and run the following command. It will register the
user described in "user_cert_with_name.pem" with the user name
"test.user" to the server running at localhost.
```bash
fido2_server.py register --db-path fido2.db --rp-id localhost --cert "user_cert_with_name.pem"
```

If the OpenSSL tools are installed on your machine, the client
certificate may be generated automatically. The following command will
register the user "other.user" the server running at localhost. The
client certificate will be generated and signed using the server
certificate and private key.
```bash
fido2_server.py register --db-path fido2.db --name "other.user" --display-name "Other User" --rp-id localhost --server-cert server_cert.pem --server-key server_key.pem
```

To register a user without user name simply omit the value. Run:
```bash
fido2_server.py register --db-path fido2.db --rp-id localhost --server-cert server_cert.pem --server-key server_key.pem
```

Or use the example certificate, if OpenSSL tools are not available:
```bash
fido2_server.py register --db-path fido2.db --rp-id localhost --cert "user_cert_with_id.pem"
```

<a name="authentication"></a>
# Authentication
The authentication of a user may be performed using the TFE handshake.
The `tls.py` script was updated to support the authentication. Other
applications may be updated in a similar fashion using library
functions.

## Using tls.py
To start a server supporting the TFE handshake, run the following
command. The server will be started locally. It will accept all users
previously registered to "fido2.db". By default the server supports the
FI and the FN mode of the handshake. This might be changed by providing
the `--fido2-modes` argument with only a subset of the modes. By setting
the `--pre-share-euname` flag, the server allows to use the single
handshake in FN mode by sharing the ephemeral user name in an earlier
connection.
```bash
tls.py server -k server_key.pem -c server_cert.pem --fido2-db fido2.db --pre-share-euname --verbose localhost:4443
```  

To connect to the server and authenticate using the TFE-FN handshake,
run the following command. The client connects to the server using the
FIDO2 extension to authenticate the user "test.user". The ephemeral user
name for the next connection will be stored in "eph_user_name.bin".
```bash
tls.py client --fido2 -u test.user --eph-uname-out eph_user_name.bin --verbose localhost:4443
```

To authenticate using the single TFE-FN handshake the stored ephemeral
user name has to be passed on to the script. Run:
```bash
tls.py client --fido2 --eph-uname-in eph_user_name.bin --verbose localhost:4443
```

To authenticate without using a user name in the TFE-FI handshake omit
the user name entirely. Run:
```bash
tls.py client --fido2 --verbose localhost:4443
```

Providing the user name in case of the single TFE-FN handshake allows to
generate a new ephemeral user name in case the one stored by the client
already expired and the server requests the user name again.
```bash
tls.py client --fido2 --eph-uname-in eph_user_name.bin --eph-uname-out eph_user_name.bin -u test.user --verbose localhost:4443
```

When the verbose flag is set the exchanged handshake messages will be
displayed.

## Using library functions
A small example of a HTTPS server supporting FIDO2 authentication could
look like this. The output if an authenticated user connects should be
two to three lines. The first one prompting that a connection was closed
before a HTTP request was received - this is caused by the first
handshake in case of a full TFE-FN handshake. The next line is a prompt
that a user was successfully authenticated and the last one contains
information about the received HTTP request. The `fido2_params` must
include the path to the user database and the relying party identifier
of the server. Other parameters may be possible and are described in the
docstring of the `Fido2ServerWrapper.__init__()` method, which the
parameters are passed to.
```python
from socketserver import *
from http.server import *
from tlslite.api import *
import struct

cert_string = open("server_cert.pem", "rb").read()
cert_string = str(cert_string, 'utf-8')
cert_chain = X509CertChain()
cert_chain.parsePemList(cert_string)

key_string = open("server_key.pem", "rb").read()
key_string = str(key_string, 'utf-8')
private_key = parsePEMKey(key_string, private=True,
                          implementations=["python"])
                          
address = ("localhost", 4443)
fido2_params = {'db_path': "fido2.db", 'rp_id': address[0]}


class MySimpleHTTPHandler(SimpleHTTPRequestHandler):
    wbufsize = -1
    
    
class MyHTTPServer(ThreadingMixIn, TLSSocketServerMixIn,
                   HTTPServer):
                   
    def __init__(self, address, request_handler):
        HTTPServer.__init__(self, address, request_handler)

    def handshake(self, connection):
        connection.setsockopt(socket.IPPROTO_TCP,
                              socket.TCP_NODELAY, 1)
        connection.setsockopt(socket.SOL_SOCKET,
                              socket.SO_LINGER,
                              struct.pack('ii', 1, 5))
        connection.handshakeServer(certChain=cert_chain,
                                   privateKey=private_key,
                                   fido2_params=fido2_params)
                                   
        cc = connection.session.clientCertChain
        if cc and cc.is_fido2_cert_chain():
            print(cc.get_fido2_user_name() + \
                  " authenticated using FIDO2")        
        return True


httpd = MyHTTPServer(address, MySimpleHTTPHandler)
httpd.serve_forever()
```

A minimal example for a HTTPS client could look like this. The domain
name of the server has to be passed to the `handshakeClientFIDO2()`
method. In the FN mode the user name must be provided. Other parameters
are possible and described in the docstring of the method.
```python
from socket import *
from tlslite.api import *

address = ("localhost", 4443)
sock = socket.socket(AF_INET, SOCK_STREAM)
sock.connect(address)

connection = TLSConnection(sock)
connection.handshakeClientFIDO2(address[0],
                                "test.user")

connection.send(b"GET / HTTP/1.0\r\n\r\n")
while True:
    try:
        r = connection.recv(10240)
        if not r:
            break
    except socket.timeout:
        break
    except TLSAbruptCloseError:
        break
connection.close()
```
 
 [1]: https://github.com/tomato42/tlslite-ng/tree/v0.8.0-alpha26
 [2]: https://github.com/Yubico/python-fido2
 [3]: https://www.w3.org/TR/webauthn/#authenticator
 [4]: https://www.w3.org/TR/webauthn/#authentication-assertion
 [5]: https://www.w3.org/TR/webauthn/#public-key-credential-source
 [6]: https://www.w3.org/TR/webauthn/#resident-credential
 [7]: https://www.w3.org/TR/webauthn/#relying-party-identifier
