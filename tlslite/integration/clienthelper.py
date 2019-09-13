# Authors: 
#   Trevor Perrin
#   Dimitris Moraitis - Anon ciphersuites
#
# See the LICENSE file for legal information regarding use of this file.

"""
A helper class for using TLS Lite with stdlib clients
(httplib, xmlrpclib, imaplib, poplib).
"""

from tlslite.checker import Checker
from tlslite.utils.dns_utils import is_valid_hostname

class ClientHelper(object):
    """This is a helper class used to integrate TLS Lite with various
    TLS clients (e.g. poplib, smtplib, httplib, etc.)"""

    def __init__(self,
                 username=None, password=None,
                 certChain=None, privateKey=None,
                 use_fido2=False, domain_name=None,
                 checker=None,
                 settings=None,
                 anon=False,
                 host=None):
        """
        For client authentication, use one of these argument
        combinations:

         - username, password (SRP)
         - certChain, privateKey (certificate)
         - use_fido2, domain_name (and user name) (FIDO2)

        For server authentication, you can either rely on the
        implicit mutual authentication performed by SRP, FIDO2,
        or you can do certificate-based server
        authentication with one of these argument combinations:

         - x509Fingerprint

        Certificate-based server authentication is compatible with
        SRP or certificate-based client authentication.

        The constructor does not perform the TLS handshake itself, but
        simply stores these arguments for later.  The handshake is
        performed only when this class needs to connect with the
        server.  Then you should be prepared to handle TLS-specific
        exceptions.  See the client handshake functions in
        :py:class:`~tlslite.tlsconnection.TLSConnection` for details on which
        exceptions might be raised.

        :param str username: SRP or FIDO2 username.  Requires the
            'password' argument for SRP.

        :param str password: SRP password for mutual authentication.
            Requires the 'username' argument.

        :param X509CertChain certChain: Certificate chain for client
            authentication.
            Requires the 'privateKey' argument.  Excludes the SRP arguments.

        :param RSAKey privateKey: Private key for client authentication.
            Requires the 'certChain' argument.  Excludes the SRP arguments.

        :param bool use_fido2: Indication whether or not to use FIDO2
            authentication. Requires the 'domain_name' parameter or 'host'
            as domain name.

        :param str domain_name: The domain name of the server to authenticate
            against using FIDO2. May be omitted if host is given as a domain
            name.

        :param Checker checker: Callable object called after handshaking to
            evaluate the connection and raise an Exception if necessary.

        :type settings: HandshakeSettings
        :param settings: Various settings which can be used to control
            the ciphersuites, certificate types, and SSL/TLS versions
            offered by the client.

        :param bool anon: set to True if the negotiation should advertise only
            anonymous TLS ciphersuites. Mutually exclusive with client
            certificate
            authentication or SRP authentication

        :type host: str or None
        :param host: the hostname that the connection is made to. Can be an
            IP address (in which case the SNI extension won't be sent). Can
            include the port (in which case the port will be stripped and
            ignored).
        """

        self.username = None
        self.password = None
        self.use_fido2 = False
        self.domain_name = None
        self.certChain = None
        self.privateKey = None
        self.checker = None
        self.anon = anon

        if host is not None and not self._isIP(host):
            # name for SNI so port can't be sent
            colon = host.find(':')
            if colon > 0:
                host = host[:colon]
            self.serverName = host
            if host and not is_valid_hostname(host):
                raise ValueError("Invalid hostname: {0}".format(host))
        else:
            self.serverName = None

        domain_name = domain_name or self.serverName

        #SRP Authentication
        if username and password and not \
                (certChain or privateKey or use_fido2 or domain_name):
            self.username = username
            self.password = password

        #Certificate Chain Authentication
        elif certChain and privateKey and not \
                (username or password or use_fido2 or domain_name):
            self.certChain = certChain
            self.privateKey = privateKey

        # FIDO2 authentication
        elif use_fido2 and domain_name and not \
                (password or certChain or privateKey):
            self.use_fido2 = True
            self.domain_name = domain_name
            self.username = username

        #No Authentication
        elif not password and not username and not \
                certChain and not privateKey and not \
                use_fido2 and not (domain_name and not host):
            pass

        else:
            raise ValueError("Bad parameters")

        self.checker = checker
        self.settings = settings

        self.tlsSession = None

    @staticmethod
    def _isIP(address):
        """Return True if the address is an IPv4 address"""
        if not address:
            return False
        vals = address.split('.')
        if len(vals) != 4:
            return False
        for i in vals:
            if not i.isdigit():
                return False
            j = int(i)
            if not 0 <= j <= 255:
                return False
        return True

    def _handshake(self, tlsConnection):
        if self.username and self.password:
            tlsConnection.handshakeClientSRP(username=self.username,
                                             password=self.password,
                                             checker=self.checker,
                                             settings=self.settings,
                                             session=self.tlsSession,
                                             serverName=self.serverName)
        if self.use_fido2 and self.domain_name:
            tlsConnection.handshakeClientFIDO2(domain_name=self.domain_name,
                                               user_name=self.username,
                                               checker=self.checker,
                                               serverName=self.serverName)
        elif self.anon:
            tlsConnection.handshakeClientAnonymous(session=self.tlsSession,
                                                   settings=self.settings,
                                                   checker=self.checker,
                                                   serverName=self.serverName)
        else:
            tlsConnection.handshakeClientCert(certChain=self.certChain,
                                              privateKey=self.privateKey,
                                              checker=self.checker,
                                              settings=self.settings,
                                              session=self.tlsSession,
                                              serverName=self.serverName)
        self.tlsSession = tlsConnection.session
