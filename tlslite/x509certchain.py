# Authors:
#    Trevor Perrin
#    Tom-Lukas Breitkopf: Allow check on FIDO2 issued certificate
# See the LICENSE file for legal information regarding use of this file.

"""Class representing an X.509 certificate chain."""

from .utils import cryptomath
from .utils.tackwrapper import *
from .utils.pem import *
from .x509 import X509
from .constants import FIDO2Mode

class X509CertChain(object):
    """This class represents a chain of X.509 certificates.

    :vartype x509List: list
    :ivar x509List: A list of :py:class:`tlslite.x509.X509` instances,
        starting with the end-entity certificate and with every
        subsequent certificate certifying the previous.
    """

    def __init__(self, x509List=None):
        """Create a new X509CertChain.

        :type x509List: list
        :param x509List: A list of :py:class:`tlslite.x509.X509` instances,
            starting with the end-entity certificate and with every
            subsequent certificate certifying the previous.
        """
        if x509List:
            self.x509List = x509List
        else:
            self.x509List = []

    def parsePemList(self, s):
        """Parse a string containing a sequence of PEM certs.

        Raise a SyntaxError if input is malformed.
        """
        x509List = []
        bList = dePemList(s, "CERTIFICATE")
        for b in bList:
            x509 = X509()
            x509.parseBinary(b)
            x509List.append(x509)
        self.x509List = x509List

    def getNumCerts(self):
        """Get the number of certificates in this chain.

        :rtype: int
        """
        return len(self.x509List)

    def getEndEntityPublicKey(self):
        """Get the public key from the end-entity certificate.

        :rtype: ~tlslite.utils.rsakey.RSAKey`
        """
        if self.getNumCerts() == 0:
            raise AssertionError()
        return self.x509List[0].publicKey

    def getFingerprint(self):
        """Get the hex-encoded fingerprint of the end-entity certificate.

        :rtype: str
        :returns: A hex-encoded fingerprint.
        """
        if self.getNumCerts() == 0:
            raise AssertionError()
        return self.x509List[0].getFingerprint()

    def checkTack(self, tack):
        if self.x509List:
            tlsCert = TlsCertificate(self.x509List[0].bytes)
            if tlsCert.matches(tack):
                return True
        return False
        
    def getTackExt(self):
        """Get the TACK and/or Break Sigs from a TACK Cert in the chain."""
        tackExt = None
        # Search list in backwards order
        for x509 in self.x509List[::-1]:
            tlsCert = TlsCertificate(x509.bytes)
            if tlsCert.tackExt:
                if tackExt:
                    raise SyntaxError("Multiple TACK Extensions")
                else:
                    tackExt = tlsCert.tackExt
        return tackExt

    def get_endentity_common_name(self):
        """
        Get the common name of the end entity of the certificate chain
        :return: The common name as a string
        """
        if self.getNumCerts() > 0:
            return self.x509List[0].get_subject_common_name()
        return None

    def is_fido2_cert_chain(self):
        """
        Return True if this is a certificate used to signal successful FIDO2
        authentication.
        :return:
        """
        if self.getNumCerts() > 0:
            organization_string = self.x509List[
                0].get_subject_organization_name()
            if organization_string == "fido2_authentication_cert":
                return True

        return False

    def get_fido2_mode(self):
        """
        Get the mode of the FIDO2 authentication this certificate was used for.
        :return: The FIDO2Mode
        """
        if not self.is_fido2_cert_chain():
            return None

        if self.getNumCerts() > 0:
            organization_string = self.x509List[
                0].get_subject_organization_unit()
            return FIDO2Mode.from_string(organization_string)

        return None

    def get_fido2_user_name(self):
        """
        Get the user name of the FIDO2 authenticated user.
        :return: The user name as a string
        """
        return self.get_endentity_common_name()

    def get_fido2_user_id(self):
        """
        Get the user id of the FIDO2 authenticated user.
        :return: The user id as bytearray
        """
        if self.getNumCerts() > 0:
            return self.x509List[0].get_subject_state()
        return None
