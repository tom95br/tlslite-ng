# In this file server side FIDO2 operations are defined
#  Copyright (C) 2019  Tom-Lukas Breitkopf
#
# This program is free software: you can redistribute it and /or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along
# with this program. If not, see <http://www.gnu.org/licenses/>.

from fido2.server import Fido2Server, RelyingParty
from fido2.utils import websafe_encode
from fido2.cose import CoseKey
from fido2.ctap2 import AttestedCredentialData
from fido2.cbor import loads
from .extensions import FIDO2ClientHelloExtension
from .messages import FIDO2NameResponse, FIDO2AssertionRequest, \
    FIDO2AssertionResponse, FIDO2NameRequest
from os import urandom
import sqlite3
from .utils.user_name_operations import UserNameOperations
from .utils.cryptomath import secureHash
from .constants import HandshakeType, FIDO2Mode
from .x509certchain import X509CertChain
from .utils.rsakey import RSAKey
from .utils.dns_utils import is_valid_hostname
from datetime import datetime, timedelta
from enum import IntEnum, unique
try:
    from pysqlcipher3 import dbapi2 as sqlcipher
    HAVE_SQLCIPHER = True
except ImportError:
    HAVE_SQLCIPHER = False


@unique
class ServerState(IntEnum):
    """ Class describing the internal state of the FIDO2 server. """
    # Initial State
    init = 0

    # A FIDO2AssertionRequest was sent
    assertion_request_sent = 1

    # A FIDO2NameRequest was sent
    name_request_sent = 2

    # The handshake ended successfully
    handshake_succeeded = 3

    # The handshake ended in a failure
    handshake_failed = 4

    # ERROR STATE: The FIDO2 authentication failed
    authentication_error = 5

    # ERROR STATE: The user requested an unsupported mode
    insufficient_security = 6


class Fido2ServerWrapper(object):
    """
    Wrapper class for a FIDO2 server. Used for handling the server side of
    the FIDO2 authentication in the TLS 1.3 handshake.
    """

    def __init__(self, params):
        """
        Create an instance of the class.
        :param params: Dictionary containing the following parameters
        db_path: Path to the user database
        rp_id: Relying Party identifier of the server.
        pre_share_eph_username: Indicates whether or not the server
                tries to establish an ephemeral user name for the next handshake
        db_encryption_key: The key the database is encrypted with.
        modes: List of allowed FIDO2 operation modes
            during authentication.
        force_fido2: Flag indicating whether or not to accept only FIDO2
            authenticated users.
        """
        # check arguments
        self._valid = False
        db_path = rp_id = encryption_key = None
        pre_share_eph_username = force_fido2 = False
        modes = FIDO2Mode.all
        if 'db_path' in params and isinstance(params['db_path'], str):
            db_path = params['db_path']
        if 'rp_id' in params and isinstance(params['rp_id'], str):
            rp_id = params['rp_id'].lower()
            if not is_valid_hostname(rp_id):
                rp_id = None
        if 'db_encryption_key' in params and \
                isinstance(params['db_encryption_key'], RSAKey):
            encryption_key = params['db_encryption_key']
        if 'pre_share_eph_user_name' in params and \
                isinstance(params['pre_share_eph_user_name'], bool):
            pre_share_eph_username = params['pre_share_eph_user_name']
        if 'modes' in params and \
                isinstance(params['modes'], list):
            modes = params['modes']
        if 'force_fido2' in params and isinstance(params['force_fido2'], bool):
            force_fido2 = params['force_fido2']

        # check if mandatory arguments are set
        if not db_path or not rp_id:
            return

        self.state = ServerState.init
        self.mode = None
        self.allowed_modes = modes

        self._db_connection = self._get_db_connection(db_path, encryption_key)
        relying_party = RelyingParty(rp_id)
        self._server = Fido2Server(relying_party)
        self.pre_share_eph_user_name = pre_share_eph_username
        self.force_fido2 = force_fido2

        self._auth_state = None
        self._user_id = None
        self._eph_user_name_server_share = None
        self._allow_credentials = []

        self._valid= bool(self._db_connection is not None)

    def __del__(self):
        """
        Check for old entries on delete.
        :return:
        """
        if not self._valid:
            return

        # check for old entries in the ephemeral user names
        cursor = self._db_connection.cursor()

        now = datetime.now()
        now = '{:%Y-%m-%d %H:%M:%S}'.format(now)

        sql_command = """
        DELETE FROM eph_user_names
        WHERE valid_through < (?)
        """

        cursor.execute(sql_command, (now, ))
        cursor.close()
        self._db_connection.commit()
        self._db_connection.close()

    def is_valid(self):
        """
        Determine if the initialization of the server went well.
        :return: True if the server is valid, False otherwise
        """
        return self._valid

    def get_accepted_message_types(self):
        """
        Get accepted messges types based on the current server state.
        :return: Tuple of HandshakeType acceptable to the server.
        """
        if self.state == ServerState.assertion_request_sent:
            return (HandshakeType.fido2_assertion_response, )
        if self.state == ServerState.name_request_sent:
            return (HandshakeType.fido2_name_response, )
        else:
            return None

    def generate_request(self, extension):
        """
        Handle the FIDO2ClientHelloExtension and return a request.
        :param extension: A FIDO2ClientHelloExtension
        :return: The FIDO2Request
        """
        if extension.mode not in self.allowed_modes:
            return self._abort_handshake(ServerState.insufficient_security,
                                         "The FIDO2 mode requested by the "
                                         "client is not supported.")
        self.mode = extension.mode

        # authentication without user name
        if self.mode == FIDO2Mode.fido2_with_id:
            self.state = ServerState.assertion_request_sent
            return self.generate_assertion_request()

        # authentication with user name
        elif extension.mode == FIDO2Mode.fido2_with_name:
            # ephemeral user name provided
            if extension.flag_set(
                    FIDO2ClientHelloExtension.FLAG.EPH_USER_NAME_SET):
                user_id, entry_found = self._get_user_id(
                    extension.eph_user_name)
                # ephemeral user name stored
                if entry_found:
                    self.state = ServerState.assertion_request_sent
                    self._user_id = user_id
                    return self.generate_assertion_request(user_id)
                # ephemeral user name not stored
                else:
                    self.state = ServerState.name_request_sent
                    return self.generate_name_request()
            # no ephemeral user name
            else:
                self.state = ServerState.name_request_sent
                return self.generate_name_request()

    def handle_response(self, fido2_response):
        """
        Handle a response by the client.
        :param fido2_response: A FIDO2Response message
        :return: The X509CertChain of the client in case of a successful
                authentication, None otherwise
        """
        if self.state == ServerState.name_request_sent and isinstance(
                fido2_response, FIDO2NameResponse):
            self.handle_name_response(fido2_response)
            return None
        elif self.state == ServerState.assertion_request_sent and isinstance(
                fido2_response, FIDO2AssertionResponse):
            return self.handle_assertion_response(fido2_response)

        else:
            self.state = ServerState.handshake_failed
            return None

    def generate_name_request(self):
        """
        Generate a FIDO2NameRequest.
        :return: The FIDO2NameRequest
        """
        eph_user_name_server_share = bytearray(urandom(32))
        self._eph_user_name_server_share = eph_user_name_server_share
        self.state = ServerState.name_request_sent

        return FIDO2NameRequest().create(eph_user_name_server_share)

    def generate_assertion_request(self, user_id=None):
        """
        Generate an assertion request
        :param user_id: The user id
        :return: The FIDO2AssertionRequest message
        """
        user_credentials = self._get_user_credentials(user_id)
        request_options, self._auth_state = \
            self._server.authenticate_begin(user_credentials)

        # check request options
        request_options = request_options['publicKey']
        challenge = websafe_encode(request_options['challenge'])
        timeout = None
        rp_id = None
        allow_credentials = None
        user_verification = None
        extensions = None
        eph_user_name_server_share = None

        # fill optional information
        if 'timeout' in request_options:
            timeout = request_options['timeout']
        if 'rpId' in request_options:
            rp_id = request_options['rpId']
        if 'allowCredentials' in request_options:
            allow_credentials = request_options['allowCredentials']
            self._allow_credentials = allow_credentials
        if 'userVerification' in request_options:
            user_verification = request_options[
                'userVerification'].value
        if 'extensions' in request_options:
            extensions = request_options['extensions']
        if self.mode == FIDO2Mode.fido2_with_name and \
                self.pre_share_eph_user_name:
            eph_user_name_server_share = bytearray(urandom(32))
            self._eph_user_name_server_share = \
                eph_user_name_server_share

        fido2_assertion_request = FIDO2AssertionRequest().create(
            challenge, timeout, rp_id, allow_credentials,
            user_verification, extensions, eph_user_name_server_share)

        return fido2_assertion_request

    def handle_assertion_response(self, response):
        """
        Validate the assertion response of a client.
        :param response: The FIDO2AssertionResponse
        :return: The X509CertChain if the user was authenticated successfully,
                None otherwise
        """
        user_id = self._user_id

        # determine PKCS to use
        credential_id = None
        if len(self._allow_credentials) == 1:
            credential_id = self._allow_credentials[0]['id']
        else:
            if not response.flag_set(
                    FIDO2AssertionResponse.FLAG.SELECTED_CRED_ID_SET):
                return self._abort_handshake(ServerState.authentication_error,
                                             "PKCS unclear.")
            credential_id = response.selected_credential_id
            if len(self._allow_credentials) > 0 and credential_id not in \
                    [c['id'] for c in self._allow_credentials]:
                return self._abort_handshake(ServerState.authentication_error,
                                             "PKCS not allowed")

        # check user handle
        if response.user_handle and user_id:
            if response.user_handle != user_id:
                return self._abort_handshake(ServerState.authentication_error,
                                             "User handle does not match the "
                                             "user being authenticated ")
        elif response.user_handle and not user_id:
            user_id = response.user_handle

        # get user credentials
        credentials = self._get_user_credentials(user_id)

        # complete the authentication
        try:
            result = self._server.authenticate_complete(
                self._auth_state, credentials, credential_id,
                response.client_data_json, response.authenticator_data,
                response.signature)
        except Exception:
            result = None
        success = bool(result is not None)

        # check success
        if not success:
            return self._abort_handshake(ServerState.authentication_error,
                                         "Verification error.")

        # check the signature counter
        new_count = response.authenticator_data.counter
        old_count = self._get_signature_counter(credential_id)

        if old_count != 0 or new_count != 0:
            if old_count < new_count:
                self._update_signature_counter(credential_id, new_count)
            else:
                return self._abort_handshake(ServerState.authentication_error,
                                             "Bad signature counter.")

        # get the client certificate chain
        cert_chain = self._get_client_certificate(user_id)
        if not cert_chain:
            return self._abort_handshake(ServerState.authentication_error,
                                         "No certificate for the client in "
                                         "the current mode available")

        # handle possible name response to store new ephemeral user name
        if response.eph_user_name_client_share and \
                self._eph_user_name_server_share:
            hash_input = self._eph_user_name_server_share + \
                         response.eph_user_name_client_share
            eph_user_name = secureHash(hash_input, 'sha256')
            self._store_eph_user_name_by_id(eph_user_name, user_id)

        # set internal state and return result
        self.state = ServerState.handshake_succeeded
        return cert_chain

    def handle_name_response(self, fido2_name_response):
        """
        Handle a name response by the client. Store the ephemeral user name
        and set the internal state.
        :param fido2_name_response: A FIDO2NameResponse message
        :return:
        """
        hash_input = self._eph_user_name_server_share + \
                     fido2_name_response.eph_user_name_client_share
        eph_user_name = secureHash(hash_input, 'sha256')

        self._store_eph_user_name(eph_user_name, fido2_name_response.user_name)
        self.state = ServerState.handshake_succeeded

    @staticmethod
    def _get_db_connection(db_path, encryption_key=None):
        """
        Connect to the database and decrypt it if necessary
        :param db_path: Path to the database
        :param encryption_key: Key to decrypt database with
        :return: A connection to the database. None if connection was not
                successful
        """

        if db_path is None or len(db_path) == 0:
            return None

        if encryption_key and HAVE_SQLCIPHER:
            key_phrase = encryption_key.sign(bytearray(encryption_key.key_type,
                                                       'utf-8')).hex()
            connection = sqlcipher.connect(db_path)
            cursor = connection.cursor()
            cursor.execute("PRAGMA key='" + key_phrase + "'")
        elif encryption_key and not HAVE_SQLCIPHER:
            print("sqlcipher not installed. Unable to handle encrypted "
                  "database")
            return None
        else:
            connection = sqlite3.connect(db_path)

        cursor = connection.cursor()
        sql_command = """ DROP TABLE IF EXISTS not_a_table;"""
        try:
            cursor.execute(sql_command)
        except sqlite3.DatabaseError:
            print(db_path + " is not an unencrypted database.")
            return None
        except sqlcipher.DatabaseError:
            print(db_path + " is not an encrypted database.")
            return None

        return connection

    def _store_eph_user_name(self, eph_user_name, user_name):
        """
        Store an ephemeral user name in the database.
        :param eph_user_name: The ephemeral user name of the user
        :param user_name: The user name of the user or None
        :return:
        """
        cursor = self._db_connection.cursor()
        user_name = UserNameOperations.format_user_name(user_name)

        sql_command = """
        SELECT DISTINCT user_id
        FROM users
        WHERE user_name=(?)
        """
        cursor.execute(sql_command, (user_name, ))
        result = cursor.fetchone()

        user_id = None
        if result:
            user_id = memoryview(result[0])

        sql_command = """
        INSERT INTO eph_user_names (eph_user_name, user_id, valid_through)
        VALUES (?, ?, ?)
        """

        # set the validity of the entry
        valid_through = datetime.now() + timedelta(days=7)
        valid_through = '{:%Y-%m-%d %H:%M:%S}'.format(valid_through)

        data = (memoryview(eph_user_name), user_id, valid_through)
        cursor.execute(sql_command, data)
        cursor.close()
        self._db_connection.commit()

    def _store_eph_user_name_by_id(self, eph_user_name, user_id):
        """
        Store an ephemeral user name in the database.
        :param eph_user_name: The ephemeral user name of the user
        :param user_id: The id of the user
        :return:
        """

        cursor = self._db_connection.cursor()

        sql_command = """
        INSERT INTO eph_user_names (eph_user_name, user_id, valid_through)
        VALUES (?, ?, ?)
        """

        # set the validity of the entry
        valid_through = datetime.now() + timedelta(days=7)
        valid_through = '{:%Y-%m-%d %H:%M:%S}'.format(valid_through)

        if user_id:
            user_id = memoryview(user_id)

        data = (memoryview(eph_user_name), user_id, valid_through)
        cursor.execute(sql_command, data)
        cursor.close()
        self._db_connection.commit()

    def _delete_eph_user_name(self, eph_user_name):
        """
        Delete an ephemeral user name from the data base
        :param eph_user_name: The ephemeral user name to delete
        :return:
        """
        if not eph_user_name:
            return
        cursor = self._db_connection.cursor()

        sql_command = """
        DELETE FROM eph_user_names
        WHERE eph_user_name=(?)
        """

        cursor.execute(sql_command, (eph_user_name, ))
        cursor.close()
        self._db_connection.commit()

    def _get_user_credentials(self, user_id):
        """
        Get all credentials associated with a user in the current mode from the
        database
        :param user_id: The id of the user
        :return: List of AttestedCredentialData
        """
        if not user_id:
            return []

        cursor = self._db_connection.cursor()

        sql_command = """
        SELECT credential_id, aaguid, public_key
        FROM credentials
        WHERE user_id=(?) AND mode=(?)
        """
        cursor.execute(sql_command, (user_id, int(self.mode)))
        results = cursor.fetchall()
        cursor.close()

        credentials = []
        if results and len(results) > 0:
            for result in results:
                credential_id = result[0]
                aaguid = result[1]
                public_key = CoseKey.parse(loads(result[2])[0])
                credential = AttestedCredentialData.create(aaguid,
                                                           credential_id,
                                                           public_key)
                credentials.append(credential)

        return credentials

    def _get_user_id(self, eph_user_name):
        """
        Get the user id based on the ephemeral user name
        :param eph_user_name: The ephemeral user name
        :return: The user id or None and a bool indicating whether or not the
            ephemeral user name was found in the database. If the bool is
            True the user id might still be None, if an entry was
            found, but the associated user is not registered.
        """
        cursor = self._db_connection.cursor()

        sql_command = """
        SELECT user_id, valid_through
        FROM eph_user_names
        WHERE eph_user_name=(?)
        """
        cursor.execute(sql_command, (eph_user_name, ))
        result = cursor.fetchone()
        cursor.close()
        user_id = None
        entry_found = False
        if result:
            now = datetime.now()
            valid_through = datetime.strptime(result[1], '%Y-%m-%d %H:%M:%S')

            # check that the entry is still valid
            if valid_through > now:
                user_id = result[0]
                entry_found = True

            # delete the entry once it was used
            self._delete_eph_user_name(eph_user_name)

        return user_id, entry_found

    def _get_client_certificate(self, user_id):
        """
        Get the client certificate based on the user id and the current mode to
        pass to the application layer.
        :param user_id: The ID of the user to get the certificate for
        :return: The X509CertChain
        """
        cursor = self._db_connection.cursor()

        sql_command = """
        SELECT certificate
        FROM certificates
        WHERE user_id=(?) AND mode=(?)
        """

        cursor.execute(sql_command, (user_id, int(self.mode)))
        result = cursor.fetchone()
        cursor.close()
        cert_chain = None
        if result:
            cert_string = result[0]
            cert_chain = X509CertChain()
            cert_chain.parsePemList(cert_string)

        return cert_chain

    def _get_signature_counter(self, credential_id):
        """
        Get the signature counter of a public key credential source based on
        its id.
        :param credential_id: ID of the PCKS
        :return: The signature counter as integer
        """
        cursor = self._db_connection.cursor()

        sql_command = """
        SELECT signature_counter
        FROM credentials
        WHERE credential_id=(?)
        """
        cursor.execute(sql_command, (credential_id, ))
        result = cursor.fetchone()
        cursor.close()
        if result:
            result = result[0]
            assert (isinstance(result, int))

        return result

    def _update_signature_counter(self, credential_id, new_counter):
        """
        Update the value of the signature counter for a public key credential
        source.
        :param credential_id: ID of the PKCS
        :param new_counter: New value of the signature counter
        :return:
        """
        # sanity check: New value must never be smaller
        old_counter = self._get_signature_counter(credential_id)
        if old_counter >= new_counter:
            return

        # update counter
        cursor = self._db_connection.cursor()

        sql_command = """
        UPDATE credentials
        SET signature_counter=(?)
        WHERE credential_id=(?)
        """
        cursor.execute(sql_command, (new_counter, credential_id))
        cursor.close()
        self._db_connection.commit()

    def _abort_handshake(self, state=ServerState.handshake_failed,
                         message=None):
        """
        Abort the handshake by settings the state and returning none object.
        :param message: Optional message to print before aborting
        :return: None
        """
        if message:
            if state == ServerState.authentication_error:
                message = "ERROR: " + message
            print(message)
        self.state = state

        return None
