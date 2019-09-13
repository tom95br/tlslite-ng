# In this file client side FIDO2 operations are defined
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

from fido2.client import Fido2Client
from fido2.hid import CtapHidDevice
from fido2.ctap2 import CTAP2
from fido2._pyu2f import hidtransport
from fido2.utils import Timeout
from .extensions import FIDO2ClientHelloExtension
from .messages import FIDO2NameResponse, FIDO2AssertionRequest, \
    FIDO2AssertionResponse, FIDO2NameRequest
from os import urandom
from os.path import isfile
from .utils.cryptomath import secureHash
from .constants import HandshakeType, FIDO2Mode
from enum import IntEnum, unique
import threading
import time
import signal
try:
    import queue
except ImportError:
    import Queue as queue


@unique
class ClientState(IntEnum):
    """ Class describing the internal state of the FIDO2 client. """
    # Initial state
    init = 0

    # The FIDO2ClientHelloExtension with an ephemeral user name was sent
    ch_with_euname_sent = 1

    # The FIDO2ClientHelloExtension without an ephemeral user name was sent
    ch_wo_euname_sent = 2

    # A FIDO2NameRequest was received
    name_request_received = 3

    # A FIDO2AssertionRequest was received
    assertion_request_received = 4

    # A FIDO2NameResponse was sent
    name_response_sent = 5

    # A FIDO2AssertionResponse was sent
    assertion_response_sent = 6

    # The handshake ended successfully
    handshake_succeeded = 7

    # The handshake ended in a failure
    handshake_failed = 8

    # ERROR STATE: Creating an assertion failed
    assertion_failed = 9

    # ERROR STATE: The server sent a bad Relying Party identifier
    bad_rpid = 10

    # ERROR STATE: The user canceled the authentication
    canceled = 11

    # ERROR STATE: No user name was provided but the server is requesting it.
    no_user_name = 12


class Fido2ClientWrapper(object):
    """
    Wrapper class for a FIDO2 client. Used for handling the client side of
    the FIDO2 authentication in the TLS 1.3 handshake.
    """

    def __init__(self, domain_name, user_name=None,
                 eph_user_name_out=None, eph_user_name_in=None,
                 abort_event=None, user_interaction_object=None):
        """
        Create instance of the class.
        :param domain_name: Domain name of the server.
        :param user_name: name of the user
        :param eph_user_name_in: File where pre shared ephemeral user name is
                stored
        :param eph_user_name_out: File to write pre shared ephemeral username to
        :param abort_event: Event for the user to abort the authentication
        :param user_interaction_object: Object to handle user interaction
        """
        self.state = ClientState.init
        self.eph_user_name = None
        self.relying_party_id = domain_name
        self.mode = 0

        # use pre shared ephemeral user name
        if eph_user_name_in is not None and isfile(eph_user_name_in):
            file = open(eph_user_name_in, "rb")
            eph_user_name = file.read()
            file.close()
            if eph_user_name and len(eph_user_name) == 32:
                self.eph_user_name = eph_user_name
                self.mode = FIDO2Mode.fido2_with_name

        # no pre shared user name in use
        if not self.eph_user_name:
            if user_name:
                self.mode = FIDO2Mode.fido2_with_name
            else:
                self.mode = FIDO2Mode.fido2_with_id

        self._user_name = user_name
        self._eph_user_name_out = eph_user_name_out
        self._abort_event = abort_event

        # by default user interaction will be done by the command line
        if user_interaction_object and isinstance(user_interaction_object,
                                                  UserInteraction):
            self._user_interaction = user_interaction_object
        else:
            self._user_interaction = CommandLineInteraction()

    def get_accepted_message_types(self):
        """
        Get all the accepted message types based on the current client
        state.
        :return: Tuple of HandshakeType acceptable to the client.
        """
        if self.mode == FIDO2Mode.fido2_with_name:
            if self.state == ClientState.ch_with_euname_sent:
                return (HandshakeType.fido2_assertion_request,
                        HandshakeType.fido2_name_request)
            elif self.state == ClientState.ch_wo_euname_sent:
                return (HandshakeType.fido2_name_request, )
            else:
                return ()
        elif self.mode == FIDO2Mode.fido2_with_id:
            if self.state == ClientState.ch_wo_euname_sent:
                return (HandshakeType.fido2_assertion_request, )
            else:
                return ()
        else:
            return ()

    def generate_client_hello_extension(self):
        """
        Generate the FIDO2ClientHelloExtension
        :return: FIDO2ClientHelloExtension
        """
        # check the mode being used
        if self.mode == FIDO2Mode.fido2_with_id:
            self.eph_user_name = None

        # check if ephemeral user name is present
        if self.eph_user_name:
            self.state = ClientState.ch_with_euname_sent
        else:
            self.state = ClientState.ch_wo_euname_sent

        return FIDO2ClientHelloExtension().create(self.mode, self.eph_user_name)

    def handle_request(self, fido2_request):
        """
        Set client state according to request
        :param fido2_request: A FIDO2Request message
        :return:
        """
        if isinstance(fido2_request, FIDO2NameRequest):
            self.state = ClientState.name_request_received

        if isinstance(fido2_request, FIDO2AssertionRequest):
            self.state = ClientState.assertion_request_received

    def generate_response(self, fido2_request, certificate_subject):
        """
        Generate a response to a request
        :param fido2_request: A FIDO2Request message
        :param certificate_subject: The common name of subject of the
        certificate used and verified in the handshake
        :return: The FIDO2Response message
        """

        if self.state == ClientState.name_request_received and isinstance(
                fido2_request, FIDO2NameRequest):
            return self.generate_name_response(fido2_request)
        if self.state == ClientState.assertion_request_received and \
                isinstance(fido2_request, FIDO2AssertionRequest):
            return self.generate_assertion_response(fido2_request,
                                                    certificate_subject)
        else:
            self.state = ClientState.handshake_failed
            return None

    def generate_name_response(self, name_request):
        """
        Generate a name response based on the name request.
        :param name_request: A FIDO2NameRequest
        :return: The FIDO2UserName message
        """
        # If only an ephemeral user name was provided the FIDO2NameRequest
        # in case of a fallback may not be answered.
        if not self._user_name:
            return self._abort_handshake(ClientState.no_user_name,
                                         "FIDO2NameRequest may not be answered")

        eph_user_name_client_share = urandom(32)
        eph_user_name_server_share = name_request.eph_user_name_server_share
        hash_input = eph_user_name_server_share + eph_user_name_client_share
        self.eph_user_name = secureHash(hash_input, 'sha256')

        # only needed in case of fallback
        if self._eph_user_name_out:
            file = open(self._eph_user_name_out, "w+b")
            file.write(self.eph_user_name)
            file.close()

        self.state = ClientState.name_response_sent

        return FIDO2NameResponse().create(eph_user_name_client_share,
                                          self._user_name)

    def generate_assertion_response(self, assertion_request,
                                    certificate_subject):
        """
        Generate a response based on the assertion request
        :param assertion_request: A FIDO2AssertionRequest
        :param certificate_subject: The common name of the subject of the
                certificate used and verified in the TLS handshake
        :return: The FIDO2AssertionResponse message
        """
        # handle AssertionRequest parameters
        challenge = assertion_request.challenge

        timeout = 120
        if assertion_request.flag_set(FIDO2AssertionRequest.FLAG.TIMEOUT_SET):
            timeout = assertion_request.timeout / 1000  # use seconds
            # set timeout to reasonbable range
            timeout = max(15, min(120, timeout))

        # TODO: [tbr] registrable suffix
        # check the rp id of the server
        rp_id = self.relying_party_id
        if rp_id != certificate_subject:
            return self._abort_handshake(state=ClientState.bad_rpid)
        if assertion_request.flag_set(FIDO2AssertionRequest.FLAG.RP_ID_SET):
            received_rpid = assertion_request.rp_id
            if received_rpid != rp_id:
                return self._abort_handshake(state=ClientState.bad_rpid)

        allow_credentials = None
        if assertion_request.flag_set(
                FIDO2AssertionRequest.FLAG.ALLOW_CREDENTIALS_SET):
            allow_credentials = assertion_request.allow_credentials

        user_verification = "preferred"
        if assertion_request.flag_set(
                FIDO2AssertionRequest.FLAG.USER_VERIFICATION_SET):
            user_verification = assertion_request.user_verification

        extensions = None
        client_extension_output = None
        if assertion_request.flag_set(
                FIDO2AssertionRequest.FLAG.EXTENSIONS_SET):
            # handle client extensions and process authenticator extensions here
            extensions = assertion_request.extensions

        # generate assertion
        assertion, client_data = self._get_assertion(challenge, rp_id, timeout,
                                                     allow_credentials,
                                                     user_verification,
                                                     extensions)
        if not (assertion and client_data):
            if self.state == ClientState.canceled:
                return self._abort_handshake(ClientState.canceled,
                                             "User canceled authentication")
            else:
                return self._abort_handshake(ClientState.assertion_failed,
                                             "Generating an assertion failed")

        # handle optional parameters
        user_handle = None
        selected_credential_id = None
        if assertion.user:
            user_handle = assertion.user['id']
        if assertion.credential:
            selected_credential_id = assertion.credential['id']

        # handle possible NameRequest
        eph_user_name_client_share = None
        if assertion_request.flag_set(
                FIDO2AssertionRequest.FLAG.EPH_UNAME_SRV_SHARE_SET) and \
                self._eph_user_name_out and \
                self.mode == FIDO2Mode.fido2_with_name:
            eph_user_name_client_share = bytearray(urandom(32))
            hash_input = assertion_request.eph_user_name_server_share + \
                         eph_user_name_client_share
            eph_user_name = secureHash(hash_input, 'sha256')
            file = open(self._eph_user_name_out, "w+b")
            file.write(eph_user_name)
            file.close()

        # create response message
        assertion_response = FIDO2AssertionResponse().create(
            client_data, assertion.auth_data, assertion.signature,
            user_handle, selected_credential_id, client_extension_output,
            eph_user_name_client_share
        )

        self.state = ClientState.assertion_response_sent
        return assertion_response

    @staticmethod
    def uv_supported(device):
        """
        Determine whether user verification is supported by the device.
        :param device: The device to check user verification capability for.
        :return: True if user verification is supported, False otherwise
        """
        try:
            ctap2 = CTAP2(device)
        except ValueError:
            return False

        try:
            info = ctap2.get_info()
        except OSError:
            return False

        return bool('uv' in info.options and info.options['uv'])

    @staticmethod
    def _uv_required(uv_string, device):
        """
        Return whether or not user verification must be enforced.
        :param uv_string: User verification requirements by the server
        :param device: The device to use.
        :return: True if user_verification is required, False otherwise
        """
        user_verification_required = False
        if uv_string == "required":
            user_verification_required = True
        if uv_string == "preferred" and Fido2ClientWrapper.uv_supported(device):
            user_verification_required = True

        return user_verification_required

    @staticmethod
    def _wait_for_abort(abort_event, thread_stop_event):
        """
        Wait for the abort signal to stop all other threads
        :param abort_event: Event used to abort the authentication by the user
        :param thread_stop_eventl: Event to stop all other threads with
        :return:
        """
        if not abort_event:
            return
        abort_event.wait()
        thread_stop_event.set()

    @staticmethod
    def _filter_allow_credentials(client, challenge, rp_id,
                                  allow_credentials):
        """
        Check which of the PKCSs described in allow_credentials are bound to
        the authenticator device. Try a silent authentication for that purpose.
        :param client: Fido2Client using the device
        :param challenge: Challenge by the server
        :param rp_id: Relying Party Identifier
        :param allow_credentials: The allow credentials to be filtered
        :return: A filtered allow_credentials list
        """
        if not allow_credentials:
            return

        user_presence_required = False
        user_verification_required = False
        filtered_allow_credentials = []

        for credential in allow_credentials:
            assertions = None
            client_data = None
            try:
                assertions, client_data = client.get_assertion(
                    rp_id, challenge, [credential], None,
                    user_presence_required, user_verification_required, None,
                    None, None)
            except Exception:
                pass
            if assertions and client_data:
                filtered_allow_credentials.append(credential)

        return filtered_allow_credentials

    def _select_assertion(self, assertions, abort_event):
        """
        Select one of the assertions the authenticator produced
        :param assertions: The assertions
        :param abort_event: Event to abort the selection with
        :return: A single assertion of type AssertionResponse
        """
        if not assertions or len(assertions) < 1:
            return None

        # if multiple assertions are present, let the user select the right one
        if assertions[0].number_of_credentials and \
                assertions[0].number_of_credentials > 1:
            users = []
            user_map = {}
            for index, value in enumerate(assertions):
                users.append(value.user)
                user_map[value.user['id']] = index
            selected_user = \
                self._user_interaction.select_user(users, abort_event)
            if selected_user and selected_user['id'] in user_map:
                assertion_index = user_map[selected_user['id']]
                assertion = assertions[assertion_index]
                return assertion
            else:
                return None
        # return only result
        else:
            return assertions[0]

    @staticmethod
    def _discover_devices(communication_queue, abort_event):
        """
        Discover FIDO2 authenticators
        :param communication_queue: Queue to put newly discovered
                authenticator in
        :param abort_event: Event to abort discovery with
        :return:
        """
        discovered = []

        # look for new devices until abort
        while not abort_event.is_set():
            new_devices = []
            for d in hidtransport.hid.Enumerate():
                if hidtransport.HidUsageSelector(d) and \
                        d not in [e.descriptor for e in discovered]:
                    # new device found
                    dev = hidtransport.hid.Open(d['path'])
                    dev = CtapHidDevice(d, hidtransport.UsbHidTransport(dev))
                    new_devices.append(dev)
                    discovered.append(dev)
            # notify main thread
            if new_devices:
                communication_queue.put((CommunicationObject.DEVICE,
                                         new_devices))
            # slow down busy wait
            time.sleep(0.1)

        # on abort put an empty list in the queue to stop the main thread
        # from waiting for results
        communication_queue.put((CommunicationObject.DEVICE, []))

    @staticmethod
    def _do_get_assertion(device, challenge, rp_id, allow_credentials,
                          user_verification, extensions, result_queue,
                          stop_event):
        """
        Call get_assertion on an individual authenticator.
        :param device: The device to use
        :param challenge: Websafe encoded challenge by the server
        :param rp_id: Relying Party identifier
        :param allow_credentials: List of acceptable PKCSs
        :param user_verification: Requirements for user verification
        :param extensions: Possible extensions
        :param result_queue: Queue to write result to
        :param stop_event: Stop event for the authenticator
        :return:
        """
        # initialize values
        client = Fido2Client(device, "https://" + rp_id)
        user_interaction = False
        assertions = None
        client_data = None
        filtered_allow_credentials = None
        response = AssertionResponseInformation(assertions, client_data,
                                                device.descriptor,
                                                user_interaction)

        # set user verification/ presence
        user_verification_required = Fido2ClientWrapper._uv_required(
            user_verification, device)
        user_presence_required = not user_verification_required

        # check which of the allow credentials are bound to the authenticator
        if allow_credentials:
            filtered_allow_credentials = \
                Fido2ClientWrapper._filter_allow_credentials(
                    client, challenge, rp_id, allow_credentials)
            if len(allow_credentials) > 0 and \
                    len(filtered_allow_credentials) == 0:
                result_queue.put((CommunicationObject.ASSERTION, response))
                return

        # get the assertion of the authenticator
        try:
            user_interaction = True
            assertions, client_data = client.get_assertion(
                rp_id, challenge, filtered_allow_credentials, extensions,
                user_presence_required, user_verification_required, None,
                stop_event, None)
        except Exception:
            if stop_event.is_set():
                user_interaction = False

        # insert result into the queue
        response = AssertionResponseInformation(assertions, client_data,
                                                device.descriptor,
                                                user_interaction)
        result_queue.put((CommunicationObject.ASSERTION, response))

    def _get_assertion(self, challenge, rp_id, timeout=120,
                       allow_credentials=None, user_verification="preferred",
                       extensions=None):
        """
        Wrapper to generate assertions
        :param challenge: Websafe encoded challenge
        :param timeout: Max time a caller is willing to wait
        :param rp_id: Relying party identifier
        :param allow_credentials: List of acceptable PKCSs
        :param user_verification: Requirements for user verification
        :param extensions: Additional parameters
        :return: The assertion of type AssertionResponse and client data of
                type ClientData
        """
        # notify user that user interaction is required
        self._user_interaction.notify_user_interaction_required(
            self._user_name, self.relying_party_id)

        # set up variables
        result_queue = queue.Queue()
        issued_requests = []
        assertions = None
        assertion = None
        client_data = None
        original_sigint_handler = None

        # if no user defined abort event is set use SIGINT signal
        if not self._abort_event:
            self._abort_event = threading.Event()
            original_sigint_handler = signal.getsignal(signal.SIGINT)
            signal.signal(signal.SIGINT, self._signal_handler)

        # wait for the timeout to expire
        with Timeout(timeout) as stop_event:

            # start a thread to wait for a user defined abort signal
            abort_observer = threading.Thread(
                target=Fido2ClientWrapper._wait_for_abort,
                args=(self._abort_event, stop_event))
            abort_observer.start()

            # start a thread to discover devices
            device_listener = threading.Thread(
                target=Fido2ClientWrapper._discover_devices,
                args=(result_queue, stop_event))
            device_listener.start()

            # while there is no result
            while not (assertions and client_data) and not stop_event.is_set():

                # wait for device discovery or assertion response
                comm_obj = result_queue.get()

                # new device discovered
                if comm_obj[0] == CommunicationObject.DEVICE:
                    new_devices = comm_obj[1]

                    # send requests to all discovered devices
                    for device in new_devices:
                        thread = threading.Thread(
                            target=Fido2ClientWrapper._do_get_assertion,
                            args=(device, challenge, rp_id,
                                  allow_credentials, user_verification,
                                  extensions, result_queue, stop_event))
                        issued_requests.append(device.descriptor)
                        thread.start()

                # response received
                if comm_obj[0] == CommunicationObject.ASSERTION:
                    assertion_response = comm_obj[1]
                    assertions = assertion_response.assertions
                    client_data = assertion_response.client_data
                    issued_requests.remove(
                        assertion_response.device_descriptor)
                    if (not (assertions and client_data) and
                            assertion_response.user_interaction):
                        self._user_interaction.notify_authenticator_failed()

            # stop current threads
            stop_event.set()

            # select an assertion if necessary
            if assertions and client_data:
                stop_event.clear()
                assertion = self._select_assertion(assertions, stop_event)

            # handle user defined abort event
            if self._abort_event.is_set():
                # user canceled operation
                assertion = None
                client_data = None
                self.state = ClientState.canceled
            else:
                # terminate the thread waiting for the abort
                self._abort_event.set()
                self._abort_event.clear()

            # if the default abort event is used, reset the original SIGINT
            # handler
            if original_sigint_handler:
                signal.signal(signal.SIGINT, original_sigint_handler)
                self._abort_event = None

        return assertion, client_data

    def _signal_handler(self, sig, frame):
        """
        Simple signal handler to support default abort signal
        :param sig:
        :param frame:
        :return:
        """
        self._abort_event.set()

    def _abort_handshake(self, state=ClientState.handshake_failed,
                         message=None):
        """
        Abort the handshake by settings the state and returning none object.
        :param message: Optional message to print before aborting
        :return: None
        """
        if message:
            self._user_interaction.display_error(message)
        self.state = state

        return None


@unique
class CommunicationObject(IntEnum):
    """ Class describing the nature of an object inside a queue used for
    communication. """
    DEVICE = 0          # a new device was discovered
    ASSERTION = 1       # an assertion was generated


class AssertionResponseInformation:
    """ Class storing all necessary information about an assertion. """

    def __init__(self, assertions, client_data, device_descriptor,
                 user_interaction):
        """
        Set values.
        :param assertions: The AssertionResponse object returned by the
                authenticator through the Fido2Client.
        :param client_data: The ClientData object returned by the Fido2Client.
        :param device_descriptor: The descriptor of the device used to
                generate the assertion.
        :param user_interaction: A boolean indicating whether of not user
                interaction took place.
        """
        self.assertions = assertions
        self.client_data = client_data
        self.device_descriptor = device_descriptor
        self.user_interaction = user_interaction


class UserInteraction(object):
    """ Base class for classes handling the interaction with a user. """

    def __init__(self):
        pass

    def notify_user_interaction_required(self, user_name, rp_id):
        """
        Notify the user that a user interaction is required.
        :param user_name: The user name
        :param rp_id: The relying party identifier
        :return:
        """
        raise NotImplementedError()

    def notify_authenticator_failed(self):
        """
        Notify a user that the chosen authenticator could not generate an
        assertion
        :return:
        """
        raise NotImplementedError

    def select_user(self, users, abort_event):
        """
        Let the user select one of the users the authenticator can authenticate
        :param users: The users
        :param abort_event: Event to abort the selection with
        :return: The id of a single user
        """
        raise NotImplementedError

    def display_error(self, message):
        """
        Display an error with message to the user
        :param message: The message
        :return:
        """
        raise NotImplementedError


class CommandLineInteraction(UserInteraction):

    def __init__(self):
        pass

    def notify_user_interaction_required(self, user_name, rp_id):
        """
        Notify the user that a user interaction is required.
        :param user_name: The user name
        :param rp_id: The relying party identifier
        :return:
        """
        if user_name:
            request_string = "\nAuthentication request for user: {0}".format(
                user_name)
        else:
            request_string = "\nAuthentication request"
        print(request_string)
        print("From service: {0}".format(rp_id))

        print("Insert and touch the authenticator device you wish to use to "
              "consent to the authentication...\n")

    def notify_authenticator_failed(self):
        """
        Notify a user that the chosen authenticator could not generate an
        assertion
        :return:
        """
        print("Creating an assertion on chosen authenticator failed.")

    def select_user(self, users, abort_event):
        """
        Let the user select one of the users the authenticator can authenticate
        :param users: The users
        :param abort_event: Event to abort the selection with
        :return: The id of a single user
        """
        print("The authenticator is able to authenticate more than one user. "
              "Please select the user you wish to authenticate:")
        for index, user in enumerate(users):
            print("{0}) ID: {1}".format(index + 1, user['id'].hex()))

        success_indicator = threading.Event()
        abort_listener = threading.Thread(target=self._abort_input,
                                          args=(abort_event, success_indicator))
        abort_listener.start()

        while not abort_event.is_set():

            # get user input
            user_input = input("Type a number from 1 to " + str(len(users)) + \
                               " to select a user: ")

            # check if it is an integer
            try:
                int_input = int(user_input)
            except ValueError:
                if not abort_event.is_set():
                    print("Input must be a number")
                continue

            # check if it is a valid index
            index = int_input - 1
            if index not in range(0, len(users)):
                print("Input must be a valid index")
                continue

            # terminate the thread waiting for the abort signal
            success_indicator.set()
            abort_event.set()
            abort_event.clear()

            # return the result
            return users[index]

        return None

    def display_error(self, message):
        """
        Display an error with message to the user
        :param message: The message
        :return:
        """
        print("ERROR: ", message)

    @staticmethod
    def _abort_input(abort_event, success_indicator):
        """
        Abort waiting for input by typing enter once the event is set.
        :param abort_event: The Abort event
        :param success_indicator: Event indicating if selection ended with
        success
        :return:
        """
        abort_event.wait()
        if not success_indicator.is_set():
            print("\nPress enter to abort")
        # TODO: [tbr] find a better way to abort input
