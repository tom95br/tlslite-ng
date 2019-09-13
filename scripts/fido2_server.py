#!/usr/bin/env python3

# This scripts helps to manage the fido2 user database on the server.
#  Copyright (C) 2019  Tom-Lukas Breitkopf
#
# This program is free software: you can redistribute it an d /or modify it
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
# with this program. If not, see <http://www.gnu.org / licenses / >.

import sqlite3
try:
    from pysqlcipher3 import dbapi2 as sqlcipher
    HAVE_SQLCIPHER = True
except ImportError:
    HAVE_SQLCIPHER = False
import sys
import getopt
import subprocess
from os import urandom, path
from fido2.server import RelyingParty, Fido2Server
from fido2.client import Fido2Client
from fido2.hid import CtapHidDevice
from fido2.utils import websafe_encode
from fido2.cbor import dumps
from tlslite.utils.user_name_operations import UserNameOperations
from tlslite.api import X509CertChain, parsePEMKey
from tlslite.constants import FIDO2Mode


def print_usage(message):
    """
    Descript usage.
    :param message: Message to be printed first
    """
    print(message)
    print("Arg: 1: [setup/ register/ clear]")
    print("setup: Initialize FIDO2 user database")
    print("register: Register a new user to the database")
    print("clear: Clear the database")

    print("\nArguments: ")
    print("{-p,--db-path}: address/ path of the data base")
    print("{-e,--encryption-key}: [optional] Path to the encryption key of an "
          "encrypted database")

    print("\nRegistration arguments: ")
    print("{-r,--rp-id}: Relying Party identifier of the server")
    print("{-n,--name}: [optional] The user name")
    print("{-d,--display-name}: [optional] A display name of the user")
    print("{--resident-key}: [optional] Flag requesting to create a "
          "resident key. Automatically set if no user name is provided.")
    print("{-c,--cert}: path to the client certificate")
    print("If openssl is installed on your machine you may use -s and -k "
          "together instead of -c to generate a client certificate signed by "
          "the server.")
    print("{-s,--server-cert}: path to the server certificate")
    print("{-k,--server-key}: path to the server private key")


def print_error(s):
    """Print error message and exit"""
    sys.stderr.write("ERROR: %s\n" % s)
    sys.exit(-1)


def handle_args(argv, arg_string, flags_list=[]):
    """
    Convert argument array to usable format
    """
    getOptArgString = ":".join(arg_string) + ":"
    try:
        opts, argv = getopt.getopt(argv, getOptArgString, flags_list)
    except getopt.GetoptError as e:
        print_error(e)
        # Default values if arg not present

    user_name = None
    display_name = None
    rp_id = None
    encoded_certificate = None
    server_cert_path = None
    server_key_path = None
    db_path = None
    encryption_key = None
    resident_key = False

    for opt, arg in opts:
        if opt == "-n" or opt == "--name":
            user_name = arg
        elif opt == "-d" or opt == "--display-name":
            display_name = arg
        elif opt == "-r" or opt == "--rp-id":
            rp_id = arg
        elif opt == "-c" or opt == "--cert":
            if not path.isfile(arg):
                print_error("Invalid path to client certificate")
            cert_chain = X509CertChain()
            data = open(arg, "rb").read()
            data = str(data, 'utf-8')
            cert_chain.parsePemList(data)
            if cert_chain.getNumCerts() == 0:
                print_error("Invalid certificate provided")
            encoded_certificate = data
        elif opt == "-s" or opt == "--server-cert":
            if not path.isfile(arg):
                print_error("Invalid path to server certificate")
            server_cert_path = arg
        elif opt == "-k" or opt == "--server-key":
            if not path.isfile(arg):
                print_error("Invalid path to server key")
            server_key_path = arg
        elif opt == "-p" or opt == "--db-path":
            db_path = arg
        elif opt == "-e" or opt == "--encrypt":
            key_string = open(arg, "rb").read()
            key_string = str(key_string, 'utf-8')
            encryption_key = parsePEMKey(key_string, private=True,
                                         implementations=["python"])
        elif opt == "--resident-key":
            resident_key = True

    ret_list = []
    if "n" in arg_string or "name=" in flags_list:
        ret_list.append(user_name)
    if "d" in arg_string or "display-name=" in flags_list:
        ret_list.append(display_name)
    if "r" in arg_string or "rp-id=" in flags_list:
        ret_list.append(rp_id)
    if "c" in arg_string or "cert=" in flags_list:
        ret_list.append(encoded_certificate)
    if "s" in arg_string or "server-cert=" in flags_list:
        ret_list.append(server_cert_path)
    if "k" in arg_string or "server-key=" in flags_list:
        ret_list.append(server_key_path)
    if "p" in arg_string or "db-path=" in flags_list:
        ret_list.append(db_path)
    if "e" in arg_string or "encryption-key=" in flags_list:
        ret_list.append(encryption_key)
    if "resident-key" in flags_list:
        ret_list.append(resident_key)

    return ret_list


def get_db_connection(db_path, encryption_key=None):
    """
    Connect to the database and decrypt it if necessary
    :param db_path: Path to the database
    :param encryption_key: Key to decrypt database with
    :return: A connection to the database
    """

    if db_path is None or len(db_path) == 0:
        print_usage("Path to database required")
        sys.exit(1)

    if encryption_key and HAVE_SQLCIPHER:
        key_phrase = encryption_key.sign(bytearray(encryption_key.key_type,
                                                   'utf-8')).hex()
        connection = sqlcipher.connect(db_path)
        cursor = connection.cursor()
        cursor.execute("PRAGMA key='" + key_phrase + "'")
    elif encryption_key and not HAVE_SQLCIPHER:
        print_error("sqlcipher not installed. Unable to handle encrypted "
                    "database")
    else:
        connection = sqlite3.connect(db_path)

    cursor = connection.cursor()
    sql_command = """ DROP TABLE IF EXISTS not_a_table;"""
    try:
        cursor.execute(sql_command)
    except sqlite3.DatabaseError:
        print_error(db_path + " is not an unencrypted database.")
    except sqlcipher.DatabaseError:
        print_error(db_path + " is not an encrypted database.")

    return connection


def generate_certificate(user, mode, server_cert_path,
                         server_key_path):
    """
    Generate a client certificate chain signed by the server. Use the
    generate_client_certificate.sh script which uses openssl tools.
    :param user: The user to generate the certificate for
    :param mode: FIDO2 mode to put into the certificate
    :param server_cert_path: Path to the server certificate
    :param server_key_path: Path to the servers private key
    :param additional_user_string: In case user string is longer than 32 Bytes
    :return: The client certificate chain as a pem encoded string
    """
    id_string = user['id'].hex()
    certificate_dir = path.dirname(path.realpath(server_cert_path))
    arg_string = "generate_client_certificate.sh -i " + \
                 id_string + " -m " + FIDO2Mode.toRepr(mode) + " -c " + \
                 path.realpath(server_cert_path) + " -k " + \
                 path.realpath(server_key_path) + " -o " + \
                 certificate_dir + "/new_cert.pem -p"
    if 'name' in user:
        arg_string += " -n \"" + user['name'] + "\""
    generator = subprocess.run(arg_string, shell=True, stdout=subprocess.PIPE)
    certificate = generator.stdout
    certificate = str(certificate, 'utf-8')
    cert_chain = X509CertChain()
    cert_chain.parsePemList(certificate)
    if cert_chain.getNumCerts() == 0:
        print_error("Invalid certificate generated")
        exit(1)
    print("Created certificate")

    return certificate


def get_information_from_certificate(certificate):
    """
    Extract user information from a client certificate
    :param certificate: The certificate
    :return:
    """
    if not certificate:
        return None, None

    # open certificate
    cert_chain = X509CertChain()
    try:
        cert_chain.parsePemList(certificate)
    except AttributeError:
        return None, None

    # check mode
    mode = cert_chain.get_fido2_mode()
    if mode not in FIDO2Mode.all:
        return None, None

    # check id
    user_id = cert_chain.get_fido2_user_id()
    try:
        user_id = bytes.fromhex(user_id)
    except (ValueError, TypeError):
        return None, None
    if len(user_id) != 64:
        return None, None

    user_name = None
    if mode == FIDO2Mode.fido2_with_name:
        user_name = cert_chain.get_fido2_user_name()
        if not user_name:
            return None, None

    user = {'id': user_id}
    if user_name:
        user['name'] = user_name
        user['displayName'] = user_name

    return user, mode


def get_or_create_user(cursor, user_name=None, display_name=None):
    """
    Retreive user information from database
    :param user_name: Name of the user
    :param display_name: Display name of the user
    :param cursor Database cursor
    :return: Whole user profile
    """
    display_name = display_name or user_name

    sql_command = """
    SELECT user_id, user_name, display_name FROM users
    WHERE user_name=(?)
    """
    cursor.execute(sql_command, (user_name, ))
    results = cursor.fetchall()

    if len(results) == 0:
        user_id = urandom(64)
        user = {'id': user_id}
        if user_name:
            user['name'] = user_name
            user['displayName'] = display_name

        sql_command = """
        INSERT INTO users (user_id, user_name, display_name)
        VALUES (?, ?, ?)"""
        data = (memoryview(user_id), user_name, display_name)
        cursor.execute(sql_command, data)
    else:
        result = results[0]
        user = {'id': result[0]}
        if result[1]:
            user['name'] = result[1]
        if result[2]:
            user['displayName'] = result[2]

    return user


def store_user(cursor, user):
    """
    Store a user to the database
    :param cursor: Database cursor
    :param user: The user to store
    :return:
    """
    # check if user exists
    sql_command = """
    SELECT user_name, display_name
    FROM users
    WHERE user_id=(?)
    """
    cursor.execute(sql_command, (memoryview(user['id']), ))
    result = cursor.fetchone()

    # user already exists
    if result:
        # compare information in database with user
        new_user_name = None
        new_display_name = None
        if 'name' in user:
            if result[0] and result[0] != user['name']:
                print_error("User with given ID but different name"
                            "already exists")
            if not result[0]:
                new_user_name = user['name']
        if 'displayName' in user:
            if result[1] and result[1] != user['displayName']:
                print_error("User with given ID but different display name "
                            "already exists")
            if not result[1]:
                new_display_name = user['displayName']

        # update user if new information
        if new_user_name:
            new_display_name = new_display_name or new_user_name
            sql_command = """
            UPDATE users
            SET user_name=(?), display_name=(?)
            WHERE user_id=(?)
            """
            data = (new_user_name, new_display_name, memoryview(user['id']))
            cursor.execute(sql_command, data)
        return

    # create a new user entry
    user_name = display_name = None
    if "name" in user:
        user_name = user['name']
        if "displayName" in user:
            display_name = user['displayName']
        else:
            display_name = user['name']
    sql_command = """
            INSERT INTO users (user_id, user_name, display_name)
            VALUES (?, ?, ?)"""
    data = (memoryview(user['id']), user_name, display_name)
    cursor.execute(sql_command, data)


def do_register_user(user, rp_id, resident_key=False):
    """
    FIDO2 registration process
    :param user: The user to register
    :param rp_id: Relying Party identifier
    :param resident_key: Boolean indicating whether or not to store a
    resident key
    :return: Newly created credentials
    """
    # begin registration
    relying_part = RelyingParty(rp_id)
    server = Fido2Server(relying_part)

    registration_data, state = server.register_begin(user)

    # make credential
    dev = next(CtapHidDevice.list_devices(), None)
    if not dev:
        print('No FIDO device found')
        sys.exit(1)

    client = Fido2Client(dev, 'https://' + rp_id)
    rp = {'id': rp_id, 'name': rp_id}
    challenge = websafe_encode(registration_data['publicKey']['challenge'])

    if resident_key:
        user['name'] = "."
        user_string = "(id: {0})".format(user['id'].hex())
    else:
        user_string = "(name: {0}, display name: {1})".format(
            user['name'], user['displayName'])

    print("\nRegistration request for user: " + user_string)
    print("From service: (Address: {0}, Name: {1})".format(rp['id'],
                                                           rp['name']))
    print('Touch your authenticator device now to consent to registration...\n')
    try:
        attestation_object, client_data = client.make_credential(
            rp, user, challenge, rk=resident_key)
    except Exception as e:
        print("Registration failed")
        raise e

    # complete registration
    registration_data = server.register_complete(state, client_data,
                                                 attestation_object)
    credential = registration_data.credential_data
    print("Registration complete")

    return credential


def store_credential(cursor, user, mode, credential):
    """
    Store credential in database
    :param credential: The credential to store
    :param user: The user the credential belongs to
    :param cursor: Database cursor
    :param mode: The FIDO2 mode
    :return:
    """
    user_id = user['id']
    sql_command = """
    INSERT INTO credentials(credential_id, aaguid, public_key, user_id, mode)
    VALUES (?, ?, ?, ?, ?);
    """
    data = (memoryview(credential.credential_id), memoryview(
        credential.aaguid), memoryview(dumps(credential.public_key)),
            memoryview(user_id), int(mode))
    cursor.execute(sql_command, data)
    print("New credential stored")


def store_certificate(cursor, user, mode, certificate,
                      server_certificate_path, server_key_path):
    """
    Store a certificate for the user
    :param cursor: Database cursor
    :param user: The user
    :param mode: The FIDO2 mode
    :param certificate: An existing certificate
    :param server_certificate_path: Path to the server certificate
    :param server_key_path: Path to the server private key
    :return:
    """
    # check if there is already a certificate present for the user
    sql_command = """
    SELECT COUNT(*)
    FROM certificates
    WHERE user_id=(?) AND mode=(?)
    """
    cursor.execute(sql_command, (memoryview(user['id']), mode))
    certificate_present = bool(cursor.fetchone()[0])
    if certificate_present:
        return

    # use the certificate the user provided
    if certificate:
        user_cert = certificate
    #  generate a new certificate
    else:
        user_cert = generate_certificate(user, mode,
                                         server_certificate_path,
                                         server_key_path)

    # store the certificate
    sql_command = """
    INSERT INTO certificates(user_id, mode, certificate)
    VALUES (?, ?, ?)
    """
    data = (memoryview(user['id']), int(mode), user_cert)
    cursor.execute(sql_command, data)


def register_user(argv):
    """
    Register a user to the database
    :param argv: arguments
    """
    (user_name, display_name, rp_id, certificate,
     server_cert_path, server_key_path, db_path, encryption_key,
     resident_key) = \
        handle_args(argv, "ndrcskpe", ["name=", "display-name=",
                                       "rp-id=", "cert=",
                                       "server-cert=", "server-key=",
                                       "db-path=", "encryption-key=",
                                       "resident-key"])

    mode = 0
    display_name = display_name or user_name
    if not rp_id:
        print_usage("Relying Party identifier missing")
        exit(1)
    if not certificate and not (server_cert_path and server_key_path):
        print_usage("Client Certificate or parameters to generate it must be "
                    "provided")
        exit(1)
    if certificate:
        server_cert_path = server_key_path = None

    # open database
    connection = get_db_connection(db_path, encryption_key)
    cursor = connection.cursor()

    # get information from certificate
    if certificate:
        user, mode = get_information_from_certificate(certificate)
        if not (user and mode):
            print_error("Invalid certificate")
        else:
            store_user(cursor, user)

    # create information
    else:
        # set the mode
        if user_name:
            mode = FIDO2Mode.fido2_with_name
        else:
            mode = FIDO2Mode.fido2_with_id

        # format the user name
        user_name = UserNameOperations.format_user_name(user_name)

        # get user
        user = get_or_create_user(cursor, user_name, display_name)

    # check mode
    if mode == FIDO2Mode.fido2_with_id and not resident_key:
        resident_key = True

    # store certificate
    store_certificate(cursor, user, mode, certificate, server_cert_path,
                      server_key_path)

    # register user
    credential = do_register_user(user, rp_id, resident_key)

    # store credential in database
    store_credential(cursor, user, mode, credential)

    # commit changes and close database
    connection.commit()
    connection.close()


def setup(argv):
    """
    Setup the fido2 database
    :return:
    """
    db_path, encryption_key = handle_args(argv, "pe", ["db-path=",
                                          "encryption-key="])

    connection = get_db_connection(db_path, encryption_key)
    cursor = connection.cursor()

    sql_command = """
    CREATE TABLE IF NOT EXISTS users(
    user_id BINARY(64) NOT NULL PRIMARY KEY,
    user_name VARCHAR(50),
    display_name VARCHAR(50)
    );
    """
    cursor.execute(sql_command)

    sql_command = """
    CREATE TABLE IF NOT EXISTS certificates(
    user_id BINARY(64) NOT NULL,
    mode INTEGER NOT NULL,
    certificate VARCHAR(65536) NOT NULL,
    PRIMARY KEY (user_id, mode),
    FOREIGN KEY (user_id) REFERENCES users(user_id)
    );"""
    cursor.execute(sql_command)

    sql_command = """
    CREATE TABLE IF NOT EXISTS credentials(
    credential_id VARBINARY(65536) NOT NULL PRIMARY KEY,
    aaguid BINARY(16) NOT NULL,
    public_key VARBINARY(131072) NOT NULL,
    signature_counter INTEGER NOT NULL DEFAULT 0,
    user_id BINARY(64) NULL NULL,
    mode INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
    );
    """
    cursor.execute(sql_command)

    sql_command = """
    CREATE TABLE IF NOT EXISTS eph_user_names(
    eph_user_name BINARY(32) NOT NULL PRIMARY KEY,
    user_id BINARY(64),
    valid_through DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
    );
    """
    cursor.execute(sql_command)

    sql_command = """
    CREATE TRIGGER IF NOT EXISTS table_limit
    AFTER INSERT ON eph_user_names
    WHEN (SELECT COUNT(*) FROM eph_user_names) > 1000
    BEGIN
        DELETE FROM eph_user_names;
    END;
    """
    cursor.execute(sql_command)

    connection.commit()
    connection.close()


def clear(argv):
    """
    Delete the existing database
    :return: 
    """
    db_path, encryption_key = handle_args(argv, "pe", ["db-path=",
                                          "encryption-key="])

    connection = get_db_connection(db_path, encryption_key)
    cursor = connection.cursor()

    try:
        sql_command = """
        DROP TABLE users;
        """
        cursor.execute(sql_command)

        sql_command = """
        DROP TABLE certificates;
        """
        cursor.execute(sql_command)

        sql_command = """
        DROP TABLE credentials;
        """
        cursor.execute(sql_command)

        sql_command = """
        DROP TRIGGER table_limit;
        """
        cursor.execute(sql_command)

        sql_command = """
            DROP TABLE eph_user_names;
            """
        cursor.execute(sql_command)

        connection.commit()
        connection.close()
    except (sqlite3.OperationalError, sqlcipher.OperationalError):
        print_error(db_path + " is already clean.")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print_usage("Missing command")
    elif sys.argv[1] == "setup"[:len(sys.argv[1])]:
        setup(sys.argv[2:])
    elif sys.argv[1] == "register"[:len(sys.argv[1])]:
            register_user(sys.argv[2:])
    elif sys.argv[1] == "clear"[:len(sys.argv[1])]:
        clear(sys.argv[2:])
    else:
        print_usage("Unknown command: %s" % sys.argv[1])
