#!/bin/bash

# This skripts help to generate a client certificate using openssl
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

# This script requires openssl to be installed

usage()
{
    printf "\nMandatory parameters:
            \n\t{-k,--key} PEM file containing the servers private key
            \n\t{-c,--cert} PEM file containing the servers certificate
            \n\t{-n,--name} The name of the user to generate the certificate for
            \n\t{-i, --id} (may replace name) The id of the user to generate the certificate for
            \n\t{-m, --mode} The FIDO2 mode the user will be using
            \n\t{-o,--out} The output path for the new certificate
            \nOptional parameters:
            \n\t{-a, --additional-information} Additional information e.g. a longer user name
            \n\t{-p,--print-only} Print the content of the script to stdout and delete it afterwards
            \n\t{-h,--help} Show this message\n\n"
}

check_args()
{
	while [ "$1" != "" ]; do
	    case $1 in
            -k | --key )
                shift
                key_path=$1
                ;;
            -c | --cert )
                shift
                cert_path=$1
                ;;
            -n | --name )
                shift
                user_name="$1"
                ;;
            -m | --mode )
                shift
                mode=$1
                ;;
            -i | --id )
                shift
                user_id=$1
                ;;
            -o | --out )
                shift
                out_path=$1
                ;;
            -p | --print-only )
                print_only=1
				;;
            -h | --help )
                usage
				exit
				;;
            * )
                usage
                exit 1
		esac
		shift
	done


	if [ -z "$key_path" ] || [ -z "$cert_path" ] || [ -z "$mode" ] || [ -z "$out_path" ]; then
	  echo "Parameter missing"
		usage
		exit
	fi

	if [ -z "$user_id" ] && [ -z "$user_name" ]; then
	  echo "User name or ID must be specified"
	  usage
	  exit
	fi
}

set_output_mode()
{
	if [ "$1" = "0" ]; then
		cont_out=/dev/null
		err_out=/dev/null
	else
		cont_out=/dev/tty
		err_out=/dev/tty
	fi
}

setup_information()
{
  information_string="/O="$fido2_string"/OU="$mode""

  if [ ${#user_id} -gt 0 ]; then
    information_string=""$information_string"/ST="$user_id""
  fi

  if [ ${#user_name} -gt 0 ]; then
    information_string=""$information_string"/CN="$user_name""
  fi
}

request_certificate()
{
	openssl req -newkey rsa:4096 -out $tmp_path -nodes -days 365 -subj "$information_string" > 	$cont_out 2>$err_out
}

sign_certificate()
{
	openssl x509 -req -in $tmp_path -CA $cert_path -CAkey $key_path -out $out_path -set_serial 01 -days 365 > $cont_out 2>$err_out
	cat $cert_path >> $out_path
}

### main
# fill in variables
key_path=""
cert_path=""
user_name=""
user_id=""
out_path=""
fido2_string="fido2_authentication_cert"
mode=""
print_only=0
cont_out=/dev/null
err_out=/dev/tty
information_string=""

check_args "$@"
dir=$(dirname "${out_path}")
tmp_path="$dir/.tmp.pem"

# set output mode
if [ "$print_only" = "1" ]; then
	set_output_mode 0
fi

# set information string
setup_information

# create certificate
request_certificate

# sign certificate
sign_certificate

# print content if requested
if [ "$print_only" = "1" ]; then
	set_output_mode 1
	cat $out_path
	rm $out_path
fi

# clean up
rm $tmp_path