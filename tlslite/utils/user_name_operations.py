# In this file user name operations are defined
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

from unicodedata import normalize, category
import re
from precis_i18n import get_profile


class UserNameOperations:

    @staticmethod
    def freeformclass_name(name):
        """
        Delete all characters from a name that are not part of the
        FreeFormClass as specified by RFC 8264
        :param name: A user name
        :return: The FreeFormClass conformant user name
        """
        ffc = get_profile('FreeFormClass')
        formatted_name = ""

        # remove all characters that are not in FreeFormClass
        for character in name:
            try:
                ffc.enforce(character)
            except UnicodeEncodeError:
                continue
            formatted_name += character

        return formatted_name

    @staticmethod
    def format_user_name(user_name):
        """
        Format a user name according to RFC8266
        :param user_name: User name provided by user
        :return: The formatted user name
        """
        if not user_name:
            return None

        # strip non-FreeFormClass characters
        user_name = UserNameOperations.freeformclass_name(user_name)

        # substitute non-ASCII spaces with ASCII SPACE
        user_name = "".join([c if category(c) != "Zs" else u'\u0020' for c in
                             user_name])

        # remove leading and trailing blanks
        user_name = user_name.strip()

        # no multiple blanks
        user_name = re.sub(' +', ' ', user_name)

        # use lower case
        user_name = user_name.lower()

        # normalize
        user_name = normalize("NFKC", user_name)

        return user_name
