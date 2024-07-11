# This file is part of the Deauth Net project.
#
# Deauth Net is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free Software Foundation,
# either version 3 of the License, or (at your option) any later version.
#
# Deauth Net is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY this will happen; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# Author: Pietro Vitagliano
# GitHub Repository: https://github.com/pietrovitagliano/DeauthNet


import re


class AccessPoint:
    """
    The AccessPoint class represents an access point in a wireless network.
    """

    def __init__(self, mac: str, ssid: str, frequency: str, channel: int, db_signal: str, encryption: list[str]):
        """
        Initializes the AccessPoint object.
        :param mac: The MAC address of the access point (always in uppercase).
        :param ssid: The SSID of the access point.
        :param frequency: The frequency of the access point.
        :param channel: The channel of the access point.
        :param db_signal: The signal strength of the access point in dB.
        :param encryption: The encryption types used by the access point.
        """

        self._mac: str = mac.upper()
        self._ssid: str = ssid
        self._frequency: str = frequency
        self._channel: int = channel
        self._db_signal: str = db_signal
        self._encryption: list[str] = sorted(encryption)

    @property
    def mac(self) -> str:
        return self._mac

    @property
    def ssid(self) -> str:
        return self._ssid

    @property
    def frequency(self) -> str:
        return self._frequency

    @property
    def channel(self) -> int:
        return self._channel

    @property
    def db_signal(self) -> str:
        return self._db_signal

    @property
    def encryption(self) -> list[str]:
        return self._encryption

    def __str__(self):
        return (f"MAC: {self._mac} - SSID: {self._ssid} - Frequency: {self._frequency} "
                f"- Channel: {self._channel} - DB Signal: {self._db_signal} - Encryption: {self._encryption}")

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        return self._mac == other.mac

    def __hash__(self):
        return hash(self._mac)

    def __lt__(self, other: 'AccessPoint'):
        if self._ssid == other._ssid:
            # Regex to look for float numbers (i.e. 2.4, 5.0, etc.)
            regex = re.compile(r'[0-9]+\.?[0-9]*')
            current_frequency: float = float(regex.search(self._frequency).group())
            other_frequency: float = float(regex.search(other._frequency).group())

            return current_frequency < other_frequency
        else:
            return self._ssid < other._ssid

    def to_dict(self) -> dict[str, object]:
        """
        Convert the AccessPoint object to a dictionary.
        If an attribute is a private, its key won't have the underscore.
        :return: The dictionary representing the AccessPoint object.
        """

        return {
            "mac": self._mac,
            "ssid": self._ssid,
            "frequency": self._frequency,
            "channel": self._channel,
            "db_signal": self._db_signal,
            "encryption": self._encryption
        }
