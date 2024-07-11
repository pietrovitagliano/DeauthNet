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


from datetime import datetime


class DeauthVictimInfo:
    """
    The DeauthVictimInfo class is used to store the reception of de-authentication frames and the victim
    to which they are directed.
    """

    def __init__(self, victim_mac: str, deauth_window_size: float):
        """
        Initializes the DeauthVictimInfo object.
        :param victim_mac: The MAC address of the victim
        :param deauth_window_size: The size of the window in seconds to consider the de-authentication frames
        """

        self._victim_mac: str = victim_mac
        self._deauth_window_size: float = deauth_window_size
        self._date_info_list: list[datetime] = []

    @property
    def victim_mac(self) -> str:
        return self._victim_mac

    def add_reception_info(self, reception_date: datetime = datetime.now()):
        """
        Add the reception information of a new de-authentication frame to the list.
        """

        self._date_info_list.append(reception_date)

    def remove_expired_reception_info(self):
        """
        Remove the reception information of the de-authentication frames that have been added before the timeout.
        """

        current_time = datetime.now()
        self._date_info_list = [time for time in self._date_info_list
                                if (current_time - time).seconds <= self._deauth_window_size]

    def get_average_frames_per_second(self) -> float:
        """
        Get the average number of de-authentication frames per second.
        :return: The average number of de-authentication frames per second
        """

        return len(self._date_info_list) / self._deauth_window_size
