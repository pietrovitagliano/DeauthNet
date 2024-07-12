# This file is part of the DeauthNet project.
#
# DeauthNet is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free Software Foundation,
# either version 3 of the License, or (at your option) any later version.
#
# DeauthNet is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY this will happen; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# Author: Pietro Vitagliano
# GitHub Repository: https://github.com/pietrovitagliano/DeauthNet


from WiFiFunctions.Detection.DeauthAttackInfo.deauth_victim_info import DeauthVictimInfo


class DeauthAttackInfo:
    """
    The DeauthAttackInfo class is used to store the information about the access points and the victims under attack,
    in order to detect the ongoing de-authentication attacks.
    """

    def __init__(self, deauth_window_size: float, deauth_frames_per_second_threshold: float):
        """
        Initializes the DeauthAttackInfo object.
        :param deauth_window_size: The size of the window in seconds to consider the de-authentication frames
        :param deauth_frames_per_second_threshold: The threshold of de-authentication frames to consider an attack
        """

        self._deauth_window_size: float = deauth_window_size
        self._deauth_frames_per_second_threshold: float = deauth_frames_per_second_threshold
        self._attack_info_dict: dict[str, dict[str, DeauthVictimInfo]] = {}

    def add_info_to_victim(self, access_point_mac: str, victim_mac: str):
        """
        Add the information about a new de-authentication frame to the victim.
        :param access_point_mac: The MAC address of the access point to which the victim is connected
        :param victim_mac: The MAC address of the victim
        """

        if access_point_mac not in self._attack_info_dict:
            self._attack_info_dict[access_point_mac] = {}

        if victim_mac not in self._attack_info_dict[access_point_mac]:
            self._attack_info_dict[access_point_mac][victim_mac] = DeauthVictimInfo(
                victim_mac=victim_mac,
                deauth_window_size=self._deauth_window_size
            )

        self._attack_info_dict[access_point_mac][victim_mac].add_reception_info()

    def get_victims_under_attack(self, access_point_mac: str) -> set[str]:
        """
        Get the set of victims under attack, using the threshold of de-authentication frames to establish which
        victims are under attack.
        :param access_point_mac: The MAC address of the access point
        :return: The set of victims under attack
        """

        victims_under_attack_set: set[str] = set()

        potential_victims: dict[str, DeauthVictimInfo] = self._attack_info_dict.get(access_point_mac, {})
        for victim_info in potential_victims.values():
            frame_per_second = victim_info.get_average_frames_per_second()

            if frame_per_second >= self._deauth_frames_per_second_threshold:
                victims_under_attack_set.add(victim_info.victim_mac)

        return victims_under_attack_set

    def remove_expired_frame_info(self, access_point_mac: str):
        """
        Remove, for the given access point MAC address, the reception information
        of the de-authentication frames that have been added before the timeout.
        :param access_point_mac: The MAC address of the access point
        """

        access_point_mac_dict: dict[str, DeauthVictimInfo] = self._attack_info_dict.get(access_point_mac, {})
        for victim_mac in access_point_mac_dict.keys():
            self._attack_info_dict[access_point_mac][victim_mac].remove_expired_reception_info()

    def clear_information(self):
        """
        Clear the information inside the dict _attack_info_dict.
        """

        self._attack_info_dict.clear()
