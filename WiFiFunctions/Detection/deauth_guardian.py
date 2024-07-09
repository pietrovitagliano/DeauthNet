from typing import MutableSet, Optional

from rich.table import Table
from scapy.packet import Packet

from GUI.gui_manager import GUIManager
from WiFiFunctions.Detection.deauth_attack_scanner import DeauthAttackScanner
from Core.access_point import AccessPoint
from WiFiFunctions.black_list_manager import BlackListManager


class DeauthGuardian(DeauthAttackScanner):
    """
    The DeauthGuardian is a class that act like an IDS, allowing to scan for ongoing de-authentication attacks and
    showing the information about the access points and the victims under attack.
    When an attack is detected, the access point is put in a blacklist to avoid the attack.
    """

    def __init__(self, wireless_adapter_key: str, channel_change_delay: float,
                 access_point_set: MutableSet[AccessPoint], deauth_frames_per_second_threshold: float,
                 table_title: str = "Deauth Guardian Started"):
        """
        Initializes the DeauthGuardian object.
        :param wireless_adapter_key: The key of the wireless interface (e.g. "wlan0")
        :param channel_change_delay: The delay in seconds to change the channel
        :param access_point_set: The set of access points to show the information about
        :param deauth_frames_per_second_threshold: The threshold of de-authentication frames to consider an attack
        :param table_title: The title of the table to show the information about the de-authentication attacks
        """

        super().__init__(wireless_adapter_key=wireless_adapter_key,
                         channel_change_delay=channel_change_delay,
                         access_point_set=access_point_set,
                         deauth_frames_per_second_threshold=deauth_frames_per_second_threshold,
                         table_title=table_title)

        # Set to store the MAC addresses of the access points in the blacklist
        self._black_list_manager: BlackListManager = BlackListManager()

    def get_black_listed_ap_mac_set(self) -> set[str]:
        return self._black_list_manager.black_listed_ap_mac_set

    def clear_blacklist(self):
        """
        Clear the blacklist of access points.
        """

        self._black_list_manager.clear_blacklist()

    def _process_deauth_packet(self, packet: Packet):
        """
        Process the packet sniffed, performing the parent's method functionalities and
        updating the blacklist of the access points
        :param packet: The packet sniffed
        """

        super()._process_deauth_packet(packet=packet)

        # Get the MAC addresses of the access points under attack and put them in the blacklist
        ap_to_put_in_black_list = self._get_attacked_victims_by_ap_dict().keys()
        # CORRECT LINE
        #self._black_list_manager.add_to_blacklist(*ap_to_put_in_black_list)

        # WRONG LINES
        for access_point_mac in ap_to_put_in_black_list:
            self._add_to_blacklist(access_point_mac=access_point_mac)

    # DELETE THIS METHOD
    def _add_to_blacklist(self, access_point_mac: str):
        """
        Add the access point with the given MAC address to the blacklist, if it is not already there.
        :param access_point_mac: The MAC address of the access point to put in the blacklist
        """

        self._black_list_manager.add_to_blacklist(access_point_mac)

    def _info_to_table(self) -> Optional[Table]:
        # Get the dictionary containing the MAC addresses of the victims under attack for each access point
        victims_by_ap_dict: dict[str, set[str]] = self._get_attacked_victims_by_ap_dict()

        # Get the table with the information about the access points and the victims under attack
        table = GUIManager().deauth_attack_info_to_table(
            access_point_set=self._access_point_set,
            victim_macs_dict=victims_by_ap_dict,
            black_listed_ap_mac_set=self._black_list_manager.black_listed_ap_mac_set,
            table_title=self._table_title
        )

        return table
