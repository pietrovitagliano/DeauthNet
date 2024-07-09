from typing import MutableSet, Optional

from rich.table import Table
from scapy.layers.dot11 import Dot11, Dot11Deauth
from scapy.packet import Packet

from GUI.gui_manager import GUIManager
from WiFiFunctions.Detection.DeauthAttackInfo.deauth_attack_info import DeauthAttackInfo
from Core.abstract_scanner import AbstractScanner
from Core.access_point import AccessPoint


class DeauthAttackScanner(AbstractScanner):
    """
    The DeauthAttackScanner is a class that allows to scan for ongoing de-authentication attacks and
    show the information about the access points and the victims under attack.
    """

    def __init__(self, wireless_adapter_key: str, channel_change_delay: float,
                 access_point_set: MutableSet[AccessPoint], deauth_frames_per_second_threshold: float,
                 table_title: str = "Scanning For De-authentication Packets"):
        """
        Initializes the DeauthAttackScanner object.
        :param wireless_adapter_key: The key of the wireless interface (e.g. "wlan0")
        :param channel_change_delay: The delay in seconds to change the channel
        :param access_point_set: The set of access points to show the information about
        :param deauth_frames_per_second_threshold: The threshold of de-authentication frames to consider an attack
        :param table_title: The title of the table to show the information about the de-authentication attacks
        """

        super().__init__(wireless_adapter_key=wireless_adapter_key,
                         channel_change_delay=channel_change_delay,
                         access_point_set=access_point_set)

        # Dictionary to store the information about the de-authentication attacks
        self._deauth_access_point_info: DeauthAttackInfo = DeauthAttackInfo(
            deauth_window_size=self._channel_change_delay,
            deauth_frames_per_second_threshold=deauth_frames_per_second_threshold
        )

        self._table_title: str = table_title

    def _update_gui(self):
        # Get the table with the information about the access points and the victims under attack
        table = self._info_to_table()

        # Refresh the information about the ongoing de-authentication attacks
        GUIManager().clear_screen()
        GUIManager().print(f"Scanning on channel {self._wifi_band_manager.get_current_channel()}...\n",
                           table if table else "",
                           "\n"
                           "Press CTRL+C to stop the scan...\n")

    def start_scan(self):
        """
        Start the scan for de-authentication attacks.
        Before starting the scan, clear the information about the
        de-authentication attacks in order to consider only the new ones.
        """

        # Clear the information about the de-authentication attacks, if there are any
        self._deauth_access_point_info.clear_information()

        super().start_scan()

    def _on_scan_update(self):
        """
        Loop of the DeauthAttackScanner object, performed inside the start_scan method.
        This method is called after the delay used to perform the scan.
        It performs the scan and updates the information about the de-authentication attacks.
        """

        # Perform the scan loop of the super class, that is sleep, update the GUI and change the channel
        super()._on_scan_update()

        # After the super class update, the channel has been changed.
        # Thus, remove the expired information about the de-authentication
        # attacks for the current channel (that is the new one)
        current_channel: int = self._wifi_band_manager.get_current_channel()

        # Remove the expired information about the de-authentication attacks for each access point in the set
        for ap in self._access_point_set:
            if ap.channel == current_channel:
                self._deauth_access_point_info.remove_expired_frame_info(access_point_mac=ap.mac)

    def _sniff_callback(self, packet: Packet):
        """
        Callback function to look for de-authentication attacks, related to scanned the access points,
        and store their information.
        :param packet: The packet sniffed
        """

        # Process the packet only if it is a de-authentication one
        if packet.haslayer(Dot11Deauth):
            self._process_deauth_packet(packet=packet)

    def _process_deauth_packet(self, packet: Packet):
        """
        Process the de-authentication packet sniffed,
        to look for de-authentication attacks and store their information.
        :param packet: The packet sniffed
        """

        # Get the MAC address of the access point
        access_point_mac: str = str(packet[Dot11].addr3).upper()

        # Store the information about the attack for the access points is in the set
        if access_point_mac in {ap.mac.upper() for ap in self._access_point_set}:
            # Get the MAC address of the victim
            victim_mac: str = str(packet[Dot11].addr1).upper()

            # Add the victim mac to the DeauthAttackInfo object
            self._deauth_access_point_info.add_info_to_victim(access_point_mac=access_point_mac, victim_mac=victim_mac)

    def _get_attacked_victims_by_ap_dict(self) -> dict[str, set[str]]:
        """
        Get the dictionary containing the MAC addresses of the victims under attack for each access point.
        :return: The dictionary containing the MAC addresses of the victims under attack for each access point
        """

        victim_macs_dict: dict[str, set[str]] = {}
        for access_point in self._access_point_set:
            ap_mac: str = access_point.mac.upper()
            victim_under_attack_set: set[str] = self._deauth_access_point_info.get_victims_under_attack(ap_mac)

            if len(victim_under_attack_set) > 0:
                victim_macs_dict[ap_mac] = victim_under_attack_set

        return victim_macs_dict

    def _info_to_table(self) -> Optional[Table]:
        """
        Convert the information about the access points and the victims under attack into a table.
        :return: The table with the information about the access points and the victims under attack
        """

        # Get the dictionary containing the MAC addresses of the victims under attack for each access point
        victims_by_ap_dict: dict[str, set[str]] = self._get_attacked_victims_by_ap_dict()

        # Get the table with the information about the access points and the victims under attack
        table = GUIManager().deauth_attack_info_to_table(access_point_set=self._access_point_set,
                                                         victim_macs_dict=victims_by_ap_dict,
                                                         table_title=self._table_title)

        return table
