import math

from sortedcontainers import SortedSet

from scapy.packet import Packet
from scapy.layers.dot11 import (
    RadioTap,
    Dot11,
    Dot11Beacon,
    Dot11Elt
)

from GUI.gui_manager import GUIManager
from Core.abstract_scanner import AbstractScanner
from Core.access_point import AccessPoint


class AccessPointScanner(AbstractScanner):
    """
    The AccessPointScanner is a class that allows to scan for Wi-Fi networks
    and store them as AccessPoint objects.
    """

    def __init__(self, wireless_adapter_key: str, channel_change_delay: float):
        """
        Initializes the AccessPointScanner object.
        :param wireless_adapter_key: The key of the wireless interface (e.g. "wlan0")
        :param channel_change_delay: The delay in seconds to change the channel
        """

        # Used to store the information about the access points
        access_point_set = SortedSet()

        super().__init__(wireless_adapter_key=wireless_adapter_key,
                         channel_change_delay=channel_change_delay,
                         access_point_set=access_point_set)

    def _update_gui(self):
        # Get the table with the information about the access points
        table = GUIManager().access_point_info_to_table(self._access_point_set)

        # Refresh the information about the access points
        GUIManager().clear_screen()
        GUIManager().print(f"Scanning on channel {self._wifi_band_manager.get_current_channel()}...\n",
                           table if table else "",
                           "\n"
                           "Press CTRL+C to stop the scan...\n")

    def _sniff_callback(self, packet: Packet):
        """
        Callback function to look for access points and store them.
        :param packet: The packet sniffed
        """

        # If the packet is not a Dot11 one, avoid processing it
        if not all(packet.haslayer(layer) for layer in [Dot11, Dot11Beacon, Dot11Elt, RadioTap]):
            return

        # Get the Access Point's MAC address and SSID address
        mac: str = str(packet[Dot11].addr2)
        ssid: str = packet[Dot11Elt].info.decode("utf-8")

        # If the MAC address or the SSID is empty, avoid processing the packet
        if len(mac.replace(" ", "")) == 0 or len(ssid.replace(" ", "")) == 0:
            return

        # Get the Access Point's frequency in Mhz, convert it to Ghz
        # and erase the decimal part of the number after the first decimal digit
        frequency: float = packet[RadioTap].ChannelFrequency * 0.001
        frequency = math.floor(frequency * 10) / 10

        # Check if the packet has the channel information and, if it doesn't, avoid to process it.
        # This is done because the channel information is mandatory to perform the de-authentication attack
        network_stats: dict = packet[Dot11Beacon].network_stats()

        # Get the Access Point's channel
        channel: int = network_stats.get("channel", -1)
        if channel < 0:
            return

        # Get the Access Point's signal strength
        try:
            db_signal = packet.dBm_AntSignal
        except AttributeError:
            db_signal = "N/A"

        # Get the Access Point's encryption type
        encryption: list[str] = network_stats.get("crypto", [])
        if len(encryption) == 0:
            encryption = ["No Encryption"]

        # Add the Access Point's info to the set
        access_point = AccessPoint(mac=mac, ssid=ssid, frequency=f"{frequency} GHz",
                                   channel=channel, db_signal=db_signal, encryption=encryption)
        self._access_point_set.add(access_point)
