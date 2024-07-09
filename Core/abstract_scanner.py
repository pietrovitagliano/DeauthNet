import time

from abc import ABC, abstractmethod
from typing import MutableSet

from scapy.config import conf
from scapy.packet import Packet
from scapy.sendrecv import AsyncSniffer

from GUI.gui_manager import GUIManager
from Core.WiFiBandManager.wifi_band_manager import WiFiBandManager
from Core.access_point import AccessPoint
from WiFiFunctions.wireless_utility import check_and_set_wifi_adapter_mode, WirelessAdapterModeEnum, get_known_ssids, \
    change_known_ssids_autoconnection_state, is_wireless_adapter_connected, disconnect_wireless_adapter


class AbstractScanner(ABC):
    """
    The AbstractScanner is an abstract class used to perform several
    types of scans on Wi-Fi networks.
    The scan type is defined by the implementation of the perform_scan
    and the _sniff_callback methods inside a child class.
    """

    def __init__(self, wireless_adapter_key: str, channel_change_delay: float,
                 access_point_set: MutableSet[AccessPoint]):
        """
        Initializes the AbstractScanner object.
        :param wireless_adapter_key: The key of the wireless interface (e.g. "wlan0")
        :param channel_change_delay: The delay in seconds to change the channel
        :param access_point_set: The set of access points to show the information about
        """

        self._wireless_adapter_key: str = wireless_adapter_key
        self._channel_change_delay: float = channel_change_delay
        self._access_point_set: MutableSet[AccessPoint] = access_point_set
        self._wifi_band_manager: WiFiBandManager = WiFiBandManager(self._wireless_adapter_key)

        # To perform the scan, conf.debug_dissector has to be equal to 2.
        conf.debug_dissector = 2

    @property
    def access_point_set(self) -> MutableSet[AccessPoint]:
        return self._access_point_set

    @abstractmethod
    def _update_gui(self):
        """
        Update the GUI, during the scan, with the information gathered.
        It is called inside the on_scan_update method and must be implemented in the child class.
        """
        raise NotImplementedError

    @abstractmethod
    def _sniff_callback(self, packet: Packet):
        """
        Callback function to handle the packet sniffed. It must be implemented in the child class.
        :param packet: The packet sniffed
        """
        raise NotImplementedError

    def start_scan(self):
        """
        Start sniffing the packets and handle them accordingly
        to the implementation of the _sniff_callback function.
        """

        # Get the set of the known SSIDs from the system
        known_ssid_set: set[str] = get_known_ssids()

        # Create an AsyncSniffer to scan for access points asynchronously
        async_sniffer = AsyncSniffer(iface=self._wireless_adapter_key, prn=self._sniff_callback)

        try:
            # If the Wi-Fi adapter is connected to any of the known access points, disconnect it.
            # This is done in order to not interfere with the scan.
            if len(known_ssid_set) > 0:
                # Disable the autoconnection for the SSIDs in the set
                change_known_ssids_autoconnection_state(known_ssid_set=known_ssid_set,
                                                        autoconnection_state=False)

                # Disconnect the Wi-Fi adapter if it is connected to one of the access points in the set
                if is_wireless_adapter_connected(self._wireless_adapter_key, known_ssid_set):
                    disconnect_wireless_adapter(wireless_adapter_key=self._wireless_adapter_key,
                                                verbose=True)

            # If the Wi-Fi adapter is not in monitor mode, put it in monitor mode
            check_and_set_wifi_adapter_mode(wireless_adapter_key=self._wireless_adapter_key,
                                            mode=WirelessAdapterModeEnum.MONITOR,
                                            verbose=True)

            # Update the GUI until the user presses CTRL+C to stop the scan
            while True:
                try:
                    # If the sniffer is not running, start it
                    if not async_sniffer.running:
                        async_sniffer.start()

                    # The scan is performed during this delay with the async sniffer running
                    time.sleep(self._channel_change_delay)

                    # Perform the operations that need to be executed after the scan
                    self._on_scan_update()

                # If OSError is raised, the network is down,
                # thus the Wi-Fi adapter needs to be put in monitor mode again
                except OSError:
                    if async_sniffer.running:
                        async_sniffer.stop(join=True)

                    check_and_set_wifi_adapter_mode(wireless_adapter_key=self._wireless_adapter_key,
                                                    mode=WirelessAdapterModeEnum.MONITOR,
                                                    verbose=True)

                # If the user presses CTRL+C, stop the scan
                except KeyboardInterrupt:
                    GUIManager().print("\nStopping scan...\n")
                    break

        except KeyboardInterrupt:
            pass

        finally:
            # Ensure the sniffer is always stopped
            if async_sniffer.running:
                async_sniffer.stop(join=True)

            # Perform the operations that need to be executed after the scan ends
            self._on_scan_end()

    def _on_scan_update(self):
        """
        Loop of the AbstractScanner object, performed inside the start_scan method.
        This method is called after the delay used to perform the scan.
        It updates the GUI and changes the channel.
        """

        # Update the GUI with the information gathered during the scan
        self._update_gui()

        # Go to the next channel
        self._wifi_band_manager.go_to_next_channel()

    def _on_scan_end(self):
        """
        Used to perform the operations that need to be executed after the scan ends.
        """

        # Reset the channel and the band before starting to scroll the channels
        self._wifi_band_manager.reset_state()

        # Before ending the functionality, put the wireless adapter in managed mode if it's not
        check_and_set_wifi_adapter_mode(wireless_adapter_key=self._wireless_adapter_key,
                                        mode=WirelessAdapterModeEnum.MANAGED,
                                        verbose=True)

        # Enable again the autoconnection for the known SSIDs in the set,
        # after the managed mode is turned on again
        known_ssid_set: set[str] = get_known_ssids()
        if len(known_ssid_set) > 0:
            change_known_ssids_autoconnection_state(known_ssid_set=known_ssid_set, autoconnection_state=True)



