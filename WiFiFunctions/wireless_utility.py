import subprocess
from enum import Enum

from GUI.gui_manager import GUIManager

BROADCAST_MAC: str = "FF:FF:FF:FF:FF:FF"
MAC_REGEX_PATTERN: str = r"([0-9A-Fa-f]{2}[:]){5}([0-9A-Fa-f]{2})"
WIFI_ADAPTER_ERROR_MESSAGE: str = ("An error occurred to the wireless adapter while scanning for access points.\n"
                                   "Try to disconnect and reconnect the wireless adapter.\n")


class WirelessAdapterModeEnum(Enum):
    MONITOR = "monitor"
    MANAGED = "managed"

    def __str__(self):
        return self.value

    def __repr__(self):
        return self.value


def set_wireless_adapter_mode(wireless_adapter_key: str, mode: WirelessAdapterModeEnum):
    """
    Set the wireless adapter in one of the WiFiAdapterModeEnum's modes.
    :param wireless_adapter_key: The key of the wireless interface (e.g. "wlan0")
    :param mode: The mode to set the Wi-Fi adapter to
    """

    commands = [
        f"sudo ifconfig {wireless_adapter_key} down",
        f"sudo iwconfig {wireless_adapter_key} mode {mode}",
        f"sudo ifconfig {wireless_adapter_key} up"
    ]

    for command in commands:
        subprocess.call(command, stdout=subprocess.PIPE, shell=True)


def wireless_adapter_mode_check(wireless_adapter_key: str, mode: WirelessAdapterModeEnum) -> bool:
    """
    Check if the wireless adapter is in monitor mode.
    :param wireless_adapter_key: The key of the wireless adapter (e.g. "wlan0")
    :param mode: The mode to check if the Wi-Fi adapter is in
    :return: True if the Wi-Fi adapter is in the same mode as the one passed as argument, False otherwise
    """

    # Get information about the Wi-Fi adapter with the iwconfig command
    iwconfig_info: str = subprocess.check_output(f"sudo iwconfig {wireless_adapter_key}",
                                                 stderr=subprocess.PIPE,
                                                 shell=True).decode("utf-8")

    # Check if the mode is in use
    is_mode_in_use = str(mode).lower() in iwconfig_info.lower()

    return is_mode_in_use


def get_known_ssids() -> set[str]:
    """
    Get the set of the known SSIDs from the system.
    :return: The set of known SSIDs
    """

    output: str = subprocess.check_output(f"nmcli -t -f NAME connection show",
                                          stderr=subprocess.PIPE,
                                          shell=True).decode("utf-8")

    return {ssid for ssid in output.split('\n') if ssid != ""}


def change_known_ssids_autoconnection_state(known_ssid_set: set[str], autoconnection_state: bool):
    """
    Change the state of the autoconnection for the SSIDs in the set.
    Note: The SSIDs in the set must be known by the system.
    :param known_ssid_set: The set of SSIDs to change the autoconnection state
    :param autoconnection_state: True to enable the autoconnection, False to disable it
    """

    enabling_disabling: str = "Enabling" if autoconnection_state else "Disabling"
    ssids_as_string: str = "\n".join(known_ssid_set)
    GUIManager().print(f"{enabling_disabling} autoconnection for:\n"
                       f"{ssids_as_string}\n")

    yes_no_autoconnection: str = "yes" if autoconnection_state else "no"
    for ssid in known_ssid_set:
        subprocess.call(f"nmcli connection modify \"{ssid}\" connection.autoconnect {yes_no_autoconnection}",
                        stderr=subprocess.PIPE,
                        shell=True)


def check_and_set_wifi_adapter_mode(wireless_adapter_key: str, mode: WirelessAdapterModeEnum, verbose: bool = False):
    """
    Check if the wireless adapter is in monitor mode and, if not, put it in monitor mode.
    :param wireless_adapter_key: The key of the wireless interface (e.g. "wlan0")
    :param mode: The mode to check if the Wi-Fi adapter is in
    :param verbose: If True, print the information about the monitor mode
    """

    if not wireless_adapter_mode_check(wireless_adapter_key=wireless_adapter_key, mode=mode):
        if verbose:
            GUIManager().print(f"Putting {wireless_adapter_key} in {mode.value.upper()} mode...")

        set_wireless_adapter_mode(wireless_adapter_key=wireless_adapter_key, mode=mode)


def is_wireless_adapter_connected(wireless_adapter_key: str, ssid_set: set[str]) -> bool:
    """
    Check if the wireless adapter is connected to one of the access points in the given set.
    :param wireless_adapter_key: The key of the Wi-Fi adapter
    :param ssid_set: The set of SSIDs to check if the Wi-Fi adapter is connected to
    :return: True if the Wi-Fi adapter is connected to one of the access points in the set, False otherwise
    """

    # If the Wi-Fi adapter is not connected, return False
    command: str = f"nmcli device show {wireless_adapter_key} | grep GENERAL.STATE"
    output: str = subprocess.check_output(command, shell=True).decode("utf-8")

    if "connected" not in output.lower():
        return False

    # Check if the SSID to which the Wi-Fi adapter is connected is in the set
    command = f"nmcli device show {wireless_adapter_key} | grep GENERAL.CONNECTION"
    output = subprocess.check_output(command, shell=True).decode("utf-8")

    return any(ssid.lower() in output.lower() for ssid in ssid_set)


def disconnect_wireless_adapter(wireless_adapter_key: str, verbose: bool = False):
    """
    Disconnect the wireless adapter from the network.
    :param wireless_adapter_key: The key of the wireless adapter to disconnect
    """

    if verbose:
        GUIManager().print(f"Disconnecting {wireless_adapter_key}...")

    subprocess.call(f"nmcli device disconnect {wireless_adapter_key}",
                    stdout=subprocess.PIPE,
                    shell=True)
