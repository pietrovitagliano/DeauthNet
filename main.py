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

import argparse
import json
import os
import re
import subprocess
import sys
import time

from typing import MutableSet, Optional

from GUI.gui_manager import MenuOptionEnum, GUIManager
from WiFiFunctions.Detection.deauth_attack_scanner import DeauthAttackScanner
from WiFiFunctions.Deauthentication.wifi_deauthenticator import WiFiDeauthenticator

from Core.access_point import AccessPoint
from WiFiFunctions.NetworkScan.access_point_scanner import AccessPointScanner
from WiFiFunctions.Detection.deauth_guardian import DeauthGuardian

from WiFiFunctions.wireless_utility import (set_wireless_adapter_mode, WirelessAdapterModeEnum,
                                            BROADCAST_MAC, MAC_REGEX_PATTERN,
                                            WIFI_ADAPTER_ERROR_MESSAGE, check_and_set_wifi_adapter_mode)

from exceptions import (NoRootPrivilegesException,
                        RequirementInstallationFailedException,
                        WirelessAdapterNotFoundException)
from utility import find_file


def root_privileges_check():
    """
    Check if the user has root privileges. If not, raise an exception.
    """

    if os.geteuid() != 0:
        raise NoRootPrivilegesException(
            message=f"Root privileges are required to run this script.\n"
                    f"Please try again with root privileges.\n"
        )


def check_python_min_version(major: int, minor: int):
    """
    Check if the Python version is at least the specified one.
    :param major: The major version
    :param minor: The minor version
    :raises ValueError: If the Python version is lower than the specified one.
    """

    if sys.version_info < (major, minor):
        raise ValueError(f"This project requires Python {major}.{minor} or higher. Please upgrade Python.\n")


def check_and_install_tool(*tool_names: tuple[str, str]):
    """
    Check if the specified tool is installed and, if not, install the package that contains it.
    :param tool_names: The names of the tools. Each tuple must contain the tool and the package that contains it.
    :raises RequirementInstallationFailedException: If an error occurred during the installation of a tool.
    """

    for tool, package in tool_names:
        try:
            # Check if the tool is installed
            status_code: int = subprocess.call(f"which {tool}", stdout=subprocess.PIPE,
                                               stderr=subprocess.PIPE, shell=True)

            # If the tool is not installed, execute the command to install it
            if status_code != 0:
                GUIManager().print(f"{package} is not installed. Installing...")
                for command in ["sudo apt-get update", f"sudo apt-get install -y {package}"]:
                    subprocess.call(command, stderr=subprocess.PIPE, shell=True)

        except subprocess.CalledProcessError as e:
            raise RequirementInstallationFailedException(
                message=f"An error occurred during the installation of {package}: {e}\n"
            )


def wireless_adapter_presence_check(wireless_adapter_key: str, check_attempts: int = 3):
    """
    Check if the given wireless adapter is present and raise an exception if it is not.
    :param wireless_adapter_key: The key of the wireless adapter, i.e. wlan0, wlan1, etc.
    :param check_attempts: The number of attempts to check if the wireless adapter is present.
    """

    # If NetworkManager is not active, activate it
    subprocess.call(f"sudo systemctl start NetworkManager", stdout=subprocess.PIPE, shell=True)

    # Check if at least one wireless adapter is present, otherwise exit
    GUIManager().print(f"Looking for the wireless adapter \"{wireless_adapter_key}\"...")

    is_present: bool = False
    for _ in range(check_attempts):
        # Wait for a few seconds. This is needed because sometimes the wireless adapter could be not ready yet
        time.sleep(2)

        # Get information about the wireless adapter with the iwconfig command
        try:
            iwconfig_info: str = subprocess.check_output(f"iwconfig {wireless_adapter_key}",
                                                         stderr=subprocess.PIPE,
                                                         shell=True).decode("utf-8")
        except subprocess.CalledProcessError:
            # The execution of the command will raise a CalledProcessError,
            # only if a wireless adapter with the specified wireless_adapter_key is not present.
            # Thus, set iwconfig_info to an empty string.
            iwconfig_info = ""

        is_present = not (iwconfig_info == "" or "no such device" in iwconfig_info.lower())
        if is_present:
            break

    if not is_present:
        raise WirelessAdapterNotFoundException(
            message=f"Wireless adapter {wireless_adapter_key} not found.\n"
                    f"Please check if the wireless adapter is connected and try again.\n"
        )


def get_user_choice(message: str = "Enter your choice: ") -> str:
    """
    Get the user's input.
    :param message: The message to show to the user
    :return: The input of the user
    """

    return input(message)


def initialize_wireless_adapter(wireless_adapter_key: str):
    """
    Initialize the Wi-Fi adapter by putting it in monitor mode and checking if it is associated.
    :param wireless_adapter_key: The key of the wireless adapter (e.g. "wlan0")
    """

    # Get information about the Wi-Fi adapter with the iwconfig command
    iwconfig_output = str(subprocess.check_output(f"iwconfig {wireless_adapter_key}", shell=True))

    while "unassociated" in iwconfig_output.lower():
        GUIManager().print(f"The Wi-Fi adapter is unassociated.\n"
                           "Trying to fix putting it in monitor mode.\n")

        if "monitor" in iwconfig_output.lower():
            set_wireless_adapter_mode(wireless_adapter_key, mode=WirelessAdapterModeEnum.MANAGED)
            time.sleep(0.5)

        set_wireless_adapter_mode(wireless_adapter_key, mode=WirelessAdapterModeEnum.MONITOR)


def get_info_for_deauth_attack(access_point_set: MutableSet[AccessPoint]) -> Optional[tuple[set[str], set[str]]]:
    """
    Extract the information needed to perform a de-authentication attack.
    This information is composed by the SSID and the MAC address of the device to attack.
    :param access_point_set: The set of access points to show the information about
    :return: A tuple containing the SSID and the MAC address of the device to attack or None if the user aborts.
    """

    # Define the row number set and a list to store the user's input
    row_number_set: set[int] = set()
    input_list: list[str] = list()
    try:
        while len(row_number_set) == 0:
            GUIManager().clear_screen()

            # Print access points information
            table = GUIManager().access_point_info_to_table(access_point_set=access_point_set)
            GUIManager().print(table if table else "",
                               "\n" if table else "")

            if len(input_list) > 0:
                GUIManager().print("Invalid option. Try again.\n")

            # Ask the user which access point he wants to attack
            GUIManager().print(f"Syntax: index1 index2... mac1 mac2...\n"
                               f"\n"
                               f"If no MACs are specified, the attack will be of broadcast type.\n"
                               f"(CTRL+C to abort)\n")

            # Get the user's input and split it into two parts: the index for the access point and
            # the mac address of the device to attack (optional)
            user_input: str = get_user_choice()
            input_list = user_input.split(" ")

            # Store row numbers and MAC addresses in two different lists
            row_number_set = {int(string) for string in input_list
                              if string.isdigit() and 1 <= int(string) <= len(access_point_set)}

    except KeyboardInterrupt:
        GUIManager().clear_screen()
        GUIManager().print("\nDeauth Attack aborted.\n")
        return None

    # Remove all the numbers from the input list to get the MAC addresses, converted to uppercase
    input_list = [string.upper() for string in input_list if not string.isdigit()]

    # If the user has inserted valid MAC addresses, use them,
    # otherwise use the broadcast address (default)
    victim_mac_set: set[str] = set()
    if len(input_list) == 0:
        victim_mac_set.add(BROADCAST_MAC)
    else:
        for string in input_list:
            if bool(re.match(MAC_REGEX_PATTERN, string)):
                victim_mac_set.add(string)
            else:
                GUIManager().print(f"Ignoring {string} because not valid.\n")

        if len(victim_mac_set) == 0:
            GUIManager().print("All the MAC addresses are not valid.\n"
                               "\n"
                               "Deauth Attack aborted.\n")
            return None

    # Collect all the selected access point SSIDs
    access_point_list: list[AccessPoint] = list(access_point_set)
    target_ssid_set: set[str] = {access_point_list[row_number - 1].ssid for row_number in row_number_set}

    return target_ssid_set, victim_mac_set


def initialize_essential_objects(wireless_adapter_key: str, scan_settings_json_file: str = "scan_settings.json") -> (
        tuple[AccessPointScanner, DeauthAttackScanner, DeauthGuardian, WiFiDeauthenticator]):
    """
    Initialize and return the essential objects to perform the software's functionalities.
    In order these are: AccessPointScanner, DeauthAttackScanner, DeauthGuardian and WiFiDeauthenticator.
    :param wireless_adapter_key: The key of the wireless adapter to use, i.e. wlan0, wlan1, etc.
    :param scan_settings_json_file: The name of the JSON file that contains the scan settings
    :return: A tuple containing AccessPointScanner, DeauthAttackScanner, DeauthGuardian and WiFiDeauthenticator objects.
    :raises FileNotFoundError: If the scan settings file is not found.
    """

    scan_settings_abs_file_path: str = find_file(file_name=scan_settings_json_file)
    if not os.path.exists(scan_settings_abs_file_path):
        raise FileNotFoundError(f"Settings file {scan_settings_json_file}\n"
                                f"not found in the project directory")

    with open(scan_settings_abs_file_path) as json_file:
        scan_settings_dict: dict = json.load(json_file)

    access_point_channel_change_delay: float = scan_settings_dict["access_point_channel_change_delay"]
    deauth_attack_channel_change_delay: float = scan_settings_dict["deauth_attack_channel_change_delay"]
    deauth_frames_per_second_threshold: float = scan_settings_dict["deauth_frames_per_second_threshold"]

    # Create the AccessPointScanner, DeauthAttackScanner, WiFiSentinel and WiFiDeauthenticator objects
    # to perform the software's functionalities
    access_point_scanner = AccessPointScanner(wireless_adapter_key=wireless_adapter_key,
                                              channel_change_delay=access_point_channel_change_delay)

    deauth_attack_scanner = DeauthAttackScanner(wireless_adapter_key=wireless_adapter_key,
                                                channel_change_delay=deauth_attack_channel_change_delay,
                                                deauth_frames_per_second_threshold=deauth_frames_per_second_threshold,
                                                access_point_set=access_point_scanner.access_point_set)

    deauth_guardian = DeauthGuardian(wireless_adapter_key=wireless_adapter_key,
                                     channel_change_delay=deauth_attack_channel_change_delay,
                                     deauth_frames_per_second_threshold=deauth_frames_per_second_threshold,
                                     access_point_set=access_point_scanner.access_point_set)

    wifi_deauth = WiFiDeauthenticator(wireless_adapter_key=wireless_adapter_key,
                                      access_point_set=access_point_scanner.access_point_set)

    return access_point_scanner, deauth_attack_scanner, deauth_guardian, wifi_deauth


def perform_deauth_net_function(option: MenuOptionEnum,
                                access_point_scanner: AccessPointScanner,
                                deauth_attack_scanner: DeauthAttackScanner,
                                deauth_guardian: DeauthGuardian,
                                wifi_deauthenticator: WiFiDeauthenticator):
    """
    Choose the function to perform, based on the user's input.
    :param option: The user's input converted to a MenuOptionEnum object
    :param access_point_scanner: The AccessPointScanner object to scan for access points
    :param deauth_attack_scanner: The DeauthAttackScanner object to intercept de-authentication attacks
    :param deauth_guardian: The DeauthGuardian object to intercept and block de-authentication attacks
    :param wifi_deauthenticator: The WiFiDeauthenticator object to perform de-authentication attacks
    """

    # Choose the function to perform, based on the user's input
    match option:
        # Scan for access points
        case MenuOptionEnum.WI_FI_SCAN:
            try:
                access_point_scanner.start_scan()
            except OSError:
                GUIManager().clear_screen()
                GUIManager().print(WIFI_ADAPTER_ERROR_MESSAGE)

        # Perform a de-authentication DOS attack towards an access point
        case MenuOptionEnum.DEAUTH_DOS_WIFI:
            dos_attack_info: tuple[set[str], set[str]] = get_info_for_deauth_attack(
                access_point_set=access_point_scanner.access_point_set
            )

            if dos_attack_info is not None:
                target_ssid_set, victim_mac_set = dos_attack_info

                # Create the information about the attack, for verbose purposes
                is_broadcast_attack: bool = next(iter(victim_mac_set)) == BROADCAST_MAC
                target_SSIDs: str = ", ".join(target_ssid_set)
                target_MACs: str = ", ".join(victim_mac_set)
                attack_mode: str = "Broadcast" if is_broadcast_attack else "Single Device"

                attack_info = (f"Attack Mode: {attack_mode}\n"
                               f"Target SSID/s: {target_SSIDs}\n"
                               f"Victim MAC/s: {target_MACs}\n")

                # Start the deauth attack against all the access points that belong to the same SSID,
                # in order to target all the MACs
                wifi_deauthenticator.start_dos_attack(ap_ssid_target_set=target_ssid_set,
                                                      victim_mac_set=victim_mac_set,
                                                      attack_log_info=attack_info)

        # Intercept de-authentication attacks
        case MenuOptionEnum.DETECT_DEAUTH_ATTACKS:
            try:
                deauth_attack_scanner.start_scan()
            except OSError:
                GUIManager().clear_screen()
                GUIManager().print(WIFI_ADAPTER_ERROR_MESSAGE)

        # Intercept and block de-authentication attacks
        case MenuOptionEnum.DETECT_AND_BLOCK_DEAUTH_ATTACKS:
            try:
                deauth_guardian.start_scan()
            except OSError:
                GUIManager().clear_screen()
                GUIManager().print(WIFI_ADAPTER_ERROR_MESSAGE)

        # Clear the blacklist
        case MenuOptionEnum.CLEAR_BLACK_LIST:
            if len(deauth_guardian.get_black_listed_ap_mac_set()) == 0:
                GUIManager().print("Black list already empty.\n")
            else:
                deauth_guardian.clear_blacklist()
                GUIManager().print("Black list cleared.\n")

        # Avoid the execution of other cases
        case _:
            pass


def main(wireless_adapter_key: str):
    """
    Main function.
    :param wireless_adapter_key: The key of the wireless adapter to use, i.e. wlan0, wlan1, etc.
    :raises FileNotFoundError: If the json file needed by the initialize_essential_objects function cannot be found.
    """

    try:
        initialize_wireless_adapter(wireless_adapter_key=wireless_adapter_key)

        (access_point_scanner,
         deauth_attack_scanner,
         deauth_guardian,
         wifi_deauthenticator) = initialize_essential_objects(wireless_adapter_key=wireless_adapter_key)

        # Get the minimum and maximum value of the menu options
        option_min_value: int = MenuOptionEnum.get_min_option_value()
        option_max_value: int = MenuOptionEnum.get_max_option_value()

        # Main loop until the user wants to exit
        while True:
            try:
                # Show the menu
                GUIManager().print()
                GUIManager().show_menu(title="Deauth Net Menu",
                                       wireless_adapter_key=wireless_adapter_key,
                                       access_points_set=access_point_scanner.access_point_set)

                # Get user's input
                user_option: str = get_user_choice()

                # Check if user's input is a number between the minimum and
                # the maximum value of the menu options.
                # If not, print an error message and restart the loop
                if not (user_option.isdigit() and option_min_value <= int(user_option) <= option_max_value):
                    GUIManager().clear_screen()
                    GUIManager().print("Invalid option, please try again.\n")
                    continue

                # Get the MenuOptionEnum object from the user's input
                choosen_option: MenuOptionEnum = MenuOptionEnum.get_option_from_value(value=int(user_option))

                # If there are no access points and the user's input is different from the scan option,
                # print an error message and restart the loop
                if len(access_point_scanner.access_point_set) == 0 and choosen_option != MenuOptionEnum.WI_FI_SCAN:
                    GUIManager().clear_screen()
                    GUIManager().print("No access points has been found yet. Do a scan first and try again.\n")
                    continue

                # Perform the function chosen by the user
                GUIManager().clear_screen()
                perform_deauth_net_function(option=choosen_option,
                                            access_point_scanner=access_point_scanner,
                                            deauth_attack_scanner=deauth_attack_scanner,
                                            deauth_guardian=deauth_guardian,
                                            wifi_deauthenticator=wifi_deauthenticator)

                GUIManager().clear_screen()

            # Used to catch when the user presses CTRL+C,
            # in order to exit the program.
            except KeyboardInterrupt:
                # Exit the while loop
                break

    # Used to exit the program pressing CTRL+C
    except KeyboardInterrupt:
        pass

    finally:
        # Before exiting, put the wireless adapter in managed mode if it's not
        check_and_set_wifi_adapter_mode(wireless_adapter_key=wireless_adapter_key,
                                        mode=WirelessAdapterModeEnum.MANAGED,
                                        verbose=True)


# MAIN
if __name__ == "__main__":
    # Create the argument parser to select the wireless adapter from the command line
    arg_parser = argparse.ArgumentParser()

    # Add an argument to identify the wireless adapter
    arg_parser.add_argument("-i", "--wireless_interface",
                            dest="wireless_interface",
                            default="wlan0",
                            type=str,
                            help="Wireless interface (wlan0, wlan1...). Default is wlan0.")

    # Parse the arguments
    args = arg_parser.parse_args()

    # Check if the software requirements are satisfied and at least one wireless adapter is present
    try:
        # Software requirements check
        root_privileges_check()
        check_python_min_version(major=3, minor=10)
        check_and_install_tool(("ifconfig", "net-tools"), ("iwconfig", "wireless-tools"),
                               ("ebtables", "ebtables"))

        # Clear the screen
        GUIManager().clear_screen()

        # Wireless adapter check
        wireless_adapter_presence_check(wireless_adapter_key=args.wireless_interface)

    except (NoRootPrivilegesException, ValueError,
            RequirementInstallationFailedException, WirelessAdapterNotFoundException) as e:
        GUIManager().print(f"{e}")
        exit(-1)

    # Main function
    try:
        # Start the main function
        GUIManager().print(f"Wireless adapter {args.wireless_interface} found.")
        main(wireless_adapter_key=args.wireless_interface)

        # Exit the program
        GUIManager().print("\nExiting...\n")
        exit(0)

    except SystemExit as e:
        # If the exit code is 0, exit the program successfully,
        # otherwise print the error message and exit with the specified code
        if e.code != 0:
            GUIManager().print(f"Error with code {e.code} occurred.")
            exit(e.code)

    except FileNotFoundError as e:
        GUIManager().print(f"{e}")
        exit(-1)

    except BaseException as e:
        GUIManager().print(f"Not handled error occurred: {e}")
        exit(-1)
