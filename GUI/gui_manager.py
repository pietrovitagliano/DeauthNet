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


import json
import os
from enum import Enum

from typing import MutableSet, Any, Optional

from rich.box import ROUNDED
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from Core.access_point import AccessPoint
from utility import find_file


class MenuOptionEnum(Enum):
    """
    The MenuOptionEnum is an enumeration class that contains the menu options,
    which are the actions the user can perform.
    """

    WI_FI_SCAN = 1
    DEAUTH_DOS_WIFI = 2
    DETECT_DEAUTH_ATTACKS = 3
    DETECT_AND_BLOCK_DEAUTH_ATTACKS = 4

    @classmethod
    def get_option_from_value(cls, value: int) -> Optional["MenuOptionEnum"]:
        """
        Get the MenuOptionEnum object from the value.
        :param value: The value of the MenuOptionEnum object
        :return: The MenuOptionEnum object
        """

        return next((option for option in MenuOptionEnum if option.value == value), None)

    @classmethod
    def get_min_option_value(cls) -> int:
        """
        Get the minimum value of the MenuOptionEnum objects.
        :return: The minimum value of the MenuOptionEnum objects
        """

        return min(option.value for option in MenuOptionEnum)

    @classmethod
    def get_max_option_value(cls) -> int:
        """
        Get the maximum value of the MenuOptionEnum objects.
        :return: The maximum value of the MenuOptionEnum objects
        """

        return max(option.value for option in MenuOptionEnum)


class GUIManager:
    """
    The GUIManager is a class that handles the GUI of the program.
    It allows to print messages and show the main menu, clear the screen, etc.
    """

    # Pattern Singleton Implementation
    _instance = None

    def __new__(cls):
        """
        Create a new instance of the GUIManager object, if it doesn't exist yet.
        """

        if cls._instance is None:
            cls._instance = super(GUIManager, cls).__new__(cls)

        return cls._instance

    def __init__(self):
        """
        Initialize the GUIManager object.
        :raises FileNotFoundError: If the gui_styles.json file is not found
        """

        # Get the abs path of the gui's style file and load the gui's style from it
        gui_settings_abs_file_path: str = find_file(file_name="gui_styles.json")
        with open(gui_settings_abs_file_path) as json_file:
            self._gui_settings_dict: dict = json.load(json_file)

        # Get the console's style from the gui's style
        console_dict: dict = self._gui_settings_dict.get("console", {})

        # Create the Console object with the console_dict
        self._console = Console(**console_dict)

    def print(self, *objects: Any, sep: str = " ", end: str = "\n", **kwargs):
        """
        Print the objects passed as parameters using the _console attribute.
        :param objects: The objects to print
        :param sep: The separator between the objects
        :param end: The end character
        :param kwargs: The other keyword arguments
        """

        self._console.print(*objects, sep=sep, end=end, **kwargs)

    def clear_screen(self):
        """
        Clear the console screen.
        """

        self._console.clear()
        os.system("clear")

    def show_menu(self, title: str, wireless_adapter_key: str, access_points_set: MutableSet[AccessPoint]):
        """
        Show the main menu with information about the wireless interface in use and the options available.
        :param title: The title of the menu
        :param wireless_adapter_key: The wireless interface key
        :param access_points_set: The set of access points
        """

        # Get the main menu's style from the gui's style
        main_menu_style_dict: dict = self._gui_settings_dict.get("main_menu", {})

        # Get the panel's from the main menu's style and set the title
        panel_style_dict: dict = main_menu_style_dict.get("panel", {})
        panel_style_dict["title"] = title

        # Get the text's style from the main menu's style
        text_style_dict: dict = main_menu_style_dict.get("text", {})

        # Text with the information about the wireless interface in use and the options available
        text = Text(
            f"Wireless Interface in Use: {wireless_adapter_key}\n\n"
            f"{MenuOptionEnum.WI_FI_SCAN.value} - Scan for Wi-Fi Networks\n"
            f"{MenuOptionEnum.DEAUTH_DOS_WIFI.value} - De-authenticate Wi-Fi Networks\n"
            f"{MenuOptionEnum.DETECT_DEAUTH_ATTACKS.value} - Detect De-authentication Attacks\n"
            f"{MenuOptionEnum.DETECT_AND_BLOCK_DEAUTH_ATTACKS.value} - Detect and Block De-authentication Attacks\n"
            f"\n"
            f"CTRL + C - Exit",
            **text_style_dict
        )

        # Use of Panel to create a colored box around the menu
        panel = Panel(text, padding=(1, 2), **panel_style_dict)

        # Get the access points table
        access_point_table = self.access_point_info_to_table(access_points_set)

        # Print the menu
        self.print(access_point_table if access_point_table else "",
                   "\n" if access_point_table else "",
                   panel,
                   "\n")

    def access_point_info_to_table(self, access_point_set: MutableSet[AccessPoint]) -> Optional[Table]:
        """
        Convert the set of access points into a table.
        :param access_point_set: The set of access points
        """

        access_points_set_number: int = len(access_point_set)
        if access_points_set_number == 0:
            return None

        # Convert the access points to a list of dictionaries
        access_point_dict_list: list[dict[str, object]] = [{k: v for k, v in access_point.to_dict().items()}
                                                           for access_point in access_point_set]

        return self._list_of_dict_to_table(table_title=f"Access Points Found: {access_points_set_number}",
                                           list_to_convert=access_point_dict_list)

    def deauth_attack_info_to_table(self, access_point_set: MutableSet[AccessPoint],
                                    victim_macs_dict: dict[str, set[str]],
                                    black_listed_ap_mac_set: Optional[set[str]] = None,
                                    table_title: str = "",
                                    useful_headers: tuple[str, ...] = ("mac", "ssid", "frequency"),
                                    victims_header="Detected Victims",
                                    blacklist_header="In Black List") -> Optional[Table]:
        """
        Convert the information about the de-authentication attacks into a table.
        :param access_point_set: The set of access points to show the information about
        :param victim_macs_dict: The dictionary with the victims' MAC addresses under attack for each access point
        :param black_listed_ap_mac_set: The set of MAC addresses of the access points in the black list
        :param table_title: The title of the table
        :param useful_headers: The headers to show in the table
        :param victims_header: The header of the column with the victims' MAC addresses
        :param blacklist_header: The header of the column with the information about the black list
        :return: The table with the information about the de-authentication attacks
        """

        if len(access_point_set) == 0:
            return None

        # Convert the access points to a list of dictionaries and add the additional information to each dictionary
        access_point_dict_list: list[dict[str, object]] = []
        for access_point in access_point_set:
            # Remove the attributes that are not useful to show information about the ongoing attacks.
            # If useful_headers is empty, show all the attributes
            access_point_as_dict: dict[str, object] = {k: v for k, v in access_point.to_dict().items()
                                                       if len(useful_headers) == 0 or k.lower() in useful_headers}

            # Add the text to show in the table for the victims to the access point dictionary
            victim_mac_set = victim_macs_dict.get(access_point.mac, None)
            victims_text: str = "\n".join(victim_mac_set) if victim_mac_set else "none"
            access_point_as_dict[victims_header] = victims_text.upper()

            # Add the text to show in the table for the black list to the access point dictionary
            if black_listed_ap_mac_set is not None:
                in_black_list_text: str = "yes" if access_point.mac in black_listed_ap_mac_set else "no"
                access_point_as_dict[blacklist_header] = in_black_list_text.upper()

            # Add the access point dictionary to the list
            access_point_dict_list.append(access_point_as_dict)

        return self._list_of_dict_to_table(table_title=table_title.title(),
                                           list_to_convert=access_point_dict_list,
                                           draw_row_edges=True)

    def _list_of_dict_to_table(self, table_title: str,
                               list_to_convert: list[dict[str, object]],
                               draw_row_edges: bool = False) -> Table:
        """
        Convert a list of dictionary into a table.
        The dictionary represents an object and the keys are the columns' headers.
        :param table_title: The title of the table
        :param list_to_convert: The list of dictionary to convert.
        :param draw_row_edges: Whether to draw the edges of the table's rows.
        :return: The table containing the objects.
        """

        # Get the table style from the gui's style
        table_style_dict: dict = self._gui_settings_dict.get("table_style", {})

        table: Optional[Table] = None
        for index, obj_as_dict in enumerate(list_to_convert, start=1):
            # Create a table with capitalized field names as the columns
            if table is None:
                # Get the attribute names of the object as a list
                obj_key_list = list(obj_as_dict.keys())

                # Set the index column and the object's attributes as the table's columns
                # Index is the first column and the headers are capitalized
                table = Table(title=f" {table_title}",
                              box=ROUNDED,
                              **table_style_dict.get("table", {}) if table_style_dict else {})

                for key in ["index"] + obj_key_list:
                    table.add_column(key.upper(), **table_style_dict.get("column", {}) if table_style_dict else {})

            # Get the values of the object as a list
            obj_value_list: list = list(obj_as_dict.values())

            # For a better representation:
            # if an attribute is a list, join its elements into a single string
            # else convert the attribute into a string (rich library requires strings to add rows to the table)
            obj_value_list = [", ".join(elem) if isinstance(elem, list) else str(elem) for elem in obj_value_list]

            # Add a row to the table with the index and the object's values
            table.add_row(str(index), *obj_value_list, end_section=draw_row_edges)

        return table
