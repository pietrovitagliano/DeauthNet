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


import os
import subprocess

from typing import Optional

# This script must be in the project root directory
PROJECT_ROOT_DIRECTORY: str = os.path.abspath(os.path.dirname(__file__))


def find_file(file_name: str, root_directory: str = PROJECT_ROOT_DIRECTORY) -> Optional[str]:
    """
    Find a file by its name in the given directory and all its subdirectories.
    :param file_name: The name of the file to find.
    :param root_directory: The directory to start the search from.
    If not specified, the project root directory will be used.
    :return: The absolute path of the file if it was found, otherwise None.
    """

    for directory, _, files in os.walk(root_directory):
        if file_name in files:
            return os.path.join(directory, file_name)

    return None


def change_channel_from_shell(wireless_interface_key: str, channel: int):
    """
    Change the current channel of the wireless interface to the specified one.
    :param wireless_interface_key: The key of the wireless interface.
    :param channel: The channel to change to.
    """

    subprocess.call(f"sudo iwconfig {wireless_interface_key} channel {channel}",
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=True)
