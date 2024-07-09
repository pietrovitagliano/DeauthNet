import json
import os
import subprocess

from Core.WiFiBandManager.wifi_band import WiFiBand
from utility import find_file, change_channel_from_shell


class WiFiBandManager:
    """
    The WiFiBandManager is a class that allows to manage several Wi-Fi bands and their channels.
    It allows to change the current channel to the next available one, circularly.
    """

    def __init__(self, wireless_adapter_key: str,
                 wifi_band_manager_settings_json_file: str = "wifi_band_manager_settings.json"):
        """
        Initializes the WiFiBandManager object to handle several Wi-Fi bands and their channels.
        :param wireless_adapter_key: The key of the wireless interface.
        :param wifi_band_manager_settings_json_file: The name of the JSON file that contains the Wi-Fi bands settings.
        :raises FileNotFoundError: If the settings file is not found.
        """

        # Get the absolute path of the settings file
        json_file_abs_path: str = find_file(wifi_band_manager_settings_json_file)

        if not os.path.exists(json_file_abs_path):
            raise FileNotFoundError(f"Settings file {wifi_band_manager_settings_json_file}\n"
                                    f"not found in the project directory")

        # Load the Wi-Fi bands settings from the JSON file
        with open(json_file_abs_path) as json_file:
            wifi_band_list: list = json.load(json_file)

        # Set the wireless adapter key
        self._wireless_adapter_key: str = wireless_adapter_key

        # Create the bands and order them in ascending order,
        # since they could be in any order
        self._wifi_band_list: list[WiFiBand] = [WiFiBand(band_name=band["name"],
                                                         min_channel=band["min_channel"],
                                                         max_channel=band["max_channel"],
                                                         channel_step=band["channel_step"]) for band in wifi_band_list]
        self._wifi_band_list.sort()

        # Set the current band to the first band
        self._current_band: WiFiBand = self._wifi_band_list[0]

        # Set the current channel to the minimum channel of the first band
        # and set the Wi-Fi interface to the current channel
        self.reset_state()

    def get_current_channel(self) -> int:
        """
        Get the current channel of the current band.
        :return: The current channel of the current band.
        """

        return self._current_band.current_channel

    def reset_state(self):
        """
        Reset all WiFiBand objects' current channels to None and set the current band and its current channel
        to the first band and its minimum channel. Once the restart is done,
        the Wi-Fi interface is set to the current one (the first channel of the first band).
        """

        for band in self._wifi_band_list:
            band.reset_current_channel()

        first_band: WiFiBand = self._wifi_band_list[0]
        self._change_channel(channel=first_band.min_channel, band=first_band)

    def go_to_next_channel(self):
        """
        Change the current channel to the next available one.
        After reaching the maximum channel of a band, switch to the next one (circular).
        """

        # If the current channel is the maximum one of the band, before changing band,
        # is necessary to reset the current channel to the minimum channel of the band.
        band: WiFiBand = self._current_band
        if band.current_channel == band.max_channel:
            band = self._get_next_band()

        next_channel: int = band.get_next_channel()
        self._change_channel(channel=next_channel, band=band)

    def _get_next_band(self) -> WiFiBand:
        """
        Returns the next band in the list, circularly.
        :return: The band which follows the current one, circularly.
        """

        # Compute the next band index (circular)
        current_band_index: int = self._wifi_band_list.index(self._current_band)
        next_band_index: int = (current_band_index + 1) % len(self._wifi_band_list)

        return self._wifi_band_list[next_band_index]

    def _change_channel(self, channel: int, band: WiFiBand):
        """
        Change the current channel to the specified one, if it is valid.
        Also, if the band is different from the current one, update the current band too.
        :param channel: The channel to change to.
        :param band: The band of the channel.
        """

        try:
            # Change the channel using the shell command
            change_channel_from_shell(wireless_interface_key=self._wireless_adapter_key, channel=channel)

            # If the command is successful, update the current band and channel
            if band != self._current_band:
                self._current_band = band

            self._current_band.current_channel = channel

        # Ignore the exception if the command fails.
        # This is done because, assuming the wireless_interface_key is correct,
        # the subprocess.call may fail only if the channel is not valid.
        except subprocess.CalledProcessError:
            pass
