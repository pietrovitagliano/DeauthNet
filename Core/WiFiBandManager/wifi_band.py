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


class WiFiBand:
    """
    The WiFiBand class represents a Wi-Fi band.
    """

    def __init__(self, band_name: str, min_channel: int, max_channel: int, channel_step: int = 1):
        """
        Initializes the WiFiChannel object.

        :param band_name: The name of the band.
        :param min_channel: The minimum channel in the band.
        :param max_channel: The maximum channel in the band.
        :param channel_step: The channel step (range between channels).
        """

        if min_channel < 1 or max_channel < 1:
            raise ValueError("The minimum and maximum channels must be greater than 0.")

        if min_channel >= max_channel:
            raise ValueError("The minimum channel must be lower than the maximum channel.")

        self._band_name: str = band_name
        self._min_channel: int = min_channel
        self._max_channel: int = max_channel
        self._channel_step: int = channel_step

        # The current channel is negative by default.
        # It means that it is not set, since the channels are positive integers
        self._current_channel: int = -1

    @property
    def band_name(self) -> str:
        return self._band_name

    @property
    def min_channel(self) -> int:
        return self._min_channel

    @property
    def max_channel(self) -> int:
        return self._max_channel

    @property
    def current_channel(self) -> int:
        return self._current_channel

    @current_channel.setter
    def current_channel(self, channel: int):
        """
        Set the current channel to the specified one, if it is valid.
        Otherwise, raise a ValueError.
        """

        if self._min_channel <= channel <= self._max_channel:
            self._current_channel = channel
        else:
            raise ValueError(f"Channel {channel} is not in the band {self._band_name} range.")

    def reset_current_channel(self) -> None:
        """
        Reset the current channel to None.
        """

        self._current_channel = -1

    def get_next_channel(self) -> int:
        """
        Returns the next available channel in the band, starting from the current one.
        :return: The next available channel in the band (circularly).
        """

        # If the current channel is negative, return the minimum channel
        if self._current_channel < 0:
            return self._min_channel

        # Calculate the next channel.
        # If the next channel is greater than the maximum channel,
        # set it back to the minimum channel
        next_channel: int = self._current_channel + self._channel_step
        if next_channel > self._max_channel:
            next_channel = self._min_channel

        return next_channel

    def __eq__(self, other: 'WiFiBand') -> bool:
        return (self._band_name == other._band_name and
                self._min_channel == other._min_channel and
                self._max_channel == other._max_channel)

    def __lt__(self, other: 'WiFiBand') -> bool:
        return self._min_channel < other._min_channel and self._max_channel < other._max_channel

    def __gt__(self, other: 'WiFiBand') -> bool:
        return self._min_channel > other._min_channel and self._max_channel > other._max_channel
