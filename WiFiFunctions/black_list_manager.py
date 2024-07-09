import subprocess


class BlackListManager:
    """
    Class to manage a blacklist of access points.
    """

    def __init__(self):
        """
        Initializes the BlackListManager object.
        """

        # Set to store the MAC addresses of the access points in the blacklist
        self._black_listed_ap_mac_set: set[str] = set()

    @property
    def black_listed_ap_mac_set(self) -> set[str]:
        return self._black_listed_ap_mac_set

    def add_to_blacklist(self, *access_point_macs: str):
        """
        Add the given access point MAC addresses to the blacklist, if they are not already there.
        :param access_point_macs: The MAC addresses of the access points to put in the blacklist
        """

        for mac in access_point_macs:
            # If the access point is already in the blacklist, avoid adding it again
            if mac in self._black_listed_ap_mac_set:
                continue

            command: str = self._get_command_to_set_blacklist_rule(mac, put_in_blacklist=True)
            subprocess.call(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

            self._black_listed_ap_mac_set.add(mac)

    def clear_blacklist(self):
        """
        Clear the blacklist of access points.
        """

        for access_point_mac in self._black_listed_ap_mac_set:
            command: str = self._get_command_to_set_blacklist_rule(access_point_mac, put_in_blacklist=False)
            subprocess.call(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

        self._black_listed_ap_mac_set.clear()

    @classmethod
    def _get_command_to_set_blacklist_rule(cls, access_point_mac: str, put_in_blacklist: bool) -> str:
        """
        Get the command to put the access point with the given MAC address in the blacklist or remove it.
        :param access_point_mac: The MAC address of the access point to put in the blacklist
        :param put_in_blacklist: True to put the access point in the blacklist, False to remove it
        :return: The command to put the access point in the blacklist
        """

        add_remove_option: str = "-A" if put_in_blacklist else "-D"

        return f"sudo ebtables {add_remove_option} INPUT -p 0x888e --src {access_point_mac} -j DROP"
