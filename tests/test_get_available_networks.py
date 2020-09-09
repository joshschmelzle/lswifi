import sys

# wlanapi is actually in a different directory. by default when python runs this script it doesn't know about the other one.
sys.path.insert(0, "C:\\Users\\josh\\dev\\python\\lswifi\\lswifi")
# import wlanapi as WLAN_API
import time


def dequote(s):
    """
    If a string has single or double quotes around it, remove them.
    Make sure the pair of quotes match.
    If a matching pair of quotes is not found, return the string unchanged.
    """
    if (s[0] == s[-1]) and s.startswith(("'", '"')):
        return s[1:-1]
    return s


interfaces = WLAN_API.get_interfaces()
print(interfaces)
for interface in interfaces:
    WLAN_API.scan(interface.guid)
    time.sleep(0.1)
    available_networks = WLAN_API.get_wireless_available_network_list(interface)
    is_first_avail = True
    output = []
    for avail in available_networks:
        if is_first_avail:
            output.append([str(i).upper() for i in list(avail.__dict__.keys())])
            is_first_avail = False
        output.append([str(i) for i in list(avail.__dict__.values())])

    len0 = max(len(x) for x in [str(y[0]) for y in output])
    len1 = max(len(x) for x in [str(y[1]) for y in output])
    len2 = max(len(x) for x in [str(y[2]) for y in output])
    len3 = max(len(x) for x in [str(y[3]) for y in output])
    len4 = max(len(x) for x in [str(y[4]) for y in output])
    len5 = max(len(x) for x in [str(y[5]) for y in output])
    len6 = max(len(x) for x in [str(y[6]) for y in output])
    len7 = max(len(x) for x in [str(y[7]) for y in output])
    len8 = max(len(x) for x in [str(y[8]) for y in output])
    len9 = max(len(x) for x in [str(y[9]) for y in output])
    len10 = max(len(x) for x in [str(y[10]) for y in output])

    for item in output:
        print(
            "{0:<{len0}}  {1:<{len1}}  {2:{len2}}  {3:{len3}}  {4:{len4}}  {5:{len5}}  {6:{len6}}  {7:{len7}}  {8:{len8}}  {9:{len9}}  {10:{len10}}".format(
                dequote(item[0].replace("b", "", 1)),
                item[1],
                item[2],
                item[3],
                item[4],
                item[5],
                item[6],
                item[7],
                item[8],
                item[9],
                item[10],
                len0=len0,
                len1=len1,
                len2=len2,
                len3=len3,
                len4=len4,
                len5=len5,
                len6=len6,
                len7=len7,
                len8=len8,
                len9=len9,
                len10=len10,
            )
        )
