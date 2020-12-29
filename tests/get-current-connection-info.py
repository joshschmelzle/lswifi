import sys

# wlanapi is actually in a different directory. by default when python runs this script it doesn't know about the other one.
sys.path.insert(0, "C:\\Users\\josh\\dev\\python\\lswifi\\lswifi")
import ast

import wlanapi


def func_a(bool):
    interfaces = wlanapi.get_interfaces()
    for interface in interfaces:
        result_tuple = wlanapi.query_interface(interface, "current_connection")
        out = ast.literal_eval((str(result_tuple).split(",", 1)[1][:-1].strip()))
        if bool:
            print("func_a() x 1:")
            print("    {}".format(out))
            print(
                "    bssid: {}".format(out["wlanAssociationAttributes"]["dot11Bssid"])
            )


def func_b(bool):
    interfaces = wlanapi.get_interfaces()
    for interface in interfaces:
        result_tuple = wlanapi.query_interface(interface, "current_connection")
        out = result_tuple[1]["wlanAssociationAttributes"]["dot11Bssid"]
        if bool:
            print("func_b() x 1:")
            print("    {}".format(result_tuple[1]))
            print("    {}".format(out))


if __name__ == "__main__":
    print("This script uses WLAN_ASSOCIATION_ATTRIBUTES which does not include RSSI.")
    func_a(True)
    func_b(True)
    import timeit

    setup = "from __main__ import func_a"
    print(
        "func_a() x 10:\n    {} seconds".format(
            timeit.timeit("func_a(False)", setup=setup, number=10)
        )
    )
    print(
        "func_a() x 100:\n    {} seconds".format(
            timeit.timeit("func_a(False)", setup=setup, number=100)
        )
    )
    print(
        "func_a() x 1000:\n    {} seconds".format(
            timeit.timeit("func_a(False)", setup=setup, number=1000)
        )
    )
    print(
        "func_a() x 10000:\n    {} seconds".format(
            timeit.timeit("func_a(False)", setup=setup, number=10000)
        )
    )

    setup = "from __main__ import func_b"
    print(
        "func_b() x 10:\n    {} seconds".format(
            timeit.timeit("func_b(False)", setup=setup, number=10)
        )
    )
    print(
        "func_b() x 100:\n    {} seconds".format(
            timeit.timeit("func_b(False)", setup=setup, number=100)
        )
    )
    print(
        "func_b() x 1000:\n    {} seconds".format(
            timeit.timeit("func_b(False)", setup=setup, number=1000)
        )
    )
    print(
        "func_b() x 10000:\n    {} seconds".format(
            timeit.timeit("func_b(False)", setup=setup, number=10000)
        )
    )
