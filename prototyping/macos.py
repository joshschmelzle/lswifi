import subprocess
import xml.etree.ElementTree as ET

cmd = ['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-s' ,'-x']

cp = subprocess.run(cmd, capture_output=True)

def findkeydatafromchild(child, key):
    # print(child)
    found = False
    out = key
    data = None
    for i in child:
        if found:
            # print(i, i.text)
            data = i.text.replace('\n','').replace('\t','')
            found = False
        if i.text == key:
            # print(i, i.text)
            found = True
    return out, data

root = ET.fromstring(cp.stdout)
print(root)
for child in root[0]:
    rssi = findkeydatafromchild(child, 'RSSI')
    ssid = findkeydatafromchild(child, 'SSID')
    ssid_str = findkeydatafromchild(child, 'SSID_STR')
    chn = findkeydatafromchild(child, 'CHANNEL')
    cbw = findkeydatafromchild(child, 'CHANNEL_WIDTH')
    ie = findkeydatafromchild(child, 'IE')
    beacon_interval = findkeydatafromchild(child, 'BEACON_INT')
    print(ssid_str[1], rssi[1], f"{chn[1]}@{cbw[1]}", ie[1], end="\n\n")
