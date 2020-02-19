from ipwhois.net import Net
from ipwhois.asn import ASNOrigin
import ipaddress
import subprocess

def is_ipv4_network(string):
    try:
        ipaddress.IPv4Network(string)
        return True
    except ValueError:
        return False

asn_list = {    'youtube':['AS36561', 'AS43515', 'AS36040'],
                'netflix':['AS2906'],
                'facebook':['AS32934']
    }
routes_list = []

net = Net('2001:43f8:7b0::')
obj = ASNOrigin(net)

for key,value in asn_list.items():
    for val in value:
        results = (obj.lookup(asn=val,field_list='cidr'))['nets']
        for r in results:
            route = r['cidr']
            if is_ipv4_network(route):
                routes_list.append(f"/ip firewall address-list add list={key} timeout=23:55:00 address={route}")
routes_list = ";".join(set(routes_list))

# waiting for SCP implementation in ROS
#with open('asd.rsc', 'w+') as f:
#    f.write(routes_list)

ssh_key = '/home/pi/.ssh/id_rsa'
ssh_user = 'pi'
ssh_server = '192.168.88.1'

ssh = subprocess.check_output(['ssh', '-i', '{0}'.format(ssh_key), '{0}@{1}'.format(ssh_user,ssh_server), '{0}'.format(routes_list)])

