import json
import requests
from requests.auth import HTTPBasicAuth
from requests.exceptions import HTTPError
import datetime
import logging
import argparse
from getpass import getpass
import math


def parse_args() -> argparse.Namespace:
    """Parse the command line arguments from the user"""

    parser = argparse.ArgumentParser(
        description="This script will create a new volume."
    )
    parser.add_argument(
        "-cl", "--cluster", required=False, help="Netapp cluster: manta.nas.gatech.edu or raiemanta.matrix.gatech.edu"
    )
    parser.add_argument(
        "-v", "--volume_name", required=True, help="Volume to create, ex. test_arch_bdevl"
    )
    parser.add_argument(
        "-svm", "--vserver_name", required=True, help="SVM to create."
    )
    parser.add_argument(
        "-a", "--aggr_name", required=False, help="Aggregate to create the volume from, ex. manta11_hsata"
    )
    parser.add_argument(
        "-s", "--volume_size", required=True, help="Size of the volume in GB. For 1TB, type 1000."
    )
    parser.add_argument(
        "-ip", "--svm_ip", required=True, help="IP address of the SVM. Default on 1663 subnet"
    )
    parser.add_argument(
        "-ou", "--org_unit", required=True, help="Destination OU in AD. Ex. OU=Servers,OU=Staging,OU=OITSLA,OU=Servers,OU=_OIT,DC=ad,DC=gatech,DC=edu"
    )
    parser.add_argument(
        "-c", "--clients", nargs='+', required=True,
        help="Clients IP addresses or DNS names to add to export policy."
    )
    parser.add_argument("-u", "--ad_user", default="admin", help="API Username")
    parser.add_argument("-p", "--ad_pass", help="API Password")
    parsed_args = parser.parse_args()

    # collect the password without echo if not already provided
    if not parsed_args.ad_pass:
        parsed_args.ad_pass = getpass()

    return parsed_args

args = parse_args()

with requests.Session() as s:
    s.auth = HTTPBasicAuth(args.ad_user, args.ad_pass)

    def create_svm(svm_name, svm_ip, org_unit, user, passwd):
        svm_create = json.dumps({"name":svm_name,
                 "ipspace": {"name": "Default"},
                 "cifs":{"enabled": True, "name":svm_name, "ad_domain":{"fqdn":"",
                                                   "organizational_unit":org_unit,
                                                   "user":user,
                                                   "password":passwd}},
                 "ip_interfaces": [{"name": svm_name + "_cifs_lif_1",
                                              "ip": {"address": svm_ip, "netmask": "23"},
                                              "service_policy": "default-data-files",
                                              "location": {"broadcast_domain": {"name": "fg-1663"},
                                                            "home_node": {"name": "manta11", "uuid": "4ea6752a-b92f-11e9-91cb-00a098fa177a" }}}],
                 "routes": [{"gateway": "", "destination": {"address": "0.0.0.0", "netmask": "0"}}],
                 "dns": {"domains": [""], "servers": ["", ""]},
                 "language": "c.utf_8"})
        try:
            svm_post = s.post('https://<url>/api/svm/svms', data=svm_create, verify=False)
            response = svm_post.content
            status_code = svm_post.status_code
        except requests.exceptions.HTTPError as err:
            logging.error("Exception occurred", exc_info=True)
            raise HTTPError(err)
        return response, status_code

    def create_kerb(svm_name):
        kerb_create = json.dumps({ "name": "", "kdc":
                                 { "ip": "", "port": "88", "vendor": "microsoft" },
                                   "ad_server": { "name": "", "address": "" },
                                   "svm": { "name": svm_name}})
        try:
            kerb_post = s.post('https://<url>/api/protocols/nfs/kerberos/realms', data=kerb_create, verify=False)
            response = kerb_post.content
            status_code = kerb_post.status_code
        except requests.exceptions.HTTPError as err:
            logging.error("Exception occurred", exc_info=True)
            raise HTTPError(err)
        return response, status_code

    def create_export_policy(hosts, svm_name):
        root_clients = []
        for host in hosts:
            root_client = {"clients": [{"match": host}],
                        "protocols": ["cifs"], "ro_rule": ["any"],
                        "rw_rule": ["never"], "superuser": ["none"]}
            root_clients.append(root_client)
        root_export_policy = json.dumps({"name": "root_policy",
                                           "rules": root_clients,
                                           "svm": { "name": svm_name}})
        clients = []
        for host in hosts:
            client = {"clients": [{"match": host}],
                      "protocols": ["cifs"], "ro_rule": ["never"],
                      "rw_rule": ["any"], "superuser": ["any"]}
            clients.append(client)
        export_policy = json.dumps({"name": svm_name,
                                           "rules": clients,
                                           "svm": { "name": svm_name}})
        try:
            root_export_policy_post = s.post('https://<url>/api/protocols/nfs/export-policies',
                                         data=root_export_policy, verify=False)
            response1 = root_export_policy_post.content
            status_code1 = root_export_policy_post.status_code
        except requests.exceptions.HTTPError as err:
            logging.error("Exception occurred", exc_info=True)
            raise HTTPError(err)
        try:
            export_policy_post = s.post('https://<url>/api/protocols/nfs/export-policies',
                                         data=export_policy, verify=False)
            response2 = export_policy_post.content
            status_code2 = export_policy_post.status_code
        except requests.exceptions.HTTPError as err:
            logging.error("Exception occurred", exc_info=True)
            raise HTTPError(err)
        return response1, response2, status_code1, status_code2

    def create_volume(vol_space, vol_name, svm_name):
        vol_size = int(vol_space)
        p = math.pow(1024, 3)
        vol_size_in_bytes = int(vol_size * p)
        volume_create = json.dumps({
                'name': vol_name,
                'svm': {'name': svm_name},
                'aggregates': [{'name': 'manta11'}],
                'size': vol_size_in_bytes,
                'autosize': {'mode': 'grow', 'grow_threshold': 10},
                'efficiency': {'dedupe': 'background', 'policy': {'name': 'daily'}},
                'guarantee': {'type': 'none'},
                'encryption': {'enabled': 'false', 'status': {}},
                'language': 'c.utf_8',
                'nas': {'export_policy': {'name': svm_name}, 'gid': 0, 'path': '/' + vol_name,
                        'security_style': 'ntfs',
                        'uid': 0,
                        'unix_permissions': 755},
                'quota': {},
                'snapmirror': {},
                'snapshot_policy': {"name": "Default"},
                'space': {'snapshot': {'reserve_percent': 5}},
                'state': 'online',
                'style': 'flexvol',
                'type': 'rw'
            })
        try:
            volume_post = s.post('https://<url>/api/storage/volumes',
                                    data=volume_create, verify=False)
            response = volume_post.content
            status_code = volume_post.status_code
        except requests.exceptions.HTTPError as err:
            logging.error("Exception occurred", exc_info=True)
            raise HTTPError(err)
        return response, status_code

    def assign_policy_to_root(svm_name):
        root_volume = svm_name + '_root'
        try:
            get_volume_uuid = s.get('https://<url>/api/storage/volumes?name=' + str(root_volume) + '&return_records=true&return_timeout=15', verify=False)
            print("No json: ", get_volume_uuid.content)
            response = json.loads(get_volume_uuid.content)
            print(response)
            root_volume_uuid = response['records'][0]['uuid']
        except requests.exceptions.HTTPError as err:
            logging.error("Exception occurred", exc_info=True)
            raise HTTPError(err)
        root_policy = json.dumps({ "nas": { "export_policy": { "name": 'root_policy' } } })
        try:
            assign_policy = s.patch('https://<url>/api/storage/volumes/' + str(root_volume_uuid), data=root_policy)
            response = assign_policy.content
            status_code = assign_policy.status_code
        except requests.exceptions.HTTPError as err:
            logging.error("Exception occurred", exc_info=True)
            raise HTTPError(err)
        return response, status_code


if __name__ == "__main__":
    time = datetime.datetime.now().strftime("%d-%m-%Y-%H-%M")
    logging.basicConfig(level=logging.INFO,
                        format="[%(asctime)s] [%(levelname)5s] [%(module)s:%(lineno)s] %(message)s",
                        filename="na_create_cifs_volume.log" + time
                        )

    create_svm(args.vserver_name, args.svm_ip, args.org_unit, args.ad_user, args.ad_pass)
    create_kerb(args.vserver_name)
    create_export_policy(args.clients, args.vserver_name)
    assign_policy_to_root(args.vserver_name)
    create_volume(args.volume_size, args.volume_name, args.vserver_name)
    # new_svm = create_svm(args.vserver_name, args.svm_ip, args.org_unit, args.ad_user, args.ad_pass)
    # if new_svm[1] == 200:
    #     new_kerb = create_kerb(args.vserver_name)
    #     if new_kerb[1] == 200:
    #         new_policy = create_export_policy(args.clients, args.vserver_name)
    #         if new_policy[2] == 200 and new_policy[3] == 200:
    #             assign_policy_to_root(args.vserver_name)
    #             new_volume = create_volume(args.volume_size, args.volume_name, args.vserver_name)
    #             if new_volume[1] == 200:
    #                 print("Success")
    #                 print(new_svm[0])
    #                 print(new_kerb[0])
    #                 print(new_policy[0], new_policy[1])
    #                 print(new_volume[0])