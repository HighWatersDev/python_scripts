import argparse
from getpass import getpass
import logging

from netapp_ontap import config, HostConnection, NetAppRestError
from netapp_ontap.resources import Volume
from netapp_ontap.resources import ExportPolicy


def create_export_policy(vserver_name: str, export_policy: str):
    host = export_policy + ""
    for policy in ExportPolicy.get_collection(**{'svm.name': vserver_name}):
        policy.get()
        exp_policy = policy.name
        if export_policy in exp_policy:
            return export_policy
        else:
            try:
                resource = ExportPolicy()
                resource.name = export_policy
                resource.rules = [
                    {
                        "clients": [{"match": host}],
                        "protocols": ["nfs"],
                        "ro_rule": ["any"],
                        "rw_rule": ["any"],
                        "superuser": ["any"],
                    },
                ]
                resource.post(hydrate=True)
            except NetAppRestError as err:
                print("Error: Volume list  was not created: %s" % err)
            return


def make_volume_pycl(volume_name: str, vserver_name: str, aggr_name: str, volume_size: int, export_policy: str) -> None:
    """Creates a new volume in a SVM"""

    volume = Volume.from_dict({
                'name': volume_name,
                'svm': {'name':vserver_name},
                'aggregates': [{'name': aggr_name }],
                'size': volume_size,
                'autosize': {'mode': 'grow', 'grow_threshold': 10},
                'efficiency': {'dedupe': 'background', 'policy': {'name': 'daily'}},
                'guarantee': {'type': 'none'},
                'encryption': {'enabled': 'false', 'status': {}},
                'language': 'c.utf_8',
                'nas': {'export_policy': {'name': export_policy}, 'gid': 0, 'path': '/' + volume_name,
                        'security_style': 'unix',
                        'uid': 0,
                        'unix_permissions': 755},
                'quota': {},
                'snapmirror': {},
                'snapshot_policy': {"name": "none"},
                'space': {'snapshot': {'reserve_percent': 0}},
                'state': 'online',
                'style': 'flexvol',
                'type': 'rw'
    })

    try:
        volume.post()
        print("Volume %s created successfully" % volume.name)
    except NetAppRestError as err:
        print("Error: Volume was not created: %s" % err)
    return


def parse_args() -> argparse.Namespace:
    """Parse the command line arguments from the user"""

    parser = argparse.ArgumentParser(
        description="This script will create a new volume."
    )
    parser.add_argument(
        "-c", "--cluster", required=True, help="Netapp cluster: "
    )
    parser.add_argument(
        "-v", "--volume_name", required=True, help="Volume to create, ex."
    )
    parser.add_argument(
        "-svm", "--vserver_name", required=True, help="SVM to create the volume from, ex."
    )
    parser.add_argument(
        "-a", "--aggr_name", required=True, help="Aggregate to create the volume from, ex."
    )
    parser.add_argument(
        "-s", "--volume_size", required=True, help="Size of the volume in bytes."
    )
    parser.add_argument(
        "-e", "--export_policy", required=True, help="Export policy to add to volume. Use <host name> before"
    )
    parser.add_argument("-u", "--api_user", default="admin", help="API Username")
    parser.add_argument("-p", "--api_pass", help="API Password")
    parsed_args = parser.parse_args()

    # collect the password without echo if not already provided
    if not parsed_args.api_pass:
        parsed_args.api_pass = getpass()

    return parsed_args


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] [%(levelname)5s] [%(module)s:%(lineno)s] %(message)s",
    )
    args = parse_args()
    config.CONNECTION = HostConnection(
        args.cluster, username=args.api_user, password=args.api_pass, verify=False,
    )

    make_volume_pycl(args.volume_name, args.vserver_name, args.aggr_name, args.volume_size, args.export_policy)

