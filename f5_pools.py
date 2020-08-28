from f5.bigip import ManagementRoot
from f5.utils.responses.handlers import Stats


hostname = ''
username = ''
password = ''
mgmt = ManagementRoot(hostname, username, password)

vs = mgmt.tm.ltm.virtuals.get_collection()

for virt in vs:
    print("Name: ", virt.name, "Partition: ", virt.partition, "Port: ", virt.destination.split(":")[-1])
    try:
        my_virtual = mgmt.tm.ltm.virtuals.virtual.load(partition=virt.partition, name=virt.name)
        v_stats = Stats(my_virtual.stats.load())
        print("VIP status: ", v_stats.stat.status_availabilityState.description)
        dic = virt.raw
        dic = dic.items()
        for key, v in dic:
            if key == 'pool':
                new_v = v.split('/')
                part = new_v[1]
                pol = new_v[2]
                pols = mgmt.tm.ltm.pools.pool.load(partition=part, name=pol)
                p_stats = Stats(pols.stats.load())
                for member in pols.members_s.get_collection():
                    print("Pool member: ", member.name)

    except:
        pass
