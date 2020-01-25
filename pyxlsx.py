import openpyxl
import paramiko


def openpx():
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy)
    ssh.connect(hostname='hostname', username='user', password='pass')
    ssh.invoke_shell()
    fqdn = None
    wb = openpyxl.load_workbook('FILENAME.xlsx')
    sheet1 = wb.active
    for cellObj in sheet1["B"]:
        fqdn = cellObj.value
        rest_of_str = str("{} org description service-name changelog app-responsible-1 app-responsible-2".format(fqdn))
        stdin, stdout, stderr = ssh.exec_command(rest_of_str)
        mlist = stdout.readlines()
        print(mlist)
    ssh.close()
    return fqdn
openpx()
