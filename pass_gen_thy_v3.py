import os
import binascii
import crypt
import random
import string
import hmac
import datetime
import logging
from zeep import Client
import salt.client


# Variables
auth_user = ''
auth_password = ''
thycotic_client = Client('https://<url>/webservices/sswebservice.asmx?wsdl')
salt_client = salt.client.LocalClient()


# Creates a SHA512 hash from the password
def get_hash(password):
    return crypt.crypt(password, crypt.mksalt(crypt.METHOD_SHA512))


# Generates a random string and creates 16 character password from it
def gen_pass(chars=string.ascii_letters + string.digits + '/?!@#%^&*()-_=+{}[]|;:<>,.'):
    password = ''
    rand = binascii.b2a_uu(os.urandom(16)) + binascii.b2a_base64(os.urandom(16))
    while len(password) < 16:
        choice = random.choice(rand)
        if choice in chars:
            password += choice
    return password


def validate(password, hashed):
    return hmac.compare_digest(crypt.crypt(password, hashed), hashed)


# Takes password and its hash and updates local account password on each rhel6 minion
def gen():
    passwd = gen_pass()
    hashed = get_hash(passwd)
    out = (passwd, hashed)
    return out


def validate_result (result):
    if result == None:
        return True
    if len (result) == 1 and 'string' in result:
        return False
    if 'Errors' not in result:
        return True
    if result['Errors'] == None:
        return True
    return False


def secret_sauce():
    logging.basicConfig(filename='thycotic-queue-run.log', filemode='a',
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.DEBUG)
    r = thycotic_client.service.Authenticate(auth_user, auth_password, '', 'ad.gatech.edu')  # connects to hygiene
    if not validate_result(r):
        logging.error("Failed to connect to Thycotic: ", r['Errors'])
        return False
    auth_token = r['Token']
    tstamp = datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')

    host = salt_client.cmd('G@os:RedHat and G@osmajorrelease:6', 'grains.item', ['fqdn'], tgt_type='compound')
    r = thycotic_client.service.SearchFolders(auth_token, 'oit-ops')  # searches for the folder with secrets to update
    if not validate_result(r):
        logging.error("Failed to search folders: ", r['Errors'])
        return False
    folder = r['Folders']['Folder'][0]
    for item in host:
        fqdn = item
        secret_name = fqdn + '/operator'
        r = thycotic_client.service.SearchSecretsByFolder (auth_token, secret_name, folder['Id'], True, False, False)
        if not validate_result(r):
            logging.error("Failed to find secret in Thycotic: ", r['Errors'])
            continue
        found = False
        if r['SecretSummaries'] != None:
            ss = r['SecretSummaries']['SecretSummary']
            for s in ss:
                if s['SecretName'] == secret_name:
                    found = True
                    break
        if found:    # secret exists already, make sure it's active and set the password
            secret_id = s['SecretId']
            r = thycotic_client.service.GetSecret(auth_token, secret_id, True)
            if not validate_result(r):
                logging.error("Failed to get secret from Thycotic: ", r['Errors'])
                continue
            secret = r['Secret']  # updates existing secret
            secret['Active'] = True
            for i in secret['Items']['SecretItem']:
                if i['FieldName'] == 'Password':
                    current_pass = i['Value']
            cred = gen()
            new_pass = cred[0]
            hashed = cred[1]
            salt_client.cmd(fqdn, 'shadow.set_password', ['operator', hashed])
            for item in secret['Items']['SecretItem']:
                if item['FieldName'] == 'Password':
                    item['Value'] = new_pass
                if item['FieldName'] == 'Notes':
                    item['Value'] = tstamp + ' changed by Salt Master'
            secret['SecretSettings']['AutoChangeEnabled'] = False
            secret['SecretSettings']['IsChangeToSettings'] = True
            r = thycotic_client.service.UpdateSecret(auth_token, secret)
            if not validate_result(r):  # revert password back to the previous one
                old_hash = get_hash(current_pass)
                salt_client.cmd(fqdn, 'shadow.set_password', ['operator', old_hash])
                salt_client.cmd(fqdn, 'smtp.send_msg', ['someone@', 'Password update failed', 'profile=salt_smtp'])
                continue
        else:  # secret doesn't exist
            r = thycotic_client.service.GetSecretTemplates(auth_token)  # searches for template for new secret
            if not validate_result(r):
                logging.error("Failed to find secret template: ", r['Errors'])
                return False
            template = None
            for t in r['SecretTemplates']['SecretTemplate']:
                if t['Name'] == 'Unix Account (SSH)':
                    template = t
            if template == None:
                logging.error("Failed to find Unix account template: ", r['Errors'])
                return False
            r = thycotic_client.service.GetNewSecret(auth_token, template['Id'], folder['Id'])  # creates new secret from template
            if not validate_result(r):
                logging.error("Failed to get new secret: ", r['Errors'])
                return False
            secret = r['Secret']
            secret['Name'] = secret_name
            secret['Active'] = True
            cred = gen()
            new_pass = cred[0]
            hashed = cred[1]
            salt_client.cmd(fqdn, 'shadow.set_password', ['operator', hashed])
            for item in secret['Items']['SecretItem']:
                if item['FieldName'] == 'Machine':
                    item['Value'] = fqdn
                if item['FieldName'] == 'Username':
                    item['Value'] = 'operator'
                if item['FieldName'] == 'Password':
                    item['Value'] = new_pass
                if item['FieldName'] == 'Notes':
                    item['Value'] = tstamp + ' provisioned by Salt Master - '
            secret['SecretSettings']['AutoChangeEnabled'] = False
            secret['SecretSettings']['ProxyEnabled'] = True
            secret['SecretSettings']['IsChangeToSettings'] = True
            r = thycotic_client.service.AddNewSecret(auth_token, secret)  # adds new secret
            if not validate_result(r):
                #logging.error("Failed to add new secret: ", r['Errors'])
                old_hash = get_hash(new_pass)
                salt_client.cmd(fqdn, 'shadow.set_password', ['operator', old_hash])
                salt_client.cmd(fqdn, 'smtp.send_msg',
                                ['someone@', 'Password update failed', 'profile=salt_smtp'])
                continue
    return True


def main():
    print(secret_sauce())


if __name__ == '__main__':
    main()
