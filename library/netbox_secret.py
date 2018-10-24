#!/usr/bin/env python
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

try:
    import pynetbox
    PYNETBOX_IMPORT = True
except ImportError:
    PYNETBOX_IMPORT = False

DOCUMENTATION = """
module: netbox_secret
version_added: "2.4"
short_description: create, modify and delete device objects
description:

options:
  state:
    required: true
    description:
      - State of an object
      - List will list all secret information for an object
    choices: [present, absent, show]

  name:
    required: true
    description:
      - String value for the property being manipulated

  secret:
    required: false
    description:
      - String of the secret you would like to set

  secret_role:
    required: false
    description:
      - String value for the secret role you would like to use
      - If the specified secret_role does not exist, a new one will be created

  url:
    required: true
    description:
      - Base url of the netbox instance. Ex: http://netbox.example.com

  token:
    required: true
    description:
      - API authentication Token

  private_key:
    required: true
    description:
      - Path to the private key used to decrypt secrets. Can be relative or absolute path

"""

from ansible.module_utils.basic import *
from ansible.module_utils.urls import *
from ansible.module_utils.basic import AnsibleModule
from ansible.errors import AnsibleError
import os

def run_module():

    module_args = dict(
            device = dict(type='str'),
            state = dict(type='str', default='present',
                         choices=['present', 'absent', 'show']),
            name = dict(type='str'),
            secret = dict(type='str'),
            secret_role = dict(type='str'),
            url = dict(type='str', required=True),
            token = dict(type='str', required=True),
            private_key = dict(type='str')
        )

    result = dict(
        changed=False,
        msg='',
        role_created=False
    )

    module = AnsibleModule(
        argument_spec = module_args
    )

    # Define variables for each parameter
    device = module.params['device'] if 'device' in module.params else None
    state = module.params['state']
    name = module.params['name'] if 'name' in module.params else None
    secret = module.params['secret'] if 'secret' in module.params else None
    secret_role = module.params['secret_role'] if 'secret_role' in module.params else None
    url = module.params['url']
    token = module.params['token']
    private_key = os.path.abspath(str(module.params['private_key']))
    result['secret_role'] = secret_role

    # Fail if secret_role is not defined
    if state != 'show' and secret_role == None:
        module.fail_json(msg='State is {}. Please define secret_role'.format(state))
    # Fail if pynetbox is not installed
    if not PYNETBOX_IMPORT:
        module.fail_json(msg='pynetbox is not installed on this system. \
            Please run `pip install pynetbox`')
    # Try to instantiate a netbox connection object
    try:
        nb = pynetbox.api(url, private_key_file=private_key, token=token)
    except Exception as e:
        module.fail_json(msg='Failed to connect to the netbox instance at {}. {}'.format(url,e))

    # Present state
    if state == 'present':
        if secret_role != None:
            # Get the secret_role object when defined
            secret_role_obj = nb.secrets.secret_roles.get(name=secret_role)
            if secret_role_obj == None:
                # If object doesn't exist, try to create it
                try:
                    nb.secrets.secret_roles.create(name=secret_role, slug=secret_role.replace(' ', '-').lower(), users=[''])
                except pynetbox.lib.query.RequestError as e:
                    module.fail_json(msg=e.error)
                result['changed'] = True
                result['role_created'] = True

        # Filter device secrets based on device name
        device_secrets = [ i for i in nb.secrets.secrets.filter(device=device) 
                          if (str(i.role) == secret_role and str(i.name) == name)]
        # Get device object for secret being manipulated
        device_secret_obj = device_secrets[0] if len(device_secrets) > 0 else None
        if device_secret_obj == None:
            if name != None and device != None and secret != None:
                # Fail if device doesn't exist
                try:
                    device_id = nb.dcim.devices.get(name=device).id
                except AttributeError as e:
                    module.fail_json(msg='The device doesn\'t exist for the secret you are trying to create')
                role_id = nb.secrets.secret_roles.get(name=secret_role).id
                # Try to create the secret object
                try:
                    nb.secrets.secrets.create(name=name, role=role_id, 
                                              device=device_id, plaintext=secret)
                except pynetbox.lib.query.RequestError as e:
                        module.fail_json(msg=e.error)
                # Set result to changed if no failures
                result['changed'] = True
                result['msg'] = 'Secret created for device {} and role {}'.format(device, secret_role)
            else:
                # Name, device and secret need to be defined
                module.fail_json(msg='Please define name, device, and \
                                 secret if trying to create a secret object')
        else:
            # Update the secret object when it exists
            device_secret_obj.plaintext = secret
            # Save the secret object
            if device_secret_obj.save():
                result['changed'] = True
                result['secret_changed'] = True
                result['msg'] = 'Secret for device {} has been updated'.format(device)
    # Absent state
    elif state == 'absent':
        if name != None and device != None and secret_role != None:
            # Try to get secret role id, fail if it doesn't exist
            try:
                role_id = nb.secrets.secret_roles.get(name=secret_role).id
            except NoneType:
                module.fail_json(msg='There is no secret role: {}'.format(secret_role))
            # Try to get secret object, fail if it doesn't exist
            try:
                secret_obj = [i for i in nb.secrets.secrets.filter(device=device, name=name) if i.role.id == role_id][0]
            except IndexError:
                module.fail_json(msg='A secret for the defined device and name doesn\'t exist')
            # Try to delete the secret object
            if secret_obj.delete():
                result['changed'] = True
                result['secret_deleted'] = True
                result['msg'] = 'Secret \'{}\' for device {} has been deleted'.format(name,secret)
        else:
                # Name, device and secret need to be defined
                module.fail_json(msg='Please define name, device and device_role if trying to delete a secret object')
    # Show state
    elif state == 'show':
        # Set empty dictionary
        args = {}
        if name != None:
            args['name'] = name
        if secret_role != None:
            role_id = nb.secrets.secret_roles.get(name=secret_role).id
        if device != None:
            args['device'] = device
        # Filter using pointer to arguments
        secrets_list = nb.secrets.secrets.filter(**args)
        result['secrets'] = []
        for i in secrets_list:
            # No secret_role defined
            if secret_role != None:
                # Only build result list with matching secret role
                if i.role.id == role_id:
                    result['secrets'].append({'secret_role': i.role.name,'password': i.plaintext, 'name': i.name, 'device': i.device.name})
            # Build result with matching secrets
            else:
                result['secrets'].append({'secret_role': i.role.name,'password': i.plaintext, 'name': i.name, 'device': i.device.name})
        # Fail if length of secret results is 0
        if len(result['secrets']) == 0:
            module.fail_json(msg='No secrets were matched with these parameters')
    # Exit the module
    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()
