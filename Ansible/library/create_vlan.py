

"""
VLAN Creation Module
===========================
Location: Ansible/library/create_vlan.py

Usage:
  - create_vlan:
      vlan_id: 100
      vlan_name: "Production"
      state: present
"""

from ansible.module_utils.basic import AnsibleModule


def main():
    # Define module arguments
    module_args = dict(
        vlan_id=dict(type='int', required=True),
        vlan_name=dict(type='str', required=True),
        state=dict(type='str', choices=['present', 'absent'], default='present'),
    )

    module = AnsibleModule(argument_spec=module_args)

    vlan_id = module.params['vlan_id']
    vlan_name = module.params['vlan_name']
    state = module.params['state']

    # Validate VLAN ID
    if vlan_id < 1 or vlan_id > 4094:
        module.fail_json(msg=f"Invalid VLAN ID: {vlan_id}. Must be 1-4094")

    # Build commands
    if state == 'present':
        commands = [
            f'vlan {vlan_id}',
            f'name {vlan_name}'
        ]
        msg = f"✓ VLAN {vlan_id} ({vlan_name}) created"
    else:
        commands = [f'no vlan {vlan_id}']
        msg = f"✓ VLAN {vlan_id} deleted"

    # Return result
    result = {
        'changed': True,
        'vlan_id': vlan_id,
        'vlan_name': vlan_name,
        'commands': commands,
        'message': msg
    }

    module.exit_json(**result)


if __name__ == '__main__':
    main()
