#!/usr/bin/env python3.7


import os
import json
import optparse
import pandevice
import pandevice.base
import pandevice.errors
import pandevice.panorama
import pandevice.objects
import pandevice.policies
from typing import List, Optional


dg = None
objects = {}
options = None
pan = None


def parse_config():
    global dg, options, pan
    parser = optparse.OptionParser(version='%prog 1.0.0',
                                   description='%prog connects to the given PAN device with the given user and password'
                                               ' and retrieves the configuration.  It then creates a Terraform file to '
                                               'recreate the configuration.  If the device is a Panorama device a Device'
                                               ' Group can be specified.  Options are not necessary if environment '
                                               'variables are set.')
    parser.add_option('-p', '--pan-device', default=os.environ.get('PANDEVICE', None),
                      help='Panorama or PANOS device to pull configuration from (Env Var: PANDEVICE')
    parser.add_option('-u', '--user', default=os.environ.get('PANUSER', None),
                      help='User to access Panorama or PANOS Firewall (Env Var: PANUSER')
    parser.add_option('-P', '--password', default=os.environ.get('PANPASS', None),
                      help='Password for PAN device (Env Var: PANPASS)')
    parser.add_option('-d', '--device-group', default=os.environ.get('PANDEVICEGROUP', None),
                      help='DeviceGroup if PAN device is Panorama (Env Var: PANDEVICEGROUP)')
    (options, args) = parser.parse_args()
    if len(args) != 0:
        parser.error('This command takes no arguments, only options!')
    if options.pan_device is None:
        parser.error('Pan Device must be specified as an environment variable named PANDEVICE, '
                     'or via the command-line option -p or --pan-device')
    if options.user is None:
        parser.error('User must be specified as an environment variable named PANUSER, '
                     'or via the command-line option -u or --user')
    if options.password is None:
        parser.error('Password must be specified as an environment variable named PANPASS, '
                     'or via the command-line option -P or --password')
    try:
        pan = pandevice.base.PanDevice.create_from_device(options.pan_device, options.user, options.password)
    except pandevice.errors.PanURLError as e:
        print('Error connecting to PAN Device {} with user {}'.format(options.pan_device, options.user))
        exit(1)
    if type(pan) == pandevice.panorama.Panorama:
        if options.device_group is None:
            parser.error('Device Group must be specified if PAN Device is a Panorama as an environment variable named '
                         'PANDEVICEGROUP, or via the command-line option -d or --device-group')
        dg = pandevice.panorama.DeviceGroup(options.device_group)
        pan.add(dg)
        try:
            dg.refresh(running_config=True)
        except pandevice.errors.PanObjectMissing:
            print('Device Group {} not found in Panorama running config'.format(options.device_group))
            exit(2)
    else:
        dg = pan
        # For Panorama Device Groups Address Objects and Address Groups are read in when we refresh the
        # Device Group.  For firewalls, we need to refresh them individually
        ao = pandevice.objects.AddressObject()
        dg.add(ao)
        ao.refreshall(dg, running_config=True)
        ag = pandevice.objects.AddressGroup()
        dg.add(ag)
        ag.refreshall(dg, running_config=True)


def name_to_resource(s: str) -> str:
    return s.replace('.', '_')


def parse_address_objects():
    global dg, objects, options, pan
    names: List[str] = [ao.name for ao in dg.findall(pandevice.objects.AddressObject)]
    for name in sorted(names):
        ao: pandevice.objects.AddressObject = dg.find(name, pandevice.objects.AddressObject)
        if dg == pan:
            print('resource "panos_address_object" "{}" {{'.format(name_to_resource(ao.name)))
            objects[ao.name] = '${{panos_address_object.{}.name}}'.format(name_to_resource(ao.name))
        else:
            print('resource "panos_panorama_address_object" "{}" {{'.format(name_to_resource(ao.name)))
            objects[ao.name] = '${{panos_panorama_address_object.{}.name}}'.format(name_to_resource(ao.name))
            print('  device_group = "{}"'.format(options.device_group))
        print('  type         = "{}"'.format(ao.type))
        print('  name         = "{}"'.format(ao.name))
        print('  value        = "{}"'.format(ao.value))
        if ao.description is not None:
            print('  description  = {}'.format(json.dumps(ao.description)))
        if ao.tag is not None:
            print('  tags         = {}'.format(json.dumps(ao.tag)))
        print('}')


def transform_object_reference(l: list) -> list:
    global objects
    return [objects[i] if i in objects else i for i in l]


def parse_address_group():
    global dg, objects, options, pan
    names: List[str] = [ag.name for ag in dg.findall(pandevice.objects.AddressGroup)]
    for name in sorted(names):
        ag: pandevice.objects.AddressGroup = dg.find(name, pandevice.objects.AddressGroup)
        if dg == pan:
            print('resource "panos_address_group" "{}" {{'.format(name_to_resource(ag.name)))
            objects[ag.name] = '${{panos_address_group.{}.name}}'.format(name_to_resource(ag.name))
        else:
            print('resource "panos_panorama_address_group" "{}" {{'.format(name_to_resource(ag.name)))
            objects[ag.name] = '${{panos_panorama_address_group.{}.name}}'.format(name_to_resource(ag.name))
            print('  device_group      = "{}"'.format(options.device_group))
        print('  name              = "{}"'.format(ag.name))
        if ag.static_value is not None:
            print('  static_addresses  = {}'.format(json.dumps(transform_object_reference(ag.static_value))))
        if ag.dynamic_value is not None:
            print('  dynamic_match     = "{}"'.format(ag.dynamic_value))
        if ag.description is not None:
            print('  description       = {}'.format(json.dumps(ag.description)))
        if ag.tag is not None:
            print('  tags              = {}'.format(json.dumps(ag.tag)))
        print('}')


def rule_dumps_values(m):
    for p in sorted(m.keys()):
        if m[p] is not None:
            print('    {} = {}'.format(p, json.dumps(m[p])))


def process_rules(rules: List[pandevice.policies.SecurityRule]):
    global dg, options, pan
    for rule in rules:
        print('  rule {')
        if rule.category is None:
            rule.category = ["any"]
        rule_dumps_values({
            'name': rule.name,
            'description': rule.description,
            'source_zones': rule.fromzone,
            'source_addresses': rule.source,
            'negate_source': rule.negate_source,
            'source_users': rule.source_user,
            'hip_profiles': rule.hip_profiles,
            'destination_zones': rule.tozone,
            'destination_addresses': rule.destination,
            'negate_destination': rule.negate_destination,
            'applications': rule.application,
            'services': rule.service,
            'categories': rule.category,
            'action': rule.action,
            'log_start': rule.log_start,
            'log_end': rule.log_end,
            'log_setting': rule.log_setting,
            'tags': rule.tag,
            'disabled': rule.disabled,
            'schedule': rule.schedule,
            'icmp_unreachable': rule.icmp_unreachable,
            'disable_server_response_inspection': rule.disable_server_response_inspection,
            # Below is a total hack.  SecurityRule.group is supposed to be a str, but is returned as a list
            # Make sure this doesn't break when pandevice is fixed by checking type
            'group': rule.group[0] if type(rule.group) == list else rule.group,
            'virus': rule.virus,
            'spyware': rule.spyware,
            'vulnerability': rule.vulnerability,
            # Below is a total hack.  SecurityRule.url_filtering is supposed to be a str, but is returned as a list
            # Make sure this doesn't break when pandevice is fixed by checking type
            'url_filtering': rule.url_filtering[0] if type(rule.url_filtering) == list else rule.url_filtering,
            'file_blocking': rule.file_blocking,
            'wildfire_analysis': rule.wildfire_analysis,
            'data_filtering': rule.data_filtering,
            'target': rule.target,
            'negate_target': rule.negate_target
        })

        print('  }')


def parse_rulebase():
    global dg, options, pan
    if dg == pan:
        print('resource "panos_security_policy" "policy" {')
        rulebase = pandevice.policies.Rulebase()
        dg.add(rulebase)
        process_rules(pandevice.policies.SecurityRule.refreshall(rulebase))
        print('}')
    else:
        print('resource "panos_panorama_security_policy" "{}-pre" {{'.format(options.device_group))
        print('  device_group      = "{}"'.format(options.device_group))
        print('  rulebase          = "pre-rulebase"')
        rulebase = pandevice.policies.PreRulebase()
        dg.add(rulebase)
        process_rules(pandevice.policies.SecurityRule.refreshall(rulebase))
        print('}')
        print('resource "panos_panorama_security_policy" "{}-post" {{'.format(options.device_group))
        print('  device_group      = "{}"'.format(options.device_group))
        print('  rulebase          = "post-rulebase"')
        rulebase = pandevice.policies.PostRulebase()
        dg.add(rulebase)
        process_rules(pandevice.policies.SecurityRule.refreshall(rulebase))
        print('}')


def main():
    global dg, options, pan
    parse_config()
    parse_address_objects()
    parse_address_group()
    parse_rulebase()


if __name__ == '__main__':
    main()
