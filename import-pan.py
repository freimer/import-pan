#!/usr/bin/env python3.7


import os
import json
import pandevice
import pandevice.panorama
import pandevice.objects
import pandevice.policies
from typing import List, Optional


def main():
    pano = pandevice.panorama.Panorama(os.environ['PANORAMA'], os.environ['USERNAME'], os.environ['PASSWORD'])
    # et = pano.op('show system info', xml=True)
    # print(et)
    pandevice.panorama.DeviceGroup(os.environ['DEVICEGROUP']).refreshall(pano)
    dg = pano.find(os.environ['DEVICEGROUP'], pandevice.panorama.DeviceGroup)
    names: List[str] = [ao.name for ao in dg.findall(pandevice.objects.AddressObject)]
    for name in sorted(names):
        ao: pandevice.objects.AddressObject = dg.find(name, pandevice.objects.AddressObject) # type:
        print('resource "panos_panorama_address_object" "{}" {{'.format(ao.name))
        print('  device_group = "{}"'.format(os.environ['DEVICEGROUP']))
        print('  type         = "{}"'.format(ao.type))
        print('  name         = "{}"'.format(ao.name))
        print('  value        = "{}"'.format(ao.value))
        if ao.description is not None:
            print('  description  = "{}"'.format(ao.description))
        if ao.tag is not None:
            print('  tags         = {}'.format(json.dumps(ao.tag)))
        print('}')
    names: List[str] = [ag.name for ag in dg.findall(pandevice.objects.AddressGroup)]
    for name in sorted(names):
        ag: pandevice.objects.AddressGroup = dg.find(name, pandevice.objects.AddressGroup) # type:
        print('resource "panos_panorama_address_object" "{}" {{'.format(ag.name))
        print('  device_group      = "{}"'.format(os.environ['DEVICEGROUP']))
        print('  name              = "{}"'.format(ag.name))
        if ag.static_value is not None:
            print('  static_addresses  = {}'.format(json.dumps(ag.static_value)))
        if ag.dynamic_value is not None:
            print('  dynamic_match     = "{}"'.format(ag.dynamic_value))
        if ag.description is not None:
            print('  description       = "{}"'.format(ag.description))
        if ag.tag is not None:
            print('  tags              = {}'.format(json.dumps(ag.tag)))
        print('}')
    rulebase = pandevice.policies.PreRulebase()
    dg.add(rulebase)
    rules = pandevice.policies.SecurityRule.refreshall(rulebase)
    print('resource "panos_panorama_security_policy" "{}" {{'.format(os.environ['DEVICEGROUP']))
    print('  device_group      = "{}"'.format(os.environ['DEVICEGROUP']))
    for rule in rules: # type: pandevice.policies.SecurityRule
        print('  rule {')
        print('    name = "{}"'.format(rule.name))
        if rule.description is not None:
            print('    description = "{}"'.format(rule.description))
        print('    source_zones = {}'.format(json.dumps(rule.fromzone)))
        print('    source_addresses = {}'.format(json.dumps(rule.source)))
        if rule.negate_source is not None:
            print('    negate_source = true')
        print('    source_users = {}'.format(json.dumps(rule.source_user)))
        print('    hip_profiles = {}'.format(json.dumps(rule.hip_profiles)))
        print('    destination_zones = {}'.format(json.dumps(rule.tozone)))
        print('    destination_addresses = {}'.format(json.dumps(rule.destination)))
        if rule.negate_destination is not None:
            print('    negate_destination = true')
        print('    applications = {}'.format(json.dumps(rule.application)))
        print('    services = {}'.format(json.dumps(rule.service)))
        print('    categories = {}'.format(json.dumps(rule.category)))
        if rule.action is not None:
            print('    action = "{}"'.format(rule.action))
        print('  }')
    print('}')

if __name__ == '__main__':
    main()

