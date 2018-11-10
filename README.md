# import-pan.py

import-pan.py is a simple program to read the configuration of a Palo Alto Networks firewall and import all the objects into a Terraform template.
It has the ability to read in configurations from individual firewalls, as well as a Device Group from Panorama.


```
Usage: import-pan.py [options]

import-pan.py connects to the given PAN device with the given user and
password and retrieves the configuration.  It then creates a Terraform file to
recreate the configuration.  If the device is a Panorama device a Device Group
can be specified.  Options are not necessary if environment variables are set.

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -p PAN_DEVICE, --pan-device=PAN_DEVICE
                        Panorama or PANOS device to pull configuration from
                        (Env Var: PANDEVICE
  -u USER, --user=USER  User to access Panorama or PANOS Firewall (Env Var:
                        PANUSER
  -P PASSWORD, --password=PASSWORD
                        Password for PAN device (Env Var: PANPASS)
  -d DEVICE_GROUP, --device-group=DEVICE_GROUP
                        DeviceGroup if PAN device is Panorama (Env Var:
                        PANDEVICEGROUP)
```
