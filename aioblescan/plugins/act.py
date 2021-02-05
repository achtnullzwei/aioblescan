#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#
from struct import unpack
import json
import aioblescan as aios


class Act(object):

    def decode(self, packet):
        data = {}
        raw_data = packet.retrieve('Advertised Data')
        if raw_data:
            svc_data = raw_data[0].retrieve('Service Data uuid')[0].val.hex()
            rssi = packet.retrieve('rssi')
            mac = packet.retrieve("peer")
            if svc_data == "181a":
                act_data = raw_data[0].retrieve('Adv Payload')[0].val.hex()
                data['uuid'] = svc_data + act_data[0:12]
                data['rssi'] = rssi[-1].val
                data['mac'] = mac[-1].val
                data['temperature'] = int(act_data[12:16],16)/10
                data['humidity'] = int(act_data[16:18],16)
                data['battery'] = int(act_data[18:20],16)
                return json.dumps(data)