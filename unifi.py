#!/usr/bin/env python3

from typing import Optional, Dict, List

import ipaddress

from scapy.all import conf, srp, Ether, IP, UDP, Raw, RandShort

conf.checkIPaddr = False

ans, unans = srp(
    Ether(dst="ff:ff:ff:ff:ff:ff") /
        IP(dst="255.255.255.255") /
        UDP(sport=RandShort(), dport=10001) /
        # \x01\x00\x00 is the discover packet header, and \x00 is the payload
        # length
        Raw(load='\x01\x00\x00\x00'),
    timeout=5,
    multi=True,
    verbose=0,
)


class FieldType(int):
    '''
    FieldType maps integers to model strings.
    '''
    MAC = 0x01
    MAC_and_IP = 0x02
    Firmware = 0x03
    RadioName = 0x0b
    ModelShort = 0x0c
    ESSID = 0x0d
    ModelFull = 0x14

    def __str__(self):
        match int(self):
            case self.MAC:
                return 'MAC'
            case self.MAC_and_IP:
                return 'MAC and IP'
            case self.Firmware:
                return 'Firmware'
            case self.RadioName:
                return 'RadioName'
            case self.ModelShort:
                return 'Model Short'
            case self.ESSID:
                return 'ESSID'
            case self.ModelFull:
                return 'Model Full'
            case _:
                return f'Unknown (0x{int(self):02x})'


class Response:
    '''
    Response contains the fields of a discovery response.
    Unknown fields are stored in the `unknown` dict attribute.
    '''
    mac: Optional[str] = None
    mac_and_ip: Optional[List[str]] = [None, None]
    firmware: Optional[str] = None
    radio_name: Optional[str] = None
    model_short: Optional[str] = None
    essid: Optional[str] = None
    model_full: Optional[str] = None
    unknown: Dict[str,List[str]] = {}


devices = []
for sent, received in ans:
    payload = received[Raw].load
    if payload[0:3] != b'\x01\x00\x00':
        continue
    ip = received[IP].src
    mac = received[Ether].src
    payload_size = int(payload[3])
    if len(payload) != payload_size + 4:
        print(f"Invalid payload length, want {payload_size+4}, got {len(payload)}")
        continue
    offset = 4
    resp = Response()
    while True:
        if offset >= len(payload):
            break
        type_ = FieldType(payload[offset])
        size = int.from_bytes(payload[offset+1:offset+3], byteorder='big')
        if size == 0:
            break
        data = payload[offset+3:offset+3+size]
        #print(f"Type={type_} size={size} payload={data}")
        match type_:
            case FieldType.MAC:
                resp.mac = ':'.join([f'{x:02x}' for x in data])
            case FieldType.MAC_and_IP:
                resp.mac_and_ip = [
                    ':'.join([f'{x:02x}' for x in data[:6]]),
                    ipaddress.IPv4Address(data[6:]),
                ]
            case FieldType.Firmware:
                resp.firmware = data.decode('ascii')
            case FieldType.RadioName:
                resp.radio_name = data.decode('ascii')
            case FieldType.ModelShort:
                resp.model_short = data.decode('ascii')
            case FieldType.ESSID:
                resp.essid = data.decode('ascii')
            case FieldType.ModelFull:
                resp.model_full = data.decode('ascii')
            case _:
                resp.unknown[type_] = data
        offset += 3 + size
    devices.append(resp)


for d in devices:
    print(f'ip={d.mac_and_ip[1]} mac={d.mac} model_short={d.model_short} '
          f'model_full={d.model_full} radio_name={d.radio_name} essid={d.essid}')
