# pip3 install certifi xmltodict requests
import os
import requests
import sys
import xml.etree.ElementTree as ET
import datetime
import time
import subprocess
import certifi
from datetime import datetime
import xmltodict

def reduce_to_dict(item):
    if isinstance(item, list):
        return [reduce_to_dict(i) for i in item]
    elif isinstance(item, dict):
        r = {}
        for k, v in item.items():
            r[k.lower()] = reduce_to_dict(v)
        return r
    return item

class QConnector(object):
    SESSION_PATH = "/api/2.0/fo/session/"
    KB_VULN_PATH = '/api/2.0/fo/knowledge_base/vuln/'
    ASSET_HOST_PATH = "/api/2.0/fo/asset/host/"
    HOST_VM_DETECTION = "/api/2.0/fo/asset/host/vm/detection/"
    HOST_INFO = "/get_host_info.php"
    BASE_HEADERS = {"X-Requested-With": "Curl"}
    DATETIME_FMT = "%Y-%m-%d"

    def __init__(self, username, password, hostname):
        self.username = username
        self.password = password
        self.hostname = hostname
        self.last_date = datetime.utcnow()
        self.headers = self.BASE_HEADERS.copy()
        self.session = requests.Session()
        self.qualys_api_url = "https://{}:443".format(hostname)

    def do_login(self):
        params = {}
        params = {"action": "login", 
                  "username": self.username,
                  "password": self.password}
        r = self.session.post(self.qualys_api_url+self.SESSION_PATH, data=params,
                            headers=self.headers, verify=certifi.where())
        login = False
        xmlreturn = ET.fromstring(r.text)
        for elem in xmlreturn.findall('.//TEXT'):
            if elem.text == "Logged in":
                login = True
                break
        if not login:
            raise Exception("Failed to login")

    def do_logout(self):
        params = { 'action':'logout' }
        r = self.session.post(self.qualys_api_url+self.SESSION_PATH, data=params,
                   headers=self.headers, verify=certifi.where())
        login = False
        xmlreturn = ET.fromstring(r.text)
        for elem in xmlreturn.findall('.//TEXT'):
            if elem.text == "Logged out":
                login = True
                break
        if not login:
            raise Exception("Failed to logout")

    def do_host_assets(self, details="All", truncation_limit=1000000, use_last=True):
        params = { "action": "list",
                   "truncation_limit":truncation_limit,
                   "details": details,
                 }        
        if use_last:
            vm_scan_date_after =  self.last_date.strftime('%Y-%m-%d')
            params['vm_scan_date_after'] = vm_scan_date_after
            self.last_date = datetime.now()

        r = self.session.post(self.qualys_api_url+self.ASSET_HOST_PATH, data=params,
                   headers=self.headers, verify=certifi.where())

        if r.status_code == 200:
            xd = xmltodict.parse(r.text)
            host_list = []
            x2d_hl = xd['HOST_LIST_OUTPUT']['RESPONSE']['HOST_LIST']['HOST']
            if isinstance(x2d_hl, dict):
                hl = reduce_to_dict(x2d_hl)
                host_list.append(hl)
                return host_list
            for i in x2d_hl:
                hl = reduce_to_dict(i)
                host_list.append(hl)
            return host_list
        
        raise Exception("Failed to obtain the host list")

    def do_host_vm_detection(self, details="All", truncation_limit=1000000, 
                             show_cloud_tags=1, use_last=True, ips=None, ids=None):
        params = { "action": "list",
                   "truncation_limit":truncation_limit,
                   "show_cloud_tags": show_cloud_tags
                 }
        if ips is not None:
            params['ips'] = ips
            del params['truncation_limit']
            del params['show_cloud_tags']
        elif ids is not None:
            params['ids'] = ids
            del params['truncation_limit']
            del params['show_cloud_tags']

        if use_last:
            vm_scan_date_after =  self.last_date.strftime('%Y-%m-%d')
            self.last_date = datetime.now()
            params['vm_scan_date_after'] = vm_scan_date_after

        r = self.session.post(self.qualys_api_url+self.HOST_VM_DETECTION, data=params,
                   headers=self.headers, verify=certifi.where())

        if r.status_code == 200:
            xd = xmltodict.parse(r.text)
            host_list = []
            x2d_hl = xd['HOST_LIST_VM_DETECTION_OUTPUT']['RESPONSE']['HOST_LIST']['HOST']
            if isinstance(x2d_hl, dict):
                hl = reduce_to_dict(x2d_hl)
                host_list.append(hl)
                return host_list
            for i in x2d_hl:
                hl = reduce_to_dict(i)
                host_list.append(hl)
            return host_list
        
        raise Exception("Failed to obtain the host list")
        return r

    def do_kb_vuln(self, details="All", ids=None, is_patchable=1,  use_last=True):
        params = { "action": "list",
                   "is_patchable":is_patchable,
                   "details": details
                 }
        if ids:
            params['ids'] = ids


        if use_last:
            last_modified_after =  self.last_date.strftime('%Y-%m-%d')
            params['last_modified_after'] = last_modified_after
            self.last_date = datetime.now()

        r = self.session.post(self.qualys_api_url+self.KB_VULN_PATH, data=params,
                   headers=self.headers, verify=certifi.where())

        # if r.status_code == 200:
        #     xd = xmltodict.parse(r.text)
        #     host_list = []
        #     x2d_hl = xd['HOST_LIST_VM_DETECTION_OUTPUT']['RESPONSE']['HOST_LIST']['HOST']
        #     for i in x2d_hl:
        #         hl = reduce_to_dict(i)
        #         host_list.append(hl)
        #     return host_list
        
        # raise Exception("Failed to obtain the host list")
        return r

    def do_host_info(self, host_ip=None, host_dns=None, host_netbios=None, general_info=1, vuln_details=1):
        if host_ip is None and host_dns is None and host_netbios is None:
            return self.do_host_assets()
        params = {'general_info': general_info, 'vuln_details': vuln_details}
        if host_ip:
            params['host_ip'] = host_ip
        if host_netbios:
            params['host_netbios'] = host_netbios
        if host_dns:
            params["host_dns"] = host_dns
        r = self.session.get(self.qualys_api_url+self.HOST_INFO, params=params,
                   headers=self.headers, verify=certifi.where())
        return r

    def get_host_info(self, host_ip=None, host_dns=None, host_netbios=None, general_info=1, vuln_details=1):
        self.do_login()
        l = self.do_host_info(host_ip=host_ip, host_dns=host_dns, 
                              host_netbios=host_netbios, general_info=general_info, vuln_details=vuln_details)
        self.do_logout()
        return l        

    def get_host_assets(self, truncation_limit=10, use_last=False):
        self.do_login()
        l = self.do_host_assets(truncation_limit=truncation_limit, use_last=use_last)
        self.do_logout()
        return l

    def get_vm_detections(self, truncation_limit=10, use_last=False, ips=None, ids=None):
        self.do_login()
        l = self.do_host_vm_detection(truncation_limit=truncation_limit, use_last=use_last,
                                      ips=ips, ids=ids)
        self.do_logout()
        return l

if __name__ == "__main__":
    username = os.environ['QUALYSUSR']
    password = os.environ['QUALYSPW']
    hostname = 'qualysguard.qg3.apps.qualys.com'

    s = QConnector(username, password, hostname)
    hosts = s.get_host_assets()
    print(hosts)