#### Setup Environment

##### Python Setup
```bash
git clone https://github.com/deeso/qconnector
cd qconnector

# create the virtual environment (first setup)
python3 -m venv qc-venv
source qc-venv/bin/activate
pip3 install -r requirements

# update the environment variables
cp docker/environment docker/my_environment
source qc-venv/bin/activate
source docker/my_environment
```

##### Boiler Plate for getting host information
```python
from qconnector.qc import QConnector
import os
username = os.environ['QUALYSUSER']
password = os.environ['QUALYSPW']
hostname = os.environ['QUALHST']
s = QConnector(username, password, hostname)
hosts = s.get_host_assets(truncation_limit=1000000)
print(hosts[:2])

ip = hosts[0]['ip']
vm = s.get_vm_detections(ips=ip)
print(vm)
```

##### Setting up Docker
```bash
# make sure database.env variables)
# POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_DB
# match my_environment (environment) DATABASE_URI

cd docker
docker-compose up
```

##### Python Initialize Database
```python
from qconnector.qc_orm import init_db
init_db()
```

##### Python Inserting Objects in the database
```python
from qconnector.qc_orm import *
from qconnector.qc import *
init_db()
username = os.environ['QUALYSUSER']
hostname = os.environ['QUALHST']
password = os.environ['QUALYSPW']
s = QConnector(username, password, hostname)
hosts = s.get_host_assets(truncation_limit=10)

hinfos = []
hinfo = None
for host in hosts:
    hinfo = HostInfo.get(**host) 
    hinfos.append(hinfo)

vm_infos = s.get_vm_detections(ips=hinfo.ip)
vuln_info = VulnInfo.get(hid=hinfo.id, **vm_infos[0]['detection_list']['detection'][0])
hinfo.add_vuln_info(vuln_info)

k = db_session.query(HostInfo).filter(HostInfo.id==hinfo.id)
print(k[0].id, k[0].vuln_infos[0].id)
```

hi