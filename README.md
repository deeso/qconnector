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
```
