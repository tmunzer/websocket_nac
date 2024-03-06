# Mist Websockets Examples

This repository is listing some simple working examples of code using the Mist Websockets.


## MIT LICENSE
 
Copyright (c) 2022 Thomas Munzer

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the  Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


## Test instruction
1. Upgrade distro and install screen
```
stag@raspberrypi:~/websocket_nac/src $ sudo apt update && sudo apt dist-upgrade -y && sudo apt install screen
[...]
stag@raspberrypi:~ $
```


2. clone the project repository and go to the `<project_root>/src` folder
```
stag@raspberrypi:~ $ git clone https://github.com/tmunzer/websocket_nac
Cloning into 'websocket_nac'...
remote: Enumerating objects: 72, done.
remote: Counting objects: 100% (72/72), done.
remote: Compressing objects: 100% (45/45), done.
remote: Total 72 (delta 30), reused 65 (delta 23), pack-reused 0
Receiving objects: 100% (72/72), 56.31 KiB | 2.01 MiB/s, done.
Resolving deltas: 100% (30/30), done.
stag@raspberrypi:~ $ cd websocket_nac/src
stag@raspberrypi:~/websocket_nac/src
```


3. create the environment file to store the important information
```
stag@raspberrypi:~/websocket_nac/src $ vi ~/.mist_env
```

Environment file example:
```
MIST_HOST = api.mist.com
MIST_APITOKEN = xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
MIST_ORG_ID = 203d3d02-xxxxx-xxxxx-xxxxx-76896a3330f4
MIST_SITE_ID = f5fcbee5-xxxxx-xxxxx-xxxxx-1619ede87879
```


4. create the Python virtual environment to run the script and activate it
```
stag@raspberrypi:~/websocket_nac/src $ python3 -m venv ~/.venv/websocket_nac
stag@raspberrypi:~/websocket_nac/src $ source ~/.venv/websocket_nac/bin/activate
(websocket_nac) stag@raspberrypi:~ $
```

5. insall script dependencies
```
(websocket_nac) stag@raspberrypi:~/websocket_nac/src $ python3 -m pip install -r requirements.txt
[...]
(websocket_nac) stag@raspberrypi:~/websocket_nac/src $
```

6. start the script
```
(websocket_nac) stag@raspberrypi:~/websocket_nac/src $ python3 ./acct_server.py --ppsk_sync_org --syslog_server=10.3.20.16
MIST_HOST     : api.mist.com
MIST_WS_HOST  : api-ws.mist.com
MIST_APITOKEN : jXrX3L...xw9Uyv
MIST_ORG_ID   : 203d3d02-dbc0-4c1b-9f41-76896a3330f4
MIST_SITE_ID  : f5fcbee5-fbca-45b3-8bf1-1619ede87879
onopen
{'event': 'channel_subscribed', 'channel': '/sites/f5fcbee5-fbca-45b3-8bf1-1619ede87879/stats/clients'}
[...]
```

Script Parameters
| Script Parameter | Default | Description |
|-----------------|---------|--------------|
|--ppsk_sync_org | N/A | Enable Mist Org PPSK synchronisation. Used to set the client username with the PPSK name |
|--ppsk_sync_sites | N/A | Enable Mist Sites PPSK synchronisation. Used to set the client username with the PPSK name |
|--ppsk_interval= | 3600 |Interval between PPSK synchronisations, in secondes |
|--radius_server= | N/A | RADIUS Server IP Address where to send the Accountingmessages to Setting this parameter is enabling RADIUS Accounting |
|--radius_port= | 1813 | RADIUS Server Port where to send the Accounting messages to |
|--radius_secret= | secrect | RADIUS shared secret |
|--syslog_server= | N/A | SYSLOG Server IP Address where to send the Accounting messages to. Setting this parameter is enabling SYSLOG  Accounting |
|--syslog_port= | 514 | RADIUS Server Port where to send the Accounting SYSLOG to |
|--interim_interval= | 60 | Interval between each ACCT INTERIM Message, in seconds. 0 to disable ACCT INTERIM Messages. |
|--client_timeout= | 120 | Duration before marking a client as disconnected if Mist is no more sending update, in seconds. Once a client is marked as disconnected, an ACCT Stop message will be sent and the client data will be removed. (minimum: 120, maximum: 3600) |
|-l, --log_file= | None | define the filepath/filename where to write the logs. If not set, logs are displayed on the console |
|-e, --env= | ~/.mist_env | define the env file to use (see mistapi env file documentation here: https://pypi.org/project/mistapi/) |