#!/usr/bin/python3
"""
api_call.py -k <api_key_file> -m <method> -a <api_endpoint> [-D <payload_file>]
This script calls an API with a method and optionally supplies a payload file (for POST method)
It can be used for example to submit a query job
  python3 api_post.py -k my_api_key_file -m POST -a /query_job -D my_payload_file
Where my_payload_file contains:
{
  "query": "select * from processes limit 100 "
}

It can also be used for example to GET assets
  python3 api_post.py -k my_api_key_file -m GET -a /assets
"""

import sys
import json
import warnings
warnings.filterwarnings("ignore")
sys.path.insert(1, '..')   # add the parent directory to the module path (uptapi is expected there in JW dev)
import uptapi

usage='Usage: python3 api_call.py -k <apikey_file> -m <method> -a <api_endpoint> -D <payload_file>'

method = ''
api_key_file = ''
api_endpoint = ''
payload_file = ''

# loop thru all the args
for i in range(1, len(sys.argv)):
    if sys.argv[i] == '--keyfile' or sys.argv[i] == '-k':
        api_key_file = sys.argv[i + 1]
    if sys.argv[i] == '--method' or sys.argv[i] == '-m':
        method = sys.argv[i + 1]
    if sys.argv[i] == '--api' or sys.argv[i] == '-a':
        api_endpoint = sys.argv[i + 1]
    if sys.argv[i] == '--postdatafile' or sys.argv[i] == '-D':
        payload_file = sys.argv[i + 1]

if not api_key_file or not method or not api_endpoint:
    print('Usage: ./api_call.py -k <api_key_file> -m <method> -a <api_endpoint> [-D payload_file]')
    sys.exit(1)

# read the Uptycs API key file
auth = uptapi.UptApiAuth(api_key_file)

# read the payload from the payload file (if provided)
if payload_file:
    print('Reading payload from file %s' % payload_file )
    with open(payload_file) as f:
        data = f.read()
        payload = json.loads(data)
else:
    payload = {}
    
# make the API call
#print('Calling %s on %s' % (method, api_endpoint) )
api_call = uptapi.UptApiCall(auth, api_endpoint, method, payload)

# print the response json
print(api_call.response_json)
