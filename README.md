# uptapi
Uptycs API Python SDK

This python SDK allows users to access the Uptycs API providing they have a valid API key file. 

Install the requirements: 
`pip install -r requirements.txt`

This example runs the demo program:  
`python3 uptdemo.py <api_keyfile.json>`  
The demo program includes the following use cases:
 - List asset details
 - List asset tags
 - Add a tag to an asset
 - Print the default asset group id
 - Run a realtime query
 - Run a global (historic) query
 - Download an install package

  
These examples show how to hit an arbitary Uptycs API endpoint: 
```
python3 api_call.py -k <api_keyfile.json> -m POST -a /query -D query_payload.json
python3 api_call.py -k <api_keyfile.json> -m GET  -a /assets 
 
api_call.py options:
  -k, --keyfile TEXT              Uptycs json key file.
  -m, --method TEXT               restAPI method [GET|POST|PUT|DELETE]]
  -a, --api TEXT                  API endpoint name [/alerts, /assets, etc]
  -D, --postdatafile TEXT         post json data file
```

   
This example gets event/alert rule exceptions then filters using grep:  
`python3 get_exceptions.py <api_keyfile.json> | grep <search-string>`
