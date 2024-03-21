import sys
sys.path.insert(1, '..')   # add the parent directory to the module path (uptapi is expected there in some dev environments)
import json
import uptapi
import warnings
warnings.filterwarnings("ignore")  

# the first argument should be the api key filename
api_key_file = ''
for i in range(1, len(sys.argv)):
    if i == 1:
        api_key_file = sys.argv[i]

if not api_key_file:
    print('Usage: python3 get_exceptions.py <api_key_file>')
    sys.exit(1)

auth = uptapi.UptApiAuth(api_key_file)

exceptions = uptapi.UptApiCall(auth, '/exceptions', 'GET', {})

# print the whole json response
#print(json.dumps(exceptions.response_json))

# print each of the response items (exceptions)  
for item in exceptions.response_json['items']: 
   print(json.dumps(item))
   