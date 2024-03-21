"""
demo.py
This program demonstrates using some classes in the Python Uptycs API module: uptapi
"""

import json
import sys
sys.path.insert(1, '..')   # add the parent directory to the module path (uptapi is expected there in some dev environments)
import uptapi
import warnings
warnings.filterwarnings("ignore")

# the first argument should be the api key filename
api_key_file = ''
domain_suffix = ''
for i in range(1, len(sys.argv)):
    if i == 1:
        api_key_file = sys.argv[i]
    elif sys.argv[i] == '--domainsuffix' or sys.argv[i] == '-d':
        domain_suffix = sys.argv[i + 1]

if not api_key_file:
    print('Usage: uptdemo.py <api_key_file> [--domainsuffix <domain>]')
    sys.exit(1)

auth = uptapi.UptApiAuth(api_key_file, domain_suffix=domain_suffix)

# get JSON for all assets
assets = uptapi.UptAssets(auth)
print('JSON for the first asset:')
for a in assets.items:
    print(a)
    break

# get one asset's hostname (here we do so for item[0], the first asset)
hostname = assets.items[0]['hostName']
# lookup the id of the asset from the hostname and print the asset's tags
id = assets.get_id_from_hostname(hostname)
print("\nTags for asset id: %s, hostname: %s" % (id, hostname))
asset_json = assets.get_json_from_id(id)
print(asset_json['tags'])

print('Adding tag mytag=myvalue to %s' % hostname)
assets.add_tag(id, 'mytag=myvalue')
# assets.remove_tag(id, 'mytag=myvalue')

print('\nHostname, OS, and last activity time (first 3 assets)')
i = 1
for a in assets.items:
    if i > 3:
        break
    print('Hostname: %s, OS: %s, Last Activity: %s' % (a['hostName'], a['osDisplay'], a['lastActivityAt']))
    i += 1

# Query Uptycs global store.
# Get unique list of processes and open socket remote IP addresses, since yesterday, across all assets (limit to 5 rows for brevity)
sql = """SELECT DISTINCT p.upt_hostname, p.path, remote_address
         FROM processes p, process_open_sockets pos
         WHERE p.pid = pos.pid AND pos.upt_day = p.upt_day
         AND p.upt_asset_id = pos.upt_asset_id
         AND p.upt_day > CAST(date_format(current_date - interval '1' day,'%Y%m%d') AS INTEGER) 
         AND remote_address <> '' AND remote_address <> '0.0.0.0' LIMIT 5"""
query_global = uptapi.UptQueryGlobal(auth, sql)
print('\nGlobal query result for processes with remote address since yesterday (limit 5 rows for brevity):')
print(query_global.col_names_csv())
print(query_global.row_data_csv())

# query Uptycs realtime, all Ubuntu assets, for process name starting with 'sy'
sql = "SELECT uid, pid, name, path FROM processes p WHERE p.name LIKE 'sy%'"
filter = {"os": {"equals": "Ubuntu"} }
query_rt = uptapi.UptQueryRt(auth, sql, filter)
print('Realtime query result for processes starting with "sy" from Ubuntu machines (realtime query), print 5 rows for brevity:')
i = 1
for row in query_rt.rows:
    if i > 5:
        break
    print(row)
    i += 1

# query the Global DB to get the asset group id for the 'assets' group
sql = "select name, id from upt_asset_groups where name = 'assets'"
query_global = uptapi.UptQueryGlobal(auth, sql)
asset_group_id = query_global.response_json['items'][0]['id']
print('\nDefault asset group id: %s' % asset_group_id)

# list unique osFlavor values from the osqueryPackages API
result = uptapi.UptApiCall(auth, '/osqueryPackages', 'GET', {})
unique_flavors = []
for item in result.response_json['items']:
    if 'osFlavor' in item and item['osFlavor'] not in unique_flavors:
        unique_flavors.append(item['osFlavor'])
print('\nPossible OS values for /packageDownloads API')
for osFlavor in unique_flavors:
    print('OS: %s' % osFlavor)
# or you can print the entire API response JSON
#string = json.dumps(result.response_json, indent = 4)
#print('\n %s' % string)

# download the osquery package for AssetGroup=assets (asset_group_id captured above) and osFlavor=debian
print('\nDownloading ubuntu/debian osquery package for asset_group=assets...')
result = uptapi.UptApiCall(auth, '/packageDownloads/osquery/debian/'+asset_group_id, 'GET', {})
# Package filename is returned in the headers (example format below):
# 'Content-Disposition': 'attachment; filename="assets-osquery-5.3.0.11-Uptycs.deb"',
filename = result.headers['Content-Disposition'].split("filename=",1)[1].replace('"', '')

# Note the default package downloads are for x86 and do not include UptycsProtect
# For UptycsProtect(Remediate) and Graviton packages, specify API endpoint parameters as shown below:
# /packageDownloads/osquery/debian/<asset_group_id>?remediationPackage=true&gravitonPackage=true

# write the binary package (result.content) to a file
with open(filename, 'wb') as f:
    f.write(result.content)
print('Package saved to %s' % filename)

