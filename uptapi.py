"""
uptapi.py
Uptycs API helper library (for Python 3)

Requires: PyJWT, requests

This modules contains classes to interact with the Uptycs API using Python
Some commonly used classes include:
   UptApiAuth()     - Read an Uptycs API key file and create authorization header
   UptApiCall()     - Call an Uptycs API method
   UptAlertRule()   - Get or Create an alert rule
   UptAssets()      - Show/update assets registered in Uptycs, add/remove tags from assets
   UptEventRule()   - Get or Create an event rule
   UptLkpTable()    - Get or Create a lookup table (typically for whitelists/blacklists)
   UptQueryGlobal() - Run a query against global (flight recorder)
   UptQueryRt()     - Run a query against realtime

 Revision History
   2019.09.06   jwayte@uptycs.com  Initial Version
   2019.09.13   jwayte@uptycs.com  Added support for DELETE in UptApiCall class
   2019.09.18   jwayte@uptycs.com  Added UptLkpTable class
   2019.10.29   jwayte@uptycs.com  Added UptEventRules class
   2019.11.11   jwayte@uptycs.com  Updated UptEventRules class to call /eventRules/<id> to get more details (intervalSeconds, tableName, etc.)
                                   Changed UptAlertRuleQuery class to UptQuery
   2019.11.13   jwayte@uptycs.com  Added methods UptAlertRules.get_rule_by_name() and UptAlertRule.add_query()
   2019.11.18   jwayte@uptycs.com  Added optional name_list parameter to class UptAlertRules, to limit alerts written to memory.
   2019.11.19   jwayte@uptycs.com  Added UptQuery.post_from_file() to write/overwrite query from json file
   2019.11.25   jwayte@uptycs.com  Added logic to UptEventRules and UptAlertRules to print message if 0 rules returned.
                                   Added UptEventRule.disable() UptAlertRule.disable() method
   2019.12.05   jwayte@uptycs.com  Changed UptQuery to add parameter and make more parameters named
   2019.12.05   jwayte@uptycs.com  Changed UptQuery to add parameter and make more parameters named
   2019.12.12   jwayte@uptycs.com  Added UptReport and UptReports classes
   2020.01.30   jwayte@uptycs.com  Added UptQuery.write() method to write query JSON to file
   2020.04.09   jwayte@uptycs.com  Added UptDestination and UptDestinations classes to allow setting alert rule destinations
   2020.04.22   jwayte@uptycs.com  Updated classes UptAlertRule, UptEventRule, UptQuery to add self.json member and self.set_json() method
   2020.06.10   jwayte@uptycs.com  Updated class LogHandler to allow filename to be specified
   2020.06.15   jwayte@uptycs.com  Added support for custom domain_suffix in class UptApiAuth
   2020.06.22   jwayte@uptycs.com  Updated UptApiAuth to support JSON input arg for API key fields: key, secret, customerId, domain
   2020.07.08   jwayte@uptycs.com  Added message to check --domainsuffix if failed UptAuth, added UptAuth.tenant_url property
   2020.07.14   jwayte@uptycs.com  Added UptReports.delete()
   2020.07.17   jwayte@uptycs.com  Added type "builder" to event and alert rules
   2020.07.22   jwayte@uptycs.com  Added LogHandler.set_level() to allow for debug level logging at runtime
   2020.08.24   jwayte@uptycs.com  Added support for all JSON elements in Wizard event/alert rules
   2020.08.27   jwayte@uptycs.com  Added UptReport.get_full_json to populate full report json to self.json
   2020.09.17   jwayte@uptycs.com  Added logic to handle export of event rules with no tags
   2020.12.11   jwayte@uptycs.com  Added code to support download of agents
   2021.11.15   jwayte@uptycs.com  Added UptQueryGlobal.write_csv()
   2022.02.08   jwayte@uptycs.com  Updated UptApiAuth to work with jwt 2.3
   2022.05.05   jwayte@uptycs.com  Added exp: header in jwt encryption for API authorization
   2022.10.11   jwayte@uptycs.com  Added capturing response.headers in UptApiCall(), to get filename of package download
   2023.01.13   jwayte@uptycs.com  Add UptThreatBook() class to allow running a Threat Book and viewing run results

"""

import json
import requests
import sys
import jwt
import datetime
import logging
import os
import datetime
import time

TIMEOUT = 60


class LogHandler:
    """ Allows logging to file and console simultaneously.
        Includes datetime & class name in the output, along with the log message.
    """
    def __init__(self, logger_name, filename=''):
        if len(filename) > 0:
            log_filename = filename
        else:
            log_filename = 'uptapi.log'
        FORMAT = '%(asctime)15s: %(name)s: %(message)s'
        logging.basicConfig(filename=log_filename, format=FORMAT, level=logging.INFO)
        self.logger = logging.getLogger(logger_name)
        # and console handler so log messages go to screen too
        consoleHandler = logging.StreamHandler()
        logFormatter = logging.Formatter(FORMAT)
        consoleHandler.setFormatter(logFormatter)
        if not len(self.logger.handlers):
            self.logger.addHandler(consoleHandler)

    def debug(self, msg):
        self.logger.debug(msg)

    def info(self, msg):
        self.logger.info(msg)

    def warning(self, msg):
        self.logger.warning(msg)

    def error(self, msg):
        self.logger.error(msg)

    def critical(self, msg):
        self.logger.critical(msg)

    def set_level(self, level):
        self.logger.setLevel(level=level)


class UptApiCall:
    """ Class to call any Uptycs API
        Future enhancement could add support for /url?param=value filters
        self.rc = 0 on success, 1 on error
    """
    def __init__(self, upt_auth, api_endpoint, method, payload):
        auth = upt_auth
        current_utc = datetime.datetime.utcnow()
        self.logger = LogHandler('uptapi.UptApiCall ' + str(current_utc))
        self.logger.debug('Calling ' + method + ', on API endpoint: ' + api_endpoint + ', url: ' + upt_auth.base_url)

        self.items = [] # this can be set by calling get_items() (if method = GET)
        self.content = '' # to store the agent binary data if applicable

        if method == 'GET' and api_endpoint.startswith('/packageDownloads/'):
            response = requests.get(auth.base_url + api_endpoint, headers=auth.header, verify=False, timeout=TIMEOUT, allow_redirects=True)
            self.content = response.content  # agent binary
            self.headers = response.headers
        elif method == 'GET':
            response = requests.get(auth.base_url + api_endpoint, headers=auth.header, verify=False,timeout=TIMEOUT)
            self.response_json = response.json()
            self.headers = response.headers
        elif method == 'POST':
            payload_json = json.dumps(payload)
            response = requests.post(auth.base_url+api_endpoint, headers=auth.header, data=payload_json, verify=False, timeout=TIMEOUT)
            self.response_json = response.json()
            self.headers = response.headers
        elif method == 'PUT':
            payload_json = json.dumps(payload)
            response = requests.put(auth.base_url + api_endpoint, headers=auth.header, data=payload_json, verify=False, timeout=TIMEOUT)
            self.response_json = response.json()
            self.headers = response.headers
        elif method == 'DELETE':
            response = requests.delete(auth.base_url + api_endpoint, headers=auth.header, data={}, verify=False, timeout=TIMEOUT)
            self.headers = response.headers
        else:
            self.logger.error("Error! Method must be 'GET', 'POST', 'PUT', or 'DELETE'. Supplied method was: "+method)
            sys.exit(1)

        # check response status code, 200 is success
        if (response.status_code != 200):
            self.logger.error("Error during "+method+" on "+api_endpoint+", url: "+ auth.tenant_url)
            self.logger.error(json.dumps(response.json(), indent=4))
            self.rc = 1
        else:
            self.logger.debug("Success with "+method+" on "+api_endpoint+", url: "+auth.tenant_url)
            self.rc = 0

    def get_items(self):
        # store each JSON item in a collection
        for i in self.response_json['items']:
            self.items.append(i)


class UptAssets:
    """ A class to handle Uptycs assets
    """
    def __init__(self, upt_auth):
        """ Call Uptycs /assets API and save total asset JSON in one variable: response_json """
        self.logger = LogHandler(str(self.__class__))
        self.auth = upt_auth
        # get all asset JSON by calling /assets API
        assets = UptApiCall(self.auth, '/assets', 'GET', {})
        self.response_json = assets.response_json
        self.items = []
        for asset in self.response_json['items']:
            self.items.append(asset)
        self.count = len(self.items)

    def get_id_from_hostname(self, hostname):
        """ Lookup the asset id from the hostname.
            Note: if more than one asset has this hostname, only the first will be returned. """
        for a in self.items:
            if a['hostName'] == hostname:
                return a['id']
        # if no matching hostname return -1
        return -1

    def get_json_from_id(self, id):
        """ Lookup the asset's JSON from the asset id. """
        for a in self.items:
            if a['id'] == id:
                return a
        # if no matching id return -1
        return -1

    def add_tag(self, id, tag):
        """ Add a tag to an asset (by asset_id).
            Tags can be passed as a key (e.g. 'mytag').
            Or tags can be passed as key=value (e.g. 'mytag=myvalue') """
        # get the existing tags for the asset
        asset_json = self.get_json_from_id(id)
        asset_tags = asset_json['tags']
        # add the new tag --add code to check if already there and give warning
        if tag in asset_tags:
            self.logger.warning('Did not add tag: %s, asset id: %s already has that tag.' % (tag, id))
        else:
            asset_tags.append(tag)
            # create the payload and PUT the new tags
            payload = { "tags": asset_tags }
            UptApiCall(self.auth, '/assets/'+id, 'PUT', payload)

    def remove_tag(self, id, tag):
        """ Remove a tag from an asset (by asset_id).
            Tags can be passed as a key (e.g. 'mytag').
            Or tags can be passed as key=value (e.g. 'mytag=myvalue') """
        # get the existing tags for the asset
        asset_json = self.get_json_from_id(id)
        asset_tags = asset_json['tags']
        # remove the specified tag --add code to check if not there and give warning
        if tag in asset_tags:
            asset_tags.remove(tag)
            # create the payload and PUT the new tag set (with the one tag removed)
            payload = {"tags": asset_tags}
            UptApiCall(self.auth, '/assets/' + id, 'PUT', payload)
        else:
            self.logger.warning('Did not remove tag: %s, asset id: %s does not have it.' % (tag, id))


class UptAlertRule:
    """ Uptycs alert rules can be of type 'sql' or 'javascript'
        A collection of these objects is returned by the class UptAlertRules.
        Each alert rule can contain 0 or more alert rule context queries.
        An alert rule can be written to Uptycs with the post() method
        Note: For better resiliency consider future change: remove hard coded field names (e.g. self.code) for free form JSON elements
    """

    def __init__(self, name='', code='', description='', rule='', type='', grouping='', interval_seconds=0, id='', event_code='', event_min_severity='low', json=''):
        self.logger = LogHandler(str(self.__class__))
        self.json = {}
        self.alert_tags = []
        if json:
            self.name = json['name']
            self.code = json['code']
            self.description = json['description']
            self.rule = json['rule']  # SQL or Javascript code
            self.type = json['type']
            # tags
            if json['alertTags']:
                for t in json['alertTags']:
                    self.alert_tags.append(t)
            if json['type'] == "sql":
                self.interval_seconds = json['sqlConfig']['intervalSeconds']
            elif json['type'] in ["javascript"]:
                self.event_code = json['scriptConfig']['eventCode']
                self.event_min_severity = json['scriptConfig']['eventMinSeverity']
            elif json['type'] in ["builder", "uptycs"]:
                do = 'nothing'
            else:
                print('Error! Alert rule type must be "sql", "javascript", "builder", or "uptycs". Value provided: ' + type)
                sys.exit(1)
            self.grouping = json['grouping']
            self.alert_rule_queries = []  # this is populated in a call to get_alert_rule_queries()
            self.get_alert_rule_queries(json)

        else:
            self.name = name
            self.code = code
            self.description = description
            self.rule = rule                           # SQL or Javascript code
            if type not in ["sql", "javascript", "builder", "uptycs"]:
                print('Error! Alert rule type must be "sql", "javascript", "builder", or "uptycs". Value provided: '+type)
                sys.exit(1)
            self.type = type
            self.grouping = grouping
            self.interval_seconds = interval_seconds  # only applies to 'sql' type
            self.id = id
            self.event_code = event_code
            self.event_min_severity = event_min_severity
            self.alert_rule_queries = []    # this is populated in a call to get_alert_rule_queries()
        self.set_json()

    def add_query(self, upt_auth, query_name):
        """ Adds (context) query (by name) to the alert rule """
        print("Adding query: '%s' to alert rule: '%s'" % (query_name, self.name))
        auth = upt_auth

        # Get the new query fields (we will need queryId)
        queries = UptQueries(auth)
        new_query = queries.get_query_by_name(query_name)

        # Start building the JSON payload, add any existing queries first
        alertRuleQueries = []
        for q in self.alert_rule_queries:
            alertRuleQueries.append({"queryId": q.id})
            # return if the alert rule already has this query id
            if q.id == new_query.id:
                print('Alert rule already contains this context query')
                return 0

        # add the new queryId to the collection (for the JSON payload)
        alertRuleQueries.append({"queryId": new_query.id})
        # build the payload
        payload = {
            "alertRuleQueries": alertRuleQueries
        }
        # call the API to PUT the JSON payload
        result = UptApiCall(auth, '/alertRules/' + self.id, 'PUT', payload)
        # add the new query to the alert_rule_queries collection (so if another query is added, then the JSON will contain all)
        self.alert_rule_queries.append(new_query)

    def disable(self, upt_auth):
        """ Disable an alert rule """
        auth = upt_auth
        payload = { "enabled": False }
        result = UptApiCall(auth, '/alertRules/'+self.id, 'PUT', payload)
        if result.rc == 0:
            print("Disabled alert rule: '%s' on tenant: %s" % (self.name, auth.domain))

    def get_alert_rule_queries(self, alert_rule_json):
        """ Parse the alert rule JSON to create each query then add it to the collection: alert_rule_queries """
        alertRuleQueries = []
        for q in alert_rule_json['alertRuleQueries']:
            if 'id' in q:
                alert_rule_query = UptQuery(name=q['name'], description=q['description'], query=q['query'],
                                            type=q['type'], execution_type=q['executionType'], grouping=q['grouping'],
                                            shared=q['shared'], id=q['id'])
            else:
                alert_rule_query = UptQuery(name=q['name'], description=q['description'], query=q['query'], type=q['type'], execution_type=q['executionType'], grouping=q['grouping'], shared=q['shared'])

            alertRuleQuery = {"name": q['name'],
                              "description": q['description'],
                              "query": q['query'],
                              "type": q['type'],
                              "executionType": q['executionType'],
                              "grouping": q['grouping'],
                              "shared": q['shared']
                              }

            if q['parameters']:
                paramList = []
                for p in q['parameters']:
                    alert_rule_query.add_parameter(p['dataType'], p['key'], p['multiple'], p['optional'])
                    paramJson = { "dataType": p['dataType'],
                                  "key": p['key'],
                                  "multiple": p['multiple'],
                                  "optional": p['optional']
                                }
                    paramList.append(paramJson)
                self.alert_rule_queries.append(alert_rule_query)
                alertRuleQuery['parameters'] = paramList
            alertRuleQueries.append(alertRuleQuery)

        # add the alert rule queries to the alert rule JSON
        self.json["alertRuleQueries"] = alertRuleQueries

    def post(self, upt_auth, force=False):
        """ POST the alert rule and any context queries to Uptycs
            If the alert rule is aleady present and force is True then PUT to overwrite
        """
        auth = upt_auth

        # first import to Uptycs (POST) any (context) queries
        for q in self.alert_rule_queries:
            q.post(auth, force=force)

        # check to see if the alert rule already exists
        alert_rules = UptApiCall(auth, '/alertRules', 'GET', {})
        found = False
        id = ''
        for item in alert_rules.response_json['items']:
            if item['name'] == self.name:
                id = item['id']
                found = True
        if not found:
            print("Importing new alert rule: '%s' to tenant: %s" % (self.name, auth.tenant_url))
            result = UptApiCall(auth, '/alertRules', 'POST', self.json)
            if result.rc != 0:
                print("POST failed for alert rule: '%s' on tenant: %s" % (self.name, auth.tenant_url))
            # get the alert id after the post has occurred
            id = result.response_json['id']
        if found and force:
            print('Found alert rule with name: %s, overwriting it.' % self.name)
            result = UptApiCall(auth, '/alertRules/'+id, 'PUT', self.json)
            if result.rc != 0:
                print("Error importing alert rule: '%s' to tenant: '%s'" % (self.name, auth.tenant_url))
        elif found and not force:
            self.logger.warning('Found alert rule with name: %s, but force = False, so it will not be overwritten.' % self.name)
            return

        # update the alert rule with the context queries (using id)
        if not found or found and force:
            alertRuleQueries = []
            for q in self.alert_rule_queries:
                alertRuleQueries.append({ "queryId": q.id })
            payload = {  "alertRuleQueries": alertRuleQueries }
            # call the API to PUT the queryId's onto the alert rule (this will add the context queries)
            result = UptApiCall(auth, '/alertRules/'+id, 'PUT', payload)

    def set_destination(self, upt_auth, destination_id):
        """ Set the destination on an alert rule """
        auth = upt_auth
        payload = { "destinations": [ { "destinationId": destination_id } ]
                  }
        result = UptApiCall(auth, '/alertRules/'+self.id, 'PUT', payload)

    def set_json(self):
        # build the base alert rule JSON
        self.json = {
            "name": self.name,
            "code": self.code,
            "description": self.description,
            "rule": self.rule,
            "type": self.type,
            "grouping": self.grouping,
            "alertTags": self.alert_tags
        }
        # add type specific elements
        if self.type == 'sql':
            self.json["sqlConfig"] = {"intervalSeconds": self.interval_seconds}
        elif self.type == 'javascript':
            self.json["scriptConfig"] = {   "eventCode": self.code,
                                            "eventMinSeverity": self.event_min_severity
                                        }
        elif self.type == 'builder':
            self.json['builderConfig'] = {}


class UptAlertRules:
    """ A collection of alert rules retrieved from one API call '/alertRules GET'
        And a call for each alert rule to /alertRules/<id> GET', for the context queries
        An optional "name_list" can be provided to limit the alert rules
    """

    def __init__(self, api_auth, name_list = [], event_code_list = [], silent=False):
        auth = api_auth
        self.alert_rules = []
        ar_api = UptApiCall(upt_auth = auth, api_endpoint = '/alertRules', method = 'GET', payload={})
        for arj in ar_api.response_json['items']:
            if arj['name'] in name_list \
               or (arj['type'] == "javascript" and arj['scriptConfig']['eventCode'] in event_code_list ) \
               or (arj['type'] == "builder" and arj['code'] in event_code_list ) \
               or len(name_list) == 0 and len(event_code_list) ==0:
                if not silent:
                    print("Exporting alert rule: '%s' from tenant: '%s'" % (arj['name'], auth.tenant_url))
                alert_rule = UptAlertRule(json=arj)
                alert_rule.get_alert_rule_queries(arj)
                self.alert_rules.append(alert_rule)
        self.count = len(self.alert_rules)
        if self.count == 0:
            print('Warning, 0 alert rules, check that you provided the correct alert rule name(s)')

    def get_rule_by_code(self, code):
        """ Return the alert rule that matches the passed code. """
        for ar in self.alert_rules:
            if ar.code == code:
                return ar

    def get_rule_by_name(self, name):
        """ Return the alert rule that matches the passed name. """
        for ar in self.alert_rules:
            if ar.name == name:
                return ar

    def print(self):
        for ar in self.alert_rules:
            print('Alert Rule Name: %s' % ar.name)
            print('  Code: %s' % ar.code)
            for arq in ar.alert_rule_queries:
                print('  Context Query: %s' % arq.query)


class UptApiAuth:
    """ Uptycs API Authorization created from an API key file or api_config_json.
        The key and secret are read then encoded with the jwt module to create the authorization header
        You can download an API key file from the Uptycs GUI: Configuration - Users
        If api config details provided in JSON then the following keys must be present: key, secret, domain, customerId """

    def __init__(self, api_config_file='', silent=True, logfile='', domain_suffix='', api_config_json={}):
        logger = LogHandler('uptapi.UptApiAuth', filename=logfile)

        # Cloud based calls provide api key details in request JSON (instead of an api key file)
        if api_config_json:
            if not silent:
                logger.info('Reading Uptycs API connection & authorization details from api_config_json')
            try:
                key = api_config_json['key']
                secret = api_config_json['secret']
                self.domain = api_config_json['domain']
                customer_id = api_config_json['customerId']
                if "domainSuffix" in api_config_json:
                    domain_suffix = api_config_json['domainSuffix']
            except:
                logger.info("api_config_json missing required key: 'key' or 'secret' or 'domain' or 'customerId'" )
                sys.exit(1)

        if api_config_file:
            try:
                if not silent:
                    logger.info('Reading Uptycs API connection & authorization details from %s' % api_config_file)
                data = json.load(open(api_config_file))
                key = data['key']
                secret = data['secret']
                self.domain = data['domain']
                customer_id = data['customerId']
            except:
                logger.error("Error loading JSON from API key file: %s" % api_config_file)
                logger.error("Please ensure you have a correct Uptycs API key file at path: "+api_config_file)
                sys.exit(1)

        if domain_suffix == '':
            self.base_url = "https://%s.uptycs.io/public/api/customers/%s" % (self.domain, customer_id)
            self.tenant_url = "https://%s.uptycs.io" % self.domain
        else:
            self.base_url = "https://%s%s/public/api/customers/%s" % (self.domain, domain_suffix, customer_id)
            self.tenant_url = "https://%s%s" % (self.domain, domain_suffix)
        
        t = time.time() + 60  # default to 60 secs expiration for the bearer toke
        try:
            authvar = jwt.encode({'iss': key, 'exp': t}, secret)
        except:
            logger.error("Error encoding key and secret with jwt module")
            sys.exit(1)

        authorization = ("Bearer %s" % authvar)
        
        self.header = {}
        self.header['authorization'] = authorization
        utcnow = datetime.datetime.utcnow()
        date = utcnow.strftime("%a, %d %b %Y %H:%M:%S GMT")
        self.header['date'] = date
        self.header['Content-type'] = "application/json"

        # make a call to /schema to ensure we can connect
        response = requests.get(self.base_url + '/schema', headers=self.header, data={}, verify=False,
                                 timeout=TIMEOUT)
        # check response for error code
        if (response.status_code != requests.codes.ok):
            logger.error("Error connecting to '%s'" % self.base_url )
            logger.info("Ensure your API key and --domainsuffix (if not '.uptycs.io') are correct")
            sys.exit(1)


class UptDestination:
    """ Uptycs destinations are used to send alerts to Slack, Email, PagerDuty, or HTTP (SIEM) """

    def __init__(self, name, type, address, id=''):
        self.name = name
        self.type = type    # email, slack, http, pager_duty  ## need to verify
        self.address = address
        self.id = id
        # need to add support for authentication elements


class UptDestinations:
    """ A collection of destinations retrieved from API call '/destinations GET' """

    def __init__(self, api_auth):
        auth = api_auth
        self.destinations = []
        dest_api = UptApiCall(upt_auth = auth, api_endpoint = '/destinations', method = 'GET', payload={})
        for d in dest_api.response_json['items']:
            print("Exporting Destination: '%s' from tenant: '%s'" % (d['name'], auth.domain))
            destination = UptDestination(name=d['name'], type=d['type'], address=d['address'], id=d['id'])
            self.destinations.append(destination)
        self.count = len(self.destinations)
        if self.count == 0:
            print('Warning, 0 destinations, check that you provided the correct destination name(s)')

    def get_destination_by_name(self, name):
        """ Return the destination that matches the passed name. """
        for d in self.destinations:
            if d.name == name:
                return d

    def print(self):
        for d in self.destinations:
            print('Destination Name: %s' % d.name)
            print('Destination Type: %s' % d.type)
            print('Destination Address: %s' % d.address)
            print('Destination Id: %s' % d.id)


class UptEventRule:
    """ An Uptycs event rule. A collection of these are created by calling UptEventRules.
        A new event rule can be written to an Uptycs tenant with the post() method.
        Can disable an event rule with the disable() method.
    """

    def __init__(self, name='', code='', description='', rule='', type='', grouping='', interval_seconds=0, id='', table_name='', added=True, json=''):
        self.logger = LogHandler(str(self.__class__))
        # if JSON passed in we parse the relevant pieces out
        if json:
            self.name = json['name']
            self.code = json['code']
            self.description = json['description']
            self.rule = json['rule']  # SQL or Javascript code
            self.type = json['type']
            # tags
            self.event_tags = []
            if json['eventTags']:
                for t in json['eventTags']:
                    self.event_tags.append(t)
            # conditional logic based on rule type
            if json['type'] == "sql":
                self.interval_seconds = json['sqlConfig']['intervalSeconds']
            elif json['type'] == 'javascript':
                self.table_name = json['scriptConfig']['tableName']
                self.added = json['scriptConfig']['added']
            elif json['type'] == 'builder':
                self.builder_config = json['builderConfig']
                if 'id' in self.builder_config:
                    del self.builder_config['id']
                if 'customerId' in self.builder_config:
                    del self.builder_config['customerId']
                if 'disableAlert' not in self.builder_config['autoAlertConfig']:
                    self.builder_config['autoAlertConfig'] = { "disableAlert": False }
            elif json['type'] == 'uptycs':
                nothing = 'to_do'
            else:
                print('Error! Event rule type must be "sql", "javascript", "builder", or "uptycs". Value provided: ' + self.type)
                sys.exit(1)
            self.grouping = json['grouping']

        else: #json not provided
            self.name = name
            self.code = code
            self.description = description
            self.rule = rule                           # SQL or Javascript code
            if type not in ['sql', 'javascript', 'builder', 'uptycs']:
                self.logger.error('Error! Alert rule type must be "sql", "javascript", "builder", or "uptycs". Value provided: '+type)
                sys.exit(1)
            self.type = type
            self.grouping = grouping
            self.interval_seconds = interval_seconds  # only applies to 'sql' type
            self.id = id
            self.table_name = table_name
            self.added = added
        self.json = {}
        self.set_json()

    def post(self, upt_auth, force=False):
        """ POST the event rule JSON to Uptycs using '/eventRules POST' """
        auth = upt_auth

        # check to see if the event rule already exists
        event_rules = UptApiCall(auth, '/eventRules', 'GET', {})
        found = False
        id = ''
        for item in event_rules.response_json['items']:
            if item['name'] == self.name:
                id = item['id']
                found = True
        if not found:
            print("Importing new event rule: '%s' to tenant: %s" % (self.name, auth.domain))
            result = UptApiCall(auth, '/eventRules', 'POST', self.json)
            if result.rc != 0:
                print("Error importing event rule: '%s'" % self.name)
        if found and force:
            print("Found event rule: '%s', overwriting it." % self.name)
            result = UptApiCall(auth, '/eventRules/'+id, 'PUT', self.json)
            if result.rc != 0:
                print("Error updating event rule: '%s' for overwrite" % self.name)
        if found and not force:
            self.logger.info('Found event rule with name: %s, but force = False, so it will not be overwritten.' % self.name)
            return 1

    def disable(self, upt_auth):
        """ Disable an event rule """
        auth = upt_auth
        payload = { "enabled": False }
        result = UptApiCall(auth, '/eventRules/'+self.id, 'PUT', payload)
        if result.rc == 0:
            print("Disabled event rule: '%s' on tenant: %s" % (self.name, auth.domain))

    def set_json(self):
        if self.type == "javascript":
            self.json = {  "name": self.name,
                           "code": self.code,
                           "description": self.description,
                           "rule": self.rule,
                           "type": self.type,
                           "grouping": self.grouping,
                           "eventTags": self.event_tags,
                           "scriptConfig": {
                               "tableName": self.table_name,
                               "added": self.added
                           }
                        }
        elif self.type == "builder":
            self.json = {"name": self.name,
                         "code": self.code,
                         "description": self.description,
                         "rule": self.rule,
                         "type": self.type,
                         "grouping": self.grouping,
                         "eventTags": self.event_tags,
                         "builderConfig": self.builder_config
                         }
        elif type == "sql":
            self.json = {  "name": self.name,
                           "code": self.code,
                           "description": self.description,
                           "rule": self.rule,
                           "type": self.type,
                           "sqlConfig": {"intervalSeconds": self.interval_seconds},
                           "grouping": self.grouping,
                           "eventTags": self.event_tags,
                       }
        else:  # type=uptycs
            self.json = {  "name": self.name,
                           "code": self.code,
                           "description": self.description,
                           "rule": self.rule,
                           "type": self.type,
                           "grouping": self.grouping,
                           "eventTags": self.event_tags,
                       }


class UptEventRules:
    """ A collection of all event rules retrieved from one API call to '/eventRules GET'
        Followed by a call for each event rule to /eventRules/<id> to get more details
    """

    def __init__(self, api_auth, name_list = []):
        auth = api_auth
        self.event_rules = []
        # get the base JSON for all event rules by calling /eventRules
        event_rules_json = UptApiCall(upt_auth = auth, api_endpoint = '/eventRules', method = 'GET', payload={})
        # parse the various JSON fields into UptEventRule objects
        count = 0
        for erj in event_rules_json.response_json['items']:
            id = erj['id']

            if erj['name'] in name_list or len(name_list) == 0:
                print("Exporting event rule: '%s' from tenant: %s" % (erj['name'], auth.tenant_url))
                # GET the individual JSON for the event rule (by id) from the Uptycs API
                single_event_rule = UptApiCall(upt_auth = auth, api_endpoint = '/eventRules/'+id, method = 'GET', payload={})
                # create the event object
                event_rule = UptEventRule(json=single_event_rule.response_json)

                count = count + 1
                self.event_rules.append(event_rule)


class UptLkpTable:
    """ Uptycs lookup table, can be used as whitelist/blacklist by Javascript alert rules. """

    def __init__(self, lkp_table_name):
        self.lkp_table_name = lkp_table_name
        self.id = ''
        self.row_count = 0
        self.active = False
        self.column_name = ''
        self.auth = ''
        self.logger = LogHandler(str(self.__class__))

    def create(self, upt_auth, column_name, sql='', data=[], force=False):
        """ Creates a lookup table with entries from the supplied 'data' array or from executing the supplied 'sql'.
            Note column_name must appear in the sql statement.
            If (force == True) then any existing lookup table of the same name will be overwritten
        """
        auth = upt_auth
        self.auth = upt_auth
        self.column_name = column_name

        # check to see if a lookup table already exists with the same name
        lookup_tables = UptApiCall(self.auth, '/lookupTables', 'GET', {})
        found = False
        for item in lookup_tables.response_json['items']:
            if item['name'] == self.lkp_table_name:
                id = item['id']
                found = True
        if found and force:
            # delete the lookup table
            self.logger.info('Deleting existing lookup table: %s' % self.lkp_table_name)
            delete_result = UptApiCall(auth, '/lookupTables/'+id, 'DELETE', {})
        elif found and not force:
            self.logger.warning('Found existing lookup table: %s' % self.lkp_table_name)
            self.logger.warning('Will not overwrite because force = False')
            return

        # if 'sql' provided then run the query to get the data
        if sql != '':
            self.logger.info('Running SQL to get data for lookup table')
            query = UptQueryGlobal(auth, sql)

            # convert the returned JSON to lookup table format (sample format below)
            ''' [   
                    {   "column_name": "value1",
                        "description": ""       
                    },
                    {   "column_name": "value2",
                        "description": ""  
                    }    
                ]'''
            data_filename = self.auth.domain + '_' + self.lkp_table_name + '_data.txt'
            self.logger.info('Writing query results to file: '+data_filename)
            # save the data to file so the user can look at it if necessary
            data_file = open(data_filename, "w")
            data_file.write("[")
            i = 1
            items = []
            for r in query.rows:
                item = {
                          column_name: r[column_name],
                          "description": ""
                       }
                items.append(item)                 # this is the collection we use to load the lookup table data below
                if i > 1:
                    data_file.write(',')
                data_file.write('\n'+str(item))    # this is the file we save to the lookup table data to (in case the user wants to see it)
                i += 1
            data_file.write("\n]")
        elif data:
            items = data
        else:
            self.logger.error('Error! Neither "data" nor "sql" parameter provided!')
            return

        # create the lookup table, we need to build the create JSON payload first
        lkp_table_json = {
                            "name": self.lkp_table_name,
                            "idField": column_name
                         }
        self.logger.info('Creating empty lookup table: ' + self.lkp_table_name)
        lkp_table_create = UptApiCall(auth, '/lookupTables', 'POST', lkp_table_json)
        id = lkp_table_create.response_json['id']

        # load the data
        if sql != '':
            self.logger.info('Loading lookup table data, copy saved to file: ' + data_filename)
        else:
            self.logger.info('Loading lookup table data')
        load_result = UptApiCall(auth, '/lookupTables/'+id+'/data', 'POST', items)

        # activate the lookup table
        activate_json = { "active": "true" }
        activate_result = UptApiCall(auth, '/lookupTables/' + id, 'PUT', activate_json)

    def get(self, upt_auth):
        """ Gets the id, active status, and row_count for an existing lookup table  """
        result = uptapi.UptApiCall(auth, '/lookupTables', 'GET', {})
        found = False
        for item in result.response_json['items']:
            if item['name'] == self.lkp_table_name:
                self.id = item['id']
                self.row_count = item['rowCount']
                self.active = item['active']
                break
        if not found:
            self.logger.error("Could not find lookup table: " + self.lkp_table_name)

    def get_data(self, upt_auth):
        """ Gets the data for an existing lookup table
            ** Cannot implement this method until there is an API method to GET data **
        """
        auth = upt_auth
        if not self.id:
            self.get()

        # get the lookup table data
        result = uptapi.UptApiCall(auth, '/lookupTables/'+self.id+'/data', 'GET', {})

        for item in result.response_json['items']:
            foo = 'bar' # add items to array here


    def add_row(self, value):
        """ Adds a row to a lookup table.
            Does so by dumping the existing lookup table data to JSON, reading it, adding one row,
            dropping the lookup table and recreating it.
        """

    def delete_row(self, value):
        """ Delets a row from a lookup table.
            Does so by dumping the existing lookup table data to JSON, reading it, deleting the row,
            dropping the lookup table and recreating it.
        """


#class UptOsqueryPackage:
    """ Uptycs osquery agent package.
        These are the osquery install agent packages 
    """


class UptQuery:
    """ Uptycs Query.
        These are queries such as those saved under Investigate or Context Queries used in Alert Rules.
        A query can be instantiated from a JSON file or by providing explicitly the name, description, query, type, etc.
        A query can also come from a query pack (in which case the table field can be used).
    """
    def __init__(self, name='', description='', query='', table_name='', type='', execution_type='', grouping='', shared='', id='', file='', parameters='', json=''):
        if json:
            self.name = json['name']
            self.description = json['description']
            self.query = json['query']
            self.type = json['type']
            self.executionType = json['executionType']
            self.grouping = json['grouping']
            self.shared = json['shared']
            self.query_parameters = []
            for p in json['parameters']:
                param = UptQueryParameter(p['dataType'], p['key'], p['multiple'], p['optional'])
                self.query_parameters.append(param)

        elif file:
            # open the JSON file and set the query elements from the JSON file values
            with open(file) as json_file:
                query_json = json.load(json_file)
                self.name = query_json['name']
                self.description = query_json['description']
                self.query = query_json['query']
                self.type = query_json['type']
                self.executionType = query_json['executionType']
                self.grouping = query_json['grouping']
                self.shared = query_json['shared']
                self.query_parameters = []
                for p in query_json['parameters']:
                    param = UptQueryParameter(p['dataType'], p['key'], p['multiple'], p['optional'])
                    self.query_parameters.append(param)

        else: # set the query elements directly from the passed in arguments
            self.name = name
            self.description = description
            self.query = query # the SQL statement
            self.tableName = table_name # the query-pack query table name
            self.type = type # 'default', 'vulnerability', etc.
            self.executionType = execution_type  # 'global' or 'realtime'
            self.grouping = grouping # Investigate group under which they are displayed
            self.shared = shared # 'true'
            self.id = id
            self.query_parameters = []
            if parameters:
                for p in parameters:
                    param = UptQueryParameter(p['dataType'], p['key'], p['multiple'], p['optional'])
                    self.query_parameters.append(param)

        self.json = {}
        self.set_json()

    def add_parameter(self, data_type, key, multiple, optional):
        """ Add a parameter to a query """
        p = UptQueryParameter(data_type, key, multiple, optional)
        self.query_parameters.append(p)

    def post(self, upt_auth, force=False):
        """ Create the JSON payload for the query and POST it to Uptycs """
        auth = upt_auth

        # check to see if the query already exists
        queries = UptQueries(auth)
        found = False
        for q in queries.queries:
            if self.name == q.name:
                id = q.id
                found = True
        if not found:
            # query does not yet exist so call the API to POST the query
            print("Importing new query: '%s' to tenant: %s" % (self.name, auth.domain))
            result = UptApiCall(auth, '/queries', 'POST', self.json)
            if result.rc != 0:
                print("Error importing query: '%s' to tenant: %s" % (self.name, auth.domain))
            else:
                self.id = result.response_json['id']
        elif found and force:
            print("Found query: '%s' in tenant: %s, overwriting it" % (self.name, auth.domain))
            result = UptApiCall(auth, '/queries/'+id, 'PUT', self.json)
            if result.rc != 0:
                print("Error updating query: '%s' in tenant: %s" % (self.name, auth.domain))
            else:
                self.id = result.response_json['id']
        else:
            print("Query: '%s' exists but force=False, so not overwriting it" % self.name)

    def write(self, directory):
        """ Create the JSON payload for the query and write it to a directory """
        # check to see if the directory exists
        if not os.path.isdir(directory):
            print("Could not find directory: '%s' " % directory)
            sys.exit(1)
        # create the output filename (remove spaces)
        filename = directory + '/' + self.name.replace(" ","_") + ".json"
        print("Writing query: '%s' to: %s" % (self.name, filename))
        with open(filename, 'w') as outfile:
            json.dump(self.json, outfile)

    def set_json(self):
        self.json = {
            "name": self.name,
            "description": self.description,
            "query": self.query,
            "type": self.type,
            "executionType": self.executionType,
            "grouping": self.grouping,
            "shared": self.shared,
            "parameters": []
        }
        # append each of the parameters
        for p in self.query_parameters:
            self.json['parameters'].append( {
                "dataType": p.dataType,
                "key": p.key,
                "multiple": p.multiple,
                "optional": p.optional
            } )


class UptQueries:
    """ A collection of queries retrieved from API call '/queries GET'
    """
    def __init__(self, api_auth, query_list = []):
        auth = api_auth
        self.queries = []
        queries_api = UptApiCall(upt_auth=auth, api_endpoint='/queries', method='GET', payload={})
        for q in queries_api.response_json['items']:
            if q['name'] in query_list or len(query_list) == 0:
                query = UptQuery(name=q['name'], description=q['description'], query=q['query'], type=q['type'], execution_type=q['executionType'], grouping=q['grouping'], shared=q['shared'], id=q['id'], parameters=q['parameters'] )
                self.queries.append(query)
        self.count = len(self.queries)

    def get_query_by_name(self, name):
        """ Return the query that matches the passed name. """
        for q in self.queries:
            if q.name == name:
                return q


class UptQueryGlobal:
    """ Uptycs query of global store """
    def __init__(self, upt_auth, query):
        auth = upt_auth
        logger = LogHandler(str(self.__class__))

        # create the JSON API payload containing the query
        payload = {"query": query}
        payload_json = json.dumps(payload)
        logger.debug('Running query: %s' % query)
        # run the query
        response = requests.post(auth.base_url+'/query', headers=auth.header, data=payload_json, verify=False, timeout=TIMEOUT)

    # check response for error code
        if (response.status_code != requests.codes.ok):
            logger.error("Error during Uptycs 'query' API call")
            logger.error("Query SQL: %s" % query)
            sys.exit(1)
        # store the entire query response data as json
        self.response_json = response.json()
        # create a 'rows' member that contains the 'items' in the response JSON
        self.rows = self.response_json['items']
        # store the count of rows
        self.count = len(self.rows)

    # returns unique rows based on the columns provided (max of 10 columns supported)
    # one usage is to return unique alert rows based on col1=value, col2=upt_asset_id
    def dedupe_rows_on(self, col1='', col2='', col3='', col4='', col5='', col6='', col7='', col8='', col9='', col10=''):
        separator = '_x9-'
        key_strings = []
        deduped_rows = []
        for r in self.rows:
            key_string = ''
            if len(col1) > 0:
                key_string = key_string + str(r[col1]) + separator
            if len(col2) > 0:
                key_string = key_string + str(r[col2]) + separator
            if len(col3) > 0:
                key_string = key_string + str(r[col3]) + separator
            if len(col4) > 0:
                key_string = key_string + str(r[col4]) + separator
            if len(col5) > 0:
                key_string = key_string + str(r[col5]) + separator
            if len(col6) > 0:
                key_string = key_string + str(r[col6]) + separator
            if len(col7) > 0:
                key_string = key_string + str(r[col7]) + separator
            if len(col8) > 0:
                key_string = key_string + str(r[col8]) + separator
            if len(col9) > 0:
                key_string = key_string + str(r[col9]) + separator
            if len(col10) > 0:
                key_string = key_string + str(r[col10]) + separator
            if not key_string in key_strings:
                key_strings.append(key_string)
                deduped_rows.append(r)
        return deduped_rows

    # print all rows as json
    def print_rows_json(self):
        for row in self.response_json['items']:
            print(json.dumps(row, indent=4, sort_keys=True))

    # return a string containing all row data in CSV format
    def row_data_csv(self):
        all_rows = ''
        for row in self.response_json['items']:
            one_row = ''
            i = 0
            for key, value in row.items():
                if i > 0:
                    one_row = one_row + ', ' + str(value)
                else:
                    one_row = str(value)
                i += 1
            all_rows = all_rows + one_row + '\n'
        return all_rows

    # return column names in CSV format
    def col_names_csv(self):
        col_names = str('')
        try:
            item = self.response_json['items'][0]
            n = 0
            for key, value in item.items():
                if n > 0:
                    col_names = col_names+', '+str(key)
                else:
                    col_names = str(key)
                n += 1
        except:
            print('Zero rows')
        return col_names

    # write the rows to csv (first row will be column names)
    def write_csv(self, filename):
        rows = self.row_data_csv()
        f = open(filename, "a")
        f.write(self.col_names_csv())
        for r in rows: 
            f.write(r)
        f.close()


class UptQueryPack:
    """ A Query Pack exported from an Uptycs tenant. """
    def __init__(self, api_auth, name):
        auth = api_auth
        self.name = name      # Name of the query pack
        self.queries = []     # A collection of queries in the query pack (each query has the attributes: name, table_name, query)
        # call the API to get the query pack JSON
        result = UptApiCall(auth, '/queryPacks', 'GET', '')
        for queryPack in result.response_json['items']:
            if queryPack['name'] == self.name:
                for query in queryPack['queries']:
                    q = UptQuery(name=query['name'], table_name=query['tableName'], query=query['query'])
                    self.queries.append(q)

    def create_alert_rule_sql(self, column):
        """ Create SQL for an alert rule that UNIONS a SELECT column FROM tableName for all the tables (queries) in the query pack """
        sql = ''
        for q in self.queries:
            if len(sql) > 0:
                sql = sql + 'UNION '
            sql = sql + "SELECT upt_asset_id as asset, upt_time as time, '"+q.name+"' AS description, 'high' AS severity, 'file path' AS key, "+column+" AS value FROM "+q.tableName+" WHERE upt_server_time > :from AND upt_server_time <= :to AND upt_day >= CAST(date_format(current_date - interval '1' day,'%Y%m%d') AS INTEGER) "
        return sql


class UptQueryParameter:
    """ Parameter for a query. Each query may have 0 or more parameters. """
    def __init__(self, data_type, key, multiple, optional):
        self.dataType = data_type
        self.key = key
        self.multiple = multiple
        self.optional = optional


class UptQueryRt:
    """ Uptycs realtime query of assets """
    def __init__(self, upt_auth, query, filter = ''):
        auth = upt_auth
        logger = LogHandler(str(self.__class__))

        # create the JSON API payload containing the query and filter
        payload =   {   "type": "realtime",
                        "query": query,
                        "filtering": {
                          "filters":  filter
                        }
                    }
        payload_json = json.dumps(payload)
        logger.debug('Running realtime query: %s' % query)
        # run the query
        response = requests.post(auth.base_url+'/assets/query', headers=auth.header, data=payload_json, verify=False, timeout=TIMEOUT)

        # check response status code for any error
        if (response.status_code != requests.codes.ok):
            logger.error("Error during Uptycs '/assets/query' API call, SQL: "+query)
            sys.exit(1)
        # store the entire query response data as json
        self.response_json = response.json()
        # create a 'rows' member that contains the 'items' in the response JSON
        self.rows = self.response_json['items']
        # store the count of rows
        self.count = len(self.rows)


class UptReport:
    """ One Uptycs Report """
    def __init__(self, name='', description='', title='', type='', frequency='', id='', logfile=''):
        self.logger = LogHandler('uptapi.Report', filename=logfile)
        self.name = name
        self.description = description
        self.title = title
        self.type = type
        self.frequency = frequency
        self.id = id

    def delete(self, upt_auth):
        """ Delete the report with the /reports/<id> DELETE API call """
        auth = upt_auth
        self.logger.info("Deleting report: '%s' from tenant: %s" % (self.name, auth.tenant_url))
        result = UptApiCall(auth, '/reports/'+self.id, 'DELETE', '')

    def get_full_json(self, upt_auth):
        """ Gets the full json for the report """
        auth = upt_auth
        result = UptApiCall(auth, '/reports/'+self.id, 'GET', '')
        return result.response_json


class UptReports:
    """ A class for retrieving all or a subset of Uptycs Report
        The delete() method will delete all retrieved reports (use with caution!!
    """
    def __init__(self, upt_auth, match_string='', report_list=[], logfile=''):
        """ match_string is an optional parameter used to limit retrieved reports to those which name contains the string. E.g. "CIS"
            report_list is an optional list of report names, again used to limit the retrieved reports
        """
        self.logger = LogHandler('uptapi.Reports', filename=logfile)
        self.auth = upt_auth
        self.reports = []
        reports_result = UptApiCall(upt_auth=self.auth, api_endpoint='/reports', method='GET', payload={})
        for r in reports_result.response_json['items']:
            if (r['name'] in report_list and len(report_list) > 0) or (match_string in r['name'] and len(match_string) > 0) or ( len(report_list) == 0 and len(match_string) == 0):
                report = UptReport(name=r['name'], description=r['description'], type=r['type'], title=r['title'], frequency=r['frequency'], id=r['id'])
                self.reports.append(report)
        self.count = len(self.reports)
        if len(match_string) > 0 and self.count == 0:
            self.logger.warning("Warning: No reports found for match_string: '%s'" % match_string)
        if len(report_list) > 0 and self.count == 0:
            self.logger.warning("Warning: No reports found for provided report list: '%s'" % report_list)

    def delete(self):
        """ Delete all reports in the list !! """
        for r in self.reports:
            r.delete(self.auth)


class UptThreatBook:
    """ A class to handle a single Threat Book.
        The .run() method is used to run a threat book
        The .get_results() method is used try and wait until results are available then get them
    """
    def __init__(self, upt_auth, threat_book_name):
        self.auth = upt_auth
        self.id = ''
        self.run_id = ''  # populated by the run() method
        self.run_json = '' # JSON response after running the threat book
        self.results = {"sections": []}  # JSON array of section results
        self.logger = LogHandler(str(self.__class__))

        # get all threat book id's and names
        threat_books = UptApiCall(self.auth, '/threatBooks', 'GET', {})
        for threat_book in threat_books.response_json['items']:
            # if this threat book name matches the desired one then set the id
            if threat_book['name'] == threat_book_name:
                self.id = threat_book['id']
        if not self.id:
            self.logger.error("Error! Did not find threat book named: %s " % threat_book_name)
            sys.exit(1)

    def run(self, from_datetime, to_datetime):
        """ Run the threat book for datetime range: from_datetime - to_datetime
            via API POST to /threatBooks/{threatBookId}/runs with payload like:
            { "windowStartTime":"2023-01-11T20:19:23.635Z", "windowEndTime":"2023-01-12T20:19:00.000Z" }
        """
        payload = { "windowStartTime": from_datetime, "windowEndTime": to_datetime }
        threat_book_run = UptApiCall(self.auth, '/threatBooks/'+self.id+'/runs', 'POST', payload)
        self.run_id = threat_book_run.response_json['id']
        self.run_json = threat_book_run.response_json

    def get_results(self):
        """ Call /threatBooks/{threatBookId}/runs/{runId} GET until "status": "FINISHED" for all sections
            then get results for all sections, return them in JSON array self.results
        """
        all_finished = False
        result = UptApiCall(self.auth, '/threatBooks/' + self.id + '/runs' + '/' + self.run_id, 'GET', {})
        while not all_finished:
            running_count = 0
            for sr in result.response_json["sectionRuns"]:
                if sr["status"] != "FINISHED":
                    running_count += 1
            if running_count == 0:
                all_finished = True
                self.logger.info("All threat book sections complete")
            else:
                self.logger.info("At least one threat book section still running, waiting for 10 more seconds")
                time.sleep(10)
                result = UptApiCall(self.auth, '/threatBooks/' + self.id + '/runs' + '/' + self.run_id, 'GET', {})
        self.logger.info("Starting GET for threat book section results...")
        # get each section result and add it to the results array
        for sr in result.response_json["sectionRuns"]:
            self.logger.info("Getting results for section %s " % sr["threatBookSectionType"])
            section_detail = UptApiCall(self.auth, '/threatBooks/' + self.id + '/runs' + '/' + self.run_id + '/sectionResults/' + sr["id"], 'GET', {})
            self.results["sections"].append(section_detail.response_json)


class SlackMessage():
    """ Send a slack message via HTTP POST request"""
    def __init__(self, webhook, message):
        logger = LogHandler(str(self.__class__))
        # send Slack message via http POST
        headers = { 'Content-type': 'application/json' }
        data = '{"text": "%s"}'% message
        logger.info('Sending Slack message')
        response = requests.post(webhook, headers=headers, data=data, timeout=TIMEOUT)
        if (response.status_code != requests.codes.ok):
            logger.error('Error during Slack send!')
            logger.error('Slack response = %s' % str(response))
            sys.exit(1)
