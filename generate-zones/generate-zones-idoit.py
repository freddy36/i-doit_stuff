#!/usr/bin/python
# -*- coding: utf-8 -*-
# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
"""
A quick and dirty script to get all hostnames from i-doit for a given zone.
E.g. to be included in a bind zone file for automated DNS updates based on your i-doit CMDB.

Author: Frederik Kriewitz <frederik@kriewitz.eu>
Version: 1.0
License: CC0 (http://creativecommons.org/publicdomain/zero/1.0/deed.en)

Dependencies:
apt-get install python-httplib2

Example report query for report based data retrieval (see --help for details):
SELECT 
 obj_main.isys_obj__id AS '__id__', 
 obj_main.isys_obj__title AS 'LC__UNIVERSAL__TITLE###1', 
 j3.isys_catg_ip_list__hostname AS 'LC__CATP__IP__HOSTNAME###47', 
 j5.isys_cats_net_ip_addresses_list__title AS 'LC__CATG__IP_ADDRESS###47', 
 j2.isys_net_type__title AS 'LC__CMDB__CATG__NETWORK__TYPE###47'
FROM isys_obj AS obj_main 
INNER JOIN isys_cmdb_status AS obj_main_status ON obj_main_status.isys_cmdb_status__id = obj_main.isys_obj__isys_cmdb_status__id 
LEFT JOIN isys_catg_ip_list AS j3 ON j3.isys_catg_ip_list__isys_obj__id = obj_main.isys_obj__id 
LEFT JOIN isys_net_type AS j2 ON j2.isys_net_type__id = j3.isys_catg_ip_list__isys_net_type__id 
LEFT JOIN isys_cats_net_ip_addresses_list AS j5 ON j3.isys_catg_ip_list__isys_cats_net_ip_addresses_list__id = j5.isys_cats_net_ip_addresses_list__id 
WHERE TRUE 
 AND obj_main.isys_obj__status = '2' /* only normal objects */
 AND j3.isys_catg_ip_list__status = '2' /* only normal host adresses */
 AND j3.isys_catg_ip_list__hostname LIKE '%.example.com' /* only specific domains */
 AND j3.isys_catg_ip_list__hostname NOT LIKE '%.lab.example.com' /* exclude */
ORDER BY j3.isys_catg_ip_list__hostname ASC;

"""

import sys
import re
import json
import httplib2
import argparse
import operator

def is_valid_hostname(hostname):
    """Validates hostnames."""
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1] # strip exactly one dot from the right, if present
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))

def is_valid_ip(ip):
    """Validates IP addresses."""
    return is_valid_ipv4(ip) or is_valid_ipv6(ip)

def is_valid_ipv4(ip):
    """Validates IPv4 addresses.
    """
    pattern = re.compile(r"""
        ^
        (?:
          # Dotted variants:
          (?:
            # Decimal 1-255 (no leading 0's)
            [3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}
          |
            0x0*[0-9a-f]{1,2}  # Hexadecimal 0x0 - 0xFF (possible leading 0's)
          |
            0+[1-3]?[0-7]{0,2} # Octal 0 - 0377 (possible leading 0's)
          )
          (?:                  # Repeat 0-3 times, separated by a dot
            \.
            (?:
              [3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}
            |
              0x0*[0-9a-f]{1,2}
            |
              0+[1-3]?[0-7]{0,2}
            )
          ){0,3}
        |
          0x0*[0-9a-f]{1,8}    # Hexadecimal notation, 0x0 - 0xffffffff
        |
          0+[0-3]?[0-7]{0,10}  # Octal notation, 0 - 037777777777
        |
          # Decimal notation, 1-4294967295:
          429496729[0-5]|42949672[0-8]\d|4294967[01]\d\d|429496[0-6]\d{3}|
          42949[0-5]\d{4}|4294[0-8]\d{5}|429[0-3]\d{6}|42[0-8]\d{7}|
          4[01]\d{8}|[1-3]\d{0,9}|[4-9]\d{0,8}
        )
        $
    """, re.VERBOSE | re.IGNORECASE)
    return pattern.match(ip) is not None

def is_valid_ipv6(ip):
    """Validates IPv6 addresses.
    """
    pattern = re.compile(r"""
        ^
        \s*                         # Leading whitespace
        (?!.*::.*::)                # Only a single whildcard allowed
        (?:(?!:)|:(?=:))            # Colon iff it would be part of a wildcard
        (?:                         # Repeat 6 times:
            [0-9a-f]{0,4}           #   A group of at most four hexadecimal digits
            (?:(?<=::)|(?<!::):)    #   Colon unless preceeded by wildcard
        ){6}                        #
        (?:                         # Either
            [0-9a-f]{0,4}           #   Another group
            (?:(?<=::)|(?<!::):)    #   Colon unless preceeded by wildcard
            [0-9a-f]{0,4}           #   Last group
            (?: (?<=::)             #   Colon iff preceeded by exacly one colon
             |  (?<!:)              #
             |  (?<=:) (?<!::) :    #
             )                      # OR
         |                          #   A v4 address with NO leading zeros 
            (?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)
            (?: \.
                (?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)
            ){3}
        )
        \s*                         # Trailing whitespace
        $
    """, re.VERBOSE | re.IGNORECASE | re.DOTALL)
    return pattern.match(ip) is not None

class IdoitAPI:
    """i-doit JSON-RPC API wrapper"""
    
    __baseUri = None
    __username = None
    __password = None
    __language = None
    __mandator = None
    __headers = {'Content-type': 'application/json'}
    
    
    def __init__(self, baseUri, apikey, language = None):
        self.__baseUri = baseUri
        self.__apikey = apikey
        self.__language = language
        self.__http = httplib2.Http(disable_ssl_certificate_validation=True)
        
        
    def request(self, method, specific_params):
        params = {}
        params['apikey'] = self.__apikey
        if self.__language:
            params['language'] = self.__language
        
        params.update(specific_params)
        
        request = {
            "method": method,
            "params": params,
            "id": 0,
            "jsonrpc": "2.0"
            }
            
        resp, content = self.__http.request(self.__baseUri + "/?api=jsonrpc", "POST", headers = self.__headers, body = json.dumps(request))
        try:
            content_json = json.loads(content)
            if "error" in content_json:
                raise Exception("Request failed" + content);
            return content_json['result']
        except:
            raise Exception("unable to parse JSON: " + content);

    def getObjects(self, filter = None, raw = None, order_by = None, sort = None, limit = None):
        """Return a list of objects
        
        Only objects with status normal are concidered.

        Keyword arguments:
        filter -- dictionary of filter attributes, supported keys:
                    ids: Object identifiers (integer or array of integers)
                    type: Object type (integer)
                    title: Object title (string)
                    sysid: SYSID (string)
                    first_name: First name of person (string)
                    last_name: Last name of person (string)
                    email: Email address of person (string)
        raw -- return raw values (boolean)
        order_by -- Order by one of the supported filter arguments (default: not ordered)
        sort -- Order result ascending ('ASC') or descending ('DESC')
        limit -- Limitation: where to start and number of elements, i.e. 0 or 0,10.
                 Defaults to null that means no limitation.
        """

        method = "cmdb.objects"
        params = {}
        
        if(filter != None):
            params['filter'] = filter
        if(raw != None):
            params['raw'] = raw
        if(order_by != None):
            params['order_by'] = order_by
        if(sort != None):
            params['sort'] = sort
        if(limit != None):
            params['limit'] = limit
        
        return self.request(method, params)
        
    def getCategory(self, objID, catgID = None, catsID = None, raw = None, condition = None):
        """Return a global (catg) or specific (cats) category of a specific object
        
        Keyword arguments:
        objID -- Object identifiers
        catgID -- Global category ID
        catsID -- Global category ID
        raw -- return raw values (boolean)
        condition -- FIXME: undocumented
        """

        method = "cmdb.category"
        params = {}
        
        params['objID'] = objID
        if(raw != None):
            params['raw'] = raw
        if(catgID != None):
            params['catgID'] = catgID
        if(catsID != None):
            params['catsID'] = catsID
        if(condition != None):
            params['condition'] = condition

        return self.request(method, params)
        
    def getObjectsByRelation(self):
        """Return objects by relation.
        
        Keyword arguments:
        id -- 
        relation_type -- 
        raw -- return raw values (boolean)
        """

        method = "cmdb.objects_by_relation"
        params = {}
        
        # TODO: implement

        return self.request(method, params)
    
    def getObjectTypes(self, filter = None, raw = None, order_by = None, sort = None, limit = None):
        """Fetches object types by filter.
        
        Keyword arguments:
        filter -- dictionary of filter attributes, supported keys:
                    id: Object identifiers (integer)
                    ids: Object identifiers (array of integers)
                    type: Object type (integer)
                    title: Object title (string)
                    titles: Object titles (array of string)
                    enabled:  Only object types enabled or disabled in GUI (boolean)
        raw -- return raw values (boolean)
        order_by -- Order by one of the supported filter arguments (default: not ordered)
        sort -- Order result ascending ('ASC') or descending ('DESC')
        limit -- Limitation: where to start and number of elements, i.e. 0 or 0,10.
                 Defaults to null that means no limitation.
        """

        method = "cmdb.object_types"
        params = {}
        
        if(filter != None):
            params['filter'] = filter
        if(raw != None):
            params['raw'] = raw
        if(order_by != None):
            params['order_by'] = order_by
        if(sort != None):
            params['sort'] = sort
        if(limit != None):
            params['limit'] = limit

        return self.request(method, params)
        
    def getObjectTypeCategories(self, type, raw = None, category = None):
        """Fetches categories by object type.
        
        Keyword arguments:
        type -- Object type (integer)
        raw -- return raw values (boolean)
        category -- Limit to one or more category types (int, string or array of ints/strings).
                    Value(s) can be category identifiers, constants or short names ('global', 'specific' or 'custom').
        """

        method = "cmdb.object_type_categories"
        params = {}
        
        if(type != None):
            params['type'] = type
        if(raw != None):
            params['raw'] = raw
        if(category != None):
            params['category'] = category

        return self.request(method, params)

    def getReports(self, id):
        """Retrieve report results
        
        Keyword arguments:
        id -- Report ID (integer)
        """

        method = "cmdb.reports"
        params = {}
        
        if(type != None):
            params['id'] = id

        return self.request(method, params)

def getHostnamesSlow(idoitAPI):
    objectTypesToCheck = []
    
    C__CATG__IP = None # catgID for host addresses, will be set in the following loop
    
    print >> sys.stderr, "--- Looking up all object type with host address categoriy set"
    objectTypes = idoitAPI.getObjectTypes()
    for objectType in objectTypes:
        # get categories for a specific object type
        objectTypeCategories = idoitAPI.getObjectTypeCategories(objectType['id'], raw = True, category = 'C__CMDB__CATEGORY__TYPE_GLOBAL') # FIXME: works only with raw=True in 1.1
        #print(json.dumps(objectTypeCategories, indent = 2))
        for objectTypeCategory in objectTypeCategories.get('catg', []):
            # check if the host address category is enabled for the current object
            if objectTypeCategory['isysgui_catg__const'] == "C__CATG__IP":
                C__CATG__IP = objectTypeCategory['isysgui_catg__id'] # store the id for later use
                #if int(objectTypeCategory['selected']) == 1: # no longer available/necessary in version 1.1?
                    # it is enabled, add the object type to the list to check
                objectTypesToCheck.append(objectType)
                break
    
    for objectType in objectTypesToCheck:
        print >> sys.stderr, "--- Checking object type %s (%s): %s" % (objectType['id'], objectType['const'], objectType['title'])
    
        objects = idoitAPI.getObjects(filter = {"type": objectType['id']})
        for object in objects:
            hostaddresses = idoitAPI.getCategory(object['id'], catgID = C__CATG__IP)
            if(hostaddresses):
                #print(json.dumps(hostaddresses, indent = 2))
                for hostaddress in hostaddresses:
                    if(hostaddress['hostname']): # only print IPs with hostnames set
                        hostname = {}
                        hostname['hostname'] = hostaddress['hostname']
                        ip_type = hostaddress['net_type']['const']
                        if ip_type == "C__CATS_NET_TYPE__IPV4":
                            ip_address = hostaddress['ipv4_address']['ref_title']
                            hostname['host_address'] = hostaddress['ipv4_address']['ref_title']
                            hostname['type'] = "A"
                        else:
                            hostname['host_address'] = hostaddress['ipv6_address']['ref_title']
                            hostname['type'] = "AAAA"
                        #print "hostname: %s, ip_type %s, address: %s" % (hostaddress['hostname'], ip_type, ip_address)
                        yield hostname

def getHostnamesReport(idoitAPI, reportId):
    rows = idoitAPI.getReports(reportId)
    for row in rows:
        # row: {u'Host address': u'192.168.0.42', u'Title': u'test', u'Hostname': u'test.example.com', u'__obj_id__': u'7510', u'Type': u'IPv4 (Internet Protocol v4)'}
       hostname = {}
       hostname['hostname'] = row['Hostname']
       hostname['host_address'] = row['Host address']
       if "IPv6" in row['Type']:
           hostname['type'] = "AAAA"
       elif "IPv4" in row['Type']:
           hostname['type'] = "A"
       else:
           hostname['type'] = None

       yield hostname

if __name__ == "__main__":
    parser = argparse.ArgumentParser(epilog="""There are two ways how the data can be retrieved. By default only the standard API will be used which might be to slow for you. Alternatively it's possible to specify the id of a report (--report_id) which will return all the data at once (much faster). In order for this to work a corresponding report must be created first. Check the header of the script for an example.""")

    parser.add_argument('--url', help='URL to the i-doit installation (e.g. https://i-doit.example.com)', required=True, type=str)
    parser.add_argument('--api_key', help='API key to be used for authentication', required=True, type=str)
    parser.add_argument('--zone', help='zone which should be used as filter (e.g. example.com)', required=True, type=str, action='append')
    parser.add_argument('--exclude', help='subdomains which should be excluded (e.g. .lab.example.com)', required=False, type=str, action='append', default=[])
    parser.add_argument('--report_id', help='ID of report to be used (see below)', required=False, type=int)
    args = parser.parse_args()

    idoitAPI = IdoitAPI(args.url, args.api_key)

    if args.report_id:
        hostnames = list(getHostnamesReport(idoitAPI, args.report_id))
    else:
        hostnames = list(getHostnamesSlow(idoitAPI))

    hostnames.sort(key=operator.itemgetter('hostname'))
    for hostname in hostnames:
        for zone in args.zone:
            if hostname['hostname'].endswith(zone):
                if any(hostname['hostname'].endswith(x) for x in args.exclude):
                    continue
                if hostname['type'] not in ['A', 'AAAA']:
                    print >> sys.stderr, "--- skipping %s (unknown type)" % (str(hostname))
                    continue
                if not is_valid_hostname(hostname['hostname']):
                    print >> sys.stderr, "--- skipping %s (invalid hostname)" % (str(hostname))
                    continue
                if hostname['type'] == "AAAA" and not is_valid_ipv6(hostname['host_address']):
                    print >> sys.stderr, "--- skipping %s (invalid IPv6 address)" % (str(hostname))
                    continue
                if hostname['type'] == "A"    and not is_valid_ipv4(hostname['host_address']):
                    print >> sys.stderr, "--- skipping %s (invalid IPv4 address)" % (str(hostname))
                    continue

                subdomain = hostname['hostname'][0:-len(zone)]
                if len(subdomain) == 0:
                    subdomain = "@"
                elif(subdomain[-1] == "."):
                    subdomain = subdomain[0:-1]
                else:
                    continue
       
                print "%-30s %s\t %s" % (subdomain, hostname['type'], hostname['host_address'])
                break

