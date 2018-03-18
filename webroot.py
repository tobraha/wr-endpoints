from __future__ import print_function # For those of you that need a talkin' too...  >:(
import requests
import base64
import csv
import sys

# WR API Credentials
print('\n--- Webroot API Credentials')
clientID = input('Enter Webroot API Client ID: ')
clientSecret = input('Client Secret: ')

# Webroot GSM Portal User Login
print('\n\n--- Webroot Admin Console Login')
wruser = input('Webroot Global Console Login Email: ')
wrpass = input('Enter Webroot Portal Password: ') # TODO: mask this input

# GSM Parent Keycode (same for all admins and sites)
keycode = input('Enter GSM Parent Keycode: ')

# The base URL for the Webroot API
baseURL = 'https://unityapi.webrootcloudav.com'

def _url(path):
    return baseURL + path

def getToken(s):
    """
    Get our access token from Webroot.  Good for 300 seconds, 
    then use refresh_token for 15 minutes.
    
    Returns the entire response in JSON form.
    Use token_data['access_token'] for the primary token.
    """
    s.headers.update({'Content-Type' : 'application/x-www-form-urlencoded'})
    s.headers.update(Accept='application/json')
    
    data = dict(username=wruser)
    data.update(password=wrpass)
    data.update(grant_type='password')
    data.update(scope='Console.GSM')
    
    print('Retrieving Access Token...')
    r = s.post(tokenURL, data=data, auth=requests.auth.HTTPBasicAuth(clientID, clientSecret))
    token_data = r.json()
    return token_data

def getSites(s):
    """
    Query the base site URL with the keycode.
    
    JSON response is returned with all site metadata.
    We'll use this for the Site Name, Site ID, and 
    default Site Policy.
    """
    s.headers.update({'Content-Type': 'application/json'})
    print('Retrieving site list...')
    r = s.get(siteIDURL)
    return r.json()

def getEndpoints(site, s):
    """
    Given the site as a parameter, use the SiteId to return
    a JSON response with metadata of all endpoints.
    """
    r = s.get(siteIDURL + '/' + site['SiteId'] + '/endpoints')
    
    # If we receive an error, update the token with the refresh_token
    if r.status_code == 401:
        s.headers.update(Authorization='Bearer ' + token['refresh_token'])
        s.get(siteIDURL + '/' + site['SiteID'] + '/endpoints')
    return r.json()

# The only two URLs we'll need for this data.
tokenURL = _url('/auth/token')
siteIDURL = _url('/service/api/console/gsm/' + keycode + '/sites')

def main():
    
    # Start a session to keep TCP connection alive for faster queries
    s = requests.Session()
    
    # Add our token to request headers for the session
    token = getToken(s)
    s.headers.update(Authorization='Bearer ' + token['access_token'])
    
    sites = getSites(s)    
    
    # Main Loop
    with open('Webroot_Endpoints.csv', 'w', newline='') as csvfile:
        c = csv.writer(csvfile, quoting=csv.QUOTE_MINIMAL)
        c.writerow(['Site Name', 'Machine Name', 'Machine Policy', 'Last Seen', 'Agent Version', 'Group Name', 'Site Default Policy'])
        for site in sites['Sites']:
            print('Requesting data for site: ' + site['SiteName'])
            endpoints = getEndpoints(site, s)
            # Some sites are expired or we have no access
            if not 'Endpoints' in endpoints:
                print('   [!] Unable to retrieve endpoint info fot site!')
                print('   [!] ' + endpoints['error_description'])
                continue
            for endpoint in endpoints['Endpoints']:
                c.writerow([site['SiteName'], endpoint['HostName'], endpoint['PolicyName'], 
                            endpoint['LastSeen'], endpoint['AgentVersion'], 
                            endpoint['GroupName'], site['PolicyName']])
    
    return 0
    
if __name__ == '__main__':
    sys.exit(main())    