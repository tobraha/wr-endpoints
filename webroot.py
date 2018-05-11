from __future__ import print_function # For those of you that need a talkin' to...  >:(
import requests
import csv
import sys
from getpass import getpass

# Webroot GSM Portal User Login
print('\n--- Webroot Admin Console Login')
wruser = input('Webroot Global Console Login Email: ')
wrpass = getpass('Enter Webroot Portal Password: ')

# WR API Credentials
print('\n--- Webroot API Credentials')
clientID = input('Enter Webroot API Client ID: ')
clientSecret = input('Client Secret: ')
# GSM Parent Keycode (same for all admins and sites)
keycode = input('Enter GSM Parent Keycode: ')

# The base URL for the Webroot API
baseURL = 'https://unityapi.webrootcloudav.com'

def _url(path):
    return baseURL + path

def getToken(token):
    """
    Get our access token from Webroot.  Good for 300 seconds, 
    then use refresh_token to obtain a new token.
    
    If an existing token is passed, the refresh_token
    will be used to request a new token.
    
    Returns the entire response in JSON form.
    Use token_data['access_token'] for the primary token.
    """
    
    s.headers.update({'Content-Type' : 'application/x-www-form-urlencoded'})
    s.headers.update(Accept='application/json')
    
    # if we don't already have token, get a new one with console creds.
    if not token:
        data = dict(username=wruser)
        data.update(password=wrpass)
        data.update(grant_type='password')
    # otherwise, use refresh_token to renew
    else:
        data = dict(refresh_token=token['refresh_token'])
        data.update(grant_type='refresh_token')
    # this will be the same regardless
    data.update(scope='Console.GSM')
    
    print('Retrieving Access Token...')
    r = s.post(tokenURL, data=data, 
               auth=requests.auth.HTTPBasicAuth(clientID, clientSecret)).json()
    return r

def getSites():
    """
    Query the base site URL with the keycode.
    
    JSON response is returned with all site metadata.
    We'll use this for the Site Name, Site ID, and 
    default Site Policy.
    """
    s.headers.update({'Content-Type':'application/json'})
    print('Retrieving site list...')
    r = s.get(siteIDURL)
    token_data = r.json()
    return token_data

def getEndpoints(site):
    """
    Given the site as a parameter, use the SiteId to return
    a JSON response with metadata of all endpoints.
    """
    r = s.get(siteIDURL + '/' + site['SiteId'] + '/endpoints').json()
    
    # If we receive an error, our token may have timed out.  Try renewing.
    if 'statusCode' in r:
        if r['error'] == 'invalid_token':
            getToken(token)
            s.headers.update(Authorization='Bearer ' + token['access_token'])
            r = s.get(siteIDURL + '/' + site['SiteId'] + '/endpoints').json()
    return r

# The only two URLs we'll need for this data.
tokenURL = _url('/auth/token')
siteIDURL = _url('/service/api/console/gsm/' + keycode + '/sites')
    
# Start a session to keep TCP connection alive for faster queries
s = requests.Session()

# Add our token to request headers for the session
token = dict()
token = getToken(token)
s.headers.update(Authorization='Bearer ' + token['access_token'])
    
def main():
    sites = getSites()
    
    # Main Loop
    with open('Webroot_Endpoints.csv', 'w', newline='') as csvfile:
        c = csv.writer(csvfile, quoting=csv.QUOTE_MINIMAL)
        c.writerow(['Site Name', 'Machine Name', 'Machine Policy', 'Installed OS',
                    'Last Seen', 'Agent Version', 'Group Name', 'Site Default Policy'])
        for site in sites['Sites']:
            print('Requesting data for site: ' + site['SiteName'])
            endpoints = getEndpoints(site)
            # Some sites are expired or we have no access
            if not 'Endpoints' in endpoints:
                print('   [!] ' + endpoints['error_description'])
                continue
            for endpoint in endpoints['Endpoints']:
                c.writerow([site['SiteName'], endpoint['HostName'], endpoint['PolicyName'], 
                            endpoint['WindowsFullOS'], endpoint['LastSeen'], endpoint['AgentVersion'], 
                            endpoint['GroupName'], site['PolicyName']])
    
    return 0
    
if __name__ == '__main__':
    sys.exit(main())    