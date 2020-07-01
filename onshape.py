#!/usr/bin/env pybricks-micropython
import gc 
import os
import random
import string
import json
import hmac
import hashlib 
import base64
import urllib.parse
import urequests
import utime



__all__ = [
    'Onshape'
]

class Onshape():
    '''
    Provides access to the Onshape REST API.

    Attributes:
        - stack (str): Base URL
        - creds (str, default='./creds.json'): Credentials location
        - logging (bool, default=True): Turn logging on or off
    '''
    def __init__(self, stack, creds = '/home/robot/microPython_Onshape/creds.json', logging = True):
        '''
        Create the request signature to authenticate

        Args:
            - method (str): HTTP method
            - date (str): HTTP date header string
            - nonce (str): Cryptographic nonce
            - path (str): URL pathname
            - query (dict, default={}): URL query string in key-value pairs
            - ctype (str, default='application/json'): HTTP Content-Type
        '''
        
        try:
            f = open(creds, "r")
        except OSError:
            raise IOError('%s is not a file' % creds)


        with open(creds) as f:
            try:
                stacks = json.load(f)
                if stack in stacks:
                    self._url = stack
                    self._access_key = stacks[stack]['access_key'].encode('utf-8')
                    self._secret_key = stacks[stack]['secret_key'].encode('utf-8')
                    self._logging = logging


                    # Testing Block
                    addSpacing()
                    print('CLIENT PARAMETERS:')
                    print('stack: ', self._url)
                    print('access key: ', self._access_key)
                    print('secret key: ', self._secret_key)
                    print('logging: ', self._logging)
                
                
                else:
                    raise ValueError('specified stack not in file')
            except TypeError:
                raise ValueError('%s is not valid json' % creds)
    


    def _make_nonce(self):
        '''
        Generate a unique ID for the request, 25 chars in length

        Returns:
            - str: Cryptographic nonce
        '''
        chars = string.digits + string.ascii_letters
        nonce = ''.join(random.choice(chars) for i in range(25))


        # Testing Block
        print('NONCE GENERATED:')
        print(nonce)
        addSpacing()


        return nonce

    def _make_auth(self, method, date, nonce, path, query={}, ctype='application/json'):
        '''
        Create the request signature to authenticate

        Args:
            - method (str): HTTP method
            - date (str): HTTP date header string
            - nonce (str): Cryptographic nonce
            - path (str): URL pathname
            - query (dict, default={}): URL query string in key-value pairs
            - ctype (str, default='application/json'): HTTP Content-Type
        '''


        # Testing Block
        query = urllib.parse.urlencode(query)
        print('QUERY:')
        print(query)
        addSpacing()


        hmac_str = (method + '\n' + nonce + '\n' + date + '\n' + ctype + '\n' + path +
                    '\n' + query + '\n').lower().encode('utf-8')

    
        # Testing Block
        print('HMAC:')
        print(hmac_str)
        addSpacing()


        signature = base64.b64encode(hmac.new(self._secret_key, hmac_str, digestmod=hashlib._sha256.sha256).digest())
        
        
        # Testing Block
        print('SIGNATURE: ')
        print(signature)
        addSpacing()


        auth = 'On ' + self._access_key.decode('utf-8') + ':HmacSHA256:' + signature.decode('utf-8')

        return auth

    def _make_headers(self, method, path, query={}, headers={}):    
        '''
        Creates a headers object to sign the request

        Args:
            - method (str): HTTP method
            - path (str): Request path, e.g. /api/documents. No query string
            - query (dict, default={}): Query string in key-value format
            - headers (dict, default={}): Other headers to pass in

        Returns:
            - dict: Dictionary containing all headers
        '''
        
        date = self.getCurrentTime()



        # Testing Block 
        print('TIMESTAMP GENERATED:')
        print(date)
        addSpacing()



        nonce = self._make_nonce()
        ctype = headers.get('Content-Type') if headers.get('Content-Type') else 'application/json'

        # Testing Block
        print('CTYPE:')
        print(ctype)
        addSpacing()

        auth = self._make_auth(method, date, nonce, path, query=query, ctype=ctype)

        print('AUTH:')
        print(auth)
        addSpacing()

        req_headers = {
            'Content-Type': 'application/json',
            'Date': date,
            'On-Nonce': nonce,
            'Authorization': auth,
            'User-Agent': 'Onshape Python Sample App',
            'Accept': 'application/json'
        }

        # add in user-defined headers
        for h in headers:
            req_headers[h] = headers[h]


        # Testing Block
        print('REQ_HEADERS:')
        print(req_headers)
        addSpacing()

        return req_headers

    def request(self, method, path, query={}, headers={}, body={}, base_url=None):
        '''
        Issues a request to Onshape

        Args:
            - method (str): HTTP method
            - path (str): Path  e.g. /api/documents/:id
            - query (dict, default={}): Query params in key-value pairs
            - headers (dict, default={}): Key-value pairs of headers
            - body (dict, default={}): Body for POST request
            - base_url (str, default=None): Host, including scheme and port (if different from creds file)

        Returns:
            - requests.Response: Object containing the response from Onshape
        '''

        req_headers = self._make_headers(method, path, query, headers)   
        if base_url is None:
            base_url = self._url
        url = base_url + path + '?' + urllib.parse.urlencode(query)
        

        # Testing Block
        print('URL:')
        print(url)
        addSpacing()


        body = json.dumps(body) if type(body) == dict else body


        # Testing Block
        print('BODY')
        print(body)
        addSpacing()


        res = urequests.get(url, headers=req_headers, data=body)
        return res

    def getCurrentTime(self):
        months = {1:'Jan', 2:'Feb', 3:'Mar', 4:'Apr', 5:'May', 6:'Jun', 7:'Jul', 8:'Aug', 9:'Sep', 10:'Oct', 11:'Nov', 12:'Dec'}
        weekdays = {0:'Mon', 1:'Tue', 2:'Wed', 3:'Thu', 4:'Fri', 5:'Sat', 6:'Sun'}
        singleDig = { 1:'01', 2:'02', 3:'03', 4:'04', 5:'05', 6:'06', 7:'07', 8:'08', 9:'09'}
        time = utime.localtime()
        convTime = time[2]
        convTime2 = time[3]
        convTime3 = time[4]
        convTime4 = time[5]
        if time[2] in singleDig:
                convTime = singleDig[time[2]]
        if time[3] in singleDig:
                convTime2 = singleDig[time[3]]
        if time[4] in singleDig:
                convTime3 = singleDig[time[4]]
        if time[5] in singleDig:
                convTime4 = singleDig[time[5]]
        curTime = weekdays[time[6]] +', ' + str(convTime) + " " + months[time[1]] + ' ' + str(time[0]) + " " + str(convTime2) + ":" + str(convTime3) + ":" + str(convTime4) + ' GMT'
        return curTime


'''
Testing Below
'''

def addSpacing():
    print('------------------------------------')
    print('')
    print('')
    print('------------------------------------')

base_url = 'https://rogers.onshape.com'

test = Onshape(base_url,logging=False)
addSpacing()
print('CREATED THE ONSHAPE OBJECT!')
addSpacing()


did = '2696c6465ac59aff8ca3dfc1'
wid = 'be80594917e5b1877e38d94e'
eid = 'bd2b08bfd9046a3e25896bf3'


headers = {'Accept': 'applicaton/vnd.onshape.v1+json', 'Content-Type': 'application/json'}


r = test.request('GET', path = '/api/partstudios/d/2696c6465ac59aff8ca3dfc1/w/be80594917e5b1877e38d94e/e/8b59dcfebfc34d65d9a48a0b/features', query = {}, body = {}, headers = headers)

x = json.loads(r.data)
print(json.dumps(x, indent=4))