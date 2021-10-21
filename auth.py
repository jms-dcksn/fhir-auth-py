import json
import requests
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from requests.structures import CaseInsensitiveDict
import jwt
import uuid

def main():
    epoch_time = int(time.time()) + 120
    
    print(epoch_time)
    #instance = JWT()
    message = {
        # Client ID for non-production
        'iss': '9dca6746-d56e-4d88-9736-ad94a608ddc1',
        'sub': '9dca6746-d56e-4d88-9736-ad94a608ddc1',
        'aud': 'https://fhir.epic.com/interconnect-fhir-oauth/oauth2/token',
        'jti': str(uuid.uuid1()),
        'exp': epoch_time
    }

    # Load RSA key from a PEM file.
    with open('C:/Users/jamesdickson/Documents/FHIR/PEM/privatekey.pem', 'rb') as f:
        signing_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    compact_jws = jwt.encode(message, signing_key, algorithm='RS384')
    #print(compact_jws)

    claims = jwt.decode(compact_jws, options={"verify_signature": False})
    headers_decoded = jwt.get_unverified_header(compact_jws)
    #print(claims)
    #print(headers_decoded)

    headers = CaseInsensitiveDict()
    headers['Content-Type'] = 'application/x-www-form-urlencoded'

    data = {
        'grant_type': 'client_credentials',
        'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        'client_assertion': compact_jws
    }
    
    x = requests.post('https://fhir.epic.com/interconnect-fhir-oauth/oauth2/token', headers=headers, data=data)
    json_resp = x.json()
    access_token = json_resp['access_token']
    print('access token: ', access_token)


main()