import json
import urllib3

	

def lambda_handler(event, context):

    OLD_HOST = 'https://api.parsecgaming.com/'
    http = urllib3.PoolManager()

    def login(email, password, tfa=''):
        r = http.request('POST', OLD_HOST + 'v1/auth',
        headers={'Content-Type': 'application/json'},
        body=json.dumps({'email': email, 'password': password, 'tfa': tfa}).encode('utf-8'))

        return json.loads(r.data.decode('utf-8')), r.status
    
    #Hardcoding this - because we are hardcore.
    email = 'parsec@ds-fix.com'
    password = 'pineappleexpress2008'
    
    res, status_code = login(email, password)
    
    print('\n[%d] /v1/auth/' % status_code)
    
    if status_code == 200:
        print('\nsession_id = %s' % res['session_id'])
        return {
            'statusCode': 200,
            'body': res['session_id']
        }

    return {
        'statusCode': 404,
        'body': ''
    }