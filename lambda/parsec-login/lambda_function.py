import json
import urllib3
import base64

def lambda_handler(event, context):
    #print("Received event: " + json.dumps(event, indent=2))

    OLD_HOST = 'https://api.parsecgaming.com/'
    http = urllib3.PoolManager()

    def encryptDecrypt(session_id, guid):
        key = guid
        output = []

        input = "{\"session_id\":\"" + session_id + "\"}2";
        
        for i in range(len(input)):
            xor_num = ord(input[i]) ^ ord(key[i % len(key)])
            output.append(chr(xor_num))
        
        return ''.join(output)

    def login(email, password, tfa=''):
        r = http.request('POST', OLD_HOST + 'v1/auth',
        headers={'Content-Type': 'application/json'},
        body=json.dumps({'email': email, 'password': password, 'tfa': tfa}).encode('utf-8'))

        return json.loads(r.data.decode('utf-8')), r.status
    
    #Hardcoding this - because we are hardcore.
    email = 'parsec@ds-fix.com'
    password = 'pineappleexpress2008'
    #guid = '0b965d0b-23d1-4b7f-83cc-b3ec099af687'
    guid = event['headers']['winguid']
    
    res, status_code = login(email, password)
    
    print('\n[%d] /v1/auth/' % status_code)
    
    if status_code == 200:
        print('\nsession_id = %s' % res['session_id'])

        file = encryptDecrypt(res['session_id'], guid)

        return {
            'headers': {
                'Content-type': 'application/octet-stream',
                'content-disposition': 'attachment; filename=user.bin'
            },
            'statusCode': 200,
            'body': file
        }

    return {
        'statusCode': 404,
        'body': ''
    }