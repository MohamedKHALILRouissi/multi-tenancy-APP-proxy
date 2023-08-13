# this is internal microservice to create dynamic subdomain on demand , based on RESTFUL API 
# the service it self is not exposed publicly so 
#                - rate limiting will not be high priority  
#                - security layer parsing and serailization of API input ( protect agaisnt RCE and PATH traversl as the API used to create and search for specific file )

# this microservice will have a nginx template for reverse proxy , creating a wildcard forwarding will increase the false/positive in the enumuration phase , but it easily bypassable
# if will redirect anything to home , and the new created subdomain will be forwarded to the right subdomain , the attack can filter the html string to actualy detect default redirection

###################### THIS IS PROTOTYPE NOT PRODUCTION READY ######################## 
# the usage of this will be docker run -it -p 80:80 -p 443:443 -v /<path>/:/etc/nginx/conf.d , where conf.d contain the config file inside
# <path>
# GODADDY
# 60 request per minute , 429 and an error message indicating that your rate limit has been surpassed 




from flask import Flask, request, jsonify
import secrets
import os
import subprocess
import requests
import base64
import time



# used to make the microservice more dynamic
path_to_template_auto = "/etc/nginx/conf.d/templatesecauto.sample"   # the sample must exist in the docker volume 
path_to_template_manu = "/etc/nginx/conf.d/templatesecmanual.sample"
config_output_path = "/etc/nginx/conf.d"
DOMAINNAME= os.environ.get('PY_DOMAINNAME') # domain name must be complete with *.com
API_KEY = os.environ.get('PY_API_KEY')
API_SECRET = os.environ.get('PY_API_SECRET')
URL= "https://api.godaddy.com"
HEADERS = { 
    "Authorization" : f"sso-key {API_KEY}:{API_SECRET}",
    "accept" : "application/json" 
    }
HOST= os.environ.get('PY_HOST')
EMAIL = os.environ.get('PY_EMAIL')

app = Flask(__name__)


# in-memory storage for domains and user-domain mapping (replace this with a proper database in production)
# later on use caching as it will be faster to request 



domains = set()

# function layer 
def generate_unique_hash():
    # generate a random 12-digit hash
    while True:
        random_hash = str(secrets.randbelow(10**12)).zfill(12)  # Ensure 12-digit format
        if random_hash not in domains: # Ensure that the hash is unique 
            domains.add(random_hash)
            return random_hash
        



def checkdomaingodaddy(domain):
    # check wether the domain specified exist , this will be onetime so no need to handle 429
    response = requests.get(URL + f"/v1/domains/{domain}",headers=HEADERS)
    if response.status_code == "404" :
        return False
    return True



def adddomaindaddy(domain):
    headers = { 
        "Authorization": f"sso-key {API_KEY}:{API_SECRET}",
        "Accept": "application/json",
        "Content-Type": "application/json" 
    }

    data = [{     
        "data": "@",
        "name": domain,
        "ttl": 600,
        "type": "CNAME"
    }]

    response = requests.patch(URL + f"/v1/domains/{DOMAINNAME}/records", headers=headers, json=data)

    if response.status_code == 200:
        return None  # No error, return None
    elif response.status_code == 429:
        return "Rate limit of GoDaddy API triggered. Please handle this asynchronously."
    else:
        try:
            error_message = response.json().get('message')
            if not error_message:
                error_message = "An unknown error occurred with GoDaddy API."
            return error_message
        except Exception:
            return "An unknown error occurred with GoDaddy API."
    
def removedomaindaddy(domain):
    # remove domain 
    response = requests.delete(URL + f"/v1/domains/{DOMAINNAME}/records/A/{domain}", headers=HEADERS)
    
    if response.status_code == 204:
        return None  # No error, return None
    elif response.status_code == 404:
        return "Record name not found."
    elif response.status_code == 429:
        return "Rate limit of GoDaddy API triggered. Please handle this asynchronously."
    else:
        try:
            error_message = response.json().get('message')
            if not error_message:
                error_message = "An unknown error occurred with GoDaddy API."
            return error_message
        except Exception:
            return "An unknown error occurred with GoDaddy API."

# Endpoint 1: create a random subdomain for a user and nginx config file generated ( this require no mapping or tracking thus it used to generate the file and subdomain , storing and tracking handled at another layer )
@app.route('/createrandomdomain', methods=['GET'])
def create_random_domain():
    if request.method != 'GET':
        return jsonify({'message': 'method Not Allowed'}), 405
    try:

        new_domain = generate_unique_hash()
        result = adddomaindaddy(new_domain)
        if result is not None:
            return jsonify({'message': result}), 400

        with open(path_to_template_auto, 'r') as template_file:
            template_content = template_file.read()

        template_content = template_content.replace('<$variable1>', new_domain)
        template_content = template_content.replace('<$domain>', DOMAINNAME)
        template_content = template_content.replace('<$host>', HOST)
        config_file_path = os.path.join(config_output_path, f"{new_domain}.{DOMAINNAME}.conf")
        with open(config_file_path, 'w') as config_file:
            config_file.write(template_content)
        domain = f"{new_domain}.{DOMAINNAME}"
        time.sleep(120)
        subprocess.run(['certbot', '--nginx', '--hsts' , '-m' , EMAIL , '-d' , domain , '--agree-tos' , '-n' ], check=True)  # Add check=True to raise an exception if the command fails

        return jsonify({'message': f'domain {new_domain} created successfully.'}), 200
    except Exception as e:
        return jsonify({'message': f'an error occurred while generating the domain: {str(e)}'}), 500
               

@app.route('/createdomaintenantbased', methods=['POST'])
def create_domain_tenant_based():
    if request.method != 'POST':
        return jsonify({'message': 'method Not Allowed'}), 405
    tenant_id = request.form.get('tenant-id')
    subdomain = request.form.get('subdomain')
    sslkey_b64 = request.form.get('sslkey')
    sslcertificat_b64 = request.form.get('sslcertificat')
    try:
        if (sslkey_b64 and not sslcertificat_b64) or (sslcertificat_b64 and not sslkey_b64):
            return jsonify({'message': 'Both SSL key and certificate are required if one is provided'}), 400

        sslkey = None
        sslcertificat = None
        domain = f"{subdomain}.{DOMAINNAME}"
        if sslkey_b64 and sslcertificat_b64:
            sslkey = base64.b64decode(sslkey_b64).decode('ascii')
            sslcertificat = base64.b64decode(sslcertificat_b64).decode('ascii')
            if "----- END PRIVATE KEY -----" not in sslkey:
                return jsonify({'message': 'Invalid SSL key format'}), 400
            
            if "----- END CERTIFICATE -----" not in sslcertificat:
                return jsonify({'message': 'Invalid SSL certificate format'}), 400

        if not tenant_id or not subdomain:
            return jsonify({'message': 'both tenant-id and subdomain parameters are required'}), 400
    
        result = adddomaindaddy(subdomain)

        if result is not None:
            return jsonify({'message': result}), 400

        if not sslkey and not sslcertificat:
            with open(path_to_template_auto,'r') as template_file:
                template_content = template_file.read()
            template_content = template_content.replace('<$variable1>',subdomain)
            template_content = template_content.replace('<$domain>',DOMAINNAME)
            template_content = template_content.replace('<$host>',HOST)
            config_file_path = os.path.join(config_output_path, f"{subdomain}.{DOMAINNAME}.conf")
            with open(config_file_path, "w") as config_file:
                config_file.write(template_content)

            time.sleep(120)
            subprocess.run(['certbot', '--nginx', '--hsts', '-m' , EMAIL ,'-d' , domain , '--agree-tos' , '-n' ], check=True)
            return jsonify({'message': f'Domain {subdomain} created successfully'}), 200
                


        # manual add cert defined by the user 
        if sslkey and sslcertificat:
            new_dir_name = subdomain + '.' + DOMAINNAME
            new_dir_path = os.path.join('/letsencrypt/certs/live', new_dir_name)
            os.makedirs(new_dir_path, exist_ok=True)
            sslkey_path = os.path.join(new_dir_path, 'privkey.pem')
            sslcertificat_path = os.path.join(new_dir_path, 'cert.pem')

            with open(sslkey_path, 'w') as sslkey_file:
                sslkey_file.write(sslkey)

            with open(sslcertificat_path, 'w') as sslcertificat_file:
                sslcertificat_file.write(sslcertificat)

            with open(path_to_template_manu, 'r') as template_file:
                template_content = template_file.read()

            template_content = template_content.replace('<$variable1>', subdomain)
            template_content = template_content.replace('<$domain>', DOMAINNAME)
            template_content = template_content.replace('<$dir>',new_dir_path)
            template_content = template_content.replace('<$host>', HOST)   
            config_file_path = os.path.join(config_output_path, f"{domains}.{DOMAINNAME}.conf")
            with open(config_file_path, 'w') as config_file:
                config_file.write(template_content)
            subprocess.run(['nginx', '-s', 'reload'], check=True)
            return jsonify({'message': f'Domain {subdomain} created successfully'}), 200

        
    except FileNotFoundError as e:
        return jsonify({'message' : 'file not found '}), 500
    except Exception as e:
        return jsonify({'message': f'an error occurred while creating the config file or domain: {str(e)}'}), 500



@app.route('/removedomain', methods=['POST'])
def remove_domain():
    if request.method != 'POST':
        return jsonify({'message': 'Method Not Allowed'}), 405
    method = request.form.get('type')
    domain = request.form.get('domain')
    
    try:
        if not domain or not method :
            return jsonify({'error': 'domain and method parameter is required'}), 400
        
        result = removedomaindaddy(domain)
        domaint = f"{domain}.{DOMAINNAME}"

        if result is not None:
            return jsonify({'error': result}), 400
        
        file = f"{domain}.{DOMAINNAME}.conf"

        config_file_path = os.path.join(config_output_path, file )
        os.remove(config_file_path)

        if method == "auto":
            subprocess.run(["certbot", "revoke", "--cert-name", f"{domain}.{DOMAINNAME}", "--delete-after-revoke"], check=True)
            return jsonify({'message': f'Domain {domain} removed successfully'}), 200
        if method == "manu":
            new_dir_path = os.path.join('/letsencrypt/certs/live', domaint)
            os.removedirs(new_dir_path)
            subprocess.run(["nginx", "-s", "reload"], check=True)
            return jsonify({'message': f'Domain {domain} removed successfully'}), 200


        
    except Exception as e:
        return jsonify({'error': f'An error occurred while removing the domain: {str(e)}'}), 500

if __name__ == '__main__':
    if checkdomaingodaddy(DOMAINNAME) == False:
        print("domain not found")
        exit
    app.run(debug=True , host='0.0.0.0' , port=3000)
