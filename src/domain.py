# this is internal microservice to create dynamic subdomain on demand , based on RESTFUL API 
# the service it self is not exposed publicly so 
#                - rate limiting will not be high priority  
#                - security layer parsing and serailization of API input ( protect agaisnt RCE and PATH traversl as the API used to create and search for specific file )

# this microservice will have a nginx template for reverse proxy , creating a wildcard forwarding will increase the false/positive in the enumuration phase , but it easily bypassable
# if will redirect anything to home , and the new created subdomain will be forwarded to the right subdomain , the attack can filter the html string to actualy detect default redirection

###################### THIS IS PROTOTYPE NOT PRODUCTION READY ######################## 


# missing seralization of



# the usage of this will be docker run -it -p 80:80 -p 443:443 -v /<path>/:/etc/nginx/conf.d , where conf.d contain the config file inside
# <path>


# GODADDY
# 60 request per minute , 429 and an error message indicating that your rate limit has been surpassed 




from flask import Flask, request, jsonify
import secrets
import os
import subprocess
import requests


# used to make the microservice more dynamic
path_to_template = "/etc/nginx/conf.d/template.sample"   # the sample must exist in the docker volume 
config_output_path = "/etc/nginx/conf.d"
DOMAINNAME= os.environ.get('DOMAINNAME')
API_KEY = os.environ.get('API_KEY')
API_SECRET = os.environ.get('API_SECRET')
URL= "https://api.godaddy.com"
HEADERS = { 
    "Authorization" : f"sso-key {API_KEY}:{API_SECRET}",
    "accept" : "application/json" 
    }

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



def adddomaindaddy(host,domain):
    # add the new domain to the go daddy first
    headers = { 
    "Authorization" : f"sso-key {API_KEY}:{API_SECRET}",
    "accept" : "application/json",
    "Content-Type" : "application/json" 
    }

    data = [{     
        "data": host,
        "name": domain,
        "ttl": 600,
        "type": "A"
    }]

    response = requests.patch(URL + f"/v1/domains/{DOMAINNAME}/records",headers=headers,json=data)

    if ( response.status_code == "200" ):
        return 0
    elif ( response.status_code == "429"):
        print("stored in the memory and served")
        return 2
    elif ( response.status_code == "404"):
        print("domain not found")
        return 1
    else:
        return 3
    
def removedomaindaddy(domain):
    # remove domain 
    response = requests.delete(URL + f"/v1/domains/{DOMAINNAME}/records/A/{domain}",headers=HEADERS)
    if response.status_code == "204":
        return 0
    if response.status_code == "404":
        print("record name not found")
        return 1
    if response.status_code == "429":
        print("stored in the memory and servred")
        return 2
    else:
        return 3

# Endpoint 1: create a random subdomain for a user and nginx config file generated ( this require no mapping or tracking thus it used to generate the file and subdomain , storing and tracking handled at another layer )
@app.route('/createrandomdomain', methods=['GET'])
def create_random_domain():
    if request.method != 'GET':
        return jsonify({'message': 'method Not Allowed'}), 405
    try:

        host = request.args.get('host')
        if host is None:
            return jsonify({'message' : 'host is required in the query'}), 400

        result = adddomaindaddy(host,new_domain)
        if result == 1:
            return jsonify({'message': 'the domain not found please correct this in the env and rebuild the container'}) , 500
        elif result == 2:
            return jsonify({'message': 'rate limit of godaddy triggered please handle this asyncr'}) , 204
        elif result == 3:
            return jsonify({'message' : "godaddy error "}) , 500

        new_domain = generate_unique_hash()
        config_filename = new_domain + '.conf'
        with open(path_to_template, 'r') as template_file:
            template_content = template_file.read()
        template_content = template_content.replace(f'<$variable1>', str(new_domain))
        template_content = template_content.replace(f'<$variable2>', str(''))
        with open(os.path.join(config_output_path, config_filename), 'w') as output_file:
            output_file.write(template_content)
        subprocess.run(['nginx', '-s', 'reload'], check=True)  # Add check=True to raise an exception if the command fails




        return jsonify({'message': f'domain {new_domain} created successfully.'}), 200
    except Exception as e:
        return jsonify({'message': f'an error occurred while generating the domain: {str(e)}'}), 500
               

@app.route('/createdomaintenantbased', methods=['POST'])
def create_domain_tenant_based():
    if request.method != 'POST':
        return jsonify({'message': 'method Not Allowed'}), 405
    tenant_id = request.form.get('tenant_id')
    subdomain = request.form.get('subdomain')
    host = request.form.get('host')
    try:
        if not tenant_id or not subdomain or not host:
            return jsonify({'message': 'both tenant-id and subdomain parameters are required'}), 400
    
        resutl = adddomaindaddy(host,subdomain)

        if resutl == 1:
            return jsonify({'message': 'the domain not found please correct this in the env and rebuild the container'}) , 500
        elif resutl == 2:
            return jsonify({'message': 'rate limit of godaddy triggered please handle this asyncr'}) , 204
        elif resutl == 3:
            return jsonify({'message' : "godaddy error "}) , 500


        config_filename = subdomain + '.conf'

        replacements = { 'variable1': subdomain , 'variable2': '' }  # Updated variable names
        with open(path_to_template, 'r') as template_file:
            template_content = template_file.read()

        for placeholder, value in replacements.items():
            template_content = template_content.replace(f'<${placeholder}>', str(value))

        with open(os.path.join(config_output_path, config_filename), 'w') as output_file:
            output_file.write(template_content)
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
    domain = request.form.get('domain')
    try:
        if not domain:
            return jsonify({'message': 'Domain parameter is required'}), 400

        
        resutl = removedomaindaddy(domain)

        if resutl == 1:
            return jsonify({'message' : 'record not found'}), 400
        elif resutl == 2:
            return jsonify({'message' : 'godaddy rate limit handle this async'}), 204
        elif resutl  == 3:
            return jsonify({'message' : 'goaddy error'}), 500

        


        # Delete the associated configuration file
        config_filename = domain + '.conf'
        config_file_path = os.path.join(config_output_path, config_filename)
        if os.path.exists(config_file_path):
            os.remove(config_file_path)
            subprocess.run(['nginx', '-s', 'reload'], check=True)
            return jsonify({'message': f'Domain {domain} removed successfully'}), 200
        else:
            return jsonify({'message': f'Domain {domain} not found.'}), 404
    except Exception as e:
        return jsonify({'message': f'An error occurred while removing the domain: {str(e)}'}), 500



# Endpoint 6: 404 handling 
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def handle_undefined_routes(path):
    # Return an error response for any undefined route (HTTP status code 404) , i think it better to return all the endpoint instead of Not Found
    return jsonify({'error': 'Not Found , please dont not expose this to external , this is a internal service only if you see this message from the external fix it'}), 404


if __name__ == '__main__':
    if checkdomaingodaddy(DOMAINNAME) == False:
        print("domain not found")
        exit
    app.run(debug=True , host='0.0.0.0' , port=3000)
