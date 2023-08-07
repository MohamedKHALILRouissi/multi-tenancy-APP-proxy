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



from flask import Flask, request, jsonify
import os
import subprocess


# used to make the microservice more dynamic
path_to_template = "/etc/nginx/conf.d/template.sample"   # the sample must exist in the docker volume 
config_output_path = "/etc/nginx/conf.d"


app = Flask(__name__)


# in-memory storage for domains and user-domain mapping (replace this with a proper database in production)
# later on use caching as it will be faster to request 





# function layer 
def generate_unique_hash():
    # generate a random 12-digit hash
    while True:
        random_hash = str(secrets.randbelow(10**12)).zfill(12)  # Ensure 12-digit format
        if random_hash not in domains: # Ensure that the hash is unique 
            domains.add(random_hash)
            return random_hash
        




# Endpoint 1: create a random subdomain for a user and nginx config file generated ( this require no mapping or tracking thus it used to generate the file and subdomain , storing and tracking handled at another layer )
@app.route('/createrandomdomain', methods=['GET'])
def create_random_domain():
    if request.method != 'GET':
        return jsonify({'error': 'method Not Allowed'}), 405
    try:
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
    try:
        if not tenant_id or not subdomain:
            return jsonify({'message': 'both tenant-id and subdomain parameters are required'}), 400
    
         
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
    app.run(debug=True , host='0.0.0.0' , port=3000)
