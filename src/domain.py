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
import secrets
import os


# used to make the microservice more dynamic
path_to_template = "/etc/nginx/conf.d/template.sample"   # the sample must exist in the docker volume 
config_output_path = "/etc/nginx/conf.d"



app = Flask(__name__)


# in-memory storage for domains and user-domain mapping (replace this with a proper database in production)
# later on use caching as it will be faster to request 

domains = set()
user_domain_mapping = {}


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
        return jsonify({'message': f'domain {new_domain} created successfully.'}), 200
    except Exception as e:
        return jsonify({'error': f'an error occurred while generating the domain: {str(e)}'}), 500
    

# Endpoint 2: create a domain for a used based of input tenant and generate nginx config file for the new subdomain
# PROBLEM TO BE FIXED : the tenant id can be used multiple times generating multiple configfile
@app.route('/createdomaintenantbased', methods=['POST'])
def create_domain_tenant_based():
    if request.method != 'POST':
        return jsonify({'error': 'method Not Allowed'}), 405
    username = request.form.get('username')
    tenant = request.form.get('tenant')
    try:
        if not username or not tenant:
            return jsonify({'error': 'both username and tenant parameters are required'}), 400
    
        new_domain = generate_unique_hash()
        config_filename = new_domain + '.conf'

        replacements = { 'variable1': new_domain , 'variable2': tenant } # this to make more dynamic instead of using the variable new_domain use the full command , this will allow you to have one generic file 
        with open(path_to_template, 'r') as template_file:
            template_content = template_file.read()

        for placeholder, value in replacements.items():
            template_content = template_content.replace(f'<${placeholder}>', str(value))

        with open(os.path.join(config_output_path, config_filename), 'w') as output_file:
            output_file.write(template_content)

        if username in user_domain_mapping:
            user_domain_mapping[username]['domains'].append(new_domain)
        else:
            user_domain_mapping[username] = {'username': username, 'domains': [new_domain]}
        return jsonify({'message': f'Domain {new_domain} created successfully'}), 200
    except FileNotFoundError as e:
        return jsonify({'error' : 'file not found '}), 500
    except Exception as e:
        return jsonify({'error': f'an error occurred while creating the config file or domain: {str(e)}'}), 500


# Endpoint 3: return all the domain associated to the user ( use pagination , enhance required on the page side )
@app.route('/domainsmapuser', methods=['GET'])
def domains_map_user():
    if request.method != 'GET':
        return jsonify({'error': 'method Not Allowed'}), 405
    username = request.args.get('username')
    pag = int(request.args.get('pag', 50))
    if not username:
        return jsonify({'error': 'username parameter is required'})  
    if username not in user_domain_mapping:
        return jsonify({'error': f'user {username} not found'}), 404
    try:
        mapped_domains = user_domain_mapping[username]['domains']
        num_domains = len(mapped_domains)
        start_index = 0
        end_index = num_domains if pag >= num_domains else pag
        paginated_domains = mapped_domains[start_index:end_index]
        return jsonify({'username': username, 'domains': paginated_domains}), 200
    except Exception as e:
        return jsonify({'error': f'an error occurred while processing the request: {str(e)}'}), 500

# Endpoint 4: return the user of specified domain 
@app.route('/domainmapuser', methods=['GET'])
def domain_map_user():
    if request.method != 'GET':
        return jsonify({'error': 'method Not Allowed'}), 405
    domain = request.args.get('domain')
    try:
        if not domain:
            return jsonify({'error': 'domain parameter is required'}), 400
        for username, data in user_domain_mapping.items():
            if domain in data['domains']:
                return jsonify({'domain': domain, 'username': username}), 200

        return jsonify({'error': f'domain {domain} not found'}), 404 # change it to something more usefull not 404 
    except Exception as e:
        return jsonify({'error': f'an error occurred while processing the request: {str(e)}'}), 500

@app.route('/removedomain', methods=['GET'])
def remove_domain():
    if request.method != 'GET':
        return jsonify({'error': 'Method Not Allowed'}), 405

    domain = request.args.get('domain')
    try:
        if not domain:
            return jsonify({'error': 'Domain parameter is required'}), 400

        if domain in domains:
            domains.remove(domain)

            # Remove the domain from the user-domain mapping
            for username, mapped_domains in user_domain_mapping.items():
                if domain in mapped_domains['domains']:
                    mapped_domains['domains'].remove(domain)
                    break

            # Delete the associated configuration file
            config_filename = domain + '.conf'
            config_file_path = os.path.join(config_output_path, config_filename)
            if os.path.exists(config_file_path):
                os.remove(config_file_path)

            return jsonify({'message': f'Domain {domain} removed successfully'}), 200
        else:
            return jsonify({'error': f'Domain {domain} not found.'}), 404
    except Exception as e:
        return jsonify({'error': f'An error occurred while removing the domain: {str(e)}'}), 500


# Endpoint 6: 404 handling 
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def handle_undefined_routes(path):
    # Return an error response for any undefined route (HTTP status code 404) , i think it better to return all the endpoint instead of Not Found
    return jsonify({'error': 'Not Found'}), 404


if __name__ == '__main__':
    app.run(debug=True , host='0.0.0.0' , port=3000)
