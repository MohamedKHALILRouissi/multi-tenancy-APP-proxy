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

domains = set()
user_domain_mapping = {}


@app.route('/createdomaintenantbased', methods=['POST'])
def create_domain_tenant_based():
    if request.method != 'POST':
        return jsonify({'error': 'method Not Allowed'}), 405
    tenant_id = request.form.get('tenant-id')
    subdomain = request.form.get('subdomain')
    try:
        if not tenant_id or not subdomain:
            return jsonify({'error': 'both tenant-id and subdomain parameters are required'}), 400
    
         
        config_filename = subdomain + '.conf'

        replacements = { 'variable1': subdomain , 'variable2': '' }  # Updated variable names
        with open(path_to_template, 'r') as template_file:
            template_content = template_file.read()

        for placeholder, value in replacements.items():
            template_content = template_content.replace(f'<${placeholder}>', str(value))

        with open(os.path.join(config_output_path, config_filename), 'w') as output_file:
            output_file.write(template_content)
        subprocess.run(['nginx', '-s', 'reload'], check=True)

        if tenant_id in user_domain_mapping:  # Updated variable name
            user_domain_mapping[tenant_id]['domains'].append(subdomain)  # Updated variable name
        else:
            user_domain_mapping[tenant_id] = {'tenant-id': tenant_id, 'domains': [subdomain]}  # Updated variable name
        return jsonify({'message': f'Domain {subdomain} created successfully'}), 200
    except FileNotFoundError as e:
        return jsonify({'error' : 'file not found '}), 500
    except Exception as e:
        return jsonify({'error': f'an error occurred while creating the config file or domain: {str(e)}'}), 500


@app.route('/domainsmapuser', methods=['GET'])
def domains_map_user():
    if request.method != 'GET':
        return jsonify({'error': 'method Not Allowed'}), 405
    tenant_id = request.args.get('tenant-id')  # Updated variable name
    pag = int(request.args.get('pag', 50))
    if not tenant_id:
        return jsonify({'error': 'tenant-id parameter is required'})  # Updated variable name
    if tenant_id not in user_domain_mapping:  # Updated variable name
        return jsonify({'error': f'tenant {tenant_id} not found'}), 404  # Updated variable name
    try:
        mapped_domains = user_domain_mapping[tenant_id]['domains']  # Updated variable name
        num_domains = len(mapped_domains)
        start_index = 0
        end_index = num_domains if pag >= num_domains else pag
        paginated_domains = mapped_domains[start_index:end_index]
        return jsonify({'tenant-id': tenant_id, 'domains': paginated_domains}), 200  # Updated variable name
    except Exception as e:
        return jsonify({'error': f'an error occurred while processing the request: {str(e)}'}), 500


@app.route('/domainmapuser', methods=['GET'])
def domain_map_user():
    if request.method != 'GET':
        return jsonify({'error': 'method Not Allowed'}), 405
    domain = request.args.get('domain')
    try:
        if not domain:
            return jsonify({'error': 'domain parameter is required'}), 400
        for tenant_id, data in user_domain_mapping.items():  # Updated variable name
            if domain in data['domains']:
                return jsonify({'domain': domain, 'tenant-id': tenant_id}), 200  # Updated variable name

        return jsonify({'error': f'domain {domain} not found'}), 404  # change it to something more useful not 404
    except Exception as e:
        return jsonify({'error': f'an error occurred while processing the request: {str(e)}'}), 500


@app.route('/removedomain', methods=['POST'])
def remove_domain():
    if request.method != 'POST':
        return jsonify({'error': 'Method Not Allowed'}), 405

    domain = request.form.get('domain')
    try:
        if not domain:
            return jsonify({'error': 'Domain parameter is required'}), 400

        if domain in domains:
            domains.remove(domain)

            # Remove the domain from the user-domain mapping
            for tenant_id, mapped_domains in user_domain_mapping.items():  # Updated variable name
                if domain in mapped_domains['domains']:
                    mapped_domains['domains'].remove(domain)
                    break

            # Delete the associated configuration file
            config_filename = domain + '.conf'
            config_file_path = os.path.join(config_output_path, config_filename)
            if os.path.exists(config_file_path):
                os.remove(config_file_path)
            subprocess.run(['nginx', '-s', 'reload'], check=True)

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
    return jsonify({'error': 'Not Found , please dont not expose this to external , this is a internal service only if you see this message from the external fix it'}), 404


if __name__ == '__main__':
    app.run(debug=True , host='0.0.0.0' , port=3000)
