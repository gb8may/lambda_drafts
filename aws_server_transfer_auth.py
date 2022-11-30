import os
import json
import boto3
import base64
from ipaddress import ip_network, ip_address
from botocore.exceptions import ClientError


def lambda_handler(event, context):
    required_param_list = ["serverId", "username", "protocol", "sourceIp"]
    for parameter in required_param_list:
        if parameter not in event:
            print("Incoming " + parameter + " missing - Unexpected")
            return {}

    input_serverId = event["serverId"]
    input_username = event["username"]
    input_protocol = event["protocol"]
    input_sourceIp = event["sourceIp"]
    input_password = event.get("password", "")

    print("ServerId: {}, Username: {}, Protocol: {}, SourceIp: {}"
          .format(input_serverId, input_username, input_protocol, input_sourceIp))

    print("Start User Authentication Flow")
    if input_password != "":
        print("Using PASSWORD authentication")
        authentication_type = "PASSWORD"
    else:
        if input_protocol == 'FTP' or input_protocol == 'FTPS':
            print("Empty password not allowed for FTP/S")
            return {}
        print("Using SSH authentication")
        authentication_type = "SSH"

    secret = get_secret(input_serverId + "/" + input_username)

    if secret is not None:
        secret_dict = json.loads(secret)
        user_authenticated = authenticate_user(authentication_type, secret_dict, input_password, input_protocol)
        ip_match = check_ipaddress(secret_dict, input_sourceIp, input_protocol)

        if user_authenticated and ip_match:
            print("User authenticated, calling build_response with: " + authentication_type)
            return build_response(secret_dict, authentication_type, input_protocol)
        else:
            print("User failed authentication return empty response")
            return {}
    else:
        print("Secrets Manager exception thrown - Returning empty response")
        return {}


def lookup(secret_dict, key, input_protocol):
    if input_protocol + key in secret_dict:
        print("Found protocol-specified {}".format(key))
        return secret_dict[input_protocol + key]
    else:
        return secret_dict.get(key, None)


def check_ipaddress(secret_dict, input_sourceIp, input_protocol):
    accepted_ip_network = lookup(secret_dict, "AcceptedIpNetwork", input_protocol)
    if not accepted_ip_network:
        print("No IP range provided - Skip IP check")
        return True

    net = ip_network(accepted_ip_network)
    if ip_address(input_sourceIp) in net:
        print("Source IP address match")
        return True
    else:
        print("Source IP address not in range")
        return False


def authenticate_user(auth_type, secret_dict, input_password, input_protocol):
    if auth_type == "SSH":
        print("Skip password check as SSH login request")
        return True
    else:
        password = lookup(secret_dict, "Password", input_protocol)
        if not password:
            print("Unable to authenticate user - No field match in Secret for password")
            return False

        if input_password == password:
            return True
        else:
            print("Unable to authenticate user - Incoming password does not match stored")
            return False


def build_response(secret_dict, auth_type, input_protocol):
    response_data = {}
    role = lookup(secret_dict, "Role", input_protocol)
    if role:
        response_data["Role"] = role
    else:
        print("No field match for role - Set empty string in response")
        response_data["Role"] = ""

    policy = lookup(secret_dict, "Policy", input_protocol)
    if policy:
        response_data["Policy"] = policy

    home_directory_details = lookup(secret_dict, "HomeDirectoryDetails", input_protocol)
    if home_directory_details:
        print("HomeDirectoryDetails found - Applying setting for virtual folders - "
              "Note: Cannot be used in conjunction with key: HomeDirectory")
        response_data["HomeDirectoryDetails"] = home_directory_details
        print("Setting HomeDirectoryType to LOGICAL")
        response_data["HomeDirectoryType"] = "LOGICAL"

    home_directory = lookup(secret_dict, "HomeDirectory", input_protocol)
    if home_directory:
        print("HomeDirectory found - Note: Cannot be used in conjunction with key: HomeDirectoryDetails")
        response_data["HomeDirectory"] = home_directory

    if auth_type == "SSH":
        public_key = lookup(secret_dict, "PublicKey", input_protocol)
        if public_key:
            response_data["PublicKeys"] = [public_key]
        else:
            print("Unable to authenticate user - No public keys found")
            return {}

    return response_data


def get_secret(id):
    region = os.environ["SecretsManagerRegion"]
    print("Secrets Manager Region: " + region)
    print("Secret Name: " + id)

    client = boto3.session.Session().client(service_name="secretsmanager", region_name=region)

    try:
        resp = client.get_secret_value(SecretId=id)
        if "SecretString" in resp:
            print("Found Secret String")
            return resp["SecretString"]
        else:
            print("Found Binary Secret")
            return base64.b64decode(resp["SecretBinary"])
    except ClientError as err:
        print("Error Talking to SecretsManager: " + err.response["Error"]["Code"] + ", Message: " +
              err.response["Error"]["Message"])
        return None
