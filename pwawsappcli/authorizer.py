## #!/usr/bin/env python3
##
# Copyright 2019 Pixelworks Inc.
#
# Author: Houyu Li <hyli@pixelworks.com>
#
# Command for authorizer application
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# 		http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
## // ##

import os, sys, argparse, getpass, base64, time, json, configparser, datetime
from argparse import RawTextHelpFormatter
from json import JSONDecodeError

import requests
from requests import RequestException

from authlib.jose import jwt
from authlib.jose.errors import JoseError

import boto3

from . import config

def command():
    """Command: pw-app-authz-cli

    Get authenticated against:
        Pixelworks ADFS
        Pixelworks Identity Provider for 3rd Party User

    Get authorized based on assumable IAM roles and IAM policies

    Set proper AWS credential profile based on application name
    """
    # Load config values first
    c = config.load()

    # Extract config options based on sections
    c_default = c[u'DEFAULT']
    c_authz = c[u'authorizer']

    # Need to get list of apps first
    available_apps = _get_app_names(c_authz[u'URL_APP_NAMES'])

    parser = argparse.ArgumentParser(
        description = u'Authenticate against Pixelworks identiy providers\n  and get autorized to access AWS resources of Pixelworks.',
        formatter_class = RawTextHelpFormatter
    )
    # Username is mandatory
    parser.add_argument(u'-u',
        nargs = 1,
        required = True,
        help = u'Username is in E-mail format',
        metavar = u'USERNAME'
    )
    # To read password from STDIN
    parser.add_argument(u'-s',
        action = u'store_true',
        help = u'Read password from STDIN'
    )
    # For Pixelworks employees
    parser.add_argument(u'-P',
        action = u'store_true',
        help = u'User is considered as a Pixelworks employee account'
    )
    # For picking up applications
    parser.add_argument(u'-a',
        nargs = 1,
        required = True,
        choices = available_apps,
        help = u'Select application to access\nAvailable applications: \n  %s' % (u'\n  '.join(available_apps)),
        metavar = u'APPNAME'
    )
    # For China regions
    parser.add_argument(u'-C',
        action = u'store_true',
        help = u'To access resources in AWS China regions'
    )
    # For MFA code
    parser.add_argument(u'-M',
        nargs = 1,
        default = [u'000000'],
        help = u'MFA code if MFA is enable for account',
        metavar = (u'MFACODE')
    )

    args = parser.parse_args()

    # Prepare some variables
    u_username = u''
    u_password = u''
    aws_api_url = u''
    aws_region = u''
    app_name = args.a[0]
    mfa_code = args.M[0]
    # Extra value for UI matching
    ui_aws_region = u''
    ui_user_type = u''

    # Get the password first
    if args.s:
        # Read password from STDIN
        u_password = sys.stdin.readline()
    else:
        # Prompt for password
        u_password = getpass.getpass(prompt = u'Password: ')
    # Remove leading and trailing spaces
    u_password = u_password.strip()
    # If empty password, exit
    if len(u_password) == 0:
        print(u"Empty password. Exit(3)", file = sys.stderr)
        sys.exit(3)

    # The input username
    u_username = args.u[0]

    # Determine region and login API URL
    if args.C:
        # China regions is selected
        ui_aws_region = u'china'
        aws_region = c_authz[u'CONF_REGION_C']
        # By default, we assume 3rd party account
        ui_user_type = u'3rd'
        aws_api_url = c_authz[u'API_URL_C_3RD']
        if args.P:
            # Pixelworks account
            ui_user_type = u'pw'
            aws_api_url = c_authz[u'API_URL_C_PW']
    else:
        # Use global regions
        ui_aws_region = u'global'
        aws_region = c_authz['CONF_REGION_G']
        # By default, we assume 3rd party account
        ui_user_type = u'3rd'
        aws_api_url = c_authz[u'API_URL_G_3RD']
        if args.P:
            # Pixelworks account
            ui_user_type = u'pw'
            aws_api_url = c_authz[u'API_URL_G_PW']

    # Hold response string
    login_res = None

    # Now the login request
    try:
        # Generate the authorization token
        authz_token = jwt.encode(
            {
                u'alg': c_authz[u'TOKEN_ALG']
            },
            {
                u'sub': c_authz[u'TOKEN_SUB'],
                u'iss': app_name,
                u'exp': int(time.time()) + int(c_authz['TOKEN_EXP'])
            },
            base64.b64decode(c_authz[u'P_KEY'].encode())
        )

        # Send POST request with data and token
        login_req = requests.post(
            aws_api_url,
            data = u'{ "username": "%s", "password": "%s", "mfa": "%s", "app": "%s" }' % (u_username, u_password, mfa_code, app_name),
            headers = {
                u'Authorizationtoken': authz_token
            }
        )

        # Get JSON string from response
        login_res = login_req.json()
    except JoseError:
        print(u"Generate token error. Exit(4)", file = sys.stderr)
        sys.exit(4)
    except RequestException:
        print(u"Login request failed. Check network. Exit(5)", file = sys.stderr)
        sys.exit(5)
    except:
        print(u"Unknown error. Exit(99)", file = sys.stderr)
        sys.exit(99)

    # Now parse the response data and save in config file
    try:
        # If login success, we should be able to parse the response string as a JSON object
        login_data = json.loads(login_res)

        # Section names in config files
        app_section_name = app_name
        app_cache_section_name = u'%s_cache' % (app_name)
        app_conf_section_name = u'profile %s' % (app_section_name)
        app_cache_conf_section_name = u'profile %s' % (app_cache_section_name)

        # The credentials config file
        aws_cred = configparser.ConfigParser()
        aws_cred.read(c_default[u'MY_AWS_CRED'])
        # First, we write the credentials in _cache section
        aws_cred[app_cache_section_name] = {
            u'aws_access_key_id': login_data[u'Credentials'][u'AccessKeyId'],
            u'aws_secret_access_key': login_data[u'Credentials'][u'SecretAccessKey'],
            u'aws_session_token': login_data[u'Credentials'][u'SessionToken']
        }
        # Then, we write credential_process in main app section, if not exists
        if not aws_cred.has_option(
            app_section_name,
            u'credential_process'
        ):
            aws_cred[app_section_name] = {
                u'credential_process': u'%s --app-name %s' % (c_authz[u'CRED_PROC'], app_name)
            }
        # Write credential file back
        with open(c_default[u'MY_AWS_CRED'], 'w') as aws_cred_file:
            aws_cred.write(aws_cred_file)

        # The config file
        aws_conf = configparser.ConfigParser()
        aws_conf.read(c_default['MY_AWS_CONF'])
        # Set config for main app profile
        aws_conf[app_conf_section_name] = {
            u'region': aws_region,
            u'output': u'json',
            u'app_session_id': login_data[u'AppSessionId'],
            u'ui_user_id': u_username,
            u'ui_user_type': ui_user_type,
            u'ui_aws_region': ui_aws_region
        }
        # Set config for _cache profile
        aws_conf[app_cache_conf_section_name] = {
            u'region': aws_region,
            u'output': 'json',
            u'expiration': login_data[u'Credentials'][u'sExpiration']
        }
        # Write config file back
        with open(c_default['MY_AWS_CONF'], 'w') as aws_conf_file:
            aws_conf.write(aws_conf_file)

        # Create an app config file if not exists
        app_conf_path = os.path.join(c_default[u'MY_HOME'], u'.aws', app_name)
        if not os.path.isfile(app_conf_path):
            # Create an empty file first
            open(app_conf_path, 'a').close()
            # Load with configparser
            app_conf = configparser.ConfigParser()
            app_conf.read(app_conf_path)
            # Set default values
            app_conf[u'DEFAULT'] = {
                u'aws_region': aws_region,
                u'first_run': u'1'
            }
            # Write the app config file
            with open(app_conf_path, 'a') as app_conf_file:
                app_conf.write(app_conf_file)

    except JSONDecodeError:
        # Otherwise, it's a plain string that telling some errors
        print(u"Exit(6): %s" % (login_res), file = sys.stderr)
        sys.exit(6)
    except:
        print(login_res)
        print(u"Unknown error. Exit(99.1)", file = sys.stderr)
        sys.exit(99)

    # And finally, all done.
    print(u"Authorization done. Profile name \"%s\"" % (app_name))

def renew():
    """Command: pw-app-authz-renew

    Renew credential processor

    Get application name from option --app-name
    Get session ID based on app name
    If cached credential is not to expire within 10 minutes,
      return the cached credential.
    Otherwise, invoke AWS Lambda function with session ID to get new credential.
    """

    # Load config values first
    c = config.load()

    # Extract config options based on sections
    c_default = c[u'DEFAULT']
    c_authz = c[u'authorizer']

    parser = argparse.ArgumentParser(
        description = u'Renew AWS application credential based on application name'
    )
    # Application name is mandatory
    parser.add_argument(
        '--app-name',
        nargs = 1,
        required = True,
        help = u'The application name'
    )

    args = parser.parse_args()

    # Prepare some variables
    app_name = args.app_name[0]
    renew_cred = 0

    # Section names in config files
    app_section_name = app_name
    app_cache_section_name = u'%s_cache' % (app_name)
    app_conf_section_name = u'profile %s' % (app_section_name)
    app_cache_conf_section_name = u'profile %s' % (app_cache_section_name)

    # The credential data to be returned by print to stdout
    cred_data = {}
    cred_data[u'Version'] = 1

    # Check in config file for expiration time
    aws_conf = None
    try:
        aws_conf = configparser.ConfigParser()
        aws_conf.read(c_default['MY_AWS_CONF'])
    except:
        print(u"Unable to parse config file. Exit(1)", file = sys.stderr)
        sys.exit(1)

    if not aws_conf.has_option(
        app_cache_conf_section_name,
        u'expiration'
    ):
        # If no expiration set in profile _cache section,
        #  then we need to renew the credential.
        renew_cred = 1
    else:
        # Expiration time is there.
        # We need to check the time.
        # If current time is within 10 minutes compared to expiration time,
        #  then we do renew
        try:
            time_exp = _gen_expiration_10min_less(
                aws_conf[app_cache_conf_section_name][u'expiration']
            )

            if datetime.datetime.utcnow() >= time_exp:
                renew_cred = 1
        except:
            # If any error, we will need to renew
            renew_cred = 1

    if renew_cred == 1:
        # Sure to renew credentials

        # Profiled AWS session, based on _cache credential
        aws_sess = boto3.session.Session(
            profile_name = app_cache_section_name
        )

        # Get current application session ID from config file in app profile section
        # If not exists, exit with error
        if not aws_conf.has_option(
            app_conf_section_name,
            u'app_session_id'
        ):
            print(u"No saved application session ID (app_session_id). Exit(2)", file = sys.stderr)
            sys.exit(2)
        # Generate payload for renew function
        renew_payload = {
            u'session_id': aws_conf[app_conf_section_name][u'app_session_id']
        }
        # Invoke the Lambda function
        renew_res = None
        try:
            lambda_client = aws_sess.client(u'lambda')
            renew_res = lambda_client.invoke(
                FunctionName = c_authz[u'LAMBDA_RENEW'],
                Payload = json.dumps(renew_payload)
            )
        except:
            print(u"Unable to invoke renew function. Exit(3)", file = sys.stderr)
            sys.exit(3)

        # Extract result data
        res_data = json.loads(renew_res[u'Payload'].read().decode())

        # Renew success or not
        if int(res_data[u'statusCode']) == 200:
            # Renew successfully

            # The actual data body
            res_body = json.loads(res_data[u'body'])

            # Load credential file
            aws_cred = None
            try:
                aws_cred = configparser.ConfigParser()
                aws_cred.read(c_default[u'MY_AWS_CRED'])
            except:
                print(u"Unable to parse credential file. Exit(1)", file = sys.stderr)
                sys.exit(1)
            # Set credential data
            aws_cred[app_cache_section_name] = {
                u'aws_access_key_id': res_body[u'Credentials'][u'AccessKeyId'],
                u'aws_secret_access_key': res_body[u'Credentials'][u'SecretAccessKey'],
                u'aws_session_token': res_body[u'Credentials'][u'SessionToken']
            }
            # If credential_process not exists, add it.
            if not aws_cred.has_option(
                app_section_name,
                u'credential_process'
            ):
                aws_cred[app_section_name] = {
                    u'credential_process': u'%s --app-name %s' % (c_authz[u'CRED_PROC'], app_name)
                }
            # Save
            try:
                with open(c_default[u'MY_AWS_CRED'], 'w') as aws_cred_file:
                    aws_cred.write(aws_cred_file)
            except:
                print(u"Unable to save credential file. Exit(5)", file = sys.stderr)
                sys.exit(5)

            # Also update config file
            aws_conf[app_conf_section_name][u'app_session_id'] = res_body[u'AppSessionId']
            aws_conf[app_cache_conf_section_name][u'expiration'] = res_body[u'Credentials'][u'sExpiration']
            # Save
            try:
                with open(c_default['MY_AWS_CONF'], 'w') as aws_conf_file:
                    aws_conf.write(aws_conf_file)
            except:
                print(u"Unable to save config file. Exit(6)", file = sys.stderr)
                sys.exit(6)

            # Renew done

            # Now print out the new credential for use
            cred_data[u'AccessKeyId'] = res_body[u'Credentials'][u'AccessKeyId']
            cred_data[u'SecretAccessKey'] = res_body[u'Credentials'][u'SecretAccessKey']
            cred_data[u'SessionToken'] = res_body[u'Credentials'][u'SessionToken']
            cred_data[u'Expiration'] = _gen_expiration_10min_less(
                res_body[u'Credentials'][u'sExpiration']).strftime(u'%Y-%m-%dT%H:%M:%SZ')

            print(json.dumps(cred_data))

            sys.exit()
        else:
            # Something wrong when renewing
            print(u"Renew failed: %s. Exit(4)" % (json.loads(res_data[u'body'])), file = sys.stderr)
            sys.exit(4)
    else:
        # Not yet to renew
        # Use the cached one

        # Load credential file
        aws_cred = None
        try:
            aws_cred = configparser.ConfigParser()
            aws_cred.read(c_default[u'MY_AWS_CRED'])
        except:
            print(u"Unable to parse credential file. Exit(1.1)", file = sys.stderr)
            sys.exit(1)

        # Only return if all keys are there
        if aws_cred.has_option(app_cache_section_name, u'aws_access_key_id') \
            and aws_cred.has_option(app_cache_section_name, u'aws_secret_access_key') \
            and aws_cred.has_option(app_cache_section_name, u'aws_session_token'):

            # Print out the cached credential
            cred_data[u'AccessKeyId'] = aws_cred[app_cache_section_name][u'aws_access_key_id']
            cred_data[u'SecretAccessKey'] = aws_cred[app_cache_section_name][u'aws_secret_access_key']
            cred_data[u'SessionToken'] = aws_cred[app_cache_section_name][u'aws_session_token']
            cred_data[u'Expiration'] = _gen_expiration_10min_less(
                aws_conf[app_cache_conf_section_name][u'expiration']).strftime(u'%Y-%m-%dT%H:%M:%SZ')

            print(json.dumps(cred_data))

            sys.exit()
        else:
            print(u"No credential data found in credential file. Exit(7)", file = sys.stderr)
            sys.exit(7)

def _get_app_names(url):
    """Get app_names.json remotely"""

    apps = []

    try:
        req = requests.get(url)
        for app_info in req.json():
            apps.append(app_info[u'id'])
    except:
        print(u"Unable to get list of applications. Exit(2)", file = sys.stderr)
        sys.exit(2)

    return apps

def _gen_expiration_10min_less(input_dt_str, input_fmt = u'%Y-%m-%dT%H:%M:%SZ'):
    """The function to generate expiration time, 10 minutes shorter"""

    input_dt = datetime.datetime.strptime(input_dt_str, input_fmt)

    return input_dt - datetime.timedelta(minutes = 10)
