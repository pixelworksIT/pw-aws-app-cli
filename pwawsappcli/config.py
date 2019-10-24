## #!/usr/bin/env python3
##
# Copyright 2019 Pixelworks Inc.
#
# Author: Houyu Li <hyli@pixelworks.com>
#
# Load config values from user specific config file
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

import os, sys, configparser

# The fixed config file name
PW_APP_CONF_FN = u'.pwawsapprc'

def load():
    """Load config options and values for predefined config file

    Return options and values in a ConfigParser object
    """

    # The user HOME
    user_home = os.path.expanduser(u'~')

    # Config file fullpath
    pw_app_conf_file = os.path.join(user_home, PW_APP_CONF_FN)

    # Make sure the config file is there
    if not os.path.isfile(pw_app_conf_file):
        # If file not exists
        print(u"Cannot find config file %s . Please contact system administrator. Exit(1)" % (pw_app_conf_file), file = sys.stderr)
        sys.exit(1)
    # Make sure config file is readable
    try:
        open(pw_app_conf_file, 'a').close()
    except:
        print(u"Failed to access config file. Please check permission. Exit(2)", file = sys.stderr)
        sys.exit(2)

    # Now load the config file
    pw_app_conf = None
    try:
        pw_app_conf = configparser.ConfigParser()
        pw_app_conf.read(pw_app_conf_file)
    except:
        # Error on parsing config file
        print(u"Unable to parse config file. Please check format. Exit(3)", file = sys.stderr)
        sys.exit(3)

    # Prepare AWS directory and files
    aws_files = _prepare_aws_config()

    # Merge aws file options and values into the main config dictionary
    for opt, value in aws_files.items():
        pw_app_conf[u'DEFAULT'][opt] = value

    return pw_app_conf

def _prepare_aws_config():
    """Check and prepare AWS config and credential file

    Return related file paths
    """

    user_home = os.path.expanduser(u'~')

    u_aws_files = {
        u'MY_HOME': user_home,
        u'MY_AWS_CONF': os.path.join(user_home, u'.aws', u'config'),
        u'MY_AWS_CRED': os.path.join(user_home, u'.aws', u'credentials')
    }

    try:
        if not os.path.isdir(os.path.join(u_aws_files[u'MY_HOME'], u'.aws')):
            os.makedirs(os.path.join(u_aws_files[u'MY_HOME'], u'.aws'), exist_ok = True)
        if not os.path.isfile(u_aws_files[u'MY_AWS_CONF']):
            open(u_aws_files[u'MY_AWS_CONF'], 'a').close()
        if not os.path.isfile(u_aws_files[u'MY_AWS_CRED']):
            open(u_aws_files[u'MY_AWS_CRED'], 'a').close()
    except:
        print(u"Unable to prepare path %s and files in it. Permission issue? Exit(4)" % (os.path.join(u_aws_files[u'MY_HOME'], u'.aws')), file = sys.stderr)
        sys.exit(4)

    return u_aws_files