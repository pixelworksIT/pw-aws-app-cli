Pixelworks AWS Application Commandline Tools
======

Using Pixelworks AWS Applications from commandline.

This tools is designed for Pixelworks employees, customers and vendors to access AWS resources of Pixelworks under business contract.

Quick Installation
------

```
$ git clone https://github.com/pixelworksIT/pw-aws-app-cli.git
$ cd pw-aws-app-cli
$ pip3 install .
```

**Note:** Python >= 3.2 is required.

Usage
------

### Get Authenticated and Authorized

```
$ pw-app-authz-cli --help
usage: pw-app-authz-cli [-h] -u USERNAME [-s] [-P] -a APPNAME [-C]
                        [-M MFACODE]

Authenticate against Pixelworks identiy providers
  and get autorized to access AWS resources of Pixelworks.

optional arguments:
  -h, --help   show this help message and exit
  -u USERNAME  Username is in E-mail format
  -s           Read password from STDIN
  -P           User is considered as a Pixelworks employee account
  -a APPNAME   Select application to access
               Available applications:
                 pwVaultBox
                 Git
  -C           To access resources in AWS China regions
  -M MFACODE   MFA code if MFA is enable for account
```

#### Examples

For Pixelworks employees to get access to Git service

```
$ pw-app-authz-cli -u example@pixelworks.com -P -a Git -M 123456
```

For other users

```
$ pw-app-authz-cli -u example@abc.com -a Git
```

Save your password in text file to avoid input password

```
$ touch ~/.mypass
$ chmod 600 ~/.mypass
$ echo "Uor#Pas5w0rd" > ~/.mypass
$ pw-app-authz-cli -u example@abc.com -a Git < ~/.mypass
```

### Using the Authorized Credential Profile

After get authenticated and authorized, an AWS credential profile will be created for you using the name of the application you specified in the command (-a).

In above examples, a profile named "Git" is created. Then you can access corresponding AWS resources as allowed by the profile.

For example:

```
$ aws --profile Git codecommit create-repository ...
```

### The Real Credential Provider

Open file `~/.aws/credentials` , find section `[Git]`, as used in above example. It looks like following

```
[Git]
credential_process = pw-app-authz-renew --app-name Git
```

Here you will mention the command `pw-app-authz-renew` . It is the command that providing real AWS credential to AWS command line tool and applications based on AWS SDK. It is installed along with `pw-app-authz-cli` .

In case the command is not in PATH, please update the configuration with full path to `pw-app-authz-renew`, in `~/.aws/credentials` .

Known Common Errors
------

Following are known errors that you will see commonly when using `pw-app-authz-cli`. Please try the command again if you see these errors.

 * `{'message': 'Internal server error'}`
 * `Exit(6): 2FA auth failed`
 * `Exit(6): Login error`
