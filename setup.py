import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name = "pwawsappcli",
    version = "0.0.1",
    author = "HouYu Li",
    author_email = "hyli@pixelworks.com",
    description = "Command line tools for Pixelworks AWS applications",
    long_description = long_description,
    long_description_content_type = "text/markdown",
    url = "https://github.com/pixelworksIT/pw-aws-app-cli",
    license = "Apache Software License",
    packages=setuptools.find_packages(),
    install_requires = ["requests", "authlib", "boto3"],
    entry_points = {
        'console_scripts':[
            'pw-app-authz-cli=pwawsappcli.authorizer:command',
            'pw-app-authz-renew=pwawsappcli.authorizer:renew'
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent"
    ],
)