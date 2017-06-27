#!/usr/bin/env python

"""AWS CLI Switch Roles setup."""

import argparse
import boto3
import errno
import ConfigParser
from botocore.exceptions import ClientError
import os
from datetime import datetime, timedelta

parser = argparse.ArgumentParser()

# Loop through the arguments provided to the method
arguments = [
    {
        'accept': '--profile',
        'required': False,
        'help': "Profile to switch from"
    },
    {
        'accept': '--role',
        'required': False,
        'help': "Role Name to switch to"
    },
    {
        'accept': '--account',
        'required': False,
        'help': "Account to switch to"
    },
    {
        'accept': '--username',
        'required': False,
        'help': "Username of the user your switching from"
    },
    {
        'accept': '--name',
        'required': False,
        'help': "What to call the new profile"
    },
    {
        'accept': '--mfa',
        'required': False,
        'help': "MFA code to use"
    },
    {
        'accept': '--all',
        'required': False,
        'help': "Expired profiles"
    },
    {
        'accept': '--list',
        'required': False,
        'help': "List profiles currently available to use"
    },
    {
        'accept': '--external_id',
        'required': False,
        'help': "External Id for the role"
    }
]


# Check all the arguments passed in
for a in arguments:

    # Add the argument to the parser
    if a['accept'] is '--list' or a['accept'] is '--all':
        parser.add_argument(
            a['accept'],
            required=a['required'],
            action='store_true',
            help=a['help']
        )
    else:
        parser.add_argument(
            a['accept'],
            required=a['required'],
            metavar='<arg>',
            type=str,
            help=a['help']
        )

    # # Return the parsed arguments
x = parser.parse_args()


def get_new_session(sts, serial):
    """Get new STS session token.

    Args:
        sts (boto3.sts.client): the STS client to use
        serial (str): a string for the MFA device to use

    Returns:
        boto3.sts.session_token: can be used to get new role tokens
    """
    try:
        if x.mfa:
            mfa = x.mfa
        else:
            mfa = raw_input("What is your MFA code for {}? ".format(x.profile))

        session_token = sts.get_session_token(
            DurationSeconds=10800,
            SerialNumber=serial,
            TokenCode=mfa
        )
        return session_token
    except ClientError as e:
        print("MFA Code is not valid")
        print(e)
        quit()


def write_aws_config(aws_config, config_file):
    """Write updates to the Config object in the specified file."""
    config_file_path = os.path.expanduser(config_file)
    print("Writing!")
    with open(config_file_path, 'w+') as fh:
        aws_config.write(fh)


def get_role(profile=None):
    """Return a new role from STS.

    Args:
        profile (dict, optional): Profile tuple that contains info needed

    Returns:
        boto3.sts.assumed_role: Used later
    """

    arg_list = {
        "RoleArn": 'arn:aws:iam::{}:role/{}'.format(
            profile.account,
            profile.role
        ),
        "RoleSessionName": 'SwitchRole',
        "DurationSeconds": 3600
    }

    if profile.external_id:
        arg_list['ExternalId'] = profile.external_id

    return sts.assume_role(**arg_list)


def mkdir_p(path):
    """Make Directory."""
    try:
        os.makedirs(path)
    except OSError as exc:  # Python >2.5
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise


def update_aws_config(
        part,
        configuration,
        profile,
        config_update,
        default_region='eu-west-1'):
    """Update Config object with passed in details."""
    # Check if part to update is config or creds
    if part == "default":

        if configuration.has_section(profile) and \
           configuration.has_option(profile, "profile"):
            x.profile = configuration.get(profile, "profile")

        if not configuration.has_section("switch-role"):
            configuration.add_section("switch-role")

        if not x.profile and configuration.has_option(
            "switch-role",
            "profile"
        ):
            x.profile = configuration.get("switch-role", "profile")
        elif x.profile and configuration.has_option("switch-role", "profile"):
            configuration.set("switch-role", "profile", x.profile)
        elif x.profile and not configuration.has_option(
            "switch-role",
            "profile"
        ):
            configuration.set("switch-role", "profile", x.profile)
        else:
            x.profile = raw_input(
                """What is the AWS profile you would like to use for \
this request? """
            )
            configuration.set("switch-role", "profile", x.profile)

        if not x.username and configuration.has_option("switch-role", "user"):
            x.username = configuration.get("switch-role", "user")
        elif x.username and configuration.has_option("switch-role", "user"):
            configuration.set("switch-role", "user", x.username)
        elif x.username and not configuration.has_option(
            "switch-role",
            "user"
        ):
            configuration.set("switch-role", "user", x.username)
        else:
            x.username = raw_input(
                """What is the AWS username you would like to use for \
this request? """
            )
            configuration.set("switch-role", "user", x.username)

    if part == "config":
        if not configuration.has_section(profile):
            configuration.add_section(profile)

        configuration.set(profile, 'output', "json")
        configuration.set(profile, 'region', "eu-west-1")

        if not x.role and configuration.has_option(profile, "last_role"):
            x.role = configuration.get(profile, "last_role")
        elif x.role and configuration.has_option(profile, "last_role"):
            configuration.set(profile, "last_role", x.role)
        elif x.role and not configuration.has_option(profile, "last_role"):
            configuration.set(profile, "last_role", x.role)
        else:
            x.role = raw_input(
                "What is the AWS role you would like to use for this request? "
            )
            configuration.set(profile, "last_role", x.role)

        if not x.profile and configuration.has_option(profile, "profile"):
            x.profile = configuration.get(profile, "profile")
        elif x.profile and configuration.has_option(profile, "profile"):
            configuration.set(profile, "profile", x.profile)
        elif x.profile and not configuration.has_option(profile, "profile"):
            configuration.set(profile, "profile", x.profile)
        else:
            x.role = raw_input(
                "What is the Profile you would like to use for this request? "
            )
            configuration.set(profile, "profile", x.profile)

        if not x.account and configuration.has_option(
            profile,
            "account"
        ):
            x.account = configuration.get(profile, "account")
        elif x.account and configuration.has_option(profile, "account"):
            configuration.set(profile, "account", x.account)
        elif x.account and not configuration.has_option(profile, "account"):
            configuration.set(profile, "account", x.account)
        else:
            x.account = raw_input(
                "What is the AWS Account number you would like to switch to? "
            )
            configuration.set(profile, "account", x.account)

        if not x.external_id and configuration.has_option(profile, "external_id"):
            x.external_id = configuration.get(profile, "external_id")
        elif x.external_id and configuration.has_option(profile, "external_id"):
            configuration.set(profile, "external_id", x.external_id)
        elif x.external_id and not configuration.has_option(profile, "external_id"):
            configuration.set(profile, "external_id", x.external_id)

    elif part == "credentials":

        if not configuration.has_section(profile):
            configuration.add_section(profile)

        configuration.set(
            profile,
            'aws_access_key_id',
            config_update['Credentials']['AccessKeyId']
        )
        configuration.set(
            profile,
            'aws_secret_access_key',
            config_update['Credentials']['SecretAccessKey']
        )
        configuration.set(
            profile,
            'aws_security_token',
            config_update['Credentials']['SessionToken']
        )
        configuration.set(
            profile,
            'aws_session_token',
            config_update['Credentials']['SessionToken']
        )

        configuration.set(
            profile,
            'token_expiration',
            config_update['Credentials']['Expiration']
        )

    return configuration

paths = {
    "config": "~/.aws/config",
    "creds": "~/.aws/credentials"
}

aws_config = ConfigParser.ConfigParser()
config_file_path = os.path.expanduser(paths['config'])
aws_config.read([config_file_path])


aws_credentials = ConfigParser.ConfigParser()
credentials_file_path = os.path.expanduser(paths['creds'])
aws_credentials.read([credentials_file_path])


if not x.list:
    aws_config = update_aws_config(
        "default",
        aws_config,
        "profile " + x.name,
        aws_config
    )

    role_got = False
    s = boto3.session.Session(
        profile_name=x.profile
    )
    try:
        account = s.client('sts').get_caller_identity()['Account']
    except Exception as e:
        account = str(e).split('::')[2].split(":")[0]

    serial = "arn:aws:iam::{}:mfa/{}".format(account, x.username)
    aws_conifg = update_aws_config(
        "config",
        aws_config,
        "profile " + x.name,
        ""
    )

    sts = None
    to_check = 'switch-role ' + x.profile
    if aws_credentials.has_section(to_check):
        if aws_credentials.has_option(to_check, 'aws_session_token'):
            try:
                sts = s.client(
                    'sts',
                    aws_access_key_id=aws_credentials.get(
                        to_check, 'aws_access_key_id'
                    ),
                    aws_secret_access_key=aws_credentials.get(
                        to_check, 'aws_secret_access_key'
                    ),
                    aws_session_token=aws_credentials.get(
                        to_check, 'aws_session_token'
                    )
                )
                role_token = get_role(profile=x)
                role_got = True

            except Exception as e:
                print(e)
                pass

    if not role_got:
        sts = s.client('sts')
        session_token = get_new_session(sts, serial)

        print("""Session token obtained for {}... Getting switch role session \
        for {}({}) """.format(x.profile, x.name, x.account))

        sts = s.client(
            'sts',
            aws_access_key_id=session_token['Credentials']['AccessKeyId'],
            aws_secret_access_key=session_token[
                'Credentials'
            ]['SecretAccessKey'],
            aws_session_token=session_token['Credentials']['SessionToken']
        )

        write_aws_config(aws_config, config_file=paths['config'])
        # if x.account is set, use that for arn, if not get from config,
        # if not in config, ask for it and update the config

        role_token = role_token = get_role(profile=x)

        aws_credentials = update_aws_config(
            "credentials",
            aws_credentials,
            "switch-role " + x.profile,
            session_token
        )

    aws_credentials = update_aws_config(
        "credentials",
        aws_credentials,
        x.name,
        role_token
    )

    # load arguments
    # see whats in use already
    write_aws_config(aws_credentials, config_file=paths['creds'])
    print("""Switch role completed - You can now use --profile {} in \
    your aws cli commands""".format(x.name))
else:
    if x.all:
        print("Listing All Profiles")
    else:
        print("Listing Valid Profiles")

    expired = []
    valid = []
    for section in aws_config.sections():
        if "profile" in section:
            if aws_credentials.has_section(section[8:]):
                if aws_credentials.has_option(section[8:], 'token_expiration'):
                    expire = datetime.strptime(aws_credentials.get(
                        section[8:], 'token_expiration'
                    ), '%Y-%m-%d %H:%M:%S+00:00') + timedelta(hours=1)
                    now = datetime.now()
                    if now > expire:
                        msg = "\033[91mExpired\033[00m"
                        expired.append("{} | {}".format(msg, section[8:]))
                    else:
                        diff = (expire - now).seconds / 60
                        if diff < 15:
                            msg = "\033[33m{} minutes remaining\
                             \033[00m".format(diff)
                        else:
                            msg = "\033[92m{} minutes remaining \
                            \033[00m".format(diff)

                        valid.append("{} | {}".format(msg, section[8:]))

    if x.all:
        for n in expired:
            print(n)

    for i in valid:
        print(i)
