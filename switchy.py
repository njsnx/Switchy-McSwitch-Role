#!/Users/Neil/.pyenv/shims/python

"""AWS CLI Switch Roles setup."""

import argparse
import boto3
import errno
import configparser
from botocore.exceptions import ClientError
import os
import json
from datetime import datetime, timedelta

class SwitchyMcSwitchRole(object):


    def __init__(self, config_file='./configuration.json'):

        self.configuration_file = self.load_config(config_file)
        self.aws_config_parts = self.configuration_file['configuration']['aws_config']

        self.setup_argparse()


    def setup_argparse(self):
        parser = argparse.ArgumentParser()
        arguments = self.configuration_file['arguments']
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
        self.passed_arguments = parser.parse_args()

    def load_config(self, config):
        parsed = None
        with open(config) as f:
            parsed = json.load(f)
        return parsed

    def get_new_session(self, sts, serial):
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
                mfa = input("What is your MFA code for {}? ".format(x.profile))

            session_token = sts.get_session_token(
                DurationSeconds=10800,
                SerialNumber=serial,
                TokenCode=mfa
            )
            return session_token
        except ClientError as e:
            print("MFA Code is not valid")
            quit()

    def main(self):



    def write_aws_config(self, aws_config, config_file):
        """Write updates to the Config object in the specified file."""
        config_file_path = os.path.expanduser(config_file)
        with open(config_file_path, 'w+') as fh:
            aws_config.write(fh)


    def get_role(self, profile=None):
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


    def mkdir_p(self, path):
        """Make Directory."""
        try:
            os.makedirs(path)
        except OSError as exc:  # Python >2.5
            if exc.errno == errno.EEXIST and os.path.isdir(path):
                pass
            else:
                raise

    def get_input(self, ask_text):
        """Get User input. Python 2/3 friendly"""
        try:
            return raw_input(ask_text)
        except NameError:
            return input(ask_text)

    def update_aws_config(
            self, 
            part,
            configuration,
            profile,
            config_update,
            default_region='eu-west-1'):
        """Update Config object with passed in details."""
        # Check if part to update is config or creds
        with open('./configuration.json') as f:
            config_parts = json.load(f)['configuration']['aws_config']

        argument_dict = vars(x)    
        if part == "default":

            if configuration.has_section(profile) and \
               configuration.has_option(profile, "profile"):
                x.profile = configuration.get(profile, "profile")

            if not configuration.has_section("switch-role"):
                configuration.add_section("switch-role")

            
            for config_part, config in config_parts['default'].items():
                # if argument not provided but in config
                argument = argument_dict[config['arg']]
                
                
                if not argument and configuration.has_option(
                    "switch-role",
                    config_part
                ):
                    argument_dict[config['arg']] = configuration.get("switch-role", config_part) # set argument to config item
                # elif the argument exists AND config has the option, set the config to be the argument
                elif argument and configuration.has_option("switch-role", config_part):
                    configuration.set("switch-role", config_part, argument)
                # elif argument exists but config DOES NOT have the option, add the option to the config
                elif argument and not configuration.has_option(
                    "switch-role",
                    config_part
                ):
                    configuration.set("switch-role", config_part, argument)
                # if not in config or argument, ask for a value to give 
                else:
                    new_value = get_input(
                        config['input_text']
                    )
                    argument_dict[config['arg']] = new_value
                    configuration.set("switch-role", config_part, new_value)


        if part == "config":
            if not configuration.has_section(profile):
                configuration.add_section(profile)

            configuration.set(profile, 'output', "json")
            configuration.set(profile, 'region', "eu-west-1")

            for config_part, config in config_parts['config'].items():
                argument = argument_dict[config['arg']]

                if not argument and configuration.has_option(profile, config_part):
                    x.role = configuration.get(profile, config_part)
                elif argument and configuration.has_option(profile, config_part):
                    configuration.set(profile, config_part, argument)
                elif argument and not configuration.has_option(profile, config_part):
                    configuration.set(profile, config_part, argument)
                else:

                    input_text = config.get('input_text', None)
                    if input_text:
                        new_value = get_input(
                            config['input_text']
                        )
                        argument_dict[config['arg']] = new_value
                        configuration.set(profile, config_part, new_value)

        elif part == "credentials":
            cred_parts = {
                'aws_access_key_id': 'AccessKeyId',
                'aws_secret_access_key': 'SecretAccessKey',
                'aws_security_token': 'SessionToken',
                'aws_session_token': 'SessionToken',
                'token_expiration': 'Expiration',
            }


            if not configuration.has_section(profile):
                configuration.add_section(profile)

            for part, value in cred_parts.items():

                configuration.set(
                    profile,
                    part,
                    config_update['Credentials'][value]
                )

        return configuration
