#!/Users/Neil/.pyenv/shims/python
"""MFA Chameleon."""
import boto3
import base64
import os
import keyring
import qrcode
import argparse
from subprocess import check_output
try:
    import configparser
except:
    import ConfigParser
import clipboard


class MFAChameleon:
    """MFA Chameleon Class."""

    def __init__(self, account=None):
        """Init Method."""
        self.debug = False
        self.new = False
        self.serial = None

        if not account:

            parser = argparse.ArgumentParser()
            parser.add_argument(
                "account", type=str, help="The account to work with"
            )
            parser.add_argument("-n", "--new", action='store_true')
            parser.add_argument("-s", "--serial")
            parser.add_argument("-d", "--debug", action='store_true')
            parser.add_argument("-l", "--list", action='store_true')

            self.args = parser.parse_args()
            self.account = self.args.account
            self.debug = self.args.debug
            self.new = self.args.new
            self.serial = self.args.serial
        if account:
            self.account = account

        self.session = boto3.session.Session(
            profile_name=os.environ['mfa_cham_profile'],
            region_name="eu-west-1"
        )
        self.location = "{}/.mfa".format(os.path.expanduser('~'))

    def encrypt(self, content, account):
        """Encrypt a value."""
        return base64.b64encode(
            self.session.client('kms').encrypt(
                KeyId=os.environ['mfa_cham_key'],
                Plaintext=content,
                EncryptionContext={
                    "MFAChameleon": "Encrypt{}".format(account.title())
                }
            )['CiphertextBlob']
        ).decode("utf-8")

    def decrypt(self, blob, account):
        """Decrypt a value."""
        serial = self.session.client('kms').decrypt(
            CiphertextBlob=base64.b64decode(blob),
            EncryptionContext={
                "MFAChameleon": "Encrypt{}".format(account.title())
            }
        )['Plaintext'].decode('utf-8')
        if self.debug:
            print("DEBUG: Serial: {}".format(serial))
        return serial

    def get_mfa(self, account):
        """Get MFA."""
        config, cfg = self.load_config()
        keychain = keyring.get_password("MFAChameleon", account)

        if keychain:
            serial = self.decrypt(keychain, account)
            output = check_output(
                ["/usr/local/bin/oathtool", "--totp", "-b", serial]
            ).decode('utf-8')
            clipboard.copy(output)

            return output.strip('\n'), serial
        else:
            print("Can't find a Keychain item for {a}".format(a=account))
        return None, None

    def load_config(self):
        """Load Config."""
        cfgfile = "{}/accounts".format(self.location)

        try:
            config = configparser.ConfigParser()
        except:
            config = ConfigParser.ConfigParser()

        config.read([cfgfile])

        return config, self.location

    def save(self, content, account):
        """Save the config file."""
        config, location = self.load_config()
        keychain = keyring.get_password("MFAChameleon", account)

        if keychain:
            print("Keychain already exists for {a}".format(a=account))
        else:
            keychain = keyring.set_password("MFAChameleon", account, content)

    def create_qr(self, serial, account):
        """Create QR Code."""
        x = "otpauth://totp/{account}?secret={serial}&issuer={account}".format(
            account=account,
            serial=serial
        )

        qr = qrcode.QRCode(
            version=1,
            box_size=2
        )

        qr.add_data(x)

        img = qr.make_image()
        img.save(
            "{}/{}.png".format(
                self.location,
                account
            ),
            "PNG"
        )

        check_output(["open", "{}/{}.png".format(
            self.location,
            account
        )]).decode('utf-8')

    def main(self):
        """Main method."""
        account = self.account
        is_new = self.new
        serial = self.serial

        if is_new and serial:
            print("Creating new setup for {}".format(account))

            encrypted = self.encrypt(serial, account)
            self.save(encrypted, account)
            mfa, serial = self.get_mfa(account)
            if mfa:
                self.create_qr(serial, account)

        else:
            mfa, serial = self.get_mfa(account)

        return mfa

if __name__ == '__main__':

    mfa = MFAChameleon()
    print(mfa.main())
