#Switchy McSwitch Roles 
Easy Peasy CLI access to switch roles.

Using AWS switch roles has never been easier thanks to **#SwitchyMcSwitchRoles**, running this simple script and telling it what role you want to use will generate you a set of keys you can use for 1 hour for roles we can switch too.


## Easiest Setup:
```
./switchy.py --name amazing-aws
```
You will now be prompted for the following:

* **Account** - Account Number to switch to
* **Role** - Role to switch to in account
* **Profile** - CLI profile to use to switch from
* **Username** - Your username within the account your switching for MFA
* **MFA** - Your MFA code to use in this request

Once you have completed the initial setup, assuming everything is entered correctly, the magical python script will generate you a new profile in *~/.aws/config* and creds in *~/.aws/credentials*.

You will now be able to run normal aws cli commands, specifiying the profile as name you gave it on setup.

```
aws --profile amazing-aws ec2 describe-instances
```

Your keys/profile can also be used in normal AWS scripting SDK's (I recommend using profiles rather than keys to prevent issues when they expire)

###Keys expire###
Your keys will be valid for 1 hour. After this, simply run the inital command as above. This time, you will only be asked for your  MFA code as your original details have been stored against that profile or added to a default block for future use (profile and username are kept for other profiles too)

###Adding other profiles
Once you have added your first profile, your username and profile specified will be stored as defaults for future commands.

If you now run 
```
./switchy.py --name my-new-profile
```

You should now only be prompted for the account number, role to use and MFA code. 


##Overiding stored defaults or running the command with more control
On top of being able to add your profiles easily with the easy setup, you can also specify any of the parameters on command run.

If the profile has already been configured, account number and last role will be updated to use new values supplied (you can supply what you want, i.e account number and role or just role etc)

To run a command in full, you can use the following arguments.

``` --account ``` - Account number to use/override

``` --username ``` - Username to switch from (overrides default value if previously used)

``` --profile ``` - CLI Profile to switch from (overrides default value if previously used)

``` --role ``` - Role to switch to (overrides last_role so will be used for each call after this unless specified)

###Example
```
./switchy.py --profile crprod --account 2313213123 --role AmazingAccess --username boaty.mcboat --name new-awesome-profile
```
You will be asked for an MFA code and end up with the same result as before - you can now just call the command again, specifing ``` --name ``` only to renew your keys.

## Kudos:
You can set up switchymcswitch roles to be accessible anywhere on your terminal session by setting up a alias to the code location.

Add the following to your .bashrc/.zshrc etc:

```bash
export SWITCHROLE="YOUR HOME LOCATION/Repos/switch-role-cli/switchy.py"
alias switch=$SWITCHROLE
```

Save and reload your terminal session.

You can now use:
``` switch --name <profile>``` from anywhere!