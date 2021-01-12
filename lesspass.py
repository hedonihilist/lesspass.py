#!/usr/bin/env python
import os
import sys
import json
import getpass
import hashlib
import binascii
import argparse


"""lesspass implementation in Python"""
# Based on https://github.com/mevdschee/lesspass.py


CHARACTER_SUBSETS = {
    'lowercase': 'abcdefghijklmnopqrstuvwxyz',
    'uppercase': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    'numbers': '0123456789',
    'symbols': '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
}

def _get_password_profile(password_profile):
    default_password_profile = {
        'lowercase': True,
        'uppercase': True,
        'numbers': True,
        'symbols': True,
        'digest': 'sha256',
        'iterations': 100000,
        'keylen': 32,
        'length': 16,
        'counter': 1,
        'version': 2
    }
    result = default_password_profile.copy()
    if password_profile != None:
        result.update(password_profile)
    return result

def generate_password(site, login, master_password, password_profile=None):
    """generate_password generates a v2 lesspass password"""
    password_profile = _get_password_profile(password_profile)
    entropy = _calc_entropy(site, login, master_password, password_profile)
    return _render_password(entropy, password_profile)

def _calc_entropy(site, login, master_password, password_profile):
    salt = site + login + hex(password_profile['counter'])[2:]
    return binascii.hexlify(hashlib.pbkdf2_hmac(
        password_profile['digest'],
        master_password.encode('utf-8'),
        salt.encode('utf-8'),
        password_profile['iterations'],
        password_profile['keylen']
    ))

def _get_set_of_characters(rules=None):
    if rules is None:
        return (
            CHARACTER_SUBSETS['lowercase'] +
            CHARACTER_SUBSETS['uppercase'] +
            CHARACTER_SUBSETS['numbers'] +
            CHARACTER_SUBSETS['symbols']
        )
    set_of_chars = ''
    for rule in rules:
        set_of_chars += CHARACTER_SUBSETS[rule]
    return set_of_chars

def _consume_entropy(generated_password, quotient, set_of_characters, max_length):
    if len(generated_password) >= max_length:
        return [generated_password, quotient]
    quotient, remainder = divmod(quotient, len(set_of_characters))
    generated_password += set_of_characters[remainder]
    return _consume_entropy(generated_password, quotient, set_of_characters, max_length)

def _insert_string_pseudo_randomly(generated_password, entropy, string):
    for letter in string:
        quotient, remainder = divmod(entropy, len(generated_password))
        generated_password = (
            generated_password[:remainder] +
            letter +
            generated_password[remainder:]
        )
        entropy = quotient
    return generated_password

def _get_one_char_per_rule(entropy, rules):
    one_char_per_rules = ''
    for rule in rules:
        value, entropy = _consume_entropy('', entropy, CHARACTER_SUBSETS[rule], 1)
        one_char_per_rules += value
    return [one_char_per_rules, entropy]

def _get_configured_rules(password_profile):
    rules = ['lowercase', 'uppercase', 'numbers', 'symbols']
    return [rule for rule in rules if rule in password_profile and password_profile[rule]]

def _render_password(entropy, password_profile):
    rules = _get_configured_rules(password_profile)
    set_of_characters = _get_set_of_characters(rules)
    password, password_entropy = _consume_entropy(
        '',
        int(entropy, 16),
        set_of_characters,
        password_profile['length'] - len(rules)
    )
    characters_to_add, character_entropy = _get_one_char_per_rule(password_entropy, rules)
    return _insert_string_pseudo_randomly(password, character_entropy, characters_to_add)



LESSPASS_PROFILES_DIR='~/.lesspass'
LESSPASS_CONFIG_FILENAME='lesspass.json'

class IncompleteProfile(Exception):
    def __init__(self, field):
        self.field = field

    def get_field(self):
        return self.field

def load_profile(name):
    dir_path = os.path.expanduser(LESSPASS_PROFILES_DIR)
    profile_path = os.path.join(dir_path, "{}.json".format(name))

    with open(profile_path, 'r') as f:
        profile = json.loads(f.read())
        return profile

    return None

def main(site, login, profile = None):
    try:
        user_profile = profile if profile else {}
        if site is None and login is None:
            if 'login' not in user_profile:
                raise IncompleteProfile('login')

            if 'site' not in user_profile:
                raise IncompleteProfile('site')

            site = user_profile['site']
            login = user_profile['login']

        password_profile = _get_password_profile(user_profile)
        master_password = getpass.getpass("LessPass Master Password: ")
        password = generate_password(site, login,
                                              master_password, password_profile)
        return password
    except KeyboardInterrupt:
        print("Program stopped by user!", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError as err:
        print("Profile {} not found!".format(profile), file=sys.stderr)
        sys.exit(1)
    except IncompleteProfile as err:
        msg = "You should set {} in your profile " \
              "file or set it in command line!".format(err.get_field())
        print(msg, file=sys.stderr)
        sys.exit(2)
    except BaseException as e:
        print("An error occurred!", file=sys.stderr)
        sys.exit(1)

def find_config_file(args):
    if args.config_file is not None:
        return args.config_file

    # look for config file in current directory
    config_file = LESSPASS_CONFIG_FILENAME
    cdir = os.getcwd()
    hdir = os.path.expanduser('~')

    local_config = os.path.join(cdir, config_file)
    user_config = os.path.join(hdir, config_file)

    if os.path.exists(local_config):
        return local_config
    if os.path.exists(user_config):
        return user_config
    return None

def find_config_file_or_create(args):
    config_file = find_config_file(args)
    if config_file is not None and os.path.exists(config_file):
        return config_file
    config_dir = os.getcwd()
    config_file = os.path.join(config_dir, LESSPASS_CONFIG_FILENAME)
    with open(config_file, 'w') as f:
        json.dump({}, f, indent=2)
    return config_file

def get_profile_list_from_config_file(args):
    config_file = find_config_file_or_create(args)

    with open(config_file, 'r') as f:
        configs = json.load(f)
    return configs

def add_profile_to_config_file(args):
    config_file = find_config_file_or_create(args)

    with open(config_file, 'r') as f:
        configs = json.load(f)
    if args.profile_name in configs:
        print('profile already exist:', file=sys.stderr)
        print(json.dumps(configs[args.profile_name], indent=2))
        sys.exit(-1)

    # add new profile
    profile = {
            'name':args.profile_name,
            'site':args.site,
            'login':args.login
            }

    configs[args.profile_name] = profile
    with open(config_file, 'w') as f:
        json.dump(configs, f, indent=2)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--list-all-profile', help='list all the saved profile', action='store_true', default=False)
    parser.add_argument('--show-details', help='show details of a profile', action='store_true', default=False)
    parser.add_argument('-l', '--login', help='Specify the login account')
    parser.add_argument('-s', '--site', help='Site you want to login into')
    parser.add_argument('-f', '--config-file', help='Specify the config file.')
    parser.add_argument('-S', '--save', action='store_true', help='Save profile to config file')
    parser.add_argument('profile_name', nargs='?', help='which profile name to use', default=None)

    return parser.parse_args()


def use_profile(args):
    if args.site is not None and args.login is not None:
        return False
    return True


def use_site_login(args):
    return use_profile(args)


if __name__ == '__main__':
    argc = len(sys.argv)
    args = parse_args()
    password = None

    # actually it's a dict, not list
    profile_list = get_profile_list_from_config_file(args)

    if args.list_all_profile:
        for profile,v in profile_list.items():
            print('{}\t{}'.format(profile, v['login']))
        sys.exit(0)

    if args.show_details:
        if args.profile_name is None:
            print('please specify the profile name', file=sys.stderr)
            sys.exit(-1)
        if args.profile_name not in profile_list:
            print('profile not in config file', file=sys.stderr)
            sys.exit(-1)
        print(json.dumps(profile_list[args.profile_name], indent=2))
        sys.exit(0)

    # calculate password
    if use_profile(args):
        if profile_list is None or args.profile_name not in profile_list:
            print('no such profile', file=sys.stderr)
            sys.exit(1)
        profile = profile_list[args.profile_name]
        # got profile
        password = main(profile['site'], profile['login'])
    else:
        # use site and login
        if args.site is None or args.login is None:
            print('site or login not provided', file=sys.stderr)
            sys.exit(1)
        password = main(args.site, args.login)

    # save profile
    if args.save:
        if args.profile_name is None:
            print('please specify profile name', file=sys.stderr)
            sys.exit(1)
        print('saving %s' % args.profile_name, file=sys.stderr)
        add_profile_to_config_file(args)

    # output password
    print(password, end='')
