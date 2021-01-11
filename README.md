# lesspass.py

A modified version of lesspass from [mevdschee](https://github.com/mevdschee/lesspass.py)

## Usage

Generate password:

```shell
$ python lesspass.py -s github.com -l youremail@gmail.com
```

Generate password and save the profile named 'github':

```shell
$ python lesspass.py github -S -s github.com -l youremail@gmail.com
```

Use the saved profile 'github' and generate password:

```shell
$ python lesspass.py github
```

List all saved profiles:

```shell
$ python lesspass.py --list-all-profile
```

Show 'github' profile details:

```shell
$ python lesspass.py github --show-details
```

