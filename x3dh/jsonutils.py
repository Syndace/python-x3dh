from __future__ import absolute_import

import json

def loadFromFile(path, default, execute = False):
    """
    Try to load JSON encoded data from a file.
    If loading files, return a default value.
    If execute is True, treat default as a function that generates the default value.
    """

    try:
        with open(path, "r") as f:
            return json.load(f)
    except (IOError, TypeError):
        if execute:
            return default()
        else:
            return default

def dumpToFile(path, data):
    """
    Save given data to a json file.
    """

    with open(path, "w") as f:
        json.dump(data, f)
