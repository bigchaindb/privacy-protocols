import json


class Store:
    def __init__(self, name):
        self.path = '.{}.bcdb_store'.format(name)
        try:
            with open(self.path, 'r') as fh:
                self._store = json.load(fh)
        except FileNotFoundError:
            self._store = {}

    def set(self, key, value):
        self._store[key] = value
        return self

    def get(self, key):
        return self._store[key]

    def sync(self):
        with open(self.path, 'w') as fh:
            json.dump(self._store, fh, sort_keys=True, indent=4)
        return self
