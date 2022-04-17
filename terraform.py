from dataclasses import dataclass
import json

class NoOverwriteDict(dict):
    def __setitem__(self, key, value):
        if key in self:
            raise KeyError(key)

        super().__setitem__(key, value)

    def child(self, key):
        try:
            return self[key]
        except KeyError:
            pass

        ret = type(self)()
        self[key] = ret
        return ret


@dataclass(frozen=True)
class Address:
    value: str

    def suffixed(self, suffix):
        return Interpolated("${{{}.{}}}".format(self.value, suffix))


class Code:
    def __init__(self):
        self._code = NoOverwriteDict()

    def child(self, path):
        return self._code.child(path)

    def add_resource(self, *args, **data):
        typ, name = args
        add_to = self._code.child("resource").child(typ)
        add_to[name] = Interpolated.escape(data)
        return Address("{}.{}".format(typ, name))

    def write(self, fh):
        json.dump(self._code, fh, indent=2, sort_keys=True)


class Interpolated(str):
    @classmethod
    def format(cls, fmt, *args, **kwargs):
        args = cls.escape(args)
        kwargs = cls.escape(kwargs)
        return cls(fmt.format(*args, **kwargs))

    @classmethod
    def escape_str(cls, data):
        data = data.replace("${", "$${")
        data = data.replace("%{", "%%{")
        return cls(data)

    @classmethod
    def escape(cls, data):
        if isinstance(data, cls):
            return data

        if isinstance(data, str):
            return cls.escape_str(data)

        if isinstance(data, dict):
            return {cls.escape(k): cls.escape(v) for (k, v) in data.items()}

        try:
            iterable = iter(data)
        except TypeError:
            pass
        else:
            return [cls.escape(x) for x in iterable]

        return data

    @classmethod
    def jsonencode(cls, data):
        return cls(json.dumps(cls.escape(data)))

