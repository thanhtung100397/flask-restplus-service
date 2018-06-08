import datetime

import json

from sqlalchemy.ext.declarative import DeclarativeMeta


def format_date(date, date_format='%d/%m/%Y'):
    return datetime.datetime(date.year, date.month, date.day, 0, 0).strftime(date_format)


def toJson(obj):
    return json.dumps(obj, cls=AlchemyEncoder, ensure_ascii=False)


def toDict(obj):
    fields = {}
    for field in [x for x in dir(obj) if not x.startswith('_') and x != 'metadata']:
        if field in obj.__class__.__dict__:
            data = obj.__getattribute__(field)
            try:
                json.dumps(data)
                fields[field] = data
            except TypeError:
                if isinstance(data, datetime.date):
                    fields[field] = format_date(data)
                else:
                    fields[field] = None
    return fields

class AlchemyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj.__class__, DeclarativeMeta):
            return toDict(obj)
        return json.JSONEncoder.default(self, obj)
